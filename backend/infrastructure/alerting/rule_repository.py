"""SQLite-Adapter fuer ``AlertRuleRepository`` (Altcode-Tabellen ``alert_rules`` +
``alert_history``).

Basiert auf ``modules/alerting.py`` (``init_alerts_db``/``get_rules``/``add_rule``/
``update_rule``/``delete_rule``/``get_alert_history``/``_save_alert_event``), im Stil
von ``SqliteRttHistoryRepository``: ``@contextmanager _connect`` mit Transaktion +
garantiertem close, ``_ensure_schema`` im Konstruktor, injizierter DB-Pfad. KEIN
``modules``-Import -- eigenes Schema, deckungsgleich mit dem Altcode-init.

SCHEMA (kein Migrations-Guard noetig): Das v2-Schema ist BYTE-deckungsgleich mit
``modules.alerting.init_alerts_db`` (gleiche Spalten/Defaults). ``CREATE TABLE IF NOT
EXISTS`` ist daher gegen eine vom Altcode angelegte Tabelle ein No-Op -- anders als
``rtt_history.alive`` (M.4), wo eine Spalte fehlte. v2-Adapter und A.1-Altcode-Pfad
teilen sich dieselbe Tabelle (per Test ``test_reads_altcode_table_without_guard``
gegen die nachgebaute Altcode-Tabelle belegt).

GEHEILTER PFAD (A.1-v2-Heilung): ``_ensure_schema`` laeuft im ``__init__`` -> beide
Tabellen existieren immer, bevor gelesen wird. ``recent`` gegen eine leere-aber-
initialisierte DB gibt ``[]`` statt zu werfen. Der Altcode-``get_alert_history`` rief
``init_alerts_db`` NICHT und warf gegen eine DB ohne Tabelle ``OperationalError``
(-> HTTP 500); das friert A.1 als geheilten Zustand bereits ein.

int<->bool am RAND: Die Flags (``enabled``/``notify_email``/``notify_macos``) sind in
SQLite INTEGER 0/1 (Altcode-Wire-Vertrag, A.1). Der Adapter liest sie als
``bool(row[...])`` in die Domaenen-``AlertRule`` (A.2: bool) und schreibt
``int(bool)`` zurueck. Domaene (bool) und A.1-Altcode-Pfad (int) bleiben beide
unberuehrt.
"""

import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.alerting import AlertEvent, AlertRule

# Whitelist der via ``update`` aenderbaren Felder (exakt Altcode ``update_rule``).
_UPDATABLE = ("name", "target", "threshold", "notify_email", "notify_macos", "enabled")


class SqliteAlertRuleRepository:
    """Erfuellt das ``AlertRuleRepository``-Protocol strukturell (SQLite)."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._ensure_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        # Deckungsgleich mit modules.alerting.init_alerts_db -> CREATE IF NOT EXISTS
        # ist No-Op gegen eine vom Altcode angelegte Tabelle (kein ALTER-Guard noetig).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS alert_rules (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    name            TEXT,
                    rule_type       TEXT,
                    target          TEXT DEFAULT 'any',
                    threshold       INTEGER DEFAULT 60,
                    notify_email    INTEGER DEFAULT 0,
                    notify_macos    INTEGER DEFAULT 1,
                    enabled         INTEGER DEFAULT 1,
                    last_triggered  REAL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS alert_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id     INTEGER,
                    rule_name   TEXT,
                    rule_type   TEXT,
                    target      TEXT,
                    message     TEXT,
                    ts          REAL,
                    datetime    TEXT
                );
                """
            )

    # ── rules ─────────────────────────────────────────────────

    def get_rules(self) -> list[AlertRule]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM alert_rules ORDER BY id").fetchall()
        return [self._row_to_rule(row) for row in rows]

    def add(
        self,
        name: str,
        rule_type: str,
        target: str,
        threshold: int,
        notify_email: bool,
        notify_macos: bool,
    ) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO alert_rules "
                "(name, rule_type, target, threshold, notify_email, notify_macos) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (name, rule_type, target, threshold, int(notify_email), int(notify_macos)),
            )
            rule_id = cursor.lastrowid
        # lastrowid ist nach erfolgreichem INSERT mit AUTOINCREMENT immer gesetzt.
        assert rule_id is not None
        return rule_id

    def update(
        self,
        rule_id: int,
        *,
        name: str | None = None,
        target: str | None = None,
        threshold: int | None = None,
        notify_email: bool | None = None,
        notify_macos: bool | None = None,
        enabled: bool | None = None,
    ) -> None:
        # Nur gesetzte (nicht-None) Felder schreiben -- Whitelist wie Altcode.
        # bool->int am Rand fuer die Flag-Spalten.
        candidates: dict[str, object] = {
            "name": name,
            "target": target,
            "threshold": threshold,
            "notify_email": None if notify_email is None else int(notify_email),
            "notify_macos": None if notify_macos is None else int(notify_macos),
            "enabled": None if enabled is None else int(enabled),
        }
        updates = {k: v for k, v in candidates.items() if v is not None and k in _UPDATABLE}
        if not updates:
            return
        assignments = ", ".join(f"{k} = ?" for k in updates)
        params = [*updates.values(), rule_id]
        with self._connect() as conn:
            conn.execute(f"UPDATE alert_rules SET {assignments} WHERE id = ?", params)

    def delete(self, rule_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))

    def clear_all(self) -> None:
        # Beide eigenen Tabellen (Regeln + Historie) in EINER Transaktion raeumen.
        with self._connect() as conn:
            conn.execute("DELETE FROM alert_rules")
            conn.execute("DELETE FROM alert_history")

    # ── history ───────────────────────────────────────────────

    def save_event(self, event: AlertEvent) -> None:
        # History-Insert + last_triggered der Regel auf event.timestamp setzen
        # (Altcode _save_alert_event). datetime-Spalte aus ts formatiert (Rand-Form).
        datetime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.timestamp))
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO alert_history "
                "(rule_id, rule_name, rule_type, target, message, ts, datetime) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    event.rule_id,
                    event.rule_name,
                    event.rule_type,
                    event.target,
                    event.message,
                    event.timestamp,
                    datetime_str,
                ),
            )
            conn.execute(
                "UPDATE alert_rules SET last_triggered = ? WHERE id = ?",
                (event.timestamp, event.rule_id),
            )

    def recent(self, limit: int) -> list[AlertEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT rule_id, rule_name, rule_type, target, message, ts "
                "FROM alert_history ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            AlertEvent(
                rule_id=row["rule_id"],
                rule_name=row["rule_name"],
                rule_type=row["rule_type"],
                target=row["target"],
                message=row["message"],
                timestamp=row["ts"],
            )
            for row in rows
        ]

    # ── mapping ───────────────────────────────────────────────

    @staticmethod
    def _row_to_rule(row: sqlite3.Row) -> AlertRule:
        # int 0/1 -> bool am Rand (A.2-Domaene ist bool).
        return AlertRule(
            id=row["id"],
            name=row["name"],
            rule_type=row["rule_type"],
            target=row["target"],
            threshold=row["threshold"],
            notify_email=bool(row["notify_email"]),
            notify_macos=bool(row["notify_macos"]),
            enabled=bool(row["enabled"]),
            last_triggered=row["last_triggered"],
        )
