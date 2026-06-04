"""SQLite-Adapter fuer den Port ``MetricsReader`` (M.8): liest den metrics-Querschnitt.

Aggregiert frisch aus FUENF Quell-Tabellen derselben ``cernis.db``
(``devices`` / ``rtt_history`` / ``sla_samples`` / ``scan_history`` / ``alert_history``)
in ein ``MetricsSnapshot``. Reproduziert die SQL-Aggregate des Altcode
``modules/metrics.py`` -- aber gespeist in das reine Domaenen-Aggregat statt direkt in
Export-Text.

``alert_history`` (A.7b): in M.8 als FUENFTE Quelle BEWUSST ausgelassen -- alerting war
nicht migriert, ein direkter Lese-Block waere Vorwaerts-Kopplung an eine nicht-existente
v2-Domaene gewesen. Ab A.7a beschreibt der monitor-Trigger ``alert_history`` real, darum
jetzt freigeschaltet: ``_read_alerts`` zaehlt die Zeilen der letzten 24h (epoch-float
``ts``-Konvention, wie rtt/sla). Der Reader liest die Tabelle DIREKT per SQL (wie alle
anderen Quellen), NICHT ueber den alerting-Port -- das ist die M.8-Trennung: metrics ist
Querschnitt-Leser, kennt die TABELLEN, nicht die Domaenen. Charakterisierungstreu rendert
nur ``to_prometheus`` das Feld (Altcode fuehrte ``cernis_alerts_24h`` nur dort; influx/HA
nie -- KEINE Format-Erweiterung in A.7b).

REINER KONSUMENT -- legt KEINE Tabellen an (kein ``_ensure_schema``, anders als die
schreibenden Repos und anders als der M.7-Lese-Adapter, der charakterisierungstreu
``CREATE IF NOT EXISTS`` machte). Begruendung: Eine fehlende Tabelle IST der
leere-DB-Fall und MUSS ``0``/``[]`` ergeben, nicht eine vom Reader frisch angelegte
Leer-Tabelle. Die vier Quell-Tabellen werden von ihren eigenen schreibenden Adaptern
angelegt; der metrics-Reader liest nur, was da ist.

leere-DB-Robustheit (M.8, die bewusste v2-Verbesserung gegenueber dem kaputten v1):
JEDES der fuenf Aggregate ist EINZELN gegen ``sqlite3.OperationalError`` gekapselt
(fehlende Tabelle/Spalte) -> liefert dann seinen Null-Default (``0`` bzw. ``[]``),
NIE einen Throw. Damit heilt der Reader strukturell den Altcode-Bug (Device-Block
ohne inneres try -> ganze ``/metrics``-ERROR-Zeile / HA-error-state bei leerer DB):
der Null-Snapshot ist ein valider Zustand -> valide leere/0-Export-Ausgabe.

ZWEI ZEITKONVENTIONEN -- BEWUSST NICHT VEREINHEITLICHT (Altcode-IST):
* ``rtt_history`` / ``sla_samples``: Spalte ``ts`` ist epoch-float -> Vergleich gegen
  ``time.time() - N`` (Sekunden).
* ``devices`` / ``scan_history``: Spalten ``last_seen`` / ``scanned_at`` sind ISO-Text
  (DEFAULT ``datetime('now')``) -> Vergleich per ``datetime('now', '-X')`` in SQL.
Diese Divergenz ist Altcode-Realitaet; sie hier zu vereinheitlichen waere eine
verdeckte Verhaltensaenderung. Im Kommentar markiert, damit sie nicht spaeter als
Inkonsistenz "korrigiert" wird.

``ts``-Fenster wie der Altcode: RTT latest-per-target ueber die letzten 5 Minuten
(``time.time() - 300``), SLA 24h (``- 86400``). Devices: 1h + 24h (zwei Fenster,
darum zwei ``SUM(CASE ...)`` in einer Query). Scan: 7 Tage.

Kennt ``domain.metrics``-Modelle (erlaubt: infrastructure implementiert ports + kennt
domain). ``modules``-frei (import-linter-Contract; metrics ist NICHT unter der
scanning/monitoring-Ausnahme).
"""

import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.metrics import MetricsSnapshot, RttPoint, SlaPoint

# Zeitfenster (Sekunden) -- Altcode-treu.
_RTT_WINDOW_S = 300  # letzte 5 Minuten: latest-per-target RTT
_SLA_WINDOW_S = 86400  # letzte 24h: SLA-Aggregat
_ALERTS_WINDOW_S = 86400  # letzte 24h: alert_history-COUNT (A.7b)


class SqliteMetricsReader:
    """Erfuellt das ``MetricsReader``-Protocol strukturell (SQLite, NUR lesen)."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        # KEIN _ensure_schema: reiner Konsument (s. Modul-Docstring).

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def snapshot(self) -> MetricsSnapshot:
        """Aktueller metrics-Querschnitt -- jedes Aggregat einzeln, leere-DB-robust."""
        now = time.time()
        with self._connect() as conn:
            devices = self._read_devices(conn)
            rtt_points = self._read_rtt_points(conn, now)
            sla_points = self._read_sla_points(conn, now)
            scans = self._read_scans(conn)
            alerts_24h = self._read_alerts(conn, now)

        return MetricsSnapshot(
            device_total=devices["total"],
            device_known=devices["known"],
            device_unknown=devices["unknown"],
            device_active_1h=devices["active_1h"],
            device_active_24h=devices["active_24h"],
            rtt_points=rtt_points,
            sla_points=sla_points,
            scans_7d=scans["scans_7d"],
            scan_hosts_max=scans["scan_hosts_max"],
            alerts_24h=alerts_24h,
        )

    # ── devices (ISO-Text-Zeitachse) ─────────────────────────────────────────

    def _read_devices(self, conn: sqlite3.Connection) -> dict[str, int]:
        """Device-Zaehler inkl. ZWEIER Aktiv-Fenster (1h UND 24h) -- ISO-Text-Vergleich.

        Fehlende ``devices``-Tabelle -> alle Zaehler ``0`` (leere-DB-Fall, kein Throw).
        """
        try:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN is_known = 1 THEN 1 ELSE 0 END) AS known,
                    SUM(CASE WHEN is_known = 0 THEN 1 ELSE 0 END) AS unknown,
                    SUM(CASE WHEN last_seen > datetime('now', '-1 hour')
                        THEN 1 ELSE 0 END) AS active_1h,
                    SUM(CASE WHEN last_seen > datetime('now', '-1 day')
                        THEN 1 ELSE 0 END) AS active_24h
                FROM devices
                """
            ).fetchone()
        except sqlite3.OperationalError:
            row = None
        if row is None:
            return {"total": 0, "known": 0, "unknown": 0, "active_1h": 0, "active_24h": 0}
        # SUM ueber 0 Zeilen -> NULL: ``or 0`` faengt das (Altcode-Muster).
        return {
            "total": row["total"] or 0,
            "known": row["known"] or 0,
            "unknown": row["unknown"] or 0,
            "active_1h": row["active_1h"] or 0,
            "active_24h": row["active_24h"] or 0,
        }

    # ── rtt_history (epoch-float-Zeitachse) -- latest pro Target ──────────────

    def _read_rtt_points(self, conn: sqlite3.Connection, now: float) -> tuple[RttPoint, ...]:
        """Letzter RTT je Target im 5-Min-Fenster -- liest ``alive`` (M.4-Fix sichtbar).

        ``GROUP BY target_id HAVING MAX(ts)`` (Altcode-influx-Variante) -> je Target
        die juengste Zeile. Fehlende Tabelle/Spalte ``alive`` -> ``()`` (leere-DB-Fall).
        """
        try:
            rows = conn.execute(
                """
                SELECT target_id, rtt_ms, alive
                FROM rtt_history
                WHERE ts > ?
                GROUP BY target_id
                HAVING MAX(ts)
                """,
                (now - _RTT_WINDOW_S,),
            ).fetchall()
        except sqlite3.OperationalError:
            return ()
        return tuple(
            RttPoint(
                target_id=row["target_id"],
                rtt_ms=row["rtt_ms"] if row["rtt_ms"] is not None else 0.0,
                alive=bool(row["alive"]),
            )
            for row in rows
        )

    # ── sla_samples (epoch-float-Zeitachse) -- 24h-GROUP-BY-Aggregat ──────────

    def _read_sla_points(self, conn: sqlite3.Connection, now: float) -> tuple[SlaPoint, ...]:
        """24h-SLA-Aggregat je Target (uptime% + avg_rtt) -- Altcode-GROUP-BY.

        ``uptime_pct`` = ``alive_count / total * 100`` (3 Dez); ``avg_rtt_ms`` =
        Mittel der RTTs mit ``rtt_ms > 0`` (2 Dez) oder ``None``, wenn keine -- die
        ``None``-Semantik traegt die "avg-Zeile weglassen"-Regel in die Format-Funktion
        (Altcode ``if row["avg_rtt"]``). Fehlende Tabelle -> ``()``.
        """
        try:
            rows = conn.execute(
                """
                SELECT target_id,
                    COUNT(*) AS total,
                    SUM(alive) AS alive_count,
                    AVG(CASE WHEN rtt_ms > 0 THEN rtt_ms END) AS avg_rtt
                FROM sla_samples
                WHERE ts > ?
                GROUP BY target_id
                """,
                (now - _SLA_WINDOW_S,),
            ).fetchall()
        except sqlite3.OperationalError:
            return ()
        points: list[SlaPoint] = []
        for row in rows:
            total = row["total"] or 0
            alive_count = row["alive_count"] or 0
            uptime = round(alive_count / total * 100, 3) if total else 0.0
            avg_rtt = round(row["avg_rtt"], 2) if row["avg_rtt"] else None
            points.append(
                SlaPoint(target_id=row["target_id"], uptime_pct=uptime, avg_rtt_ms=avg_rtt)
            )
        return tuple(points)

    # ── scan_history (ISO-Text-Zeitachse) -- 7d-Aggregat ──────────────────────

    def _read_scans(self, conn: sqlite3.Connection) -> dict[str, int]:
        """Scan-Aggregat der letzten 7 Tage: Anzahl + max host_count -- ISO-Text-Vergleich.

        Fehlende ``scan_history``-Tabelle -> ``0``/``0`` (leere-DB-Fall).
        """
        try:
            row = conn.execute(
                """
                SELECT COUNT(*) AS total, MAX(host_count) AS max_hosts
                FROM scan_history
                WHERE scanned_at > datetime('now', '-7 days')
                """
            ).fetchone()
        except sqlite3.OperationalError:
            row = None
        if row is None:
            return {"scans_7d": 0, "scan_hosts_max": 0}
        return {"scans_7d": row["total"] or 0, "scan_hosts_max": row["max_hosts"] or 0}

    # ── alert_history (epoch-float-Zeitachse) -- 24h-COUNT (A.7b) ──────────────

    def _read_alerts(self, conn: sqlite3.Connection, now: float) -> int:
        """Anzahl der ``alert_history``-Zeilen der letzten 24h -- epoch-float-Vergleich.

        Altcode-treu (``modules/metrics.py`` Alert-Block): ``SELECT COUNT(*) FROM
        alert_history WHERE ts > ?`` mit ``ts > now - 86400``. ``ts`` ist epoch-float
        (gehoert zur rtt/sla-Konvention, NICHT zur ISO-Text-Konvention von
        devices/scan -- BEWUSST nicht vereinheitlicht). Fehlende ``alert_history``-
        Tabelle -> ``0`` (leere-DB-Fall, kein Throw); ``COUNT`` ueber 0 Zeilen ist 0,
        das ``or 0`` faengt den NULL-Rand (Altcode-Muster). Da ``alert_history`` ab
        A.7a real beschrieben wird, ist der 0-Fall = leere History.
        """
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS total FROM alert_history WHERE ts > ?",
                (now - _ALERTS_WINDOW_S,),
            ).fetchone()
        except sqlite3.OperationalError:
            return 0
        if row is None:
            return 0
        return int(row["total"] or 0)
