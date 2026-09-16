"""SQLite-Adapter fuer das CVE-Acknowledge-Audit (``CveAcknowledgementRepository``).

GENAU nach dem ADR-0031-Muster (``analysis_acknowledgements_db.py``): APPEND-ONLY Log,
jedes ack/unack ist eine NEUE Zeile, nichts wird je geloescht/ueberschrieben. Der
effektive Status eines (mac, cve_id, port) ist eine reine ABLEITUNG -- der JUENGSTE
Eintrag (groesste id) gewinnt: ``ack`` -> quittiert, ``unack`` -> wieder scharf. EINE
Wahrheit, kein zweiter Statusspeicher.

Granularitaet PORT-GENAU pro (mac, cve_id, port) (ADR 0037): das ist die volle Befund-
Identitaet -- quittiert man "diese CVE auf diesem Port dieses Hosts", betrifft das genau
diesen Befund; dieselbe CVE auf einem ANDEREN Port bleibt scharf. Konsistent zum
analysis-Vorbild (dort (mac, port)), nur um die cve_id ergaenzt, weil ein Port mehrere
CVEs tragen kann.

Stil EXAKT wie das analysis-Vorbild: injizierter ``db_path``, ``_ensure_schema`` im
``__init__``, ``@contextmanager _connect`` mit Transaktion + garantiertem ``close``,
``CREATE TABLE IF NOT EXISTS``, ``CHECK(action IN ('ack','unack'))`` (lauter Fehler statt
Muell). KEIN ``modules``-Import, kein stiller Fallback noetig (nur nackte Spalten).
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import structlog

from infrastructure._cve_mac import migrate_macs_to_upper, normalize_mac_case
from ports.devices import Clock

__all__ = ["SqliteCveAcknowledgementRepository"]

_logger = structlog.get_logger(__name__)


class SqliteCveAcknowledgementRepository:
    """Persistiert ack/unack-Aktionen der CVE-Befunde als append-only Log (ADR 0037)."""

    def __init__(self, db_path: Path, clock: Clock) -> None:
        self._db_path = db_path
        # Die EINE Zeitquelle (timezone-aware UTC); Verdrahtung im Composition Root.
        self._clock = clock
        self._ensure_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Connection mit Transaktion (commit/rollback) und garantiertem close."""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        # Append-only Log: AUTOINCREMENT-id ist die strenge zeitliche Ordnung (auch bei
        # gleichem created_at-Sekundenwert). action per CHECK auf 'ack'/'unack' begrenzt.
        # created_at wird in record() explizit aus der Clock gesetzt (ISO-8601 UTC mit
        # +00:00) -- der datetime('now')-Default bleibt nur als Sicherheitsnetz stehen.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cve_acknowledgements (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac        TEXT NOT NULL,
                    cve_id     TEXT NOT NULL,
                    port       INTEGER NOT NULL,
                    action     TEXT NOT NULL CHECK(action IN ('ack','unack')),
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                """
            )
            # Altbestand EINMALIG auf Grossschreibung heben (Finding 8). Hier reines
            # Hochschreiben -- mac ist kein Schluessel, Dubletten sind unschaedlich (der
            # effektive Status ist ohnehin die max(id)-Ableitung je Tripel). Zweiter
            # Start -> No-op. Fehlschlag wird LAUT geloggt, blockiert den Start nicht.
            try:
                migrated = migrate_macs_to_upper(conn, "cve_acknowledgements")
            except Exception as exc:
                _logger.error("cve_acknowledgements_mac_migration_failed", error=str(exc))
            else:
                if migrated:
                    _logger.info("cve_acknowledgements_mac_migration_done", rows=migrated)

    # ── Schreib-Pfad ──────────────────────────────────────────────────────────

    def record(self, mac: str, cve_id: str, port: int, action: str) -> None:
        """Schreibt EINE neue Log-Zeile (ack ODER unack) -- nie ein Update/Delete.

        Append-only: ein zweites ``record`` mit denselben (mac, cve_id, port) ueberschreibt
        NICHTS, sondern legt die naechste Zeile an. Der effektive Status ergibt sich erst
        beim Lesen aus dem JUENGSTEN Eintrag.

        Die MAC wird auf die kanonische Grossschreibung gehoben -- so quittiert ein ack
        denselben Befund, egal ob die MAC in Bestands- oder Scan-Schreibweise
        hereinkommt, und ``acknowledged_keys()`` trifft die (ebenfalls grossgeschriebenen)
        Befund-Schluessel aus ``cve_findings``.
        """
        # created_at explizit aus der Clock (timezone-aware UTC) als ISO-8601-String
        # MIT Zonen-Offset (+00:00) -- nicht mehr ueber den Schema-Default datetime('now').
        created_at = self._clock.now().isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO cve_acknowledgements (mac, cve_id, port, action, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (normalize_mac_case(mac), cve_id, port, action, created_at),
            )

    def clear_all(self) -> None:
        """Leert das gesamte ack-Log (nur die eigene Tabelle ``cve_acknowledgements``)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM cve_acknowledgements")

    # ── Lese-Pfad ─────────────────────────────────────────────────────────────

    def acknowledged_keys(self) -> set[tuple[str, str, int]]:
        """Die effektiv quittierten (mac, cve_id, port)-Tripel ueber ALLE Hosts.

        Reine Ableitung: ein Tripel ist quittiert, wenn sein JUENGSTER Eintrag (groesste
        id je (mac, cve_id, port)) ``action == 'ack'`` ist; ein spaeteres ``unack`` hebt
        das wieder auf. Effizient per Subquery auf ``max(id)`` je Tripel -- KEIN Laden der
        ganzen History in Python.

        Gruppiert wird ueber ``upper(mac)``, und die Schluessel kommen grossgeschrieben
        heraus: so trifft die Menge die (ebenfalls grossgeschriebenen) Befund-Schluessel
        aus ``cve_findings``. Die Gruppierung ueber die kanonische Form ist auch dann
        richtig, wenn die einmalige Migration ausnahmsweise fehlschlug -- ein altes
        kleingeschriebenes ``ack`` und ein neues grossgeschriebenes ``unack`` desselben
        Befunds landen in DERSELBEN Gruppe, sodass wirklich die juengste Entscheidung
        gilt statt zweier konkurrierender Straenge.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT a.mac, a.cve_id, a.port
                FROM cve_acknowledgements AS a
                WHERE a.id = (
                    SELECT max(b.id)
                    FROM cve_acknowledgements AS b
                    WHERE upper(b.mac) = upper(a.mac)
                      AND b.cve_id = a.cve_id
                      AND b.port = a.port
                )
                  AND a.action = 'ack'
                """
            ).fetchall()
        return {(normalize_mac_case(row["mac"]), row["cve_id"], row["port"]) for row in rows}
