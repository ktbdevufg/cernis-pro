"""SQLite-Adapter fuer die CVE-Befund-Persistenz (``CveFindingRepository``, ADR 0037).

Persistiert je (mac, cve_id, port) EINEN Befund. Upsert-Semantik wie die ARP-Baseline
(``save_baseline_entry``): neuer Schluessel -> INSERT mit ``first_seen_ts``; bekannter
Schluessel -> nur ``last_seen_ts`` + die veraenderlichen NVD-Felder (severity/score/desc/
url/published) aktualisieren, ``first_seen_ts`` BLEIBT (Basis fuers is_new-Flag).

``replace_for_host`` ist der Schreibpfad des Drip-Worker (Befund 56): er setzt den
Befundstand EINES Hosts transaktional neu, statt nur zu ergaenzen -- die Liste ist eine
Zustandsanzeige, kein Journal. ``upsert`` bleibt daneben bestehen (punktuelles
Auffrischen eines einzelnen Befunds).

Stil EXAKT wie ``analysis_acknowledgements_db.py``/``analysis_host_history_db.py``:
injizierter ``db_path``, ``_ensure_schema`` im ``__init__``, ``@contextmanager _connect``
mit Transaktion + garantiertem ``close``, ``CREATE TABLE IF NOT EXISTS``. KEIN
``modules``-Import.

KEIN stiller Fallback noetig (S3): hier liegen nur nackte Spalten, kein JSON-Blob, der
korrupt sein koennte. Der Upsert ist deterministisch; ein Lesen liefert die Zeilen 1:1
als ``CveFindingRecord`` zurueck.
"""

import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

import structlog

from domain.cve.models import CveFindingRecord
from infrastructure._cve_mac import migrate_macs_to_upper, normalize_mac_case

__all__ = ["SqliteCveFindingRepository"]

_logger = structlog.get_logger(__name__)


class SqliteCveFindingRepository:
    """Persistiert CVE-Befunde (Identitaet mac+cve_id+port) als Upsert in SQLite."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
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
        # Zusammengesetzter PRIMARY KEY (mac, cve_id, port) = die Befund-Identitaet; der
        # Upsert (INSERT .. ON CONFLICT) haengt genau daran. first_seen_ts/last_seen_ts
        # sind epoch-float (REAL). KEIN AUTOINCREMENT-id noetig -- die fachliche Identitaet
        # IST der Schluessel (anders als das append-only ack-Log, das die History haelt).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cve_findings (
                    mac           TEXT NOT NULL,
                    cve_id        TEXT NOT NULL,
                    port          INTEGER NOT NULL,
                    severity      TEXT NOT NULL,
                    cvss_score    REAL NOT NULL,
                    description   TEXT NOT NULL,
                    url           TEXT NOT NULL,
                    published     TEXT NOT NULL,
                    ip            TEXT NOT NULL DEFAULT '',
                    service       TEXT NOT NULL DEFAULT '',
                    first_seen_ts REAL NOT NULL,
                    last_seen_ts  REAL NOT NULL,
                    PRIMARY KEY (mac, cve_id, port)
                );
                """
            )
            # Altbestand EINMALIG auf Grossschreibung heben (Finding 8), kollisionssicher
            # (aeltestes first_seen_ts bleibt erhalten). Zweiter Start -> No-op. Ein
            # Fehlschlag wird LAUT geloggt, verhindert den Backend-Start aber nicht.
            try:
                migrated = migrate_macs_to_upper(conn, "cve_findings")
            except Exception as exc:
                _logger.error("cve_findings_mac_migration_failed", error=str(exc))
            else:
                if migrated:
                    _logger.info("cve_findings_mac_migration_done", rows=migrated)

    # ── Schreib-Pfad ──────────────────────────────────────────────────────────

    def replace_for_host(self, mac: str, records: Sequence[CveFindingRecord]) -> None:
        """Ersetzt den gesamten Befundstand EINES Hosts in EINER Transaktion (Befund 56).

        Die CVE-Liste ist eine ZUSTANDSANZEIGE, kein Journal: nach diesem Aufruf traegt
        die ``mac`` GENAU die uebergebenen Befunde. Was in ``records`` fehlt, ist weg
        (weggefallener Port, zurueckgezogene CVE) -- anders als ``upsert``, das nur
        ergaenzt und darum Leichen liegen liess.

        ``DELETE`` + alle ``INSERT`` liegen in DERSELBEN ``_connect``-Klammer, also in
        EINER SQLite-Transaktion: wirft ein INSERT (z. B. ein Record mit doppeltem
        (cve_id, port)), rollt ``with conn`` auch das DELETE zurueck -- der alte Bestand
        des Hosts steht dann unveraendert. Es gibt keinen Zwischenzustand, in dem ein
        Host seine Befunde verloren, die neuen aber nicht bekommen hat.

        Das ``DELETE`` traegt ein ``WHERE mac = ?`` -- ANDERE Hosts sind nie betroffen
        (im Unterschied zu ``clear_all``). Leere ``records`` sind gewollt erlaubt: dann
        bleibt nur das DELETE, der Host hat danach keine Befunde mehr.

        Die MAC wird ueber ``normalize_mac_case`` kanonisiert -- fuer das DELETE-Kriterium
        UND fuer jede eingefuegte Zeile, dieselbe Stelle wie in ``upsert``/``list_for_host``
        (Finding 8). Sonst loeschte eine kleingeschriebene MAC nichts und legte Dubletten
        daneben. Die MAC der Records wird bewusst IGNORIERT und durch die des Aufrufs
        ersetzt: der Stand gehoert per Definition dem genannten Host.
        """
        normalized = normalize_mac_case(mac)
        with self._connect() as conn:
            conn.execute("DELETE FROM cve_findings WHERE mac = ?", (normalized,))
            conn.executemany(
                """
                INSERT INTO cve_findings (
                    mac, cve_id, port, severity, cvss_score, description, url,
                    published, ip, service, first_seen_ts, last_seen_ts
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        normalized,
                        record.cve_id,
                        record.port,
                        record.severity,
                        record.cvss_score,
                        record.description,
                        record.url,
                        record.published,
                        record.ip,
                        record.service,
                        record.first_seen_ts,
                        record.last_seen_ts,
                    )
                    for record in records
                ],
            )

    def upsert(self, record: CveFindingRecord) -> None:
        """Upsert je (mac, cve_id, port): INSERT neu, sonst last_seen + NVD-Felder frisch.

        ``ON CONFLICT (mac, cve_id, port)``: ``first_seen_ts`` wird im UPDATE-Zweig
        BEWUSST NICHT angefasst (bleibt der erste Sicht-Zeitpunkt); ``last_seen_ts`` und
        die veraenderlichen NVD-Felder (Severity/Score kann NVD nachtraeglich aendern)
        werden auf die neuen Werte gesetzt.

        Die MAC geht in kanonischer Grossschreibung in die Spalte -- damit faellt ein
        Befund desselben Hosts IMMER auf denselben Schluessel, egal in welcher Form der
        Worker ihn hereinreicht (der ``CveFindingRecord`` selbst bleibt unveraendert,
        er ist frozen; normalisiert wird der SQL-Parameter).
        """
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cve_findings (
                    mac, cve_id, port, severity, cvss_score, description, url,
                    published, ip, service, first_seen_ts, last_seen_ts
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (mac, cve_id, port) DO UPDATE SET
                    severity     = excluded.severity,
                    cvss_score   = excluded.cvss_score,
                    description  = excluded.description,
                    url          = excluded.url,
                    published    = excluded.published,
                    ip           = excluded.ip,
                    service      = excluded.service,
                    last_seen_ts = excluded.last_seen_ts
                """,
                (
                    normalize_mac_case(record.mac),
                    record.cve_id,
                    record.port,
                    record.severity,
                    record.cvss_score,
                    record.description,
                    record.url,
                    record.published,
                    record.ip,
                    record.service,
                    record.first_seen_ts,
                    record.last_seen_ts,
                ),
            )

    def clear_all(self) -> None:
        """Leert alle CVE-Befunde (nur die eigene Tabelle ``cve_findings``)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM cve_findings")

    # ── Lese-Pfad ─────────────────────────────────────────────────────────────

    def list_all(self) -> list[CveFindingRecord]:
        """Alle Befunde ueber alle Hosts (Severity-stark zuerst, dann Score)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cve_findings ORDER BY cvss_score DESC, mac, cve_id, port"
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def list_for_host(self, mac: str) -> list[CveFindingRecord]:
        """Alle Befunde eines Hosts. Leere MAC -> ``[]`` (kein stabiler Schluessel).

        Die MAC wird vor der Abfrage auf die kanonische Grossschreibung gehoben. Genau
        hier sass Finding 8: eine Anfrage in der Schreibweise des Geraetebestands
        (GROSS) lief gegen kleingeschriebene Zeilen ins Leere und lieferte faelschlich
        eine leere Liste -- der Host sah dann schwachstellenfrei aus, obwohl Befunde
        gespeichert waren.
        """
        if not mac:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cve_findings WHERE mac = ? ORDER BY cvss_score DESC, cve_id, port",
                (normalize_mac_case(mac),),
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> CveFindingRecord:
        return CveFindingRecord(
            mac=row["mac"],
            cve_id=row["cve_id"],
            port=row["port"],
            severity=row["severity"],
            cvss_score=row["cvss_score"],
            description=row["description"],
            url=row["url"],
            published=row["published"],
            ip=row["ip"],
            service=row["service"],
            first_seen_ts=row["first_seen_ts"],
            last_seen_ts=row["last_seen_ts"],
        )
