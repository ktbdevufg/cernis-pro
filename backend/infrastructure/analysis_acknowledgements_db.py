"""SQLite-Adapter fuer das Acknowledge-Audit der analysis-Domaene (ADR 0031).

``SqliteAcknowledgementRepository`` persistiert das QUITTIEREN von Achse-B-Befunden als
APPEND-ONLY Log: jedes ack/unack ist eine NEUE Zeile, nichts wird je geloescht oder
ueberschrieben. Der effektive Status eines (mac, port) ist eine reine ABLEITUNG aus dem
Log -- der JUENGSTE Eintrag gewinnt (action=='ack' -> quittiert, 'unack' -> wieder
scharf). EINE Wahrheit, kein zweiter Statusspeicher.

Granularitaet ist PORT-GENAU pro (mac, port) (Karl-Entscheidung, ADR 0031): Port 3306
quittiert betrifft NUR 3306; ein neuer auffaelliger Port am selben Host loest weiter aus.

Stil EXAKT wie ``analysis_host_history_db.py`` und ``analysis_rules_db.py``: injizierter
``db_path``, ``_ensure_schema`` im ``__init__``, ``@contextmanager _connect`` mit
Transaktion + garantiertem ``close``, ``CREATE TABLE IF NOT EXISTS``. KEIN
``modules``-Import.

KEIN stiller Fallback noetig: hier liegt kein JSON-Blob, nur die nackten Spalten (mac,
port, severity, action) -- es gibt keinen kaputten Wert, der einen ``Corrupt...Error``
braeuchte. Der ``CHECK(action IN ('ack','unack'))`` haelt das Log auf den zwei legitimen
Aktionen; ein anderer Wert schlaegt am INSERT laut fehl, statt leise durchzulaufen.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

__all__ = ["SqliteAcknowledgementRepository"]


class SqliteAcknowledgementRepository:
    """Persistiert ack/unack-Aktionen als append-only Log in SQLite (ADR 0031).

    Injizierter ``db_path``; die Pfad-Aufloesung passiert im Composition Root
    (``app.py``), nicht hier. Schreib-Pfad: ``record`` (immer eine neue Zeile).
    Lese-Pfad: ``acknowledged_ports`` (die effektiv quittierten Ports einer MAC --
    der jeweils JUENGSTE Eintrag je (mac, port) entscheidet).
    """

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
        # Append-only Log: AUTOINCREMENT-id ist die strenge zeitliche Ordnung (auch wenn
        # zwei Aktionen denselben created_at-Sekundenwert teilen). severity haelt die
        # Achse-B-Stufe der quittierten Auffaelligkeit ("critical"/"notable") fuers Audit;
        # action ist per CHECK auf 'ack'/'unack' eingegrenzt (lauter Fehler statt Muell).
        # created_at als datetime('now')-Default (UTC) -- Audit-Zeitstempel.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS analysis_acknowledgements (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac        TEXT NOT NULL,
                    port       INTEGER NOT NULL,
                    severity   TEXT NOT NULL,
                    action     TEXT NOT NULL CHECK(action IN ('ack','unack')),
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                """
            )

    # ── Schreib-Pfad ──────────────────────────────────────────────────────────

    def record(self, mac: str, port: int, severity: str, action: str) -> None:
        """Schreibt EINE neue Log-Zeile (ack ODER unack) -- nie ein Update/Delete.

        Append-only: ein zweites ``record`` mit denselben (mac, port) ueberschreibt
        NICHTS, sondern legt die naechste Zeile an; die History bleibt vollstaendig.
        Der effektive Status ergibt sich erst beim Lesen aus dem JUENGSTEN Eintrag.
        """
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO analysis_acknowledgements (mac, port, severity, action) "
                "VALUES (?, ?, ?, ?)",
                (mac, port, severity, action),
            )

    def clear_all(self) -> None:
        """Leert das gesamte ack-Log (nur die eigene Tabelle ``analysis_acknowledgements``)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM analysis_acknowledgements")

    # ── Lese-Pfad ─────────────────────────────────────────────────────────────

    def acknowledged_ports(self, mac: str) -> set[int]:
        """Die effektiv quittierten Ports einer MAC -- reine Ableitung aus dem Log.

        Quittiert ist genau der Port, dessen JUENGSTER Eintrag (groesste id je
        (mac, port)) ``action == 'ack'`` ist; ein spaeteres ``unack`` hebt das wieder
        auf (kommt dann nicht zurueck). Effizient per Subquery auf ``max(id)`` je Port
        -- KEIN Laden der ganzen History in Python. Leere MAC -> leere Menge (ein Host
        ohne stabile Identitaet hat keine port-genauen Quittierungen).
        """
        if not mac:
            return set()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT a.port
                FROM analysis_acknowledgements AS a
                WHERE a.id = (
                    SELECT max(b.id)
                    FROM analysis_acknowledgements AS b
                    WHERE b.mac = a.mac AND b.port = a.port
                )
                  AND a.mac = ?
                  AND a.action = 'ack'
                """,
                (mac,),
            ).fetchall()
        return {row["port"] for row in rows}
