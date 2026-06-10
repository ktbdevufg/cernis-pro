"""SQLite-Adapter fuer die Host-Historie der analysis-Domaene (C.1).

``SqliteHostHistoryRepository`` persistiert die gesehenen Host-IDENTITAETEN, damit
"neu = noch nie gesehen" ueberhaupt entscheidbar ist. Das ist analysis' erstes
GEDAECHTNIS -- ABER es lebt hier in der Infrastruktur, NICHT in der Domaene: die
zustandslose, deterministische analysis-Engine bleibt rein und sieht spaeter nur ein
``bool`` (``ObservedHost.is_known``), das die Composition Root (C.2) aus diesem
Repository fuellt.

Stil wie ``analysis_rules_db.py`` und ``scanning/scan_history.py``: injizierter
``db_path``, ``_ensure_schema`` im ``__init__``, ``@contextmanager _connect`` mit
Transaktion + garantiertem ``close``, ``CREATE TABLE IF NOT EXISTS``. KEIN
``modules``-Import.

IDENTITAET -- die MAC, NICHT die IP: die MAC ist die stabilste Kennung; IPs wechseln per
DHCP, ein IP-Wechsel ist kein neues Geraet. Hosts OHNE MAC werden NICHT gespeichert und
gelten beim Abgleich als "bekannt" (``is_known`` True) -- ein Host ohne MAC ist nicht
stabil identifizierbar, "neu" waere dort nur Rauschen. Das ist dieselbe Linie wie
``ws_scan._record_host``, das MAC-lose Hosts beim Persistieren ueberspringt.

KEIN stiller Fallback noetig: hier liegt kein JSON-Blob, nur die MAC selbst als
PRIMARY KEY -- es gibt keinen kaputten Wert, der einen ``Corrupt...Error`` braeuchte. Die
leere MAC wird bewusst (siehe oben) als no-op / "bekannt" behandelt, nicht gespeichert.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

__all__ = ["SqliteHostHistoryRepository"]


class SqliteHostHistoryRepository:
    """Persistiert gesehene Host-MACs in SQLite -- die Host-Historie (C.1).

    Injizierter ``db_path``; die Pfad-Aufloesung passiert im Composition Root
    (``app.py``), nicht hier. Lese-Pfad: ``is_known`` / ``known_macs``. Schreib-Pfad:
    ``record_seen`` (in C.2 am Scan-Abschluss aufgerufen).
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
        # mac ist der PRIMARY KEY (die stabile Geraete-Identitaet). first_seen haelt den
        # Erst-Sicht-Zeitstempel (datetime('now')-Default) -- gesetzt beim ersten INSERT,
        # spaeter unveraendert (INSERT OR IGNORE in record_seen).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS analysis_known_hosts (
                    mac        TEXT PRIMARY KEY,
                    first_seen TEXT DEFAULT (datetime('now'))
                );
                """
            )

    # ── Lese-Pfad ─────────────────────────────────────────────────────────────

    def is_known(self, mac: str) -> bool:
        """True, wenn die (nicht-leere) MAC schon gespeichert ist.

        Leere MAC -> ``True``: ein Host ohne stabile Identitaet wird NICHT als neu
        gewertet (sonst Rauschen, siehe Modul-Docstring). Reiner Lese-Pfad.
        """
        if not mac:
            return True
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM analysis_known_hosts WHERE mac = ?", (mac,)
            ).fetchone()
        return row is not None

    def known_macs(self) -> set[str]:
        """Alle bekannten MACs als Menge -- Bulk-Lesepfad fuer die Projektion (C.2).

        Eine Abfrage statt N einzelner ``is_known``-Aufrufe, wenn die Projektion einen
        ganzen Scan gegen die Historie abgleicht.
        """
        with self._connect() as conn:
            rows = conn.execute("SELECT mac FROM analysis_known_hosts").fetchall()
        return {row["mac"] for row in rows}

    # ── Schreib-Pfad (in C.2 am Scan-Abschluss aufgerufen) ────────────────────

    def record_seen(self, mac: str) -> None:
        """Traegt die MAC ein, falls noch nicht vorhanden -- idempotent.

        ``INSERT OR IGNORE``: ein zweiter Aufruf mit derselben MAC ist ein no-op,
        ``first_seen`` bleibt der Erst-Sicht-Zeitstempel. Leere MAC -> no-op (ein Host
        ohne stabile Identitaet kommt nicht in die Historie).
        """
        if not mac:
            return
        with self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO analysis_known_hosts (mac) VALUES (?)", (mac,))
