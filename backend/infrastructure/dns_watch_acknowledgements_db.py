"""SQLite-Adapter fuer das Acknowledge-Audit der dns_watch-Domaene (Block 2, 2d).

``SqliteDnsWatchAcknowledgementRepository`` persistiert das QUITTIEREN ("Als bekannt
markieren") von DNS-Waechter-Befunden als APPEND-ONLY Log: jedes ack/unack ist eine
NEUE Zeile, nichts wird je geloescht oder ueberschrieben. Der effektive Status eines
(remote_ip, category) ist eine reine ABLEITUNG aus dem Log -- der JUENGSTE Eintrag
gewinnt (action=='ack' -> quittiert, 'unack' -> wieder offen). EINE Wahrheit, kein
zweiter Statusspeicher.

Granularitaet ist BEFUNDGENAU pro (remote_ip, category) -- analog zur PORT-GENAUEN
(mac, port)-Granularitaet der analysis-Domaene (``analysis_acknowledgements_db.py``).
Ein quittierter (1.2.3.4, "offen") betrifft NUR genau diesen Befund.

Stil EXAKT wie ``analysis_acknowledgements_db.py``: injizierter ``db_path``,
``_ensure_schema`` im ``__init__``, ``@contextmanager _connect`` mit Transaktion +
garantiertem ``close``, ``CREATE TABLE IF NOT EXISTS``. KEIN ``modules``-Import.

KEIN stiller Fallback noetig: hier liegen nur die nackten Spalten (remote_ip, category,
action) -- es gibt keinen kaputten Wert, der einen ``Corrupt...Error`` braeuchte. Der
``CHECK(action IN ('ack','unack'))`` haelt das Log auf den zwei legitimen Aktionen; ein
anderer Wert schlaegt am INSERT laut fehl, statt leise durchzulaufen.

Die abgeleiteten Schluessel haben die Form ``f"{remote_ip}:{category}"`` -- exakt der
Vertrag des ``AcknowledgedProvider`` aus 2d-1 (``BuildDnsWatch`` prueft
``f"{ip}:{category}" in diesem Set``).
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

__all__ = ["SqliteDnsWatchAcknowledgementRepository"]


class SqliteDnsWatchAcknowledgementRepository:
    """Persistiert ack/unack-Aktionen als append-only Log in SQLite (Block 2, 2d).

    Injizierter ``db_path``; die Pfad-Aufloesung passiert im Composition Root
    (``app.py``, kommt in 2d-3), nicht hier. Schreib-Pfad: ``record`` (immer eine neue
    Zeile). Lese-Pfad: ``acknowledged_keys`` (die effektiv quittierten Befunde als Menge
    der Schluessel ``f"{remote_ip}:{category}"`` -- der jeweils JUENGSTE Eintrag je
    (remote_ip, category) entscheidet).
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
        # zwei Aktionen denselben created_at-Sekundenwert teilen). action ist per CHECK
        # auf 'ack'/'unack' eingegrenzt (lauter Fehler statt Muell). created_at als
        # datetime('now')-Default (UTC) -- Audit-Zeitstempel.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS dns_watch_acknowledgements (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    remote_ip  TEXT NOT NULL,
                    category   TEXT NOT NULL,
                    action     TEXT NOT NULL CHECK(action IN ('ack','unack')),
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                """
            )

    # ── Schreib-Pfad ──────────────────────────────────────────────────────────

    def record(self, remote_ip: str, category: str, action: str) -> None:
        """Schreibt EINE neue Log-Zeile (ack ODER unack) -- nie ein Update/Delete.

        Append-only: ein zweites ``record`` mit demselben (remote_ip, category)
        ueberschreibt NICHTS, sondern legt die naechste Zeile an; die History bleibt
        vollstaendig. Der effektive Status ergibt sich erst beim Lesen aus dem JUENGSTEN
        Eintrag.
        """
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO dns_watch_acknowledgements (remote_ip, category, action) "
                "VALUES (?, ?, ?)",
                (remote_ip, category, action),
            )

    def clear_all(self) -> None:
        """Leert das gesamte ack-Log (nur die eigene Tabelle ``dns_watch_acknowledgements``)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM dns_watch_acknowledgements")

    # ── Lese-Pfad ─────────────────────────────────────────────────────────────

    def acknowledged_keys(self) -> set[str]:
        """Die effektiv quittierten Befunde als Menge der Schluessel ``f"{ip}:{cat}"``.

        Quittiert ist genau der Befund, dessen JUENGSTER Eintrag (groesste id je
        (remote_ip, category)) ``action == 'ack'`` ist; ein spaeteres ``unack`` hebt das
        wieder auf (kommt dann nicht zurueck). Effizient per Subquery auf ``max(id)`` je
        (remote_ip, category) -- KEIN Laden der ganzen History in Python.

        Schluessel-Form ist exakt ``f"{remote_ip}:{category}"`` -- passt zum
        ``AcknowledgedProvider``-Vertrag aus 2d-1.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT a.remote_ip, a.category
                FROM dns_watch_acknowledgements AS a
                WHERE a.id = (
                    SELECT max(b.id)
                    FROM dns_watch_acknowledgements AS b
                    WHERE b.remote_ip = a.remote_ip AND b.category = a.category
                )
                  AND a.action = 'ack'
                """
            ).fetchall()
        return {f"{row['remote_ip']}:{row['category']}" for row in rows}
