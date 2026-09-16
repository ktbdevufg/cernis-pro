"""SQLite-Adapter fuer den Port ``AgentRepository``.

Basiert auf der Persistenz-Logik aus ``modules/agent.py`` (Tabelle
``remote_agents``), mit den bewussten v2-Schnitten:

* TOKEN-FREI: die Spalte ``token`` wird NICHT geschrieben (und nicht gelesen).
  Das Geheimnis lebt im ``SecretStore`` unter ``token_key(id)``, den der
  Use-Case separat bedient (Variante B, wie settings). Der Altcode trug hier den
  Fernet-verschluesselten Token -- dieser Adapter kennt ihn nicht.
* Die toten Altcode-Spalten ``last_seen``/``version``/``platform`` (im Schema
  vorhanden, aber von ``save_agent`` NIE geschrieben) werden ebenfalls nicht
  angefasst -- sie sind keine Stammdaten (vgl. ``domain/agent/models.py``).
* Reine Persistenz: KEINE I/O, keine Krypto. Der Adapter schreibt fertige
  Domaenen-Objekte (``RemoteAgent``, tokenlos).
* KEIN stiller Fallback bei kaputtem JSON (Finding S3): ein nicht dekodierbares
  ``cidrs`` ist ein Fehler MIT id-Bezug (``CorruptAgentError``), kein leerer
  Roh-Fallback wie ``json.loads(d.get("cidrs") or "[]")`` im Altcode.

Der DB-Pfad wird injiziert; die Pfad-Aufloesung passiert im Composition Root
(``app.py``), nicht im Adapter -- Muster ``SqliteDeviceRepository``.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.agent import RemoteAgent
from infrastructure.agent.errors import CorruptAgentError


def _decode_cidrs(agent_id: str, raw: str) -> tuple[str, ...]:
    """JSON-TEXT -> tuple. Kein stiller Fallback: kaputtes JSON -> Exception."""
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CorruptAgentError(agent_id, raw) from exc
    if not isinstance(decoded, list):
        raise CorruptAgentError(agent_id, raw)
    return tuple(str(c) for c in decoded)


def _row_to_agent(row: sqlite3.Row) -> RemoteAgent:
    agent_id = row["id"]
    return RemoteAgent(
        id=agent_id,
        name=row["name"],
        url=row["url"],
        enabled=bool(row["enabled"]),
        cidrs=_decode_cidrs(agent_id, row["cidrs"]),
    )


class SqliteAgentRepository:
    """Erfuellt das ``AgentRepository``-Protocol strukturell (SQLite), token-frei."""

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
        # Schema wie der Bestand (``remote_agents``) -- die token/last_seen/
        # version/platform-Spalten bleiben im DDL erhalten (Strangler: alt und
        # neu koexistieren auf derselben Tabelle), werden v2-seitig aber NIE
        # geschrieben oder gelesen.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS remote_agents (
                    id        TEXT PRIMARY KEY,
                    name      TEXT,
                    url       TEXT,
                    token     TEXT,
                    enabled   INTEGER DEFAULT 1,
                    last_seen TEXT,
                    version   TEXT,
                    platform  TEXT,
                    cidrs     TEXT DEFAULT '[]'
                )
                """
            )

    def get(self, agent_id: str) -> RemoteAgent | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, name, url, enabled, cidrs FROM remote_agents WHERE id = ?",
                (agent_id,),
            ).fetchone()
        if row is None:
            return None
        return _row_to_agent(row)

    def get_all(self, enabled_only: bool) -> list[RemoteAgent]:
        query = "SELECT id, name, url, enabled, cidrs FROM remote_agents"
        if enabled_only:
            query += " WHERE enabled = 1"
        with self._connect() as conn:
            rows = conn.execute(query).fetchall()
        return [_row_to_agent(row) for row in rows]

    def save(self, agent: RemoteAgent) -> None:
        # Upsert auf id -- schreibt NUR id/name/url/enabled/cidrs. Die token-
        # Spalte bleibt unberuehrt (token-frei; das Geheimnis liegt im
        # SecretStore). Tote Spalten last_seen/version/platform ebenso.
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO remote_agents (id, name, url, enabled, cidrs) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET "
                " name = excluded.name, url = excluded.url,"
                " enabled = excluded.enabled, cidrs = excluded.cidrs",
                (
                    agent.id,
                    agent.name,
                    agent.url,
                    int(agent.enabled),
                    json.dumps(list(agent.cidrs)),
                ),
            )

    def delete(self, agent_id: str) -> None:
        # Idempotent: DELETE auf eine unbekannte id ist kein Fehler (altcode-treu).
        with self._connect() as conn:
            conn.execute("DELETE FROM remote_agents WHERE id = ?", (agent_id,))

    def clear_all(self) -> None:
        # Leert alle Agent-Stammdaten (nur die eigene Tabelle remote_agents). Die
        # Tokens liegen im SecretStore -- die loescht der Use-Case getrennt.
        with self._connect() as conn:
            conn.execute("DELETE FROM remote_agents")
