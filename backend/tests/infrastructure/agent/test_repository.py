"""Tests fuer den SQLite-Adapter ``SqliteAgentRepository`` (gegen tmp_path-DB).

Haelt das gewuenschte v2-Verhalten fest: TOKEN-FREI (die ``token``-Spalte wird
NIE geschrieben -- das Geheimnis lebt im SecretStore), Upsert auf id, cidrs-JSON-
Roundtrip, kein stiller JSON-Fallback (``CorruptAgentError``), delete idempotent,
enabled-Filter in ``get_all``.
"""

import sqlite3
from pathlib import Path

import pytest

from domain.agent import RemoteAgent
from infrastructure.agent.errors import CorruptAgentError
from infrastructure.agent.repository import SqliteAgentRepository
from ports.agent import AgentRepository

AGENT_ID = "agent-1"


@pytest.fixture
def repo(tmp_path: Path) -> SqliteAgentRepository:
    """Frisches Repository gegen eine temporaere DB."""
    return SqliteAgentRepository(tmp_path / "cernis.db")


def _agent(agent_id: str = AGENT_ID, **over: object) -> RemoteAgent:
    base: dict[str, object] = {
        "id": agent_id,
        "name": "VPS Netcup",
        "url": "http://vps.example.de:8766",
        "enabled": True,
        "cidrs": ("10.0.0.0/24",),
    }
    base.update(over)
    return RemoteAgent(**base)  # type: ignore[arg-type]


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_agent_repository_protocol(repo: SqliteAgentRepository) -> None:
    _: AgentRepository = repo


# ── save / get Roundtrip ──────────────────────────────────────────────────


def test_save_then_get_roundtrips_all_fields(repo: SqliteAgentRepository) -> None:
    repo.save(_agent())
    loaded = repo.get(AGENT_ID)
    assert loaded == _agent()


def test_get_unknown_returns_none(repo: SqliteAgentRepository) -> None:
    assert repo.get("does-not-exist") is None


def test_cidrs_json_roundtrips_as_tuple(repo: SqliteAgentRepository) -> None:
    repo.save(_agent(cidrs=("10.0.0.0/24", "192.168.1.0/24")))
    loaded = repo.get(AGENT_ID)
    assert loaded is not None
    assert loaded.cidrs == ("10.0.0.0/24", "192.168.1.0/24")


def test_empty_cidrs_roundtrips_as_empty_tuple(repo: SqliteAgentRepository) -> None:
    repo.save(_agent(cidrs=()))
    loaded = repo.get(AGENT_ID)
    assert loaded is not None
    assert loaded.cidrs == ()


def test_save_is_upsert_on_id(repo: SqliteAgentRepository) -> None:
    repo.save(_agent(name="alt", url="http://old:1"))
    repo.save(_agent(name="neu", url="http://new:2", cidrs=("1.2.3.0/24",)))
    loaded = repo.get(AGENT_ID)
    assert loaded is not None
    assert loaded.name == "neu"
    assert loaded.url == "http://new:2"
    assert loaded.cidrs == ("1.2.3.0/24",)
    # Genau ein Datensatz -- kein Duplikat durch den zweiten save.
    assert len(repo.get_all(enabled_only=False)) == 1


# ── get_all / enabled-Filter ──────────────────────────────────────────────


def test_get_all_empty_returns_empty_list(repo: SqliteAgentRepository) -> None:
    assert repo.get_all(enabled_only=False) == []


def test_get_all_enabled_only_filters_disabled(repo: SqliteAgentRepository) -> None:
    repo.save(_agent("on", enabled=True))
    repo.save(_agent("off", enabled=False))
    enabled_ids = {a.id for a in repo.get_all(enabled_only=True)}
    all_ids = {a.id for a in repo.get_all(enabled_only=False)}
    assert enabled_ids == {"on"}
    assert all_ids == {"on", "off"}


def test_enabled_flag_roundtrips_as_bool(repo: SqliteAgentRepository) -> None:
    repo.save(_agent("off", enabled=False))
    loaded = repo.get("off")
    assert loaded is not None
    assert loaded.enabled is False


# ── delete (idempotent) ───────────────────────────────────────────────────


def test_delete_removes_agent(repo: SqliteAgentRepository) -> None:
    repo.save(_agent())
    repo.delete(AGENT_ID)
    assert repo.get(AGENT_ID) is None


def test_delete_unknown_is_idempotent(repo: SqliteAgentRepository) -> None:
    # DELETE auf eine unbekannte id ist kein Fehler (altcode-treu).
    repo.delete("never-existed")
    assert repo.get("never-existed") is None


# ── kein stiller JSON-Fallback ────────────────────────────────────────────


def test_corrupt_cidrs_raises_with_id(repo: SqliteAgentRepository, tmp_path: Path) -> None:
    repo.save(_agent())
    # cidrs-Spalte direkt zu kaputtem JSON manipulieren.
    conn = sqlite3.connect(tmp_path / "cernis.db")
    conn.execute("UPDATE remote_agents SET cidrs = ? WHERE id = ?", ("{nicht json", AGENT_ID))
    conn.commit()
    conn.close()
    with pytest.raises(CorruptAgentError) as exc_info:
        repo.get(AGENT_ID)
    assert exc_info.value.agent_id == AGENT_ID


def test_cidrs_non_list_json_raises(repo: SqliteAgentRepository, tmp_path: Path) -> None:
    repo.save(_agent())
    # Gueltiges JSON, aber keine Liste -> ebenfalls korrupt (kein stilles Tolerieren).
    conn = sqlite3.connect(tmp_path / "cernis.db")
    conn.execute("UPDATE remote_agents SET cidrs = ? WHERE id = ?", ('{"a": 1}', AGENT_ID))
    conn.commit()
    conn.close()
    with pytest.raises(CorruptAgentError):
        repo.get(AGENT_ID)


# ── TOKEN NIE in der DB ────────────────────────────────────────────────────


def test_save_never_writes_token_column(repo: SqliteAgentRepository, tmp_path: Path) -> None:
    """Kritischer Vertrag (Variante B): save schreibt die token-Spalte NIE.

    Der Token lebt im SecretStore, nicht in der DB. Nach einem save muss die
    token-Spalte des Datensatzes leer/NULL sein -- der Adapter fasst sie nicht an.
    """
    repo.save(_agent())
    conn = sqlite3.connect(tmp_path / "cernis.db")
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT token FROM remote_agents WHERE id = ?", (AGENT_ID,)).fetchone()
    conn.close()
    # token-Spalte existiert im Schema, wurde aber nie geschrieben -> NULL.
    assert row["token"] is None
