"""Unit-Tests der agent-Domaene (Client-Seite) -- reine Logik, kein I/O."""

import dataclasses

import pytest

from domain.agent import AgentPingResult, RemoteAgent, token_key

# ── RemoteAgent ──────────────────────────────────────────────────────────────


def test_remote_agent_defaults() -> None:
    agent = RemoteAgent(id="a1", name="VPS", url="http://vps:8766")
    assert agent.id == "a1"
    assert agent.name == "VPS"
    assert agent.url == "http://vps:8766"
    assert agent.enabled is True
    assert agent.cidrs == ()


def test_remote_agent_has_no_token_field() -> None:
    # S4-Schnitt: TOKENLOS -- der Token lebt im SecretStore, nie im Modell.
    field_names = {f.name for f in dataclasses.fields(RemoteAgent)}
    assert "token" not in field_names
    assert field_names == {"id", "name", "url", "enabled", "cidrs"}


def test_remote_agent_cidrs_is_tuple() -> None:
    agent = RemoteAgent(id="a1", name="VPS", url="http://vps", cidrs=("10.0.0.0/24",))
    assert agent.cidrs == ("10.0.0.0/24",)
    assert isinstance(agent.cidrs, tuple)


def test_remote_agent_is_frozen() -> None:
    agent = RemoteAgent(id="a1", name="VPS", url="http://vps")
    # Attributname als Variable: vermeidet ruff B010 und den mypy-Frozen-Schreibfehler.
    field_name = "name"
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(agent, field_name, "anders")


# ── AgentPingResult ──────────────────────────────────────────────────────────


def test_agent_ping_result_defaults() -> None:
    result = AgentPingResult(reachable=True)
    assert result.reachable is True
    assert result.version == ""
    assert result.platform == ""
    assert result.hostname == ""
    assert result.error == ""


def test_agent_ping_result_full() -> None:
    result = AgentPingResult(
        reachable=True,
        version="1.0.0",
        platform="Linux",
        hostname="vps",
    )
    assert result.version == "1.0.0"
    assert result.platform == "Linux"
    assert result.hostname == "vps"


def test_agent_ping_result_unreachable_carries_error() -> None:
    # Unerreichbarkeit ist KEIN Fehlerzustand, sondern ein legitimes Ergebnis.
    result = AgentPingResult(reachable=False, error="Connection refused")
    assert result.reachable is False
    assert result.error == "Connection refused"


def test_agent_ping_result_is_frozen() -> None:
    result = AgentPingResult(reachable=True)
    field_name = "reachable"
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(result, field_name, False)


# ── token_key ────────────────────────────────────────────────────────────────


def test_token_key_exact_schema() -> None:
    assert token_key("a1") == "agent_token:a1"


def test_token_key_is_deterministic() -> None:
    assert token_key("agent-xyz") == token_key("agent-xyz")


def test_token_key_distinct_ids_distinct_keys() -> None:
    assert token_key("a1") != token_key("a2")
