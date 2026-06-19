"""Tests fuer ``SqliteCveCheckStateRepository`` (ADR 0037) -- gegen tmp_path-DB.

Belegt: get(None) fuer unbekannten Host, record->get-Round-trip, Upsert auf mac
(zweiter record ueberschreibt), Port-Set-(De-)Serialisierung inkl. leerem Set,
all_states.
"""

from pathlib import Path

import pytest

from infrastructure.cve_checkstate_db import SqliteCveCheckStateRepository

MAC = "aa:bb:cc:dd:ee:ff"


@pytest.fixture
def repo(tmp_path: Path) -> SqliteCveCheckStateRepository:
    return SqliteCveCheckStateRepository(tmp_path / "cernis.db")


def test_get_unbekannt_ist_none(repo: SqliteCveCheckStateRepository) -> None:
    assert repo.get(MAC) is None


def test_get_leere_mac_ist_none(repo: SqliteCveCheckStateRepository) -> None:
    assert repo.get("") is None


def test_record_dann_get_round_trip(repo: SqliteCveCheckStateRepository) -> None:
    repo.record(MAC, frozenset({22, 443, 80}), checked_ts=123.5)
    state = repo.get(MAC)
    assert state is not None
    assert state.mac == MAC
    assert state.last_checked_ts == 123.5
    assert state.checked_ports == frozenset({22, 80, 443})


def test_record_leeres_port_set(repo: SqliteCveCheckStateRepository) -> None:
    repo.record(MAC, frozenset(), checked_ts=10.0)
    state = repo.get(MAC)
    assert state is not None
    assert state.checked_ports == frozenset()


def test_record_upsert_ueberschreibt(repo: SqliteCveCheckStateRepository) -> None:
    repo.record(MAC, frozenset({22}), checked_ts=10.0)
    repo.record(MAC, frozenset({22, 443}), checked_ts=20.0)
    state = repo.get(MAC)
    assert state is not None
    assert state.last_checked_ts == 20.0
    assert state.checked_ports == frozenset({22, 443})
    assert len(repo.all_states()) == 1  # ein Stand je Host


def test_all_states(repo: SqliteCveCheckStateRepository) -> None:
    repo.record(MAC, frozenset({22}), checked_ts=10.0)
    repo.record("99:99:99:99:99:99", frozenset({80}), checked_ts=11.0)
    assert len(repo.all_states()) == 2
