"""Tests fuer ``SqliteBlocklistSourceRepository`` -- gegen tmp_path-DB.

Belegt den Upsert (Insert + Update ueber id), den Enum-/bool-Round-trip, das
unbekannte ``get`` -> ``None``, die ``list_all``-Sortierung (group, dann name), das
idempotente ``delete`` und ``clear_all``. Muster der uebrigen infrastructure-Repo-Tests
(``tmp_path``-DB-Fixture, wie ``test_analysis_acknowledgements_db.py``).
"""

from pathlib import Path

import pytest

from domain.blocklist import (
    BlocklistFormat,
    BlocklistGroup,
    BlocklistSource,
    BlocklistStatus,
    SourceOrigin,
)
from infrastructure.blocklist_sources_db import SqliteBlocklistSourceRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteBlocklistSourceRepository:
    return SqliteBlocklistSourceRepository(tmp_path / "cernis.db")


def _source(
    source_id: str,
    name: str,
    group: BlocklistGroup = BlocklistGroup.TRACKER_ADS,
    enabled: bool = True,
) -> BlocklistSource:
    return BlocklistSource(
        id=source_id,
        name=name,
        group=group,
        fmt=BlocklistFormat.HOSTS,
        origin=SourceOrigin.BUILTIN,
        url="https://example.com/list",
        license="MIT",
        attribution_required=False,
        enabled=enabled,
        last_fetched_ts=None,
        status=BlocklistStatus.NEVER,
        entry_count=None,
    )


# ── Upsert + Round-trip ───────────────────────────────────────────────────────


def test_upsert_dann_get_round_trip(repo: SqliteBlocklistSourceRepository) -> None:
    src = _source("a", "Alpha")
    repo.upsert(src)
    assert repo.get("a") == src


def test_enum_und_bool_round_trip(repo: SqliteBlocklistSourceRepository) -> None:
    src = BlocklistSource(
        id="t",
        name="Threat-Liste",
        group=BlocklistGroup.THREAT,
        fmt=BlocklistFormat.IP_LIST,
        origin=SourceOrigin.USER_URL,
        url=None,
        license="CC0",
        attribution_required=True,
        enabled=False,
        last_fetched_ts=123.5,
        status=BlocklistStatus.BROKEN,
        entry_count=42,
    )
    repo.upsert(src)
    geladen = repo.get("t")
    assert geladen == src
    assert geladen is not None
    assert geladen.group is BlocklistGroup.THREAT
    assert geladen.fmt is BlocklistFormat.IP_LIST
    assert geladen.origin is SourceOrigin.USER_URL
    assert geladen.status is BlocklistStatus.BROKEN
    assert geladen.attribution_required is True
    assert geladen.enabled is False


def test_upsert_aktualisiert_bestehende_id(repo: SqliteBlocklistSourceRepository) -> None:
    repo.upsert(_source("a", "Alpha", enabled=True))
    repo.upsert(_source("a", "Alpha neu", enabled=False))
    geladen = repo.get("a")
    assert geladen is not None
    assert geladen.name == "Alpha neu"
    assert geladen.enabled is False
    # Kein zweiter Datensatz: nur eine Zeile fuer id "a".
    assert len(repo.list_all()) == 1


def test_get_unbekannt_ist_none(repo: SqliteBlocklistSourceRepository) -> None:
    assert repo.get("gibtsnicht") is None


# ── list_all-Sortierung ───────────────────────────────────────────────────────


def test_list_all_sortiert_nach_group_dann_name(repo: SqliteBlocklistSourceRepository) -> None:
    repo.upsert(_source("z", "Zebra", group=BlocklistGroup.TRACKER_ADS))
    repo.upsert(_source("t", "Alpha", group=BlocklistGroup.THREAT))
    repo.upsert(_source("a", "Beta", group=BlocklistGroup.TRACKER_ADS))
    namen = [(src.group, src.name) for src in repo.list_all()]
    # threat < tracker_ads (lexikalisch); innerhalb der Gruppe nach name.
    assert namen == [
        (BlocklistGroup.THREAT, "Alpha"),
        (BlocklistGroup.TRACKER_ADS, "Beta"),
        (BlocklistGroup.TRACKER_ADS, "Zebra"),
    ]


def test_list_all_leer_ist_leere_liste(repo: SqliteBlocklistSourceRepository) -> None:
    assert repo.list_all() == []


# ── delete / clear_all ────────────────────────────────────────────────────────


def test_delete_entfernt_und_ist_idempotent(repo: SqliteBlocklistSourceRepository) -> None:
    repo.upsert(_source("a", "Alpha"))
    repo.delete("a")
    assert repo.get("a") is None
    # Zweites delete derselben id wirft nicht (idempotent).
    repo.delete("a")


def test_clear_all_leert_tabelle(repo: SqliteBlocklistSourceRepository) -> None:
    repo.upsert(_source("a", "Alpha"))
    repo.upsert(_source("b", "Beta"))
    repo.clear_all()
    assert repo.list_all() == []
