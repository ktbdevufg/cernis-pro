"""Tests fuer den SQLite-Adapter ``SqliteSettingsRepository``.

Prueft die konkrete Implementierung gegen eine temporaere DB (``tmp_path``),
nicht die echte ``cernis.db``. Gegenstueck zu den Characterization-Tests des
Altcodes: hier wird das GEWUENSCHTE Verhalten festgehalten -- insbesondere die
korrigierten Bugs (kein stiller Roh-Fallback, klare Exception mit Key-Bezug).
"""

import sqlite3
from pathlib import Path

import pytest

from domain.settings import Setting, SettingValue
from infrastructure.settings_repository import (
    CorruptSettingError,
    SqliteSettingsRepository,
)
from ports.settings import SettingsRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteSettingsRepository:
    """Frisches Repository gegen eine temporaere DB."""
    return SqliteSettingsRepository(tmp_path / "cernis.db")


def _insert_raw(db_path: Path, key: str, raw_value: str) -> None:
    """Schiebt einen Roh-/Nicht-JSON-Wert direkt in die Tabelle (Legacy-Simulation)."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?)", (key, raw_value)
        )
        conn.commit()
    finally:
        conn.close()


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_settings_repository_protocol(
    repo: SqliteSettingsRepository,
) -> None:
    # Statische Vertragspruefung (mypy): erfuellt das Protocol strukturell,
    # ohne @runtime_checkable / isinstance.
    _: SettingsRepository = repo


# ── Round-trip: set / get / get_all / delete ──────────────────────────────


def test_set_then_get_roundtrips(repo: SqliteSettingsRepository) -> None:
    repo.set(Setting(key="greeting", value="hallo"))
    assert repo.get("greeting") == Setting(key="greeting", value="hallo")


def test_set_then_get_all(repo: SqliteSettingsRepository) -> None:
    repo.set(Setting(key="a", value=1))
    repo.set(Setting(key="b", value={"x": True}))
    assert repo.get_all() == {"a": 1, "b": {"x": True}}


def test_get_all_empty_store_returns_empty_dict(
    repo: SqliteSettingsRepository,
) -> None:
    assert repo.get_all() == {}


def test_set_overwrites_existing_via_upsert(
    repo: SqliteSettingsRepository,
) -> None:
    repo.set(Setting(key="k", value="alt"))
    repo.set(Setting(key="k", value="neu"))
    assert repo.get("k") == Setting(key="k", value="neu")


def test_delete_removes_setting(repo: SqliteSettingsRepository) -> None:
    repo.set(Setting(key="k", value="v"))
    repo.delete("k")
    assert repo.get("k") is None


# ── Negativ-/Randfaelle ───────────────────────────────────────────────────


def test_get_missing_key_returns_none(repo: SqliteSettingsRepository) -> None:
    assert repo.get("missing") is None


def test_delete_missing_key_is_idempotent(
    repo: SqliteSettingsRepository,
) -> None:
    # Kein Fehler bei fehlendem Key.
    repo.delete("missing")


# ── JSON-Typen ueberleben den Round-trip ──────────────────────────────────


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        42,
        3.14,
        "text",
        ["a", 1, None],
        {"nested": {"a": [1, 2, 3]}},
    ],
)
def test_json_types_roundtrip(
    repo: SqliteSettingsRepository, value: SettingValue
) -> None:
    repo.set(Setting(key="k", value=value))
    assert repo.get("k") == Setting(key="k", value=value)


def test_bool_stays_bool_not_int(repo: SqliteSettingsRepository) -> None:
    repo.set(Setting(key="enabled", value=True))
    fetched = repo.get("enabled")
    assert fetched is not None
    assert fetched.value is True  # bleibt bool, nicht 1


# ── Korrigierte Altcode-Bugs: kein stiller Fallback ───────────────────────


def test_get_raises_on_non_json_value_no_silent_raw_fallback(
    repo: SqliteSettingsRepository, tmp_path: Path
) -> None:
    # Anders als der Altcode (get_setting liefert den Rohstring): hier ist ein
    # kaputter Wert ein Fehler MIT Key-Bezug.
    _insert_raw(tmp_path / "cernis.db", "legacy_key", "roh_plaintext")
    with pytest.raises(CorruptSettingError) as exc_info:
        repo.get("legacy_key")
    assert exc_info.value.key == "legacy_key"


def test_get_all_raises_clear_error_with_key_on_non_json_value(
    repo: SqliteSettingsRepository, tmp_path: Path
) -> None:
    # Anders als der Altcode (nichtssagender JSONDecodeError): klare Exception,
    # die den betroffenen Key benennt -- kein stilles Verschlucken.
    _insert_raw(tmp_path / "cernis.db", "legacy_key", "roh_plaintext")
    with pytest.raises(CorruptSettingError) as exc_info:
        repo.get_all()
    assert exc_info.value.key == "legacy_key"
