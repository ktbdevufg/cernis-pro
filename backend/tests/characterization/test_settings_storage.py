"""Characterization-Tests fuer das Ist-Verhalten von modules/storage.py (settings).

Halten das AKTUELLE Verhalten des Altcodes fest -- nicht das gewuenschte. Auch
ueberraschende Eigenheiten werden dokumentiert, nicht korrigiert: Diese Tests
sind das Sicherheitsnetz, gegen das die settings-Migration (Schritt 6) antritt.
Auffaelligkeiten fuers Redesign sind im ADR zu Schritt 6 gesammelt, nicht hier.
"""

import json
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def settings_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Liefert ``modules.storage`` gegen eine frische temporaere DB.

    ``CERNIS_DATA_DIR`` wird vor dem Import gesetzt, damit db_path keine echten
    Nutzerverzeichnisse anlegt; ``DB_PATH`` wird zusaetzlich direkt umgebogen.
    """
    monkeypatch.setenv("CERNIS_DATA_DIR", str(tmp_path))
    from modules import storage

    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "cernis.db"))
    storage.init_db()
    return storage


# ── Grundvertrag: get / set / bulk ────────────────────────────────────────


def test_set_and_get_string(settings_storage: Any) -> None:
    settings_storage.set_setting("greeting", "hallo")
    assert settings_storage.get_setting("greeting") == "hallo"


def test_set_and_get_dict_preserves_structure(settings_storage: Any) -> None:
    value = {"host": "fritz.box", "port": 49000, "nested": {"a": [1, 2, 3]}}
    settings_storage.set_setting("cfg", value)
    assert settings_storage.get_setting("cfg") == value


def test_set_and_get_list(settings_storage: Any) -> None:
    settings_storage.set_setting("targets", ["1.1.1.1", "8.8.8.8"])
    assert settings_storage.get_setting("targets") == ["1.1.1.1", "8.8.8.8"]


def test_int_and_bool_types_survive_roundtrip(settings_storage: Any) -> None:
    settings_storage.set_setting("count", 42)
    settings_storage.set_setting("enabled", True)
    assert settings_storage.get_setting("count") == 42
    assert settings_storage.get_setting("enabled") is True  # bleibt bool, nicht 1


def test_get_missing_returns_explicit_default(settings_storage: Any) -> None:
    assert settings_storage.get_setting("missing", "fallback") == "fallback"


def test_get_missing_returns_none_without_default(settings_storage: Any) -> None:
    assert settings_storage.get_setting("missing") is None


def test_set_overwrites_existing(settings_storage: Any) -> None:
    # INSERT OR REPLACE: das zweite set gewinnt.
    settings_storage.set_setting("k", "alt")
    settings_storage.set_setting("k", "neu")
    assert settings_storage.get_setting("k") == "neu"


def test_get_all_settings_returns_all_decoded(settings_storage: Any) -> None:
    settings_storage.set_setting("a", 1)
    settings_storage.set_setting("b", {"x": True})
    assert settings_storage.get_all_settings() == {"a": 1, "b": {"x": True}}


def test_get_all_settings_empty_db_returns_empty_dict(settings_storage: Any) -> None:
    assert settings_storage.get_all_settings() == {}


# ── Edge Cases (Characterization: dokumentiert, nicht bewertet) ────────────


def test_none_roundtrips_as_json_null(settings_storage: Any) -> None:
    # Characterization: set_setting serialisiert None via json.dumps zu "null"
    # (Text), get_setting liefert beim Auslesen wieder None zurueck -- NICHT
    # den String "None". None bleibt also erhalten.
    settings_storage.set_setting("nothing", None)
    assert settings_storage.get_setting("nothing") is None


def test_empty_string_roundtrips(settings_storage: Any) -> None:
    # Characterization: "" -> json.dumps -> '""' (Text, nicht SQL-NULL; die
    # Spalte ist NOT NULL) -> wieder "".
    settings_storage.set_setting("empty", "")
    assert settings_storage.get_setting("empty") == ""


def test_unicode_value_roundtrips(settings_storage: Any) -> None:
    settings_storage.set_setting("umlaut", "Gruesse: äöü €")
    assert settings_storage.get_setting("umlaut") == "Gruesse: äöü €"


def test_tuple_comes_back_as_list(settings_storage: Any) -> None:
    # Characterization: JSON kennt keine Tupel -> ein tuple wird als Array
    # serialisiert und als list zurueckgelesen. Typinformation geht verloren.
    settings_storage.set_setting("pair", (1, 2))
    assert settings_storage.get_setting("pair") == [1, 2]


def test_get_setting_tolerates_non_json_raw_value(settings_storage: Any) -> None:
    # Characterization: Wird ein Roh-/Nicht-JSON-Wert direkt eingefuegt (wie
    # legacy-Klartext, vgl. Finding S3), faengt get_setting den json.loads-
    # Fehler ab und liefert den Rohstring zurueck.
    with settings_storage._get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            ("legacy_key", "roh_plaintext"),
        )
    assert settings_storage.get_setting("legacy_key") == "roh_plaintext"


def test_get_all_settings_raises_on_non_json_value(settings_storage: Any) -> None:
    # Characterization: get_all_settings hat -- anders als get_setting -- KEIN
    # try/except um json.loads. Ein einziger Nicht-JSON-Wert in der Tabelle
    # laesst die gesamte Abfrage mit JSONDecodeError scheitern. Inkonsistenz
    # zwischen tolerantem get_setting und striktem get_all_settings.
    with settings_storage._get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            ("legacy_key", "roh_plaintext"),
        )
    with pytest.raises(json.JSONDecodeError):
        settings_storage.get_all_settings()
