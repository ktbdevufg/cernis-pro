"""Tests fuer ``SqliteAlertRuleRepository`` (A.4) -- CRUD + History + Schema-Vertrag.

AUFLAGE 2 (Schema-Vertrag, NICHT zirkulaer): Die Schema-Tests bauen die Altcode-
Tabelle ueber das ECHTE ``modules.alerting.init_alerts_db`` (NICHT ueber eine
nachgebaute Konstante -- das waere zirkulaer, falls die Konstante vom echten init
abweicht). ``DB_PATH`` wird am Altcode-Modul-Namespace auf die tmp-DB gebogen (wie A.1),
dann laeuft der v2-Adapter gegen GENAU diese Tabelle. Plus ein direkter
``PRAGMA table_info``-Vergleich (echtes init vs. v2-Adapter) als HARTER Vertrag, der
jede kuenftige Schema-Drift zwischen Altcode und v2 auffliegen laesst -- auch wenn die
beiden CREATE-Texte mal auseinanderlaufen. Plus: round-trip int<->bool.
"""

import sqlite3
from pathlib import Path

import pytest

from domain.alerting import AlertEvent
from infrastructure.alerting.rule_repository import SqliteAlertRuleRepository
from ports.alerting import AlertRuleRepository


def _init_altcode_db(db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Legt die Altcode-Tabellen ueber das ECHTE init_alerts_db in db_path an.

    DB_PATH am Altcode-Modul-Namespace biegen (wie A.1 -- es ist beim Import als
    String gebunden, eine Env-Var wuerde nicht mehr greifen).
    """
    from modules import alerting as altcode

    monkeypatch.setattr(altcode, "DB_PATH", str(db_path))
    altcode.init_alerts_db()


def _table_schema(db_path: Path, table: str) -> list[tuple[object, ...]]:
    """``PRAGMA table_info`` als vergleichbare Liste (name, type, notnull, default, pk)."""
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    finally:
        conn.close()
    # row: (cid, name, type, notnull, dflt_value, pk) -- cid (Position) weglassen,
    # der Rest ist der Schema-Vertrag (Spaltenname/Typ/NOTNULL/Default/PK).
    return [tuple(row[1:]) for row in rows]


@pytest.fixture
def repo(tmp_path: Path) -> SqliteAlertRuleRepository:
    return SqliteAlertRuleRepository(tmp_path / "cernis.db")


def test_conforms_to_repository_protocol(repo: SqliteAlertRuleRepository) -> None:
    _: AlertRuleRepository = repo


# ── Auflage 2: gemeinsame Tabelle mit dem ECHTEN Altcode-init ──


def test_reads_altcode_table_without_guard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Altcode-Tabelle ueber das ECHTE init_alerts_db anlegen + eine Zeile schreiben.
    db = tmp_path / "cernis.db"
    _init_altcode_db(db, monkeypatch)
    conn = sqlite3.connect(db)
    conn.execute(
        "INSERT INTO alert_rules "
        "(name, rule_type, target, threshold, notify_email, notify_macos) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("Altcode-Rule", "host_down", "any", 60, 0, 1),
    )
    conn.commit()
    conn.close()

    # v2-Adapter gegen die bestehende Altcode-Tabelle: CREATE IF NOT EXISTS = No-Op,
    # kein Schema-Konflikt, liest die Altcode-Zeile sauber.
    repo = SqliteAlertRuleRepository(db)
    rules = repo.get_rules()
    assert len(rules) == 1
    assert rules[0].name == "Altcode-Rule"
    assert rules[0].rule_type == "host_down"
    assert rules[0].enabled is True
    assert rules[0].notify_email is False
    assert rules[0].notify_macos is True


def test_v2_schema_matches_altcode_init_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # HARTER Schema-Vertrag: das ECHTE Altcode-init und der v2-Adapter erzeugen
    # spaltenidentische Tabellen (Name/Typ/NOTNULL/Default/PK je Spalte). Faengt jede
    # kuenftige Drift -- auch wenn die CREATE-Texte auseinanderlaufen.
    altcode_db = tmp_path / "altcode.db"
    _init_altcode_db(altcode_db, monkeypatch)

    v2_db = tmp_path / "v2.db"
    SqliteAlertRuleRepository(v2_db)  # _ensure_schema im __init__

    for table in ("alert_rules", "alert_history"):
        assert _table_schema(v2_db, table) == _table_schema(altcode_db, table), (
            f"Schema-Drift in {table}: v2-Adapter != modules.alerting.init_alerts_db"
        )


# ── round-trip int<->bool ─────────────────────────────────────


def test_add_get_roundtrip_int_bool(repo: SqliteAlertRuleRepository) -> None:
    rule_id = repo.add(
        name="R",
        rule_type="host_down",
        target="any",
        threshold=60,
        notify_email=True,
        notify_macos=False,
    )
    assert isinstance(rule_id, int)
    rule = repo.get_rules()[0]
    # bool in der Domaene ...
    assert rule.notify_email is True
    assert rule.notify_macos is False
    assert rule.enabled is True  # add setzt Default enabled=1


def test_sqlite_stores_flags_as_int(repo: SqliteAlertRuleRepository, tmp_path: Path) -> None:
    # ... aber SQLite haelt int 0/1 (Wire-Vertrag A.1) -- direkt nachsehen.
    repo.add(
        name="R",
        rule_type="host_down",
        target="any",
        threshold=60,
        notify_email=True,
        notify_macos=False,
    )
    conn = sqlite3.connect(tmp_path / "cernis.db")
    row = conn.execute("SELECT notify_email, notify_macos, enabled FROM alert_rules").fetchone()
    conn.close()
    assert row == (1, 0, 1)


def test_add_defaults_match_altcode(repo: SqliteAlertRuleRepository) -> None:
    repo.add(
        name="R",
        rule_type="host_down",
        target="any",
        threshold=60,
        notify_email=False,
        notify_macos=True,
    )
    rule = repo.get_rules()[0]
    assert rule.last_triggered == 0.0
    assert rule.enabled is True


# ── get_rules: Reihenfolge + leere DB ─────────────────────────


def test_get_rules_ordered_by_id(repo: SqliteAlertRuleRepository) -> None:
    repo.add(
        name="A",
        rule_type="host_down",
        target="any",
        threshold=60,
        notify_email=False,
        notify_macos=True,
    )
    repo.add(
        name="B",
        rule_type="new_device",
        target="any",
        threshold=60,
        notify_email=False,
        notify_macos=True,
    )
    assert [r.name for r in repo.get_rules()] == ["A", "B"]


def test_get_rules_empty_after_init(repo: SqliteAlertRuleRepository) -> None:
    # _ensure_schema im __init__ -> leere-aber-initialisierte DB -> [].
    assert repo.get_rules() == []


# ── update: Whitelist + int<->bool ────────────────────────────


def test_update_applies_only_given_fields(repo: SqliteAlertRuleRepository) -> None:
    rule_id = repo.add(
        name="R",
        rule_type="host_down",
        target="any",
        threshold=60,
        notify_email=False,
        notify_macos=True,
    )
    repo.update(rule_id, name="Renamed", threshold=120, enabled=False)
    rule = repo.get_rules()[0]
    assert rule.name == "Renamed"
    assert rule.threshold == 120
    assert rule.enabled is False
    # nicht uebergebene Felder unveraendert
    assert rule.target == "any"
    assert rule.notify_macos is True


def test_update_enabled_false_roundtrip(repo: SqliteAlertRuleRepository) -> None:
    rule_id = repo.add(
        name="R",
        rule_type="host_down",
        target="any",
        threshold=60,
        notify_email=False,
        notify_macos=True,
    )
    repo.update(rule_id, enabled=False)
    assert repo.get_rules()[0].enabled is False
    repo.update(rule_id, enabled=True)
    assert repo.get_rules()[0].enabled is True


def test_update_no_fields_is_noop(repo: SqliteAlertRuleRepository) -> None:
    rule_id = repo.add(
        name="R",
        rule_type="host_down",
        target="any",
        threshold=60,
        notify_email=False,
        notify_macos=True,
    )
    repo.update(rule_id)  # alle None -> kein UPDATE, kein Fehler
    assert repo.get_rules()[0].name == "R"


def test_update_rule_type_not_changeable(repo: SqliteAlertRuleRepository) -> None:
    # rule_type ist NICHT in der Whitelist (Altcode) -> kein update()-Parameter dafuer.
    rule_id = repo.add(
        name="R",
        rule_type="host_down",
        target="any",
        threshold=60,
        notify_email=False,
        notify_macos=True,
    )
    repo.update(rule_id, name="X")
    assert repo.get_rules()[0].rule_type == "host_down"


# ── delete ────────────────────────────────────────────────────


def test_delete_removes_rule(repo: SqliteAlertRuleRepository) -> None:
    rule_id = repo.add(
        name="R",
        rule_type="host_down",
        target="any",
        threshold=60,
        notify_email=False,
        notify_macos=True,
    )
    repo.delete(rule_id)
    assert repo.get_rules() == []


def test_delete_missing_id_is_idempotent(repo: SqliteAlertRuleRepository) -> None:
    repo.delete(999)  # kein Fehler


# ── history: save_event + recent ──────────────────────────────


def test_recent_empty_after_init(repo: SqliteAlertRuleRepository) -> None:
    # GEHEILTER PFAD (A.1-v2-Heilung): leere-aber-initialisierte DB -> [], kein 500.
    assert repo.recent(50) == []


def test_save_event_writes_history_and_sets_last_triggered(
    repo: SqliteAlertRuleRepository,
) -> None:
    rule_id = repo.add(
        name="R",
        rule_type="host_down",
        target="192.168.1.1",
        threshold=60,
        notify_email=False,
        notify_macos=True,
    )
    event = AlertEvent(
        rule_id=rule_id,
        rule_name="R",
        rule_type="host_down",
        target="192.168.1.1",
        message="host down",
        timestamp=1_700_000_000.0,
    )
    repo.save_event(event)

    history = repo.recent(50)
    assert len(history) == 1
    assert history[0].rule_id == rule_id
    assert history[0].message == "host down"
    assert history[0].timestamp == 1_700_000_000.0
    # last_triggered der Regel auf event.timestamp gesetzt.
    assert repo.get_rules()[0].last_triggered == 1_700_000_000.0


def test_recent_newest_first_and_limit(repo: SqliteAlertRuleRepository) -> None:
    rule_id = repo.add(
        name="R",
        rule_type="host_down",
        target="any",
        threshold=60,
        notify_email=False,
        notify_macos=True,
    )
    for ts in (100.0, 300.0, 200.0):
        repo.save_event(
            AlertEvent(
                rule_id=rule_id,
                rule_name="R",
                rule_type="host_down",
                target="any",
                message=f"m-{ts}",
                timestamp=ts,
            )
        )
    history = repo.recent(50)
    # ORDER BY ts DESC
    assert [e.timestamp for e in history] == [300.0, 200.0, 100.0]
    assert len(repo.recent(1)) == 1
