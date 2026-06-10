"""Tests fuer ``SqliteUserRuleRepository`` (A.2) -- gegen tmp_path-DB.

Belegt den gestuften Schreibpfad (error -> nichts gespeichert; nur warning -> gespeichert
+ gemeldet; duplicate_id -> error), den verlustfreien Round-trip (ports/path_prefixes/
threshold) und den LAUTEN Fehler bei kaputtem ``params_json`` (``CorruptUserRuleError``
statt eines stillen Rueckfalls). Muster der uebrigen infrastructure-Repo-Tests
(``tmp_path``-DB, struktureller Port-Vertrag via mypy-Zuweisung).
"""

import sqlite3
from pathlib import Path

import pytest

from domain.analysis import DEFAULT_RULES, Rule
from infrastructure.analysis_rules_db import (
    CorruptUserRuleError,
    SqliteUserRuleRepository,
)
from ports.analysis import RuleProvider, UserRuleStore


@pytest.fixture
def repo(tmp_path: Path) -> SqliteUserRuleRepository:
    return SqliteUserRuleRepository(tmp_path / "cernis.db")


# ── Struktureller Vertrag (beide Ports) ───────────────────────────────────────


def test_conforms_to_both_ports(repo: SqliteUserRuleRepository) -> None:
    # mypy-Beweis: der Adapter erfuellt den Lese- UND den Verwaltungs-Port.
    _read: RuleProvider = repo
    _store: UserRuleStore = repo


# ── Round-trip (verlustfrei) ──────────────────────────────────────────────────


def test_add_clean_rule_roundtrips_lossless(repo: SqliteUserRuleRepository) -> None:
    """Eine saubere Regel -> ``[]``; get_rules enthaelt sie verlustfrei."""
    rule = Rule(
        id="my_remote_ports",
        severity="notable",
        help_kind="remote_access_port",
        kind="connection_remote_port",
        title="Eigene Fernzugriffs-Ports",
        detail_template="Verbindung zu {subject} ({value}).",
        ports=frozenset({4444, 1234}),
    )

    issues = repo.add_rules([rule])
    assert issues == []

    stored = repo.get_rules()
    assert len(stored) == 1
    assert stored[0] == rule
    # ports verlustfrei (frozenset), path_prefixes/threshold die domain-Defaults.
    assert stored[0].ports == frozenset({4444, 1234})
    assert stored[0].path_prefixes == ()
    assert stored[0].threshold == 0


def test_add_path_and_threshold_rules_roundtrip(repo: SqliteUserRuleRepository) -> None:
    """path_prefixes (tuple) und threshold (int) ueberleben den Round-trip verlustfrei."""
    path_rule = Rule(
        id="my_paths",
        severity="notable",
        help_kind="process_suspicious_path",
        kind="process_temp_path",
        title="Eigene Pfade",
        detail_template="{subject} aus {value}.",
        path_prefixes=("/opt/weird/", "/home/x/"),
    )
    count_rule = Rule(
        id="my_count",
        severity="info",
        help_kind="high_connection_count",
        kind="pid_connection_count",
        title="Eigene Schwelle",
        detail_template="{subject}: {value}.",
        threshold=99,
    )

    assert repo.add_rules([path_rule, count_rule]) == []

    by_id = {rule.id: rule for rule in repo.get_rules()}
    assert by_id["my_paths"].path_prefixes == ("/opt/weird/", "/home/x/")
    assert by_id["my_count"].threshold == 99


# ── Gestufte Validierung ──────────────────────────────────────────────────────


def test_structurally_broken_rule_is_error_and_stores_nothing(
    repo: SqliteUserRuleRepository,
) -> None:
    """Leere ports -> error; NICHTS gespeichert (get_rules leer)."""
    broken = Rule(
        id="broken_ports",
        severity="notable",
        help_kind="remote_access_port",
        kind="connection_remote_port",
        title="Kaputt",
        detail_template="{subject} ({value}).",
        ports=frozenset(),  # leer -> kann nie zutreffen
    )

    issues = repo.add_rules([broken])
    assert any(issue.severity == "error" and issue.code == "empty_ports" for issue in issues)
    assert repo.get_rules() == ()  # keine Teil-Speicherung


def test_warning_duplicate_of_default_is_stored_and_reported(
    repo: SqliteUserRuleRepository,
) -> None:
    """Parameter-Duplikat zu einer DEFAULT-Regel (andere id) -> warning, ABER gespeichert."""
    # Gleiche ports wie das eingebaute remote_access_port (notwendig fuer das duplicate-
    # warning), aber eine EIGENE id -- sonst greift duplicate_id (error).
    default_ports = next(r.ports for r in DEFAULT_RULES if r.kind == "connection_remote_port")
    dup = Rule(
        id="my_own_remote",
        severity="notable",
        help_kind="remote_access_port",
        kind="connection_remote_port",
        title="Mein Fernzugriff",
        detail_template="{subject} ({value}).",
        ports=default_ports,
    )

    issues = repo.add_rules([dup])
    assert issues  # nicht leer
    assert all(issue.severity == "warning" for issue in issues)
    assert any(issue.code == "duplicate" for issue in issues)
    # nur warning -> gespeichert
    assert [rule.id for rule in repo.get_rules()] == ["my_own_remote"]


def test_duplicate_id_is_error_and_stores_nothing(repo: SqliteUserRuleRepository) -> None:
    """Eine id, die bereits gespeichert ist -> error duplicate_id, nichts gespeichert."""
    first = Rule(
        id="same_id",
        severity="info",
        help_kind="high_connection_count",
        kind="pid_connection_count",
        title="Erst",
        detail_template="{subject}: {value}.",
        threshold=10,
    )
    assert repo.add_rules([first]) == []

    second = Rule(
        id="same_id",  # kollidiert
        severity="info",
        help_kind="high_connection_count",
        kind="pid_connection_count",
        title="Nochmal",
        detail_template="{subject}: {value}.",
        threshold=20,
    )
    issues = repo.add_rules([second])
    assert any(issue.severity == "error" and issue.code == "duplicate_id" for issue in issues)
    # nicht ueberschrieben: der erste Stand bleibt, der zweite NICHT gespeichert.
    stored = {rule.id: rule.threshold for rule in repo.get_rules()}
    assert stored == {"same_id": 10}


def test_duplicate_id_within_one_batch_is_error(repo: SqliteUserRuleRepository) -> None:
    """Zwei Regeln mit derselben id in EINEM add_rules -> error duplicate_id, nichts gespeichert."""
    rule_a = Rule(
        id="dup",
        severity="info",
        help_kind="high_connection_count",
        kind="pid_connection_count",
        title="A",
        detail_template="{subject}: {value}.",
        threshold=10,
    )
    rule_b = Rule(
        id="dup",
        severity="info",
        help_kind="high_connection_count",
        kind="pid_connection_count",
        title="B",
        detail_template="{subject}: {value}.",
        threshold=20,
    )
    issues = repo.add_rules([rule_a, rule_b])
    assert any(issue.code == "duplicate_id" for issue in issues)
    assert repo.get_rules() == ()


# ── Kaputtes params_json -> lauter Fehler (kein stiller Rueckfall) ─────────────


def test_corrupt_params_json_raises(repo: SqliteUserRuleRepository, tmp_path: Path) -> None:
    """Kaputtes params_json in der DB -> CorruptUserRuleError beim get_rules."""
    # Direkt eine kaputte Zeile in die Test-DB schreiben (kein gueltiges JSON-Objekt).
    conn = sqlite3.connect(tmp_path / "cernis.db")
    try:
        with conn:
            conn.execute(
                "INSERT INTO analysis_user_rules "
                "(id, kind, severity, help_kind, title, detail_template, params_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "corrupt",
                    "connection_remote_port",
                    "notable",
                    "remote_access_port",
                    "Kaputt",
                    "{subject} ({value}).",
                    "{ this is not valid json",
                ),
            )
    finally:
        conn.close()

    with pytest.raises(CorruptUserRuleError) as excinfo:
        repo.get_rules()
    assert excinfo.value.rule_id == "corrupt"


def test_formfremd_params_json_raises(repo: SqliteUserRuleRepository, tmp_path: Path) -> None:
    """Gueltiges JSON, aber falsche Form (ports kein Listen-Feld) -> CorruptUserRuleError."""
    conn = sqlite3.connect(tmp_path / "cernis.db")
    try:
        with conn:
            conn.execute(
                "INSERT INTO analysis_user_rules "
                "(id, kind, severity, help_kind, title, detail_template, params_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "wrongform",
                    "connection_remote_port",
                    "notable",
                    "remote_access_port",
                    "Form",
                    "{subject} ({value}).",
                    '{"ports": "nicht-eine-liste"}',
                ),
            )
    finally:
        conn.close()

    with pytest.raises(CorruptUserRuleError):
        repo.get_rules()


# ── delete ─────────────────────────────────────────────────────────────────────


def test_delete_removes_rule(repo: SqliteUserRuleRepository) -> None:
    rule = Rule(
        id="to_delete",
        severity="info",
        help_kind="high_connection_count",
        kind="pid_connection_count",
        title="Weg",
        detail_template="{subject}: {value}.",
        threshold=5,
    )
    assert repo.add_rules([rule]) == []
    assert [r.id for r in repo.get_rules()] == ["to_delete"]

    repo.delete_rule("to_delete")
    assert repo.get_rules() == ()


def test_delete_unknown_id_is_noop(repo: SqliteUserRuleRepository) -> None:
    # Idempotent: eine unbekannte id ist kein Fehler.
    repo.delete_rule("does_not_exist")
    assert repo.get_rules() == ()
