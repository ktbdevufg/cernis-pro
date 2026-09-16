"""End-to-end-Test der A.2-Regelverwaltung (``/api/analysis/rules``) via TestClient.

Belegt die GESTUFTE api-Semantik gegen ein echtes tmp_path-DB-Repo (kein Fake -- so wird
der Adapter-Schreibpfad mitgeprueft): gueltige Regel -> 201 + GET listet sie; error-Regel
-> 422 + Issue-code im Body + GET listet nichts; warning-Regel -> 201 + warning im Body;
DELETE entfernt. Die drei Verwaltungs-Runner werden -- analog app.py -- ueber
``dependency_overrides`` auf ein tmp-DB-Repo verdrahtet (der api-Ring bleibt domain-frei,
das Bauen der domain.Rule passiert im Test-Runner wie im Composition Root).
"""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.analysis import (
    UserRuleBody,
    provide_add_user_rules,
    provide_delete_user_rule,
    provide_list_user_rules,
)
from app import create_app
from domain.analysis import Rule
from infrastructure.analysis_rules_db import SqliteUserRuleRepository
from infrastructure.config import AppConfig


@pytest.fixture
def app(tmp_path: Path) -> Iterator[FastAPI]:
    application = create_app(AppConfig())
    repo = SqliteUserRuleRepository(tmp_path / "cernis.db")

    # Verwaltungs-Runner wie im Composition Root: DTO -> domain.Rule -> Use-Case/Repo.
    def _add(bodies: list[UserRuleBody]) -> list[Any]:
        new_rules = [
            Rule(
                id=body.id,
                severity=body.severity,  # type: ignore[arg-type]
                help_kind=body.help_kind,  # type: ignore[arg-type]
                kind=body.kind,  # type: ignore[arg-type]
                title=body.title,
                detail_template=body.detail_template,
                path_prefixes=tuple(body.path_prefixes),
                ports=frozenset(body.ports),
                threshold=body.threshold,
            )
            for body in bodies
        ]
        return repo.add_rules(new_rules)

    application.dependency_overrides[provide_add_user_rules] = lambda: _add
    application.dependency_overrides[provide_list_user_rules] = lambda: (
        lambda: list(repo.get_rules())
    )
    application.dependency_overrides[provide_delete_user_rule] = lambda: repo.delete_rule
    yield application


def _valid_body() -> dict[str, Any]:
    return {
        "id": "my_remote",
        "kind": "connection_remote_port",
        "severity": "notable",
        "help_kind": "remote_access_port",
        "title": "Eigene Fernzugriffs-Ports",
        "detail_template": "Verbindung zu {subject} ({value}).",
        "ports": [4444, 1234],
    }


def test_post_valid_then_get_lists_it(app: FastAPI) -> None:
    """POST gueltige Regel -> 201; danach listet GET sie."""
    with TestClient(app) as client:
        response = client.post("/api/analysis/rules", json=[_valid_body()])
        assert response.status_code == 201
        assert response.json() == {"issues": []}

        listed = client.get("/api/analysis/rules")
        assert listed.status_code == 200
        rules = listed.json()
        assert len(rules) == 1
        assert rules[0]["id"] == "my_remote"
        assert sorted(rules[0]["ports"]) == [1234, 4444]


def test_post_error_rule_is_422_and_stores_nothing(app: FastAPI) -> None:
    """POST error-Regel (leere ports) -> 422 mit Issue-code; GET listet nichts."""
    broken = _valid_body()
    broken["ports"] = []  # leer -> empty_ports (error)

    with TestClient(app) as client:
        response = client.post("/api/analysis/rules", json=[broken])
        assert response.status_code == 422
        body = response.json()
        codes = [issue["code"] for issue in body["issues"]]
        assert "empty_ports" in codes
        assert any(issue["severity"] == "error" for issue in body["issues"])

        listed = client.get("/api/analysis/rules")
        assert listed.json() == []  # nichts gespeichert


def test_post_warning_rule_is_201_and_shows_warning(app: FastAPI) -> None:
    """POST warning-Regel (Parameter-Duplikat zu einer DEFAULT-Regel) -> 201 + warning sichtbar."""
    # Gleiche ports wie das eingebaute remote_access_port, eigene id -> nur duplicate-warning.
    dup = _valid_body()
    dup["id"] = "my_own_remote"
    dup["ports"] = [22, 3389, 5800, 5900]

    with TestClient(app) as client:
        response = client.post("/api/analysis/rules", json=[dup])
        assert response.status_code == 201
        body = response.json()
        assert body["issues"]  # nicht leer
        assert all(issue["severity"] == "warning" for issue in body["issues"])
        assert any(issue["code"] == "duplicate" for issue in body["issues"])

        # nur warning -> gespeichert
        listed = client.get("/api/analysis/rules")
        assert [rule["id"] for rule in listed.json()] == ["my_own_remote"]


def test_delete_removes_rule(app: FastAPI) -> None:
    with TestClient(app) as client:
        assert client.post("/api/analysis/rules", json=[_valid_body()]).status_code == 201
        assert len(client.get("/api/analysis/rules").json()) == 1

        deleted = client.delete("/api/analysis/rules/my_remote")
        assert deleted.status_code == 200
        assert deleted.json() == {"ok": True}

        assert client.get("/api/analysis/rules").json() == []
