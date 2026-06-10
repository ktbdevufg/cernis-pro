"""End-to-end-Tests des process-Routers (v2, P.3) gegen app.py via TestClient.

Belegt: ``GET /api/processes?view=flat`` serialisiert die flache Prozessliste,
``view=tree`` die rekursive Baum-Struktur (Runner via ``dependency_overrides`` durch
einen Fake ersetzt -- kein echtes psutil/proc). ``view`` ist Pflicht mit genau zwei
erlaubten Werten -> fehlend/ungueltig ergibt 422. ``GET /api/processes/permission``
liefert die ``{ok, error}``-Naht (allowed/denied) ueber den Fake-Permission-Use-Case.
"""

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.process import (
    provide_check_process_permission,
    provide_list_processes,
)
from app import create_app
from domain.process import ProcessInfo, build_process_tree
from infrastructure.config import AppConfig


@pytest.fixture
def app() -> Iterator[FastAPI]:
    yield create_app(AppConfig())


def _proc(pid: int, ppid: int | None = None, *, name: str = "foo") -> ProcessInfo:
    return ProcessInfo(
        pid=pid,
        ppid=ppid,
        name=name,
        owner="kbach",
        status="sleeping",
        create_time=123.0,
        cmdline=("/usr/bin/foo",),
    )


class _FakePermission:
    """In-Memory-Stand-in fuer CheckProcessPermission ({ok, error}-Naht)."""

    def __init__(self, ok: bool, error: str) -> None:
        self._ok = ok
        self._error = error

    def __call__(self) -> dict[str, object]:
        return {"ok": self._ok, "error": self._error}


def test_processes_flat_wire_form(app: FastAPI) -> None:
    """``view=flat`` liefert die serialisierten Prozesse (alle ProcessInfo-Felder)."""

    procs = [_proc(1, name="systemd"), _proc(10, ppid=1, name="foo")]

    async def _fake_runner(view: str) -> list[Any]:
        return procs

    app.dependency_overrides[provide_list_processes] = lambda: _fake_runner

    with TestClient(app) as client:
        response = client.get("/api/processes", params={"view": "flat"})

    assert response.status_code == 200
    body = response.json()
    assert [p["pid"] for p in body] == [1, 10]
    first = body[0]
    assert first == {
        "pid": 1,
        "ppid": None,
        "name": "systemd",
        "owner": "kbach",
        "status": "sleeping",
        "create_time": 123.0,
        "cmdline": ["/usr/bin/foo"],
    }


def test_processes_tree_wire_form(app: FastAPI) -> None:
    """``view=tree`` liefert die rekursive Baum-Struktur (info + children)."""

    forest = build_process_tree([_proc(1), _proc(10, ppid=1)])

    async def _fake_runner(view: str) -> list[Any]:
        return list(forest)

    app.dependency_overrides[provide_list_processes] = lambda: _fake_runner

    with TestClient(app) as client:
        response = client.get("/api/processes", params={"view": "tree"})

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    root = body[0]
    assert root["info"]["pid"] == 1
    assert [c["info"]["pid"] for c in root["children"]] == [10]
    # Kind ist ein Blatt
    assert root["children"][0]["children"] == []


def test_processes_view_required(app: FastAPI) -> None:
    """Fehlender Pflichtparameter ``view`` -> 422 (kein Raten)."""

    async def _fake_runner(view: str) -> list[Any]:
        return []

    app.dependency_overrides[provide_list_processes] = lambda: _fake_runner

    with TestClient(app) as client:
        response = client.get("/api/processes")

    assert response.status_code == 422


def test_processes_view_invalid(app: FastAPI) -> None:
    """Ungueltiger ``view``-Wert -> 422 (nur flat|tree erlaubt)."""

    async def _fake_runner(view: str) -> list[Any]:
        return []

    app.dependency_overrides[provide_list_processes] = lambda: _fake_runner

    with TestClient(app) as client:
        response = client.get("/api/processes", params={"view": "quatsch"})

    assert response.status_code == 422


def test_process_permission_allowed(app: FastAPI) -> None:
    app.dependency_overrides[provide_check_process_permission] = lambda: _FakePermission(True, "")

    with TestClient(app) as client:
        response = client.get("/api/processes/permission")

    assert response.status_code == 200
    assert response.json() == {"ok": True, "error": ""}


def test_process_permission_denied(app: FastAPI) -> None:
    msg = "Fuer Details fremder Prozesse muss CERNIS PRO als Root laufen."
    app.dependency_overrides[provide_check_process_permission] = lambda: _FakePermission(False, msg)

    with TestClient(app) as client:
        response = client.get("/api/processes/permission")

    assert response.status_code == 200
    assert response.json() == {"ok": False, "error": msg}
