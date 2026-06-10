"""Tests der process-Use-Cases gegen In-Memory-Fakes der Ports.

Kein echtes psutil/proc-Tooling noetig -- wir testen gegen die Protocols. Kern der
Behauptungen: ``ListProcesses.flat`` reicht die Prozesse unveraendert durch,
``ListProcesses.tree`` delegiert den Wald-Aufbau an die Domaene
(``build_process_tree``), und ``CheckProcessPermission`` liefert die
``{ok, error}``-Naht (verfuegbar/Recht/kein Recht). Async via ``asyncio.run``
(Projektmuster, kein pytest-asyncio).
"""

import asyncio

from application.process import (
    CheckProcessPermission,
    ListProcesses,
)
from domain.process import ProcessInfo

# ── In-Memory-Fakes der Ports ────────────────────────────────────────────────


class FakeProcessProvider:
    """In-Memory-Implementierung des ``ProcessProvider``-Protocols."""

    def __init__(self, processes: list[ProcessInfo] | None = None) -> None:
        self._processes = processes or []
        self.list_processes_calls = 0

    async def list_processes(self) -> list[ProcessInfo]:
        self.list_processes_calls += 1
        return list(self._processes)


class FakeProcessPermission:
    """In-Memory-Implementierung des ``ProcessPermissionPort``-Protocols."""

    def __init__(self, available: bool = True, permission_error: str | None = None) -> None:
        self._available = available
        self._permission_error = permission_error

    def is_available(self) -> bool:
        return self._available

    def check_permission(self) -> str | None:
        return self._permission_error


def _proc(pid: int, ppid: int | None = None) -> ProcessInfo:
    return ProcessInfo(
        pid=pid,
        ppid=ppid,
        name="foo",
        owner="kbach",
        status="sleeping",
        create_time=None,
        cmdline=("/usr/bin/foo",),
    )


# ── ListProcesses ────────────────────────────────────────────────────────────


def test_list_processes_flat_returns_unchanged() -> None:
    procs = [_proc(1), _proc(2, ppid=1)]
    fake = FakeProcessProvider(processes=procs)
    result = asyncio.run(ListProcesses(fake).flat())
    assert result == procs
    assert fake.list_processes_calls == 1


def test_list_processes_flat_empty() -> None:
    fake = FakeProcessProvider(processes=[])
    result = asyncio.run(ListProcesses(fake).flat())
    assert result == []


def test_list_processes_tree_builds_forest() -> None:
    # 1 Wurzel mit einem Kind -> korrekte Baum-Struktur.
    fake = FakeProcessProvider(processes=[_proc(1), _proc(10, ppid=1)])
    forest = asyncio.run(ListProcesses(fake).tree())
    assert len(forest) == 1
    root = forest[0]
    assert root.info.pid == 1
    assert tuple(c.info.pid for c in root.children) == (10,)
    assert fake.list_processes_calls == 1


def test_list_processes_tree_empty() -> None:
    fake = FakeProcessProvider(processes=[])
    forest = asyncio.run(ListProcesses(fake).tree())
    assert forest == ()


# ── CheckProcessPermission ───────────────────────────────────────────────────


def test_check_permission_available_and_allowed() -> None:
    fake = FakeProcessPermission(available=True, permission_error=None)
    result = CheckProcessPermission(fake)()
    assert result == {"ok": True, "error": ""}


def test_check_permission_available_but_denied() -> None:
    msg = "Fuer Details fremder Prozesse muss CERNIS PRO als Root gestartet werden."
    fake = FakeProcessPermission(available=True, permission_error=msg)
    result = CheckProcessPermission(fake)()
    assert result == {"ok": False, "error": msg}


def test_check_permission_not_available() -> None:
    fake = FakeProcessPermission(available=False)
    result = CheckProcessPermission(fake)()
    assert result["ok"] is False
    assert result["error"]  # nicht-leerer Grund


def test_check_permission_pass_throughs() -> None:
    fake = FakeProcessPermission(available=True, permission_error="x")
    uc = CheckProcessPermission(fake)
    assert uc.is_available() is True
    assert uc.check_permission() == "x"
