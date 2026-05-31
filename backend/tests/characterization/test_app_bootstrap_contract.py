"""Characterization: Bootstrap-/Lifespan-Contract von ``main.py``.

Haelt fest, WELCHE Init-/Teardown-Schritte der ``main.py``-Lifespan in welcher
Reihenfolge ausfuehrt -- als Sicherheitsnetz fuer den spaeteren Umzug des
Lifespan-Inits nach ``app.py`` (Phase 2). Die echten Effekte (DB-Dateien,
Monitor-Task, Scheduler-Timer) werden durch Spy-Doubles ersetzt; geprueft wird
nur die AUFRUF-SEQUENZ, nicht echtes Verhalten -- kein Netzwerk, keine Threads,
keine DB.
"""

from collections.abc import Callable, Coroutine, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

import main

# Lifespan-Schritte, die als synchrone Spies ersetzt werden (main.py:108-144).
_SYNC_STEPS = (
    "_check_version_upgrade",
    "init_db",
    "init_devices_db",
    "configure_monitor",
    "init_schedule_db",
    "init_sla_db",
    "init_alerts_db",
    "init_agents_db",
    "start_scheduler",
    "stop_monitor",
    "stop_scheduler",
)


@pytest.fixture
def bootstrap_calls(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Ersetzt jeden Lifespan-Schritt durch einen Spy, der seinen Namen protokolliert."""
    calls: list[str] = []

    def make_spy(name: str) -> Callable[..., None]:
        def _spy(*_args: object, **_kwargs: object) -> None:
            calls.append(name)

        return _spy

    for name in _SYNC_STEPS:
        monkeypatch.setattr(main, name, make_spy(name))

    # Targets-Bau ausklammern (ruft sonst echte Interfaces/Settings ab).
    monkeypatch.setattr(main, "_build_monitor_targets", lambda: [])

    # run_monitor() wird via asyncio.create_task geplant -> muss ein Coroutine
    # liefern. Aufruf wird synchron protokolliert, der Body ist ein No-op.
    def run_monitor_spy() -> Coroutine[Any, Any, None]:
        calls.append("run_monitor")

        async def _noop() -> None:
            return None

        return _noop()

    monkeypatch.setattr(main, "run_monitor", run_monitor_spy)

    yield calls


def test_lifespan_startup_init_sequence(bootstrap_calls: list[str]) -> None:
    # Eintritt in den TestClient-Kontext triggert den Lifespan-Startup.
    with TestClient(main.app):
        startup = list(bootstrap_calls)

    # Exakte Reihenfolge wie main.py:109-139 (vor dem yield).
    assert startup == [
        "_check_version_upgrade",
        "init_db",
        "init_devices_db",
        "configure_monitor",
        "run_monitor",
        "init_schedule_db",
        "init_sla_db",
        "init_alerts_db",
        "init_agents_db",
        "start_scheduler",
    ]


def test_lifespan_shutdown_teardown(bootstrap_calls: list[str]) -> None:
    # Verlassen des Kontexts triggert den Lifespan-Shutdown.
    with TestClient(main.app):
        pass

    # Teardown nach dem yield (main.py:143-144).
    assert bootstrap_calls[-2:] == ["stop_monitor", "stop_scheduler"]
