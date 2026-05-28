"""Beweis: der app.py-Lifespan ist verhaltensgleich zum main.py-Bootstrap.

Mit ``bootstrap_on_startup=True`` muss der app.py-Lifespan dieselbe Init-/
Teardown-Sequenz fahren wie main.py (der P2.1a-Contract ist der Massstab).
Spy-Doubles via ``monkeypatch.setattr(app, …)``; geprueft wird nur die
Aufruf-SEQUENZ -- kein echtes DB/Netzwerk/Threads.

Gegenstueck: ``tests/characterization/test_app_bootstrap_contract.py`` haelt
dieselbe Sequenz gegen main.py fest. Beide zusammen beweisen die Gleichheit.
"""

from collections.abc import Callable, Coroutine, Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import app as app_module
from infrastructure.config import AppConfig

# Lifespan-Schritte, die als synchrone Spies ersetzt werden (app.py-Lifespan).
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
        monkeypatch.setattr(app_module, name, make_spy(name))

    # Targets-Bau ausklammern (ruft sonst echte Interfaces/Settings ab).
    monkeypatch.setattr(app_module, "_build_monitor_targets", lambda: [])

    # run_monitor() wird via asyncio.create_task geplant -> muss ein Coroutine
    # liefern. Aufruf wird synchron protokolliert, der Body ist ein No-op.
    def run_monitor_spy() -> Coroutine[Any, Any, None]:
        calls.append("run_monitor")

        async def _noop() -> None:
            return None

        return _noop()

    monkeypatch.setattr(app_module, "run_monitor", run_monitor_spy)

    yield calls


def _bootstrap_app() -> FastAPI:
    # Flag True -> der Lifespan fuehrt den (gespyten) Bootstrap aus.
    return app_module.create_app(AppConfig(bootstrap_on_startup=True))


def test_app_lifespan_startup_matches_contract(bootstrap_calls: list[str]) -> None:
    with TestClient(_bootstrap_app()):
        startup = list(bootstrap_calls)

    # Exakt dieselbe Reihenfolge wie der main.py-Contract (P2.1a).
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


def test_app_lifespan_shutdown_teardown(bootstrap_calls: list[str]) -> None:
    with TestClient(_bootstrap_app()):
        pass

    assert bootstrap_calls[-2:] == ["stop_monitor", "stop_scheduler"]


def test_lifespan_skips_bootstrap_when_flag_off() -> None:
    # Default (Flag aus) -> KEIN Bootstrap-Schritt laeuft. Schuetzt die
    # bestehenden app-bauenden Tests (Smoke, settings-API) vor echten Effekten.
    app = app_module.create_app(AppConfig())
    with TestClient(app):
        pass
    assert not hasattr(app.state, "monitor_task")
