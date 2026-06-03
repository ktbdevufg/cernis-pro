"""Beweis: der app.py-Lifespan fuehrt die erwartete Init-/Teardown-Sequenz.

Mit ``bootstrap_on_startup=True`` faehrt der Lifespan die Bootstrap-Schritte.
Spy-Doubles via ``monkeypatch.setattr(app, …)``; geprueft wird die Aufruf-SEQUENZ
der noch-Altcode-Schritte (init_db etc.) UND die v2-monitoring-Verdrahtung
(RunMonitor-Loop + Scheduler) -- kein echtes DB/Netzwerk/Threads.

v2-ABWEICHUNG (M.9): Der monitoring-Teil der Sequenz ist umgebaut -- der
Altcode-Loop (``configure_monitor`` + ``run_monitor``) und der Altcode-Scheduler
(``start_scheduler``) sind durch die v2-Use-Cases ersetzt (``RunMonitor.run()`` als
Task + ``ApschedulerJobScheduler.start()`` + register der gespeicherten Schedules).
``init_schedule_db``/``init_sla_db`` entfallen: die v2-Repos legen ihr Schema beim
Bau selbst an (``_ensure_schema``). Der main.py-seitige Contract
(``test_app_bootstrap_contract.py``) bleibt unberuehrt -- er friert die Altcode-
Sequenz ein, M.9 wechselt den Einstiegspunkt NICHT.
"""

from collections.abc import Callable, Iterator
from typing import Any, ClassVar

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import app as app_module
from infrastructure.config import AppConfig

# Modul-globale Lifespan-Schritte (noch Altcode, als synchrone Spies ersetzbar).
# Die monitoring-v2-Schritte sind create_app-lokale Closures -> NICHT hier, sondern
# ueber gefakte Klassen (RunMonitor / ApschedulerJobScheduler) + app.state geprueft.
_SYNC_STEPS = (
    "_check_version_upgrade",
    "init_db",
    "init_devices_db",
    "init_alerts_db",
    "init_agents_db",
)


class _FakeRunMonitor:
    """Fake-RunMonitor: run() ist ein sofort endender no-op-Loop, stop() ein Flag."""

    instances: ClassVar[list["_FakeRunMonitor"]] = []

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.stopped = False
        self.ran = False
        _FakeRunMonitor.instances.append(self)

    async def run(self) -> None:
        self.ran = True

    def stop(self) -> None:
        self.stopped = True

    def current_status(self) -> dict[str, bool]:
        return {}


class _FakeJobScheduler:
    """Fake-ApschedulerJobScheduler: zeichnet start/stop/register auf."""

    instances: ClassVar[list["_FakeJobScheduler"]] = []

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.started = False
        self.stopped = False
        self.registered: list[int] = []
        _FakeJobScheduler.instances.append(self)

    def start(self, _callback: Any) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True

    def register(self, schedule: dict[str, Any], _callback: Any) -> None:
        self.registered.append(int(schedule["id"]))

    def unregister(self, schedule_id: int) -> None: ...


@pytest.fixture
def bootstrap_calls(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Spy fuer die modul-globalen Schritte + Fakes fuer die v2-monitoring-Bausteine."""
    calls: list[str] = []
    _FakeRunMonitor.instances = []
    _FakeJobScheduler.instances = []

    def make_spy(name: str) -> Callable[..., None]:
        def _spy(*_args: object, **_kwargs: object) -> None:
            calls.append(name)

        return _spy

    for name in _SYNC_STEPS:
        monkeypatch.setattr(app_module, name, make_spy(name))

    # v2-monitoring-Bausteine neutralisieren (kein echter Ping-Loop / APScheduler /
    # echte DB). RunMonitor + ApschedulerJobScheduler sind modul-global in app
    # importiert -> hier mockbar. Die uebrigen Adapter (Pinger/Repos/TargetSource)
    # werden von _build_run_monitor gebaut, aber unser Fake-RunMonitor ignoriert sie.
    monkeypatch.setattr(app_module, "RunMonitor", _FakeRunMonitor)
    monkeypatch.setattr(app_module, "ApschedulerJobScheduler", _FakeJobScheduler)
    # Die Repos/TargetSource bauen ihre DB lazy -> auf eine harmlose in-memory-leere
    # Schedule-Liste umbiegen, damit die register-Schleife nichts Echtes anfasst.
    # (Pinger/Notifier/Repos werden konstruiert, aber nie aufgerufen -- der Fake-Loop
    # ruft nichts; das Schedule-Repo wird fuer .list() echt gebaut, daher tmp-DB.)
    yield calls


def _bootstrap_app() -> FastAPI:
    # Flag True -> der Lifespan fuehrt den (gespyten/gefakten) Bootstrap aus. Die
    # tmp-DB-Umbiegung von get_db_path passiert ueber die ``tmp_db``-Fixture (die der
    # Test mit anfordert), damit die register-Schleife keine echte cernis.db anfasst.
    return app_module.create_app(AppConfig(bootstrap_on_startup=True))


@pytest.fixture
def tmp_db(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    db = tmp_path / "cernis.db"
    monkeypatch.setattr("modules.db_path.get_db_path", lambda: db)
    return db


def test_app_lifespan_startup_runs_v2_monitoring(bootstrap_calls: list[str], tmp_db: Any) -> None:
    app = _bootstrap_app()
    with TestClient(app):
        startup = list(bootstrap_calls)
        # v2-monitoring-Bausteine wurden verdrahtet + gestartet.
        run_monitor_uc = app.state.run_monitor
        assert isinstance(run_monitor_uc, _FakeRunMonitor)
        assert run_monitor_uc.ran is True
        assert hasattr(app.state, "monitor_task")
        assert len(_FakeJobScheduler.instances) >= 1
        assert _FakeJobScheduler.instances[0].started is True

    # Die noch-Altcode-Schritte in erwarteter Reihenfolge (monitoring-Schritte sind
    # KEINE modul-globalen Funktionen mehr -> hier nicht im Spy-Log).
    assert startup == [
        "_check_version_upgrade",
        "init_db",
        "init_devices_db",
        "init_alerts_db",
        "init_agents_db",
    ]


def test_app_lifespan_shutdown_stops_monitor_and_scheduler(
    bootstrap_calls: list[str], tmp_db: Any
) -> None:
    with TestClient(_bootstrap_app()):
        pass
    # Teardown: RunMonitor.stop() + Scheduler.stop() liefen.
    assert _FakeRunMonitor.instances[0].stopped is True
    assert _FakeJobScheduler.instances[0].stopped is True


def test_lifespan_skips_bootstrap_when_flag_off() -> None:
    # Default (Flag aus) -> KEIN Bootstrap-Schritt laeuft. Schuetzt die
    # bestehenden app-bauenden Tests (Smoke, settings-API) vor echten Effekten.
    app = app_module.create_app(AppConfig())
    with TestClient(app):
        pass
    assert not hasattr(app.state, "monitor_task")
