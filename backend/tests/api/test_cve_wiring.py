"""Tests der beiden cve-Quer-Naehte aus S86-A4 im Composition Root (app.py).

Geprueft wird die VERDRAHTUNG selbst, nicht noch einmal die Logik der Use-Cases:

* B2 -- der Statusendpunkt kommt an den ECHTEN Laufzeitzustand des Worker heran, ueber
  ein Callable, das ``app.state.run_cve_monitor`` liest. Ohne Worker (kein Bootstrap,
  vor dem Lifespan, nach dem Teardown) lautet die Antwort "kein Abgleich" statt eines
  Fehlers.
* B1 -- die modul-globale Weck-Naht ``app._cve_monitor_wecken`` ist streng best-effort:
  nicht verdrahtet -> stiller No-Op; werfend -> geloggt und verschluckt.

``create_app(AppConfig())`` laeuft OHNE ``bootstrap_on_startup``, also ohne echte DB und
ohne gestartete Worker (Muster ``test_analysis_wiring.py``) -- genau der Zustand, in dem
die ausfallsichere Antwort gelten muss.
"""

from typing import Any

import pytest

import app as app_module
from app import create_app
from infrastructure.config import AppConfig


def test_status_ohne_gestarteten_worker_meldet_keinen_abgleich() -> None:
    """TEST 7 (verdrahtet): kein Worker an app.state -> checking false, kein Fehler.

    Der Statusendpunkt wird ueber den echten ``dependency_overrides``-Provider aus
    create_app geholt; ``app.state.run_cve_monitor`` gibt es ohne Bootstrap nicht.
    """
    app = create_app(AppConfig())
    from api.cve import provide_get_cve_status

    get_status = app.dependency_overrides[provide_get_cve_status]()
    assert get_status().checking is False


def test_status_liest_den_echten_worker_zustand_von_app_state() -> None:
    """B2 verdrahtet: liegt ein Worker an app.state, spiegelt checking dessen Zustand.

    Ein Doppel mit ``is_checking`` steht hier stellvertretend fuer den echten
    ``RunCveMonitor`` -- geprueft wird die NAHT (liest der Provider app.state aus?),
    nicht der Worker (der hat eigene Tests).
    """
    app = create_app(AppConfig())
    from api.cve import provide_get_cve_status

    class _WorkerDoppel:
        is_checking = True

    app.state.run_cve_monitor = _WorkerDoppel()
    get_status = app.dependency_overrides[provide_get_cve_status]()
    assert get_status().checking is True


def test_weck_naht_ohne_verdrahtung_ist_ein_stiller_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """B1: nicht verdrahtet (vor dem Lifespan/ohne Bootstrap) -> kein Wurf, kein Log."""
    logged: list[str] = []
    monkeypatch.setattr(app_module.logger, "warning", lambda event, **kw: logged.append(event))
    monkeypatch.setattr(app_module, "_cve_monitor_wecken", None)

    app_module.wecke_cve_monitor_best_effort()  # darf NICHT werfen

    assert logged == []  # nicht verdrahtet ist kein Fehlerfall


def test_weck_naht_reicht_den_weckruf_durch(monkeypatch: pytest.MonkeyPatch) -> None:
    """B1: verdrahtet -> der Weckruf kommt genau einmal an der gebundenen Naht an."""
    geweckt: list[int] = []
    monkeypatch.setattr(app_module, "_cve_monitor_wecken", lambda: geweckt.append(1))

    app_module.wecke_cve_monitor_best_effort()

    assert geweckt == [1]


def test_weck_naht_verschluckt_und_loggt_fehler(monkeypatch: pytest.MonkeyPatch) -> None:
    """TEST 10 (Naht-Ebene): eine werfende Weck-Naht wirft NICHT nach aussen, sie loggt.

    Das ist die Zusicherung, auf der beide Aufrufstellen (ws_scan.py und
    _scheduled_scan) aufsetzen: ein Fehlschlag beim Wecken darf einen Scan niemals
    scheitern lassen -- und darf auch nicht still verschwinden (S3).
    """
    logged: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(
        app_module.logger, "warning", lambda event, **kw: logged.append((event, kw))
    )

    def kaputt() -> None:
        raise RuntimeError("worker weg")

    monkeypatch.setattr(app_module, "_cve_monitor_wecken", kaputt)

    app_module.wecke_cve_monitor_best_effort()  # darf NICHT werfen

    assert [name for name, _ in logged] == ["cve_monitor_wecken_fehlgeschlagen"]
    assert logged[0][1]["error"] == "worker weg"
