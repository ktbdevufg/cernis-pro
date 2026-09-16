"""Tests fuer den ``MonitoringWindowHandler`` (job_type ``monitoring_window``, 3b).

Der Handler beendet einen RECURRING-Logging-Task am ENDE seines Gesamtzeitraums
(``recur_until``) und tut sonst nichts. Er wirft NIE (Scheduler-Loop darf nicht sterben,
S3): fehlende/kaputte ``params`` werden ignoriert, ein bereits beendeter Task ist kein
Fehler. Abgedeckt:

* ``recur_until`` in der Zukunft (now < recur_until) -> stop NICHT aufgerufen.
* ``recur_until`` in der Vergangenheit (now >= recur_until) -> stop mit task_id aufgerufen.
* ``recur_until`` leer ("") -> stop NICHT aufgerufen (unbegrenzt).
* fehlende task_id -> kein Crash, stop nicht aufgerufen.
* kaputtes ``recur_until`` ("abc") -> kein Crash, stop nicht aufgerufen.
* stop wirft ``LoggingTaskNotFound`` -> Handler wirft NICHT (gefangen).

``now`` wird ueber ``now_provider`` deterministisch injiziert (Muster
test_scheduler_use_cases). Der async ``run`` laeuft ueber ``asyncio.run``. Die
Fake-StopLoggingTask ist ein Callable, das die Aufrufe je ``task_id`` zaehlt und auf
Wunsch ``LoggingTaskNotFound`` wirft; der ``cast`` macht sie fuer mypy zum erwarteten
``StopLoggingTask`` (sie erfuellt das Aufruf-Interface strukturell).
"""

import asyncio
from collections.abc import Callable
from typing import cast

from application.monitoring import LoggingTaskNotFound, StopLoggingTask
from application.monitoring.scheduler_handler import MonitoringWindowHandler

NOW = 1_700_000_000.0


class _FakeStopTask:
    """Zaehlt ``__call__``-Aufrufe je ``task_id``; wirft auf Wunsch ``LoggingTaskNotFound``."""

    def __init__(self, raises_not_found: bool = False) -> None:
        self._raises_not_found = raises_not_found
        self.calls: list[str] = []

    def __call__(self, task_id: str) -> object:
        self.calls.append(task_id)
        if self._raises_not_found:
            raise LoggingTaskNotFound(task_id)
        return None


def _at(ts: float) -> Callable[[], float]:
    return lambda: ts


def _handler(stop: _FakeStopTask, now: float = NOW) -> MonitoringWindowHandler:
    # Der Fake erfuellt das Aufruf-Interface von StopLoggingTask strukturell -- cast fuer mypy.
    return MonitoringWindowHandler(cast(StopLoggingTask, stop), now_provider=_at(now))


def _params(**fields: str) -> tuple[tuple[str, str], ...]:
    return tuple(fields.items())


def test_recur_until_in_zukunft_beendet_nicht() -> None:
    stop = _FakeStopTask()
    handler = _handler(stop, now=NOW)
    # recur_until liegt in der Zukunft -> Gesamtzeitraum laeuft noch.
    asyncio.run(handler.run(_params(task_id="t1", recur_until=str(NOW + 3600.0))))

    assert stop.calls == []


def test_recur_until_in_vergangenheit_beendet_mit_task_id() -> None:
    stop = _FakeStopTask()
    handler = _handler(stop, now=NOW)
    # recur_until liegt vor now -> Gesamtzeitraum abgelaufen -> stop(task_id).
    asyncio.run(handler.run(_params(task_id="t1", recur_until=str(NOW - 1.0))))

    assert stop.calls == ["t1"]


def test_recur_until_gleich_now_beendet() -> None:
    stop = _FakeStopTask()
    handler = _handler(stop, now=NOW)
    # now >= recur_until (Gleichheit) -> abgelaufen, beenden.
    asyncio.run(handler.run(_params(task_id="t1", recur_until=str(NOW))))

    assert stop.calls == ["t1"]


def test_recur_until_leer_beendet_nicht() -> None:
    stop = _FakeStopTask()
    handler = _handler(stop, now=NOW)
    # Leeres recur_until = unbegrenzter Gesamtzeitraum -> nichts beenden.
    asyncio.run(handler.run(_params(task_id="t1", recur_until="")))

    assert stop.calls == []


def test_recur_until_fehlt_beendet_nicht() -> None:
    stop = _FakeStopTask()
    handler = _handler(stop, now=NOW)
    # recur_until-Schluessel fehlt ganz -> wie leer (unbegrenzt) -> nichts beenden.
    asyncio.run(handler.run(_params(task_id="t1")))

    assert stop.calls == []


def test_fehlende_task_id_kein_crash() -> None:
    stop = _FakeStopTask()
    handler = _handler(stop, now=NOW)
    # Keine task_id -> ehrlich geloggt, kein Crash, stop nicht aufgerufen.
    asyncio.run(handler.run(_params(recur_until=str(NOW - 1.0))))

    assert stop.calls == []


def test_kaputtes_recur_until_kein_crash() -> None:
    stop = _FakeStopTask()
    handler = _handler(stop, now=NOW)
    # Unparsbares recur_until -> geloggt, kein Crash, stop nicht aufgerufen.
    asyncio.run(handler.run(_params(task_id="t1", recur_until="abc")))

    assert stop.calls == []


def test_stop_wirft_not_found_handler_wirft_nicht() -> None:
    stop = _FakeStopTask(raises_not_found=True)
    handler = _handler(stop, now=NOW)
    # stop wirft LoggingTaskNotFound (Task schon beendet/geloescht) -> der Handler faengt
    # es und wirft NICHT (asyncio.run wuerde sonst die Exception weiterreichen).
    asyncio.run(handler.run(_params(task_id="t1", recur_until=str(NOW - 1.0))))

    assert stop.calls == ["t1"]
