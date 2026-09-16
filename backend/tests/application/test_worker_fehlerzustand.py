"""Stille Ausfaelle der fuenf Endlos-Arbeiter (S88-P4, Aufgabe 4.1-4.3).

Fuenf Arbeiter trugen bis S88-P4 das nackte Muster ``while self._running: await tick()``:
``RunCveMonitor``, ``RunOutboundRecorder``, ``RunScheduler``, ``RunLoggingRetention`` und
``RunMonitor``. Wirft ihr ``tick``, riss der Task -- und weil niemand ein
``add_done_callback`` oder einen ``set_exception_handler`` gesetzt hat, lag die Ausnahme
danach unbeachtet im Task-Objekt an ``app.state`` und wurde erst im Teardown sichtbar.
Der Arbeiter war tot, und nach aussen sah nichts anders aus als vorher.

Diese Datei belegt dreierlei, fuer JEDEN der fuenf:

* **4.1** ``tick`` wirft -> die Schleife laeuft WEITER, und der Fehlerzustand traegt den
  Wortlaut (``last_error``) samt Zaehler (``consecutive_failures``).
* **4.2** ``CancelledError`` beendet die Schleife WEITERHIN -- er darf NICHT gefangen
  werden. Er ist das Abbruchsignal des Teardown, kein Fehler.
* **4.3** Ein gelungener ``tick`` setzt Wortlaut UND Zaehler zurueck.

FORM DER TESTS: kein zeitbasiertes "Task starten, kurz schlafen, abbrechen" (das ist
wackelig). Stattdessen zaehlt jeder Fake seine Aufrufe und ruft ``stop()``, sobald genug
Durchlaeufe belegt sind -- der Loop endet dann von selbst, deterministisch. Die Intervalle
stehen auf 0, damit kein Test wartet.

Gescheitert wird ueber ECHTE Ports, wo der Arbeiter sie im tick-Pfad beruehrt (der
Bestand wirft dort wirklich); nur wo ``tick`` seinen Rumpf vollstaendig selbst faengt
(``RunLoggingRetention``), wird ``tick`` in einer Test-Unterklasse ersetzt -- anders ist
der run-Rumpf gar nicht erreichbar.
"""

import asyncio
from collections.abc import Callable, Sequence
from typing import Any

import pytest

from application.cve import RunCveMonitor
from application.monitoring import EnforceLoggingRetention, RunLoggingRetention, RunMonitor
from application.outbound_log import RunOutboundRecorder
from application.scheduler.use_cases import RunScheduler
from domain.monitoring import MonitorTarget, PingSample
from domain.scheduler.models import JobState, ScheduledJob

_GRUND = "Datenbank ist gesperrt"


# ── Gemeinsame Hilfen ────────────────────────────────────────────────────────


class _Zaehler:
    """Zaehlt Aufrufe und stoppt den Arbeiter, sobald ``bis`` erreicht ist.

    Der Loop laeuft damit genau so lange, wie der Test es braucht -- ohne ``sleep``,
    ohne ``cancel``, ohne Wettlauf. ``stop()`` wirkt erst nach der laufenden Iteration,
    genau wie im echten Teardown.
    """

    def __init__(self, stop: Callable[[], None], bis: int) -> None:
        self._stop = stop
        self._bis = bis
        self.aufrufe = 0

    def zaehlen(self) -> None:
        self.aufrufe += 1
        if self.aufrufe >= self._bis:
            self._stop()


def _laufen(worker: Any) -> None:
    """Laesst ``run()`` bis zum eigenen ``stop()`` durchlaufen (deterministisch)."""
    asyncio.run(worker.run())


def _abbruch_beendet_schleife(worker: Any) -> None:
    """4.2: ``CancelledError`` aus ``tick`` verlaesst ``run`` UNGEFANGEN.

    Gemeinsame Behauptung aller fuenf: der Abbruch ist kein Fehler, er wird nicht als
    ``last_error`` gemerkt und er beendet die Schleife. Wuerde ein ``except Exception``
    ihn schlucken (``CancelledError`` erbt seit 3.8 von ``BaseException``, aber ein
    ``except BaseException`` waere hier der Fehler), liefe der Teardown ins Leere.
    """
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(worker.run())
    assert worker.last_error() is None
    assert worker.consecutive_failures() == 0


# ── RunCveMonitor ────────────────────────────────────────────────────────────


class _CveInventar:
    """``HostInventoryProvider``-Fake: wirft, gelingt, oder bricht ab -- je Aufruf."""

    def __init__(self, fehler: BaseException | None) -> None:
        self._fehler = fehler
        # Nachtraeglich gesetzt -- s. ``_Zielquelle`` (Henne-Ei zwischen Zaehler und
        # Arbeiter).
        self.zaehler: _Zaehler | None = None

    def list_hosts(self) -> list[Any]:
        if self.zaehler is not None:
            self.zaehler.zaehlen()
        if self._fehler is not None:
            raise self._fehler
        return []


class _CveLeerRepo:
    """Deckt die uebrigen cve-Ports ab; im Test wird keiner von ihnen erreicht."""

    def get(self, mac: str) -> None:
        return None

    def record(self, *args: Any, **kwargs: Any) -> None:
        return None

    def all_states(self) -> list[Any]:
        return []

    def list_for_host(self, mac: str) -> list[Any]:
        return []

    def list_all(self) -> list[Any]:
        return []

    def replace_for_host(self, mac: str, records: Sequence[Any]) -> None:
        return None

    def upsert(self, *args: Any, **kwargs: Any) -> None:
        return None

    def acknowledged_keys(self) -> set[tuple[str, str, int]]:
        return set()

    def clear_all(self) -> None:
        return None


class _CveLookup:
    async def lookup(self, ports: Any) -> list[Any]:
        return []


def _cve_worker(fehler: BaseException | None, bis: int = 2) -> tuple[RunCveMonitor, _Zaehler]:
    repo = _CveLeerRepo()
    inventar = _CveInventar(fehler)
    worker = RunCveMonitor(
        inventory=inventar,
        lookup=_CveLookup(),
        findings=repo,
        checkstate=repo,
        acknowledgements=repo,
        refresh_interval_provider=lambda: 0.0,
        interval=0,
    )
    zaehler = _Zaehler(worker.stop, bis)
    inventar.zaehler = zaehler
    return worker, zaehler


def test_cve_monitor_ueberlebt_tick_fehler() -> None:
    worker, zaehler = _cve_worker(RuntimeError(_GRUND), bis=3)

    _laufen(worker)

    assert zaehler.aufrufe == 3  # die Schleife lief nach dem ersten Fehler weiter
    assert worker.last_error() == _GRUND
    assert worker.consecutive_failures() == 3


def test_cve_monitor_reicht_cancelled_durch() -> None:
    worker, _ = _cve_worker(asyncio.CancelledError())

    _abbruch_beendet_schleife(worker)


def test_cve_monitor_gelungener_tick_raeumt_fehlerzustand() -> None:
    worker, _ = _cve_worker(None, bis=1)
    worker._last_error = "alter Fehler"
    worker._consecutive_failures = 7

    _laufen(worker)

    assert worker.last_error() is None
    assert worker.consecutive_failures() == 0


# ── RunOutboundRecorder ──────────────────────────────────────────────────────


class _AufzeichnungsRepo:
    """``OutboundRecordingRepository``-Fake: ``list_all`` wirft oder liefert leer.

    Der Recorder ruft ``list_all`` ZWEIMAL je Durchlauf -- einmal in ``tick`` (dort
    gefangen) und einmal im run-Rumpf fuer das Intervall (dort bis S88-P4 ungeschuetzt).
    Der Zaehler zaehlt darum nur die Aufrufe aus dem run-Rumpf, erkennbar am Wechsel-
    Schalter.
    """

    def __init__(self, fehler: BaseException | None) -> None:
        self._fehler = fehler
        self._im_tick = True
        # Nachtraeglich gesetzt -- s. ``_Zielquelle``.
        self.zaehler: _Zaehler | None = None

    def list_all(self) -> list[Any]:
        aus_dem_tick = self._im_tick
        self._im_tick = not self._im_tick
        if not aus_dem_tick and self.zaehler is not None:
            self.zaehler.zaehlen()
        if self._fehler is not None:
            raise self._fehler
        return []

    def save(self, recording: Any) -> None:
        return None

    def get(self, recording_id: str) -> None:
        return None

    def delete(self, recording_id: str) -> None:
        return None

    def clear_all(self) -> None:
        return None


class _StillesDetailRepo:
    """Deckt Detail- UND Aggregat-Repo ab; im Test wird keines von ihnen erreicht."""

    def save(self, *args: Any, **kwargs: Any) -> None:
        return None

    def delete_older_than(self, cutoff_ts: float) -> int:
        return 0

    def range(self, recording_id: str, since: float, until: float) -> list[Any]:
        return []

    def count(self) -> int:
        return 0

    def clear_all(self) -> None:
        return None

    def upsert(self, recording_id: str, contact: Any) -> None:
        return None

    def get(self, recording_id: str, remote_ip: str) -> None:
        return None

    def list_for(self, recording_id: str) -> list[Any]:
        return []

    def delete_for(self, recording_id: str) -> None:
        return None


async def _leerer_snapshot() -> list[Any]:
    return []


def _recorder(fehler: BaseException | None, bis: int = 2) -> tuple[RunOutboundRecorder, _Zaehler]:
    repo = _AufzeichnungsRepo(fehler)
    worker = RunOutboundRecorder(
        recordings=repo,
        detail=_StillesDetailRepo(),
        aggregate=_StillesDetailRepo(),
        snapshot_provider=_leerer_snapshot,
        interval_provider=lambda: 0,
        now_provider=lambda: 0.0,
    )
    zaehler = _Zaehler(worker.stop, bis)
    repo.zaehler = zaehler
    return worker, zaehler


def test_outbound_recorder_ueberlebt_fehler_im_run_rumpf() -> None:
    """Der Schutz eine Ebene HOEHER greift: ``tick`` faengt selbst, der run-Rumpf nicht.

    ``_active_recording`` im run-Rumpf ist genau die Flaeche, die ``tick`` NICHT deckt --
    dort riss der Task bisher.
    """
    worker, zaehler = _recorder(RuntimeError(_GRUND), bis=3)

    _laufen(worker)

    assert zaehler.aufrufe == 3
    assert worker.last_error() == _GRUND
    assert worker.consecutive_failures() == 3


def test_outbound_recorder_reicht_cancelled_durch() -> None:
    worker, _ = _recorder(asyncio.CancelledError())

    _abbruch_beendet_schleife(worker)


def test_outbound_recorder_gelungener_durchlauf_raeumt_fehlerzustand() -> None:
    worker, _ = _recorder(None, bis=1)
    worker._last_error = "alter Fehler"
    worker._consecutive_failures = 4

    _laufen(worker)

    assert worker.last_error() is None
    assert worker.consecutive_failures() == 0


# ── RunScheduler ─────────────────────────────────────────────────────────────


class _JobRepo:
    """``ScheduledJobRepository``-Fake: ``list_active`` wirft oder liefert leer.

    ``list_active`` liegt VOR dem ``_dispatch``-``try`` -- bis S88-P4 war genau dieser
    Zugriff ungeschuetzt.
    """

    def __init__(self, fehler: BaseException | None) -> None:
        self._fehler = fehler
        # Nachtraeglich gesetzt -- s. ``_Zielquelle``.
        self.zaehler: _Zaehler | None = None

    def list_active(self) -> list[ScheduledJob]:
        if self.zaehler is not None:
            self.zaehler.zaehlen()
        if self._fehler is not None:
            raise self._fehler
        return []

    def add(self, *args: Any, **kwargs: Any) -> int:
        return 1

    def get(self, job_id: int) -> None:
        return None

    def list_all(self) -> list[ScheduledJob]:
        return []

    def update_state(self, job_id: int, state: JobState) -> None:
        return None

    def delete(self, job_id: int) -> None:
        return None

    def clear_all(self) -> None:
        return None


def _scheduler(fehler: BaseException | None, bis: int = 2) -> tuple[RunScheduler, _Zaehler]:
    repo = _JobRepo(fehler)
    worker = RunScheduler(
        repository=repo,
        handlers={},
        interval=0,
        now_provider=lambda: 1_700_000_000.0,
    )
    zaehler = _Zaehler(worker.stop, bis)
    repo.zaehler = zaehler
    return worker, zaehler


def test_scheduler_ueberlebt_tick_fehler() -> None:
    worker, zaehler = _scheduler(RuntimeError(_GRUND), bis=3)

    _laufen(worker)

    assert zaehler.aufrufe == 3
    assert worker.last_error() == _GRUND
    assert worker.consecutive_failures() == 3


def test_scheduler_reicht_cancelled_durch() -> None:
    worker, _ = _scheduler(asyncio.CancelledError())

    _abbruch_beendet_schleife(worker)


def test_scheduler_gelungener_tick_raeumt_fehlerzustand() -> None:
    worker, _ = _scheduler(None, bis=1)
    worker._last_error = "alter Fehler"
    worker._consecutive_failures = 2

    _laufen(worker)

    assert worker.last_error() is None
    assert worker.consecutive_failures() == 0


# ── RunLoggingRetention ──────────────────────────────────────────────────────


class _MessRepo:
    """Stiller Ersatz beider Retention-Repos -- im Test wird keines von ihnen erreicht.

    Der ``tick`` ist hier ersetzt (s. ``_ZaehlendeRetention``); die Repos existieren nur,
    damit ``EnforceLoggingRetention`` baubar ist.
    """

    def delete_older_than(self, cutoff_ts: float) -> int:
        return 0

    def save(self, *args: Any, **kwargs: Any) -> None:
        return None

    def clear_all(self) -> None:
        return None

    def range(self, *args: Any, **kwargs: Any) -> list[Any]:
        return []

    def all_for(self, *args: Any, **kwargs: Any) -> list[Any]:
        return []

    def count(self, *args: Any, **kwargs: Any) -> int:
        return 0


class _ZaehlendeRetention(RunLoggingRetention):
    """Ersetzt ``tick``, weil der Bestands-``tick`` seinen ganzen Rumpf selbst faengt.

    Der run-Rumpf ist sonst gar nicht zum Scheitern zu bringen -- genau das ist der Grund,
    warum der Schutz hier eine Ebene HOEHER liegt und den Fehlerzustand ueberhaupt erst
    abfragbar macht (bis S88-P4 verschwand ein Retention-Fehler restlos im Log).
    """

    def __init__(self, zaehler_traeger: dict[str, Any], fehler: BaseException | None) -> None:
        super().__init__(EnforceLoggingRetention(_MessRepo(), _MessRepo()), interval=0)
        self._zaehler_traeger = zaehler_traeger
        self._fehler = fehler

    async def tick(self) -> None:
        zaehler: _Zaehler = self._zaehler_traeger["zaehler"]
        zaehler.zaehlen()
        if self._fehler is not None:
            raise self._fehler


def _retention(fehler: BaseException | None, bis: int = 2) -> tuple[RunLoggingRetention, _Zaehler]:
    traeger: dict[str, Any] = {}
    worker = _ZaehlendeRetention(traeger, fehler)
    zaehler = _Zaehler(worker.stop, bis)
    traeger["zaehler"] = zaehler
    return worker, zaehler


def test_logging_retention_ueberlebt_tick_fehler() -> None:
    worker, zaehler = _retention(RuntimeError(_GRUND), bis=3)

    _laufen(worker)

    assert zaehler.aufrufe == 3
    assert worker.last_error() == _GRUND
    assert worker.consecutive_failures() == 3


def test_logging_retention_reicht_cancelled_durch() -> None:
    worker, _ = _retention(asyncio.CancelledError())

    _abbruch_beendet_schleife(worker)


def test_logging_retention_gelungener_durchlauf_raeumt_fehlerzustand() -> None:
    worker, _ = _retention(None, bis=1)
    worker._last_error = "alter Fehler"
    worker._consecutive_failures = 9

    _laufen(worker)

    assert worker.last_error() is None
    assert worker.consecutive_failures() == 0


# ── RunMonitor ───────────────────────────────────────────────────────────────


class _Zielquelle:
    """``MonitorTargetSource``-Fake: ``load`` zaehlt und kann werfen.

    ``load`` ist die ERSTE der fuenf ungeschuetzten Stellen des Live-Loops (danach
    ``ping``/``rtt.save``/``event_repo.save``/``broadcast``) -- ein Fehler dort riss den
    Loop still, und das Frontend sah eine Status-Map, die einfach nicht mehr weiterlief.
    """

    def __init__(self, fehler: BaseException | None) -> None:
        self._fehler = fehler
        # Nachtraeglich gesetzt: der Zaehler braucht ``worker.stop``, den es erst nach
        # dem Bau des Arbeiters gibt -- und der Arbeiter braucht diese Quelle schon beim
        # Bau. Die Naht loest das Henne-Ei, ohne ein ``None`` durch den Konstruktor zu
        # reichen.
        self.zaehler: _Zaehler | None = None

    async def load(self) -> list[MonitorTarget]:
        if self.zaehler is not None:
            self.zaehler.zaehlen()
        if self._fehler is not None:
            raise self._fehler
        return []


class _StillerPinger:
    async def ping(self, target: MonitorTarget) -> PingSample:
        return PingSample(target_id=target.id, host=target.host, alive=True, rtt_ms=1.0)


class _StillesRepo:
    def save(self, *args: Any, **kwargs: Any) -> None:
        return None

    def clear_all(self) -> None:
        return None

    def recent(self, *args: Any, **kwargs: Any) -> list[Any]:
        return []


class _StillerKanal:
    async def notify(self, event: Any) -> None:
        return None

    async def broadcast(self, *args: Any, **kwargs: Any) -> None:
        return None

    async def raise_alert(self, event: Any) -> None:
        return None

    async def record(self, *args: Any, **kwargs: Any) -> None:
        return None


def _monitor(fehler: BaseException | None, bis: int = 2) -> tuple[RunMonitor, _Zaehler]:
    kanal = _StillerKanal()
    quelle = _Zielquelle(fehler)
    worker = RunMonitor(
        pinger=_StillerPinger(),
        rtt_history=_StillesRepo(),
        event_repo=_StillesRepo(),
        notifier=kanal,
        broadcaster=kanal,
        target_source=quelle,
        alert_raiser=kanal,
        logging_sink=kanal,
        interval=0,
    )
    zaehler = _Zaehler(worker.stop, bis)
    quelle.zaehler = zaehler
    return worker, zaehler


def test_monitor_ueberlebt_tick_fehler() -> None:
    worker, zaehler = _monitor(RuntimeError(_GRUND), bis=3)

    _laufen(worker)

    assert zaehler.aufrufe == 3
    assert worker.last_error() == _GRUND
    assert worker.consecutive_failures() == 3


def test_monitor_reicht_cancelled_durch() -> None:
    worker, _ = _monitor(asyncio.CancelledError())

    _abbruch_beendet_schleife(worker)


def test_monitor_gelungener_tick_raeumt_fehlerzustand() -> None:
    worker, _ = _monitor(None, bis=1)
    worker._last_error = "alter Fehler"
    worker._consecutive_failures = 3

    _laufen(worker)

    assert worker.last_error() is None
    assert worker.consecutive_failures() == 0


def test_monitor_behaelt_status_map_bei_fehlschlag() -> None:
    """Der Fehlschlag leert die ``_status``-Map NICHT (anders als beim Durchsatz-Poller).

    Die letzte bekannte Erreichbarkeit ist eine gueltige Aussage ueber die letzte
    gelungene Runde -- und sie ist der ``prev`` der Flankenerkennung. Ein Leeren wuerde
    jedes Target beim naechsten Erfolg als frischen Uebergang melden.
    """
    worker, _ = _monitor(RuntimeError(_GRUND), bis=2)
    worker._status["wlan"] = True

    _laufen(worker)

    assert worker.current_status() == {"wlan": True}
