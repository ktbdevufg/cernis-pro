"""Use-Cases der monitoring-Domaene -- der Live-Connectivity-Loop ``RunMonitor``.

Fuehrt den Altcode-``run_monitor`` (``modules/monitor.py``) als sauberen Use-Case
zusammen: die reine Domaenenlogik (``classify_transition`` + ``should_notify``,
M.2), die sechs Loop-Ports (M.3) und -- ueber die Ports -- die Adapter (M.4). Kennt
``domain/`` und ``ports/``, NIEMALS ``infrastructure/`` oder ``modules/``
(maschinell per import-linter erzwungen). Alle Ports kommen per Constructor-
Injection als Protocol-Typ herein. Kein Framework-Import, KEIN ``asyncio.Task``-
Management: der Use-Case bietet ``run()``/``stop()``, das ``create_task``/Teardown
treibt der Composition Root (``app.py``-Lifespan, M.9).

LOOP-FORM (testbar): ``tick()`` ist EINE Iteration ueber alle Targets -- voll mit
Fake-Ports deterministisch testbar (kein Loop-Takt). ``run()`` ist nur der triviale
Rahmen ``while self._running: await self.tick(); await sleep(interval)``. So sitzt
die GANZE Logik im getesteten ``tick``; ungetestet bleibt nur ``while``/``sleep``.

STATE: ``self._status`` haelt ``target_id -> letzter alive-bool`` -- exakt wie der
Altcode-``_status`` (nicht mehr: ``label``/``rtt`` sind KEIN Status-State). Er lebt
ueber die ``tick``-Iterationen und ist der ``prev``-Input fuer
``classify_transition``. ``current_status()`` gibt eine DEFENSIVE KOPIE der rohen
``dict[str, bool]``-Map heraus -- die ``label``-Anreicherung zur Altcode-Form
``{tid: {"alive", "label"}}`` macht der Rand (M.9: ``/api/monitor/status`` +
WS-Connect laden die Targets via ``MonitorTargetSource`` und loesen ``label`` mit
``tid``-Fallback auf). Naht-Linie wie der Broadcaster: der Use-Case gibt rohe
Domaenen-Daten, der Rand baut die Response-Shape.

TARGETS (Live-Reload): ``tick`` laedt die Targets PRO Iteration via
``MonitorTargetSource.load()``. Das gibt den Altcode-Live-Reload ohne
``configure()``-Kruecke: ein ueber ``/api/monitor/targets`` (M.9) geaendertes
Custom-Target wirkt bei der naechsten Iteration automatisch (die TargetSource liest
frisch aus den Settings).

Pro-Target-Sequenz (altcode-treu, ``run_monitor`` Z.236-285):
    target.enabled? sonst skip
    -> ping(target) -> rtt_repo.save(sample)
    -> prev = status.get(id); now = sample.alive
    -> event = classify_transition(prev, now, sample.loss_pct)
    -> status[id] = now            (IMMER -- auch ohne Event; prev der naechsten Runde)
    -> wenn event: event_repo.save(MonitorEvent)
                   + wenn should_notify(prev, event): notifier.notify(MonitorEvent)
    -> IMMER broadcaster.broadcast(target, sample, event)

BEWUSSTE, HARMLOSE REORDERING ggue. Altcode: Dort lief ``_notify_macos`` INLINE in
den classify-Zweigen, also VOR dem ``_status``-Update und VOR ``_save_event``. Hier
ist die Reihenfolge ``status-Update -> save_event -> notify``. Das aendert nichts
Beobachtbares: ``notify`` ist ein best-effort-Seiteneffekt, ``save_event`` reine
Persistenz -- es gibt keine Abhaengigkeit zwischen ihnen, und ``prev`` (der einzige
Wert, den das Status-Update beeinflusst) ist fuer ``should_notify`` bereits VOR dem
Update gelesen. Bewusst so geordnet (Klassifikation -> Status -> Konsequenzen),
nicht versehentlich abweichend.
"""

import asyncio
from typing import Any

import structlog

from domain.monitoring import (
    MonitorEvent,
    MonitorTarget,
    ScheduleParseError,
    classify_transition,
    should_notify,
)
from ports.monitoring import (
    MonitorBroadcasterPort,
    MonitorEventRepository,
    MonitorNotifierPort,
    MonitorPingerPort,
    MonitorTargetSource,
    RttHistoryRepository,
    ScanJobScheduler,
    ScanTriggerCallback,
    ScheduleRepository,
)

_logger = structlog.get_logger(__name__)

# Sekunden zwischen den tick-Durchlaeufen (Altcode ``_interval``, Default 5).
_DEFAULT_INTERVAL = 5


class RunMonitor:
    """Orchestriert den Live-Connectivity-Loop (eine ``tick`` je Mess-Runde)."""

    def __init__(
        self,
        pinger: MonitorPingerPort,
        rtt_history: RttHistoryRepository,
        event_repo: MonitorEventRepository,
        notifier: MonitorNotifierPort,
        broadcaster: MonitorBroadcasterPort,
        target_source: MonitorTargetSource,
        interval: int = _DEFAULT_INTERVAL,
    ) -> None:
        self._pinger = pinger
        self._rtt_history = rtt_history
        self._event_repo = event_repo
        self._notifier = notifier
        self._broadcaster = broadcaster
        self._target_source = target_source
        self._interval = interval
        # target_id -> letzter bekannter alive-Zustand (None = noch nie gemessen).
        self._status: dict[str, bool] = {}
        self._running = False

    async def tick(self) -> None:
        """Eine Mess-Runde ueber alle (frisch geladenen) Targets."""
        for target in self._target_source.load():
            if not target.enabled:
                # Disabled Targets werden uebersprungen (kein Ping, kein
                # Status-Update) -- altcode-treu (``if not target.enabled: continue``).
                continue
            await self._tick_target(target)

    async def _tick_target(self, target: MonitorTarget) -> None:
        """Misst ein Target, klassifiziert den Uebergang und loest die Konsequenzen aus."""
        sample = await self._pinger.ping(target)
        self._rtt_history.save(sample)

        # prev VOR dem Status-Update lesen -- es ist der Eingang fuer Klassifikation
        # UND fuer die Notify-Flanken-Regel (should_notify braucht prev).
        prev = self._status.get(target.id)
        now = sample.alive

        event = classify_transition(prev, now, sample.loss_pct)
        self._status[target.id] = now  # IMMER (auch ohne Event): prev der naechsten Runde.

        if event is not None:
            monitor_event = MonitorEvent(
                target_id=target.id,
                label=target.label,
                event=event,
                rtt_ms=sample.rtt_ms,
                timestamp=sample.timestamp,
            )
            self._event_repo.save(monitor_event)
            if should_notify(prev, event):
                await self._notifier.notify(monitor_event)

        # IMMER broadcasten -- auch bei event=None (Altcode: monitor_update jede Runde).
        await self._broadcaster.broadcast(target, sample, event)

    async def run(self) -> None:
        """Endlos-Rahmen: tickt bis ``stop()``. Trivial -- die Logik sitzt in ``tick``."""
        self._running = True
        while self._running:
            await self.tick()
            await asyncio.sleep(self._interval)

    def stop(self) -> None:
        """Beendet den ``run``-Loop nach der laufenden Iteration (Flag, kein Cancel)."""
        self._running = False

    def current_status(self) -> dict[str, bool]:
        """Rohe ``target_id -> alive``-Map (DEFENSIVE Kopie, kein Live-Ref nach aussen).

        Die Altcode-Form ``{tid: {"alive", "label"}}`` baut der Rand (M.9) durch
        ``label``-Anreicherung aus den Targets -- siehe Modul-Docstring.
        """
        return dict(self._status)


# ── Schedule-Use-Cases (M.6) ────────────────────────────────────────────────
# Die Altcode-CRUD<->Job-Kopplung (add_schedule ruft _register_job) ist entkoppelt:
# ``ManageSchedules`` haelt BEIDE Ports und orchestriert add/delete an EINER Stelle.
# ``GetSchedules``/``UpdateSchedule`` sind duenne Pass-Through-Use-Cases (nur das
# Repo) -- die EINZIGE Schicht, die der api-Ring (M.9) ansprechen darf (api -> nur
# application). Muster wie GetScanHistory/GetDevices.


class ManageSchedules:
    """Legt Schedules an / loescht sie -- orchestriert Repo (DB) + Job-Engine.

    ``add`` und ``delete`` brauchen beide Ports: die DB-Zeile UND den APScheduler-
    Job. ``add`` ist BEST-EFFORT gegenueber einem kaputten Schedule-String (s.
    ``add``-Docstring).
    """

    def __init__(self, repository: ScheduleRepository, job_scheduler: ScanJobScheduler) -> None:
        self._repository = repository
        self._job_scheduler = job_scheduler

    def add(
        self,
        name: str,
        cidr: str,
        profile_id: str,
        schedule: str,
        callback: ScanTriggerCallback,
    ) -> int:
        """Legt die Schedule-Zeile an und registriert ihren Job (best-effort).

        BEWUSSTE best-effort-Wahl bei kaputtem ``schedule``-String: Die DB-Zeile
        wird IMMER angelegt (``repository.add``), dann der Job registriert. Wirft
        ``ScanJobScheduler.register`` einen ``ScheduleParseError`` (unparsbarer
        String, S.1-Fix statt stillem 24h-Fallback), wird er GEZIELT gefangen
        (nicht ``except Exception``/``ValueError`` -- die eigenstaendige Exception
        aus M.6 S.1 macht den Fang praezise): Warn-Log, Job NICHT registriert,
        ``add`` kehrt regulaer zurueck.

        Konsequenz (sichtbar, nie still): Der User sieht sein Schedule in der Liste
        (Zeile da), aber es laeuft nicht (kein Job, Warn-geloggt). Das ist besser als
        der Altcode (still 24h -- ein voellig anderes Intervall ohne Spur) UND besser
        als das ``add`` komplett abzulehnen (dann waere die Eingabe spurlos weg). Der
        "Zeile-da-aber-kein-Job"-Zustand ist sowohl in der Liste sichtbar als auch
        geloggt.
        """
        schedule_id = self._repository.add(name, cidr, profile_id, schedule)
        row = {
            "id": schedule_id,
            "cidr": cidr,
            "profile_id": profile_id,
            "schedule": schedule,
        }
        try:
            self._job_scheduler.register(row, callback)
        except ScheduleParseError as exc:
            _logger.warning(
                "schedule_job_not_registered",
                schedule_id=schedule_id,
                schedule=schedule,
                error=str(exc),
            )
        return schedule_id

    def delete(self, schedule_id: int) -> None:
        """Loescht die Schedule-Zeile UND entfernt ihren Job (beide Ports).

        REIHENFOLGE bewusst: erst die Zeile (``repository.delete``), dann der Job
        (``job_scheduler.unregister``). Bei einem Teilausfall ist ein verwaister Job
        OHNE Zeile harmloser als eine Zeile OHNE Job: der verwaiste Job wird beim
        naechsten ``start()`` nicht neu registriert und stirbt spaetestens beim
        Neustart, waehrend eine Zeile ohne Job in der Liste scheinbar AKTIV aussieht,
        aber nie feuert (stiller Tot-Eintrag). Die Reihenfolge nicht umdrehen.
        ``unregister`` ist ohnehin idempotent (+ Log) -- ein nie/schon entfernter Job
        ist kein Fehler.
        """
        self._repository.delete(schedule_id)
        self._job_scheduler.unregister(schedule_id)


class GetSchedules:
    """Liste aller Schedules als rohe Zeilen-dicts (Pass-Through, nur Repo)."""

    def __init__(self, repository: ScheduleRepository) -> None:
        self._repository = repository

    def __call__(self) -> list[dict[str, Any]]:
        return self._repository.list()


class UpdateSchedule:
    """Aktualisiert ``enabled``/``name`` eines Schedules (Pass-Through, nur Repo).

    BEFUND (charakterisierungstreu bewahrt, NICHT in M.6 gefixt): Bei
    ``enabled=False`` wird der laufende Job NICHT entfernt -- ein deaktiviertes
    Schedule laeuft weiter (latenter Altcode-Bug). Der Fix (``enabled=False`` ->
    ``ScanJobScheduler.unregister``) gaebe diesem Use-Case spaeter den Job-Port dazu;
    das ist ein bewusster eigener Schritt, kein M.6-Auftrag -- darum hier nur das
    Repo (Pass-Through), kein Job-Port.
    """

    def __init__(self, repository: ScheduleRepository) -> None:
        self._repository = repository

    def __call__(self, schedule_id: int, enabled: bool | None, name: str | None) -> None:
        self._repository.update(schedule_id, enabled, name)
