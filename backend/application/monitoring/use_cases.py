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
import time
from typing import Any

import structlog

from domain.monitoring import (
    MonitorEvent,
    MonitorTarget,
    PingSample,
    ScheduleParseError,
    classify_transition,
    compute_sla_stats,
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
    SlaSampleRepository,
)

# Sekunden pro Tag -- fuer die ``days`` -> ``since``-Umrechnung der SLA-Use-Cases.
_SECONDS_PER_DAY = 86400

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


# ── Monitor-Lese-Use-Cases (M.9) ────────────────────────────────────────────
# Duenne Pass-Through-Use-Cases (Muster GetScanHistory/GetSchedules) fuer die
# REST-Lesepfade ``/api/monitor/events`` + ``/api/monitor/rtt/{id}``. Sie existieren,
# weil der api-Ring die Repos (Ports) NICHT direkt rufen darf (import-linter:
# api -> nur application) -- die EINZIGE Schicht, die der Router ansprechen kann.
# Sie geben die ROHEN Domaenen-Objekte (MonitorEvent / PingSample) heraus; die
# Response-Shape (ts aus timestamp, datetime-Formatierung, id weggelassen) baut der
# api-Rand per Attribut-Zugriff -- Naht-Linie wie current_status/Broadcaster: der
# Use-Case liefert Domaenen-Daten, der Rand die Wire-Form.


class GetMonitorEvents:
    """Letzte Uebergangs-Ereignisse ueber alle Targets (Pass-Through, nur Repo).

    Reicht ``MonitorEventRepository.recent(limit)`` durch (neueste zuerst, ``ts``
    absteigend wie der Altcode ``get_monitor_events``). Speist ``/api/monitor/events``.
    Keine Ereignisse -> ``[]``.
    """

    def __init__(self, repository: MonitorEventRepository) -> None:
        self._repository = repository

    def __call__(self, limit: int = 100) -> list[MonitorEvent]:
        return self._repository.recent(limit)


class GetRttHistory:
    """RTT-Verlaufspunkte EINES Targets (Pass-Through, nur Repo).

    Reicht ``RttHistoryRepository.recent(target_id, limit)`` durch (chronologisch,
    aelteste zuerst -- altcode-treu). Speist ``/api/monitor/rtt/{id}``. Unbekanntes
    Target / keine Daten -> ``[]``.
    """

    def __init__(self, repository: RttHistoryRepository) -> None:
        self._repository = repository

    def __call__(self, target_id: str, limit: int = 120) -> list[PingSample]:
        return self._repository.recent(target_id, limit)


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

    v2-ABWEICHUNG (M.9, bewusst ggue. dem abgenommenen M.6): Der
    ``ScanTriggerCallback`` ist jetzt im ``__init__`` GEBUNDEN (war in M.6 das
    fuenfte ``add``-Argument). Grund: ``add`` wird ueber ``POST /api/schedules``
    (M.9) aufgerufen, und der api-Ring kann den Callback NICHT durchreichen -- er ist
    Composition-Root-gebunden (lebt in ``app.py._scheduled_scan``, ruft ``modules``).
    EINE Bindungsstelle (hier im ctor) speist BEIDE Pfade: den REST-``add`` UND die
    lifespan-Registrierung der gespeicherten Schedules (``app.py`` uebergibt
    denselben Callback an diesen ctor und an ``ScanJobScheduler.register/start``) --
    so kann REST-add und lifespan-Job nicht divergieren. Die Adapter-Signaturen
    (``register(schedule, callback)`` / ``start(callback)``) bleiben unveraendert
    (der Adapter bleibt zustandslos); nur ``add`` verliert das Argument.
    """

    def __init__(
        self,
        repository: ScheduleRepository,
        job_scheduler: ScanJobScheduler,
        callback: ScanTriggerCallback,
    ) -> None:
        self._repository = repository
        self._job_scheduler = job_scheduler
        self._callback = callback

    def add(
        self,
        name: str,
        cidr: str,
        profile_id: str,
        schedule: str,
    ) -> int:
        """Legt die Schedule-Zeile an und registriert ihren Job (best-effort).

        Der Job wird mit dem im ctor gebundenen ``ScanTriggerCallback`` registriert
        (s. Klassen-Docstring -- EINE Callback-Quelle).

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
            self._job_scheduler.register(row, self._callback)
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


# ── SLA-Lese-Use-Cases (M.7) ────────────────────────────────────────────────
# Pass-Through-Use-Cases (Muster GetScanHistory/GetSchedules): laden die Sample-
# Zeilen ueber den Port und reichen sie in die reine Domaenen-Rechnung (M.2).
# NUR Lesen -- der Schreibpfad ist ein eigener Schritt (M.7b), s. ports/monitoring.
# Die ``days`` -> ``since``-Umrechnung passiert HIER (now - days*86400), damit das
# Repo zeitlogik-frei bleibt -- ``time.time()`` direkt wie im Altcode (modules/sla),
# kein eigener Clock-Port fuer diesen schmalen Schritt.


class GetSlaStats:
    """SLA-Gesamtstatistik EINES Targets ueber ``days`` Tage (Pass-Through, nur Repo).

    Laedt die Sample-Zeilen (``repo.samples_for``) und reicht sie in die reine
    ``compute_sla_stats`` (M.2). WICHTIG: Die Domaene setzt KEIN ``target_id`` ins
    Ergebnis-dict (sie kennt das DB-Schluesselfeld nicht) -- dieser Use-Case ergaenzt
    es, sonst braeche der ``/api/sla/{id}``-Response-Vertrag (der Altcode-
    ``get_sla_stats`` liefert ``target_id`` mit). Leere Samples -> die Domaenen-Null-
    Stats (``uptime_pct=None``), ebenfalls mit ``target_id`` angereichert.
    """

    def __init__(self, repository: SlaSampleRepository) -> None:
        self._repository = repository

    def __call__(self, target_id: str, days: int = 30) -> dict[str, Any]:
        since = time.time() - days * _SECONDS_PER_DAY
        rows = self._repository.samples_for(target_id, since)
        stats = compute_sla_stats(rows, days)
        # target_id ergaenzen (Domaene setzt es bewusst nicht) -- Vertrag /api/sla/{id}.
        return {"target_id": target_id, **stats}


class GetAllSlaStats:
    """SLA-Statistik ALLER getrackten Targets (Pass-Through, orchestriert GetSlaStats).

    Reproduziert den Altcode-``get_all_sla_stats``: ``repo.target_ids()`` -> je id eine
    ``GetSlaStats``-Berechnung. Keine Targets mit Samples -> ``[]`` (real der
    Dauerzustand, da ``sla_samples`` nie geschrieben wird -- s. ports/monitoring).
    """

    def __init__(self, repository: SlaSampleRepository) -> None:
        self._repository = repository
        self._get_one = GetSlaStats(repository)

    def __call__(self, days: int = 30) -> list[dict[str, Any]]:
        return [self._get_one(target_id, days) for target_id in self._repository.target_ids()]
