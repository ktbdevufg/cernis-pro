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
                   + wenn should_notify(prev, event):
                         notifier.notify(MonitorEvent)        (Desktop-Notification)
                         alert_raiser.raise_alert(MonitorEvent) (regelbasierter Alert, A.7a)
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
from dataclasses import dataclass
from typing import Any, cast

import structlog

from application.monitoring.errors import LoggingTaskConflict, LoggingTaskNotFound
from domain.monitoring import (
    CUSTOM_TARGETS_KEY,
    CaptureMode,
    LoggingTask,
    MonitorEvent,
    MonitorTarget,
    OperationMode,
    PingSample,
    ScheduleParseError,
    TaskState,
    classify_transition,
    compute_sla_stats,
    conflicts_with,
    is_window_active,
    should_notify,
)
from domain.monitoring import (
    pause as domain_pause,
)
from domain.monitoring import (
    resume as domain_resume,
)
from domain.monitoring import (
    start as domain_start,
)
from domain.monitoring import (
    stop as domain_stop,
)
from domain.settings import Setting, SettingValue
from ports.monitoring import (
    AlertRaiserPort,
    LoggingEventRepository,
    LoggingRttRepository,
    LoggingTaskRepository,
    MonitorBroadcasterPort,
    MonitorEventRepository,
    MonitorLoggingSinkPort,
    MonitorNotifierPort,
    MonitorPingerPort,
    MonitorTargetSource,
    RttHistoryRepository,
    ScanJobScheduler,
    ScanTriggerCallback,
    ScheduleRepository,
    SlaSampleRepository,
)
from ports.settings import SettingsRepository

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
        alert_raiser: AlertRaiserPort,
        logging_sink: MonitorLoggingSinkPort,
        interval: int = _DEFAULT_INTERVAL,
    ) -> None:
        self._pinger = pinger
        self._rtt_history = rtt_history
        self._event_repo = event_repo
        self._notifier = notifier
        self._broadcaster = broadcaster
        self._target_source = target_source
        self._alert_raiser = alert_raiser
        self._logging_sink = logging_sink
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
                # Zwei best-effort-Konsequenzen an DERSELBEN Flanke (A.7a): die
                # Desktop-Notification UND der regelbasierte Alert. Beide Ports werfen
                # NIE (Adapter faengt+loggt) -> gegenseitig isoliert ohne try/except
                # hier; Reihenfolge verhaltensneutral (notify wie bisher zuerst). Der
                # Use-Case reicht nur sein MonitorEvent durch -- KEIN rule_type/message-
                # Wissen (alerting-blind; das Mapping lebt im app.py-Adapter).
                await self._notifier.notify(monitor_event)
                await self._alert_raiser.raise_alert(monitor_event)

        # IMMER broadcasten -- auch bei event=None (Altcode: monitor_update jede Runde).
        await self._broadcaster.broadcast(target, sample, event)

        # Langzeit-Logging-Sink (B-II): EINE zusaetzliche best-effort-Konsequenz, NACH
        # broadcast -- verhaltensneutral (der bestehende ping/classify/notify/broadcast-
        # Pfad bleibt exakt wie er war; der Sink haengt sich nur HINTEN an). Position
        # nach broadcast gewaehlt, damit das Live-Update niemals hinter dem Logging-
        # Schreiben wartet. now = sample.timestamp (der bereits gemessene ts -- KEINE
        # neue Uhr im Loop); nur falls der Sentinel 0.0 anliegt (kein gesetzter ts),
        # einmalig time.time() als Bezug. Der Sink ist best-effort (wirft NIE, der
        # Adapter faengt selbst) -> KEIN try/except hier, wie bei notifier/alert_raiser.
        sink_now = sample.timestamp if sample.timestamp else time.time()
        await self._logging_sink.record(target, sample, event, sink_now)

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


# ── Targets-Schreibpfad (M.9-Nachzuegler) ───────────────────────────────────
# Der LESE-Pfad (``CompositeTargetSource.load``, infrastructure) komponiert die
# Targets aus drei Quellen; HIER ist nur die benutzerdefinierte Quelle
# (``monitor_custom_targets`` in den Settings) SCHREIBBAR. Bewusst KEIN eigener
# Port und KEINE eigene Tabelle: die Custom-Targets sind ein Settings-Wert
# (``list[dict]``), also nutzt der Schreibpfad das migrierte ``SettingsRepository``
# direkt (cross-domain Port-Import -- application darf ``ports`` kennen, der
# import-linter verbietet nur infrastructure/api). Kein ``configure_monitor`` mehr:
# der ``RunMonitor`` laedt pro ``tick`` frisch via ``MonitorTargetSource.load()``,
# also wirkt ein hier geschriebenes Target bei der naechsten Iteration automatisch
# (Altcode-Live-Reload ohne die ``configure``-Kruecke).


def _load_custom_targets(repository: SettingsRepository) -> list[dict[str, Any]]:
    """Liest die rohe Custom-Targets-Liste aus den Settings (leer, wenn nicht gesetzt).

    Altcode-treu: ``get_setting("monitor_custom_targets", []) or []`` -- ein nicht
    gesetzter Key ODER ein nicht-Listen-Wert ergibt eine leere Liste (kein Fehler),
    damit der Schreibpfad immer auf einer wohlgeformten Liste appended/filtert.
    """
    setting = repository.get(CUSTOM_TARGETS_KEY)
    if setting is None or not isinstance(setting.value, list):
        return []
    # Defensive Kopie + nur dict-Eintraege (kaputte Fremdeintraege wuerden beim
    # Zurueckschreiben sonst durchgereicht -- der LESE-Pfad ueberspringt sie ohnehin).
    return [entry for entry in setting.value if isinstance(entry, dict)]


def _save_custom_targets(repository: SettingsRepository, targets: list[dict[str, Any]]) -> None:
    """Schreibt die Custom-Targets-Liste zurueck (``Setting``-validiert)."""
    # ``list[dict[str, Any]]`` ist ein gueltiger ``SettingValue`` (JSON-serialisierbar);
    # der Cast macht die Vertraeglichkeit fuer mypy explizit, ohne Laufzeitwirkung.
    value: SettingValue = cast(SettingValue, targets)
    repository.set(Setting(key=CUSTOM_TARGETS_KEY, value=value))


class AddMonitorTarget:
    """Fuegt ein benutzerdefiniertes Monitor-Target hinzu (Altcode POST /api/monitor/targets).

    Liest die aktuelle ``monitor_custom_targets``-Liste, haengt das neue Target mit
    der Altcode-Feldform (``id``/``label``/``host``/``interface``/``enabled``) an und
    schreibt zurueck. KEINE ``configure``-Folge -- der Loop laedt frisch (Live-Reload).
    """

    def __init__(self, repository: SettingsRepository) -> None:
        self._repository = repository

    def __call__(
        self,
        target_id: str,
        label: str,
        host: str,
        interface: str = "",
        enabled: bool = True,
    ) -> None:
        targets = _load_custom_targets(self._repository)
        targets.append(
            {
                "id": target_id,
                "label": label,
                "host": host,
                "interface": interface,
                "enabled": enabled,
            }
        )
        _save_custom_targets(self._repository, targets)


class DeleteMonitorTarget:
    """Entfernt ein benutzerdefiniertes Monitor-Target nach ``id`` (Altcode DELETE).

    Filtert die ``monitor_custom_targets``-Liste nach ``id != target_id`` und schreibt
    zurueck. Idempotent: eine unbekannte ``id`` filtert nichts heraus (kein Fehler).
    Eintraege OHNE ``id``-Schluessel werden konservativ BEHALTEN (sie matchen den zu
    loeschenden ``target_id`` nicht). Nur die fest verdrahteten Internet-/Gateway-
    Targets liegen ohnehin nicht in den Settings -- sie sind nicht loeschbar.
    """

    def __init__(self, repository: SettingsRepository) -> None:
        self._repository = repository

    def __call__(self, target_id: str) -> None:
        targets = _load_custom_targets(self._repository)
        remaining = [entry for entry in targets if entry.get("id") != target_id]
        _save_custom_targets(self._repository, remaining)


# ── Langzeit-Logging-Retention (B-I) ────────────────────────────────────────
# Der EINZIGE Use-Case des B-I-Schritts 2: das Aufraeumen der dichten Logging-
# Messdaten nach Ablauf der Retention-Spanne. GETRENNT vom fluechtigen Live-Monitor
# (eigene Repos/Tabellen). Reiner Pass-Through auf ``delete_older_than`` beider
# Mess-Repos -- KEINE Uhr im Use-Case (anders als die SLA-Use-Cases, die now -
# days*86400 selbst rechnen): die Cutoffs kommen als METHODEN-Parameter herein, der
# Aufrufer (Schritt 3 / B-II) rechnet ``now - 30d`` bzw. ``now - 365d``. So bleibt der
# Use-Case deterministisch testbar (kein time.time()).

# Retention-Spannen der Logging-Messdaten in SEKUNDEN -- benannte Policy-Konstanten.
# BEWUSST NICHT hier angewendet (kein time.time() im Use-Case): sie dokumentieren die
# Policy fuer Schritt 3 / B-II, der daraus die absoluten Cutoffs rechnet
# (rtt_cutoff_ts = now - _RTT_RETENTION_S, event_cutoff_ts = now - _EVENT_RETENTION_S).
_RTT_RETENTION_S = 30 * 86400  # dichte RTT-Messpunkte: 1 Monat (30 Tage)
_EVENT_RETENTION_S = 365 * 86400  # Ereignis-/Anomalie-Flanken: 1 Jahr (365 Tage)


@dataclass(frozen=True)
class LoggingRetentionResult:
    """Ergebnis EINES Retention-Laufs: geloeschte Zeilen je Messdaten-Art.

    Klein und benannt (kein nacktes Tuple): die beiden Zahlen haben verschiedene
    Bedeutung (RTT-Messpunkte vs. Ereignis-Flanken) und der Aufrufer (Log/Mengen-
    Check) liest sie sprechend. ``rtt_deleted``/``event_deleted`` sind die
    Rueckgabewerte der jeweiligen ``delete_older_than``-Aufrufe.
    """

    rtt_deleted: int
    event_deleted: int


class EnforceLoggingRetention:
    """Loescht abgelaufene Logging-Messdaten ueber beide Mess-Repos (Pass-Through).

    Haelt das RTT- und das Event-Repo und reicht je einen ABSOLUTEN Cutoff an deren
    ``delete_older_than`` durch. KEINE Uhr, KEINE Spannen-Rechnung hier (s.
    Modul-Kommentar): die beiden Cutoffs sind ``run``-Parameter -- der Aufrufer
    (Schritt 3 / B-II) bildet sie aus ``_RTT_RETENTION_S`` / ``_EVENT_RETENTION_S``.
    Die Task-DEFINITIONEN (``LoggingTaskRepository``) sind NICHT betroffen -- Retention
    raeumt nur die Messdaten, nicht die Aufgaben selbst.
    """

    def __init__(
        self,
        rtt_repository: LoggingRttRepository,
        event_repository: LoggingEventRepository,
    ) -> None:
        self._rtt_repository = rtt_repository
        self._event_repository = event_repository

    def run(self, rtt_cutoff_ts: float, event_cutoff_ts: float) -> LoggingRetentionResult:
        """Loescht RTT-Messpunkte vor ``rtt_cutoff_ts`` und Events vor ``event_cutoff_ts``.

        Reiner Pass-Through: je ein ``delete_older_than`` pro Repo, die Rueckgaben
        (geloeschte Zeilen) gebuendelt im ``LoggingRetentionResult``. Beide Cutoffs
        sind absolute ts-Werte -- die ``now - 30d`` / ``now - 365d``-Rechnung macht der
        Aufrufer.
        """
        rtt_deleted = self._rtt_repository.delete_older_than(rtt_cutoff_ts)
        event_deleted = self._event_repository.delete_older_than(event_cutoff_ts)
        return LoggingRetentionResult(rtt_deleted=rtt_deleted, event_deleted=event_deleted)


# ── Logging-Aufgaben-Lifecycle (B-I Schritt 3) ──────────────────────────────
# Macht den Logging-Kern von aussen STEUERBAR: Anlegen + Lebenszyklus-Uebergaenge
# der Task-DEFINITIONEN ueber dem ``LoggingTaskRepository``. GETRENNT vom fluechtigen
# Live-Monitor (``RunMonitor``) -- diese Use-Cases ruehren weder Loop noch
# ``rtt_history``/``monitor_events`` an. KEINE Uhr in den Use-Cases: wo ``now`` oder
# eine ``id`` gebraucht wird, kommt sie als METHODEN-Parameter herein (der api-Rand
# liefert ``time.time()`` / ``uuid4``) -- so bleiben die Use-Cases deterministisch
# testbar (Muster: die Domaene ist zeitfrei, der Rand liefert die Zeit).
#
# KONFLIKT-Regel (Konzept): pro Ziel darf nur EINE Aufgabe gleichzeitig ``ACTIVE``
# sein. Sie greift erst beim STARTEN/FORTSETZEN (nicht beim Anlegen) -- pro Ziel sind
# beliebig viele Tasks anlegbar, der Konflikt entsteht erst, wenn ein zweiter aktiv
# werden will. Geprueft via Domaenen-``conflicts_with`` gegen ``list_all``.


def _find_active_conflict(candidate: LoggingTask, others: list[LoggingTask]) -> str | None:
    """``id`` der bereits ``ACTIVE``-Aufgabe am selben Ziel -- oder ``None``.

    Spiegelt die Domaenen-``conflicts_with`` (gleiches Praedikat: anderes ``id``,
    gleiches ``target_id``, Zustand ``ACTIVE``), liefert aber die ID des Konkurrenten
    statt nur ``bool`` -- die braucht der ``LoggingTaskConflict`` fuer die
    Konzept-Meldung. ``conflicts_with`` bleibt die Wahrheit ueber das OB (hier nur das
    WER), darum wird es vom Aufrufer zusaetzlich als Guard genutzt.
    """
    for other in others:
        if (
            other.id != candidate.id
            and other.target_id == candidate.target_id
            and other.state is TaskState.ACTIVE
        ):
            return other.id
    return None


class CreateLoggingTask:
    """Legt eine neue Logging-Aufgabe im Zustand ``CREATED`` an (reine Anlage).

    KEIN Start, KEINE Konfliktpruefung: Anlegen ist beliebig erlaubt (Konzept: pro
    Ziel beliebig viele Tasks, Konflikt erst beim Starten). ``id`` und ``created_at``
    kommen als Methoden-Parameter herein (der api-Rand liefert ``uuid4`` /
    ``time.time()``) -- der Use-Case haelt keine Uhr. Die Modus-Felder
    (``planned_start``/``planned_end`` bzw. ``max_duration_s``) reicht der Use-Case
    durch; ihre Modus-Konsistenz prueft der Router (Schritt 3b, 422), nicht hier.

    ``capture_mode``/``operation_mode`` kommen als ROHER ``str`` herein und werden HIER
    in die Domaenen-``StrEnum`` gehoben -- so kennt der api-Rand die Domaenen-Enums
    NICHT (import-linter: api -> nur application). Ein nicht zum Vokabular passender
    String wirft ``ValueError`` (StrEnum-Konstruktor) -- am Router faengt das schon die
    Body-Validierung (422) vorher ab; der Cast hier ist die zweite, autoritative Linie.

    ``interval_s`` (C-2, Mess-Intervall in Sekunden) hat den Default 5 -- denselben wie
    die Domaene (``LoggingTask.interval_s: int = 5``). Der Default liegt damit an der
    Domaene (autoritativ); dieser Use-Case-Default spiegelt ihn nur, der Router setzt
    KEINE eigene 5, sondern reicht ``interval_s`` nur durch, wenn der Client es gesetzt
    hat (sonst greift dieser Default). Die Stufen-Validierung macht der Router (422).
    """

    def __init__(self, repository: LoggingTaskRepository) -> None:
        self._repository = repository

    def __call__(
        self,
        *,
        task_id: str,
        target_id: str,
        label: str,
        purpose: str,
        capture_mode: str,
        operation_mode: str,
        created_at: float,
        planned_start: float | None = None,
        planned_end: float | None = None,
        max_duration_s: int | None = None,
        interval_s: int = 5,
    ) -> LoggingTask:
        task = LoggingTask(
            id=task_id,
            target_id=target_id,
            label=label,
            purpose=purpose,
            capture_mode=CaptureMode(capture_mode),
            operation_mode=OperationMode(operation_mode),
            state=TaskState.CREATED,
            planned_start=planned_start,
            planned_end=planned_end,
            max_duration_s=max_duration_s,
            created_at=created_at,
            interval_s=interval_s,
        )
        self._repository.save(task)
        return task


class StartLoggingTask:
    """Uebergang ``CREATED`` -> ``ACTIVE`` mit Ziel-Konfliktpruefung.

    Laedt den Task (``get``; ``None`` -> ``LoggingTaskNotFound``), prueft via
    Domaenen-``conflicts_with`` gegen ``list_all``, ob am selben Ziel bereits eine
    ``ACTIVE``-Aufgabe laeuft -> ``LoggingTaskConflict`` (mit der ID des laufenden
    Konkurrenten). Sonst Domaenen-``start`` (``InvalidTaskTransition`` aus falschem
    Ausgangszustand propagiert) -> ``save``. ``now`` ist Methoden-Parameter (api-Rand)
    und wird seit B-II als effektiver Start an ``domain_start`` durchgereicht (ADR 0033):
    der erste Start setzt damit den ``effective_start`` der Aufgabe, Bezugs-ts des
    ``IMMEDIATE``-Fensters.
    """

    def __init__(self, repository: LoggingTaskRepository) -> None:
        self._repository = repository

    def __call__(self, task_id: str, now: float) -> LoggingTask:
        task = self._repository.get(task_id)
        if task is None:
            raise LoggingTaskNotFound(task_id)
        others = self._repository.list_all()
        if conflicts_with(task, others):
            running_id = _find_active_conflict(task, others)
            # running_id ist hier nie None (conflicts_with == True heisst: es gibt
            # einen Konkurrenten) -- der Fallback auf task_id ist nur ein defensiver
            # Platzhalter fuer mypy (str statt str | None).
            raise LoggingTaskConflict(running_id or task_id, task.target_id)
        # now als effektiver Start an die Domaene (ADR 0033): erster Start setzt ihn.
        started = domain_start(task, now)
        self._repository.save(started)
        return started


class PauseLoggingTask:
    """Uebergang ``ACTIVE`` -> ``PAUSED`` (Domaenen-``pause`` -> ``save``).

    ``get`` (``None`` -> ``LoggingTaskNotFound``), dann Domaenen-``pause``; ein
    ``InvalidTaskTransition`` aus falschem Ausgangszustand propagiert (der api-Rand
    mappt ihn auf 409). KEINE Konfliktpruefung -- Pausieren entschaerft den Konflikt,
    es erzeugt keinen.
    """

    def __init__(self, repository: LoggingTaskRepository) -> None:
        self._repository = repository

    def __call__(self, task_id: str) -> LoggingTask:
        task = self._repository.get(task_id)
        if task is None:
            raise LoggingTaskNotFound(task_id)
        paused = domain_pause(task)
        self._repository.save(paused)
        return paused


class ResumeLoggingTask:
    """Uebergang ``PAUSED`` -> ``ACTIVE`` mit Ziel-Konfliktpruefung.

    Fortsetzen aus Pause ist im Sinne der Konzept-Regel ein Start (pro Ziel nur einer
    aktiv) -- darum prueft dieser Use-Case VOR dem ``resume`` ebenfalls
    ``conflicts_with`` gegen ``list_all`` (-> ``LoggingTaskConflict``). ``get``
    (``None`` -> ``LoggingTaskNotFound``); ``InvalidTaskTransition`` aus falschem
    Ausgangszustand propagiert (409 am Rand).
    """

    def __init__(self, repository: LoggingTaskRepository) -> None:
        self._repository = repository

    def __call__(self, task_id: str) -> LoggingTask:
        task = self._repository.get(task_id)
        if task is None:
            raise LoggingTaskNotFound(task_id)
        others = self._repository.list_all()
        if conflicts_with(task, others):
            running_id = _find_active_conflict(task, others)
            raise LoggingTaskConflict(running_id or task_id, task.target_id)
        resumed = domain_resume(task)
        self._repository.save(resumed)
        return resumed


class StopLoggingTask:
    """Uebergang ``{ACTIVE, PAUSED}`` -> ``FINISHED`` (Domaenen-``stop`` -> ``save``).

    ``get`` (``None`` -> ``LoggingTaskNotFound``), dann Domaenen-``stop``; ein
    ``InvalidTaskTransition`` aus falschem Ausgangszustand propagiert (409 am Rand).
    """

    def __init__(self, repository: LoggingTaskRepository) -> None:
        self._repository = repository

    def __call__(self, task_id: str) -> LoggingTask:
        task = self._repository.get(task_id)
        if task is None:
            raise LoggingTaskNotFound(task_id)
        finished = domain_stop(task)
        self._repository.save(finished)
        return finished


class DeleteLoggingTask:
    """Loescht eine Logging-Aufgaben-DEFINITION (Pass-Through, idempotent).

    Reicht ``LoggingTaskRepository.delete`` durch -- idempotent (unbekannte ``id`` ist
    kein Fehler, Muster ``ScheduleRepository.delete``). Die zugehoerigen Messdaten
    (RTT/Events) liegen in eigenen Repos und werden hier NICHT mitgeloescht (das raeumt
    die Retention, eigener Belang).
    """

    def __init__(self, repository: LoggingTaskRepository) -> None:
        self._repository = repository

    def __call__(self, task_id: str) -> None:
        self._repository.delete(task_id)


class ListLoggingTasks:
    """Alle Logging-Aufgaben-Definitionen (Pass-Through, nur Repo).

    Reicht ``LoggingTaskRepository.list_all`` roh durch (Muster ``GetSchedules``).
    Leere Tabelle -> ``[]``. Die Wire-Form baut der api-Rand.
    """

    def __init__(self, repository: LoggingTaskRepository) -> None:
        self._repository = repository

    def __call__(self) -> list[LoggingTask]:
        return self._repository.list_all()


class GetLoggingTaskDetail:
    """EINE Logging-Aufgaben-Definition anhand ihrer ``id`` (Pass-Through, nur Repo).

    ``get`` (``None`` -> ``LoggingTaskNotFound``) -> roh zurueck. Die Wire-Form baut
    der api-Rand (404-Mapping ebenfalls am Rand).
    """

    def __init__(self, repository: LoggingTaskRepository) -> None:
        self._repository = repository

    def __call__(self, task_id: str) -> LoggingTask:
        task = self._repository.get(task_id)
        if task is None:
            raise LoggingTaskNotFound(task_id)
        return task


# Schwellwert fuer den Mengen-Befund von ``CheckLogVolume`` -- ab dieser Zahl
# gespeicherter RTT-Messpunkte gilt das Volumen als "ueber Schwelle". Benannte
# Policy-Konstante (kein Magic Number am Vergleich); bewusst grosszuegig (dichte
# Logging-Messpunkte fallen schnell an, der Befund soll erst bei echter Menge feuern).
# NUR ein Befund -- die angebotene Folge-Aktion (Aufraeumen) ist ein §9-Folgeschnitt.
_LOG_VOLUME_THRESHOLD = 100_000


@dataclass(frozen=True)
class LogVolumeResult:
    """Mengen-Befund der Logging-RTT-Messdaten: Gesamtzahl + Ueber-Schwelle-Flag.

    Klein und benannt (kein nacktes Tuple): ``count`` ist die Gesamtzahl gespeicherter
    RTT-Messpunkte, ``over_threshold`` der Vergleich gegen ``_LOG_VOLUME_THRESHOLD``.
    Der Aufrufer (api-Rand / spaeterer §9-Schnitt) liest beide sprechend.
    """

    count: int
    over_threshold: bool


class CheckLogVolume:
    """Mengen-Befund der Logging-RTT-Messdaten (NUR Abfrage, keine Aktion).

    Liest ``LoggingRttRepository.count()`` und vergleicht gegen die benannte
    ``_LOG_VOLUME_THRESHOLD``. KEINE Aktion, KEIN Loeschen -- die angebotene
    Aufraeum-Aktion ist ein §9-Folgeschnitt. Bewusst rtt-only (s. Datei-/Abschluss-
    Begruendung): die dichten RTT-Messpunkte sind die dominante Menge; sie ueber EINE
    ``count()``-Abfrage zu beurteilen haelt den Befund schmal und eindeutig.
    """

    def __init__(self, rtt_repository: LoggingRttRepository) -> None:
        self._rtt_repository = rtt_repository

    def __call__(self) -> LogVolumeResult:
        count = self._rtt_repository.count()
        return LogVolumeResult(count=count, over_threshold=count > _LOG_VOLUME_THRESHOLD)


# ── Wiederaufnahme aktiver Logging-Aufgaben nach Neustart (B-II Schritt 4) ───
# Nach einem Neustart koennen Aufgaben in der DB ``ACTIVE`` stehen, deren Fenster
# inzwischen abgelaufen ist (IMMEDIATE-Maximaldauer waehrend der Auszeit verstrichen,
# SCHEDULED planned_end vorbei). Die eigentliche Wiederaufnahme der noch gueltigen
# Aufgaben ist KEIN Extra-Schritt: der Sink liest jeden Tick die aktiven Tasks frisch
# und schreibt ab dem naechsten Tick automatisch wieder. Dieser Use-Case raeumt nur die
# ABGELAUFENEN auf -- sie duerfen nicht als ewig-aktiv haengenbleiben. KEINE Uhr im
# Use-Case: ``now`` kommt als Parameter (der lifespan liefert ``time.time()``).


@dataclass(frozen=True)
class ResumeResult:
    """Ergebnis EINES Resume-Laufs: weiterlaufende vs. beendete Aufgaben.

    ``kept_active`` sind die Aufgaben mit noch offenem Fenster (sie laufen weiter, der
    Sink nimmt sie automatisch auf), ``finished`` die abgelaufenen, die auf FINISHED
    gesetzt wurden. Klein und benannt (kein nacktes Tuple) -- der lifespan liest beide
    Zahlen sprechend fuers Log.
    """

    kept_active: int
    finished: int


class ResumeActiveLoggingTasks:
    """Beendet abgelaufene ``ACTIVE``-Aufgaben nach Neustart; laesst gueltige laufen.

    Laedt ``list_all`` und prueft fuer jede ``ACTIVE``-Aufgabe ``is_window_active(task,
    now)`` (Bezugs-ts aus ``task.effective_start`` / ``planned_*`` -- die Domaene zieht
    ihn selbst, ADR 0033):

    * Fenster noch offen -> nichts tun (die Aufgabe bleibt ACTIVE; der Sink schreibt ab
      dem naechsten Tick automatisch -- DAS ist die Wiederaufnahme).
    * Fenster abgelaufen -> Domaenen-``stop`` + ``save`` (auf FINISHED setzen), damit sie
      nicht als ewig-aktiv haengenbleibt.

    Reiner, deterministisch testbarer Use-Case (kein ``asyncio``, keine Uhr) -- der
    lifespan ruft ihn einmal beim Start.
    """

    def __init__(self, repository: LoggingTaskRepository) -> None:
        self._repository = repository

    def __call__(self, now: float) -> ResumeResult:
        kept_active = 0
        finished = 0
        for task in self._repository.list_all():
            if task.state is not TaskState.ACTIVE:
                continue
            if is_window_active(task, now):
                kept_active += 1
                continue
            # Fenster abgelaufen -> beenden (stop leert effective_start, ADR 0033).
            self._repository.save(domain_stop(task))
            finished += 1
        return ResumeResult(kept_active=kept_active, finished=finished)


# ── Periodischer Retention-Runner (B-II Schritt 4) ──────────────────────────
# Setzt die Logging-Retention DURCH: ein schlanker Runner im Muster ``RunMonitor`` /
# ``RunThroughputPoll`` (run()/stop(), Logik in tick()), der periodisch
# ``EnforceLoggingRetention`` mit now-basierten Cutoffs ruft. KEINE Endlosschleife im
# lifespan -- der Composition Root treibt create_task/Teardown. Retention ist nicht
# zeitkritisch, darum ein grosszuegiges, BENANNTES Intervall (kein Magic Number).

# Intervall zwischen zwei Retention-Laeufen in SEKUNDEN: einmal pro Stunde. Benannte
# Policy-Konstante -- Retention ist nicht zeitkritisch (die Spannen sind 30 Tage / 1
# Jahr), ein stuendlicher Lauf haelt die Tabellen sauber, ohne die DB zu belasten.
_CLEANUP_INTERVAL_S = 3600


class RunLoggingRetention:
    """Periodischer Runner, der ``EnforceLoggingRetention`` in einer Schleife ruft.

    Muster ``RunMonitor``/``RunThroughputPoll``: ``tick()`` ist EIN Retention-Lauf (voll
    testbar), ``run()`` nur der triviale ``while``/``sleep``-Rahmen. KEIN
    ``asyncio.Task``-Management hier -- create_task/Teardown treibt der Composition Root
    (``app.py``-lifespan), exakt wie beim Monitor-Loop.

    BEST-EFFORT: ``tick`` faengt jeden Fehler des Retention-Laufs und loggt ihn (der
    periodische Cleanup darf nie den Task killen -- sonst liefe die Retention nach einem
    transienten DB-Fehler nie wieder). Die ``now - 30d`` / ``now - 365d``-Rechnung macht
    HIER der Runner (der Aufrufer der zeitfreien ``EnforceLoggingRetention``); ``now``
    ist ``time.time()`` -- der Runner ist der zeitbehaftete Rand um den reinen Use-Case.
    """

    def __init__(
        self,
        enforce: EnforceLoggingRetention,
        *,
        interval: int = _CLEANUP_INTERVAL_S,
    ) -> None:
        self._enforce = enforce
        self._interval = interval
        self._running = False

    async def tick(self) -> None:
        """Ein Retention-Lauf: now-basierte Cutoffs rechnen, ``enforce.run`` rufen."""
        try:
            now = time.time()
            result = self._enforce.run(
                rtt_cutoff_ts=now - _RTT_RETENTION_S,
                event_cutoff_ts=now - _EVENT_RETENTION_S,
            )
            _logger.info(
                "logging_retention_run",
                rtt_deleted=result.rtt_deleted,
                event_deleted=result.event_deleted,
            )
        except Exception as exc:
            # Best-effort: ein fehlgeschlagener Lauf darf den periodischen Task nicht
            # killen -- geloggt, naechster Lauf laeuft regulaer weiter.
            _logger.warning("logging_retention_run_failed", error=str(exc))

    async def run(self) -> None:
        """Endlos-Rahmen: tickt bis ``stop()``. Trivial -- die Logik sitzt in ``tick``."""
        self._running = True
        while self._running:
            await self.tick()
            await asyncio.sleep(self._interval)

    def stop(self) -> None:
        """Beendet den ``run``-Loop nach der laufenden Iteration (Flag, kein Cancel)."""
        self._running = False
