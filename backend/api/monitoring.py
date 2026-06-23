"""FastAPI-Router der monitoring-Domaene (v2) -- die REST-Lese-/Schedule-Pfade.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich Use-Cases aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter, Ports
und ``domain``-Typen werden hier NICHT importiert -- die Use-Cases kommen per
FastAPI-Dependency herein (Verdrahtung im Composition Root ``app.py``), und
Domaenen-Objekte werden ueber Attribut-Zugriff zu JSON serialisiert (Typ ``Any``,
genau wie der scanning-/devices-/settings-Router das haelt).

Endpunkte (Shapes am M.1-Characterization-Contract, mit den bewussten v2-
Abweichungen unten):

* ``GET  /api/monitor/status``      -> ``{tid: {alive, label}}`` (label-angereichert).
* ``GET  /api/monitor/events``      -> Liste der Uebergangs-Ereignisse, neueste zuerst.
* ``GET  /api/monitor/rtt/{id}``    -> RTT-Verlauf eines Targets, chronologisch.
* ``GET  /api/sla``                 -> SLA-Statistik aller getrackten Targets.
* ``GET  /api/sla/{id}``            -> SLA-Statistik eines Targets.
* ``GET  /api/schedules``           -> alle scan_schedules (9-Spalten-Zeilen).
* ``POST /api/schedules``           -> Schedule anlegen -> ``{ok, id}``.
* ``PATCH /api/schedules/{id}``     -> enabled/name aktualisieren -> ``{ok}``.
* ``DELETE /api/schedules/{id}``    -> Schedule loeschen -> ``{ok}``.

BEWUSSTE v2-ABWEICHUNGEN ggue. dem M.1-REST-Contract (API-Bruch erlaubt, CLAUDE.md):

* ``/api/monitor/events`` traegt KEIN ``id`` mehr. Im Altcode war ``id`` die
  ``monitor_events``-rowid (``SELECT *``); das Frontend liest sie nicht (React-key
  ist der Array-Index), und die WS-Live-Events trugen ohnehin nie ein ``id``. Das v2-
  ``MonitorEvent`` haelt kein ``id``-Feld -- es mitzuschleppen riesse den abgenommenen
  M.5-RunMonitor (baut+speichert MonitorEvent) auf, fuer ein Feld, das niemand liest.
  ``datetime`` (``%Y-%m-%d %H:%M:%S``) bleibt erhalten (das Frontend rendert es) und
  wird HIER am Rand aus dem rohen ``timestamp`` formatiert -- nicht am Adapter (die
  ``recent()``-Query bleibt schlank, das Domaenen-Objekt unberuehrt).

* targets-Schreibpfad (POST/DELETE ``/api/monitor/targets``) ist NICHT Teil von M.9
  (eigener Nachzuegler, wie der SLA-Schreibpfad M.7b).

Shape-Naht: Die Lese-Use-Cases (``GetMonitorEvents``/``GetRttHistory``) geben ROHE
Domaenen-Objekte; dieser Rand baut die Wire-Form (``ts`` aus ``timestamp``, ``event``
als StrEnum-Wert, ``datetime`` formatiert). ``/api/monitor/status`` wird ueber einen
fertig angereicherten ``Callable`` injiziert (``provide_monitor_status``): die
``label``-Anreicherung kombiniert ``RunMonitor.current_status()`` (application) mit
der ``MonitorTargetSource`` (Port) -- diese Komposition kennt nur der Composition
Root, darum als Callable hereingereicht (derselbe ``status_provider`` wie der WS-
Connect-Frame).
"""

import time
import uuid
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from application.monitoring import (
    AddMonitorTarget,
    CheckLogVolume,
    CreateLoggingTask,
    DeleteLoggingTask,
    DeleteMonitorTarget,
    EnrichedRttSample,
    GetAllSlaStats,
    GetLoggingTaskDetail,
    GetLoggingTaskEvents,
    GetLoggingTaskRtt,
    GetLoggingTaskSla,
    GetMonitorEvents,
    GetRttHistory,
    GetSchedules,
    GetSlaStats,
    InvalidTaskTransition,
    ListLoggingTasks,
    LoggingTaskConflict,
    LoggingTaskNotFound,
    ManageSchedules,
    OutageInterval,
    PauseLoggingTask,
    ResumeLoggingTask,
    SeriesAnalysis,
    StartLoggingTask,
    StopLoggingTask,
    UpdateSchedule,
    analyze_series,
)

router = APIRouter(prefix="/api", tags=["monitoring"])


# Body-Modelle (Hausmuster wie api/settings.SettingBody): optionale Felder mit
# Altcode-Defaults -- ein leerer Body ist gueltig (POST nutzt die Defaults, PATCH
# laesst ``None`` = unveraendert). Kein rohes ``Body(dict)`` (B008 + untypisiert).
class AddScheduleBody(BaseModel):
    """POST /api/schedules -- alle Felder optional mit Altcode-Defaults."""

    name: str = "Scheduled Scan"
    cidr: str = "192.168.1.0/24"
    profile_id: str = "standard"
    schedule: str = "interval:1h"


class PatchScheduleBody(BaseModel):
    """PATCH /api/schedules/{id} -- ``None`` = Feld unveraendert lassen."""

    enabled: bool | None = None
    name: str | None = None


# Erlaubte Modus-Strings am Router-Rand. Sie SPIEGELN bewusst das Domaenen-Vokabular
# (``CaptureMode``/``OperationMode``-StrEnum-Values) -- der api-Ring darf ``domain``
# NICHT importieren (import-linter), darum stehen die Werte hier als Literal-Mengen.
# Die autoritative Hebung str -> Enum macht ``CreateLoggingTask`` (application); diese
# Mengen sind nur die Frueh-Validierung am Rand (422 statt 500). Weicht das Vokabular
# je ab, faengt es spaetestens der Enum-Konstruktor im Use-Case (kein stiller Drift).
_CAPTURE_MODES = frozenset({"interface_status", "reachability", "reachability_latency"})
_OPERATION_MODES = frozenset({"scheduled", "immediate", "recurring"})

# Erlaubte Mess-Intervall-Stufen in Sekunden (C-2). Wie die Modus-Mengen oben nur die
# Frueh-Validierung am Rand (422 statt 500/stiller Drift); den Default 5 setzt NICHT
# der Router, sondern die Domaene/der Use-Case (interval_s: int = 5) -- der Router
# reicht ``None`` als "nicht gesetzt" durch, dann greift der Use-Case-Default.
_INTERVAL_STUFEN = frozenset({5, 15, 30, 60, 300})

# Erlaubte Schwellwert-Bedingungen am Router-Rand (Schnitt 4). Wie die Modus-Mengen
# oben SPIEGELN sie bewusst das Domaenen-Vokabular (``ThresholdCondition``-StrEnum-
# Values) -- der api-Ring darf ``domain`` NICHT importieren (import-linter), darum als
# Literal-Menge hier. Die autoritative str -> Enum-Hebung + der LatencyThreshold-Bau
# machen ``CreateLoggingTask`` (application); diese Menge ist nur die Frueh-Validierung
# am Rand (422 statt 500), exakt wie _CAPTURE_MODES/_OPERATION_MODES.
_THRESHOLD_CONDITIONS = frozenset({"latency_above", "unreachable"})


class ThresholdBody(BaseModel):
    """Verschachteltes Schwellwert-Objekt im CreateLoggingTaskBody (Schnitt 4).

    Spiegelt die ``LatencyThreshold``-Domaenenfelder als Wire-Form. ``condition`` ist
    ein roher ``str`` ("latency_above"/"unreachable") -- die str -> ``ThresholdCondition``-
    Hebung macht der Use-Case (Muster ``capture_mode``), der Router validiert nur das
    Vokabular gegen ``_THRESHOLD_CONDITIONS`` (422). Die uebrigen Felder tragen die
    Domaenen-Defaults (``consecutive_n=3``, ``notify_desktop=True``, ``notify_email=False``).
    """

    condition: str
    limit_ms: float = 0.0
    consecutive_n: int = 3
    notify_desktop: bool = True
    notify_email: bool = False


class CreateLoggingTaskBody(BaseModel):
    """POST /api/monitor/logging -- Anlage einer Logging-Aufgabe.

    ``target_id``/``label``/``purpose``/``capture_mode``/``operation_mode`` sind
    Pflicht (kein sinnvoller Default). Die Zeitfenster-Felder sind optional und
    modus-abhaengig: ``SCHEDULED`` braucht ``planned_start`` + ``planned_end``,
    ``IMMEDIATE`` braucht ``max_duration_s`` -- die Konsistenz prueft der Endpunkt
    (422 bei Verstoss), nicht das Modell (Pydantic kann die Kreuz-Bedingung nicht
    ausdruecken, ohne sie zu verstecken). ``id``/``created_at`` setzt der Router
    (uuid4/time.time()), nicht der Client.

    RECURRING braucht ``recur_start_minute`` + ``recur_end_minute`` (Tagesfenster);
    ``recur_weekdays`` leer = alle Tage; ``recur_from``/``recur_until`` optional
    (Gesamtzeitraum, ``recur_until`` None = unbegrenzt).
    """

    target_id: str
    label: str
    purpose: str
    capture_mode: str
    operation_mode: str
    planned_start: float | None = None
    planned_end: float | None = None
    max_duration_s: int | None = None
    # Mess-Intervall in Sekunden (C-2): optional. ``None`` = nicht gesetzt -> der
    # Use-Case-Default (5) greift; ein gesetzter Wert muss eine der erlaubten Stufen
    # sein (_validate_logging_modes, 422). NUR der Erweitert-Modus der Maske sendet es.
    interval_s: int | None = None
    # Optionaler Schwellwert-Alarm der Aufgabe (Schnitt 4): ``None`` = kein Schwellwert.
    # NUR der Erweitert-Modus der Maske sendet ihn; der Use-Case baut daraus den
    # ``LatencyThreshold`` (str -> Enum-Hebung), der Router validiert nur die rohen Werte.
    threshold: ThresholdBody | None = None
    # Wiederkehrendes Tagesfenster (3b) -- nur fuer ``operation_mode == "recurring"``
    # relevant, sonst ungenutzt. ``recur_start_minute``/``recur_end_minute`` sind
    # Minuten seit Mitternacht (0..1440); ``recur_weekdays`` leer = alle Tage (0=Mo..6=So);
    # ``recur_from``/``recur_until`` sind Unix-ts (Gesamtzeitraum), ``recur_until`` None =
    # unbegrenzt. Die Modus-/Feld-Konsistenz prueft ``_validate_logging_modes`` (422).
    recur_start_minute: int | None = None
    recur_end_minute: int | None = None
    recur_weekdays: list[int] = []
    recur_from: float | None = None
    recur_until: float | None = None


class AddTargetBody(BaseModel):
    """POST /api/monitor/targets -- ein benutzerdefiniertes Monitor-Target.

    ``id``/``label``/``host`` sind Pflicht (kein sinnvoller Default -- der Altcode
    griff direkt ``payload["id"]`` etc.); ``interface``/``enabled`` haben die
    Altcode-Defaults (``""`` / ``True``).
    """

    id: str
    label: str
    host: str
    interface: str = ""
    enabled: bool = True


# Liefert die label-angereicherte Status-Map ``{tid: {"alive", "label"}}``. Die
# Anreicherung (RunMonitor.current_status() + MonitorTargetSource) macht der
# Composition Root; der Router kennt nur diesen Callable (kein Port-/infra-Import).
type MonitorStatusProvider = Callable[[], dict[str, dict[str, Any]]]


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit den
# echten Use-Cases verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler.
def provide_monitor_status() -> MonitorStatusProvider:
    raise NotImplementedError("MonitorStatusProvider wird in app.py verdrahtet")


def provide_get_monitor_events() -> GetMonitorEvents:
    raise NotImplementedError("GetMonitorEvents wird in app.py verdrahtet")


def provide_get_rtt_history() -> GetRttHistory:
    raise NotImplementedError("GetRttHistory wird in app.py verdrahtet")


def provide_get_all_sla_stats() -> GetAllSlaStats:
    raise NotImplementedError("GetAllSlaStats wird in app.py verdrahtet")


def provide_get_sla_stats() -> GetSlaStats:
    raise NotImplementedError("GetSlaStats wird in app.py verdrahtet")


def provide_get_schedules() -> GetSchedules:
    raise NotImplementedError("GetSchedules wird in app.py verdrahtet")


def provide_manage_schedules() -> ManageSchedules:
    raise NotImplementedError("ManageSchedules wird in app.py verdrahtet")


def provide_update_schedule() -> UpdateSchedule:
    raise NotImplementedError("UpdateSchedule wird in app.py verdrahtet")


def provide_add_monitor_target() -> AddMonitorTarget:
    raise NotImplementedError("AddMonitorTarget wird in app.py verdrahtet")


def provide_delete_monitor_target() -> DeleteMonitorTarget:
    raise NotImplementedError("DeleteMonitorTarget wird in app.py verdrahtet")


def provide_create_logging_task() -> CreateLoggingTask:
    raise NotImplementedError("CreateLoggingTask wird in app.py verdrahtet")


def provide_list_logging_tasks() -> ListLoggingTasks:
    raise NotImplementedError("ListLoggingTasks wird in app.py verdrahtet")


def provide_get_logging_task_detail() -> GetLoggingTaskDetail:
    raise NotImplementedError("GetLoggingTaskDetail wird in app.py verdrahtet")


def provide_start_logging_task() -> StartLoggingTask:
    raise NotImplementedError("StartLoggingTask wird in app.py verdrahtet")


def provide_pause_logging_task() -> PauseLoggingTask:
    raise NotImplementedError("PauseLoggingTask wird in app.py verdrahtet")


def provide_resume_logging_task() -> ResumeLoggingTask:
    raise NotImplementedError("ResumeLoggingTask wird in app.py verdrahtet")


def provide_stop_logging_task() -> StopLoggingTask:
    raise NotImplementedError("StopLoggingTask wird in app.py verdrahtet")


def provide_delete_logging_task() -> DeleteLoggingTask:
    raise NotImplementedError("DeleteLoggingTask wird in app.py verdrahtet")


def provide_check_log_volume() -> CheckLogVolume:
    raise NotImplementedError("CheckLogVolume wird in app.py verdrahtet")


def provide_get_logging_task_sla() -> GetLoggingTaskSla:
    raise NotImplementedError("GetLoggingTaskSla wird in app.py verdrahtet")


def provide_get_logging_task_events() -> GetLoggingTaskEvents:
    raise NotImplementedError("GetLoggingTaskEvents wird in app.py verdrahtet")


def provide_get_logging_task_rtt() -> GetLoggingTaskRtt:
    raise NotImplementedError("GetLoggingTaskRtt wird in app.py verdrahtet")


# ── Serialisierungs-Helfer (Domaenen-Objekt -> Wire-dict am api-Rand) ─────────


def _event_to_dict(event: Any) -> dict[str, Any]:
    """``MonitorEvent`` -> Wire-dict. ``ts`` roh, ``datetime`` hier formatiert.

    ``event.event`` ist ein ``MonitorEventType``-StrEnum -- ``str(...)`` ergibt den
    Altcode-String ("up"/"down"/"degraded"). KEIN ``id`` (s. Modul-Docstring).
    """
    return {
        "target_id": event.target_id,
        "label": event.label,
        "event": str(event.event),
        "rtt_ms": event.rtt_ms,
        "ts": event.timestamp,
        "datetime": datetime.fromtimestamp(event.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
    }


def _rtt_to_dict(sample: Any) -> dict[str, Any]:
    """``PingSample`` -> Wire-dict ``{rtt_ms, loss_pct, ts}`` (``ts`` aus timestamp)."""
    return {"rtt_ms": sample.rtt_ms, "loss_pct": sample.loss_pct, "ts": sample.timestamp}


def _logging_event_to_dict(row: Any) -> dict[str, Any]:
    """``LoggingEventRow`` -> Wire-dict ``{event_type, rtt_ms, ts}`` (Felder roh durchgereicht).

    Schlanke Inline-Projektion (Muster ``_rtt_to_dict``): ``LoggingEventRow`` traegt
    bereits einen rohen ``event_type``-``str`` (kein StrEnum -- der Logging-Kern ist vom
    Live-Monitor getrennt), ``rtt_ms`` (Sentinel ``-1.0`` erlaubt) und ``ts`` (Unix-ts) --
    keine Formatierung/Hebung noetig.
    """
    return {"event_type": row.event_type, "rtt_ms": row.rtt_ms, "ts": row.ts}


def _logging_task_to_dict(task: Any) -> dict[str, Any]:
    """``LoggingTask`` -> Wire-dict. Die StrEnums (``capture_mode``/``operation_mode``/
    ``state``) als ihr ``str``-Wert (``str(...)`` ergibt den Vokabular-String); die
    Zeitfelder roh durchgereicht (Unix-ts bzw. ``None``).
    """
    return {
        "id": task.id,
        "target_id": task.target_id,
        "label": task.label,
        "purpose": task.purpose,
        "capture_mode": str(task.capture_mode),
        "operation_mode": str(task.operation_mode),
        "state": str(task.state),
        "planned_start": task.planned_start,
        "planned_end": task.planned_end,
        "max_duration_s": task.max_duration_s,
        "created_at": task.created_at,
        # effective_start (ADR 0033): der Bezugs-ts der IMMEDIATE-Restzeit. B-II
        # fuehrte das Feld in Domaene + Persistenz ein, liess es aber aus der
        # Wire-Form -- das Frontend (Schnitt C, Restzeit-Logik) braucht es. None
        # bis zum ersten Start nach ACTIVE, wieder None nach FINISHED.
        "effective_start": task.effective_start,
        # Mess-Intervall in Sekunden (C-2). Immer gesetzt (Domaenen-Default 5) -- das
        # Frontend zeigt es in der Karten-Meta bei REACHABILITY_LATENCY ("alle 30 s").
        "interval_s": task.interval_s,
        # Schwellwert-Alarm (Schnitt 4): verschachteltes dict oder ``null``, wenn kein
        # Schwellwert konfiguriert ist. ``condition`` als StrEnum-Wert (``str(...)``),
        # die bools als echte Wire-bools (nicht 0/1).
        "threshold": _threshold_to_dict(task.threshold),
        # RECURRING-Tagesfenster (3b): roh durchgereicht (Unix-ts/Minuten bzw. ``None``),
        # damit die Karte die Wiederkehr-Meta zeigen kann. ``recur_weekdays`` als sortierte
        # Liste (das frozenset waere nicht JSON-serialisierbar, Muster ScheduledJobOut).
        # NUR bei operation_mode "recurring" fachlich relevant; sonst tragen die Felder die
        # Domaenen-Leerwerte (None / leere Liste).
        "recur_start_minute": task.recur_start_minute,
        "recur_end_minute": task.recur_end_minute,
        "recur_weekdays": sorted(task.recur_weekdays),
        "recur_from": task.recur_from,
        "recur_until": task.recur_until,
    }


def _threshold_to_dict(threshold: Any) -> dict[str, Any] | None:
    """``LatencyThreshold`` -> Wire-dict, oder ``None`` wenn kein Schwellwert gesetzt.

    ``condition`` als ``str``-Wert (StrEnum), die uebrigen Felder roh durchgereicht
    (``limit_ms`` float, ``consecutive_n`` int, die notify-Flags als echte bools).
    """
    if threshold is None:
        return None
    return {
        "condition": str(threshold.condition),
        "limit_ms": threshold.limit_ms,
        "consecutive_n": threshold.consecutive_n,
        "notify_desktop": threshold.notify_desktop,
        "notify_email": threshold.notify_email,
    }


def _series_analysis_to_dict(analysis: SeriesAnalysis) -> dict[str, Any]:
    """``SeriesAnalysis`` -> Wire-dict der Serien-Auswertung (Block 3c, Etappe 2).

    Projiziert das Gesamtergebnis je verschachtelten Datentraeger (Muster
    ``_logging_event_to_dict``: der Use-Case/die Aggregation liefert die Domaenen-Daten,
    dieser Rand baut die Wire-Form). Alle Felder ROH durchgereicht -- ``None`` bleibt
    ``None`` (z. B. offener Outage ``end_ts``, un-angereicherte ``minute_of_day``/``day_key``,
    ``worst_slot_minute``), keine Rundung (das macht das Frontend).
    """
    metrics = analysis.metrics
    return {
        "has_latency": analysis.has_latency,
        "metrics": {
            "availability_pct": metrics.availability_pct,
            "outage_count": metrics.outage_count,
            "avg_outage_s": metrics.avg_outage_s,
            "worst_slot_minute": metrics.worst_slot_minute,
        },
        "outages": [
            {
                "start_ts": outage.start_ts,
                "end_ts": outage.end_ts,
                "duration_s": outage.duration_s,
                "minute_of_day": outage.minute_of_day,
                "day_key": outage.day_key,
            }
            for outage in analysis.outages
        ],
        "heatmap": [
            {"minute_of_day": slot.minute_of_day, "outage_count": slot.outage_count}
            for slot in analysis.heatmap
        ],
        "ranking": [
            {
                "minute_of_day": entry.minute_of_day,
                "day_count": entry.day_count,
                "longest_outage_s": entry.longest_outage_s,
            }
            for entry in analysis.ranking
        ],
        # Latenz-Spitzen je Tageszeit-Slot (zweite Achse). Alle Werte ROH (keine
        # Rundung -- das macht das Frontend). Leer, wenn keine gueltigen Samples vorliegen.
        "latency_slots": [
            {
                "minute_of_day": slot.minute_of_day,
                "sample_count": slot.sample_count,
                "p95_rtt_ms": slot.p95_rtt_ms,
                "max_rtt_ms": slot.max_rtt_ms,
            }
            for slot in analysis.latency_slots
        ],
    }


# ── monitor ───────────────────────────────────────────────────────────────


@router.get("/monitor/status")
def monitor_status(
    status_provider: Annotated[MonitorStatusProvider, Depends(provide_monitor_status)],
) -> dict[str, dict[str, Any]]:
    """In-Memory-Status aller Targets als ``{tid: {alive, label}}`` (label-angereichert)."""
    return status_provider()


@router.get("/monitor/events")
def monitor_events(
    get_monitor_events: Annotated[GetMonitorEvents, Depends(provide_get_monitor_events)],
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    """Letzte Uebergangs-Ereignisse ueber alle Targets, neueste zuerst."""
    return [_event_to_dict(e) for e in get_monitor_events(limit)]


@router.get("/monitor/rtt/{target_id}")
def monitor_rtt(
    target_id: str,
    get_rtt_history: Annotated[GetRttHistory, Depends(provide_get_rtt_history)],
    limit: int = Query(default=120, ge=1, le=1000),
) -> list[dict[str, Any]]:
    """RTT-Verlauf eines Targets, chronologisch (aelteste zuerst)."""
    return [_rtt_to_dict(s) for s in get_rtt_history(target_id, limit)]


# ── sla ─────────────────────────────────────────────────────────────────────


@router.get("/sla")
def sla_all(
    get_all_sla_stats: Annotated[GetAllSlaStats, Depends(provide_get_all_sla_stats)],
    days: int = Query(default=30, ge=1, le=90),
) -> list[dict[str, Any]]:
    """SLA-Statistik aller getrackten Targets. Leere sla_samples-Tabelle -> ``[]``."""
    return get_all_sla_stats(days)


@router.get("/sla/{target_id}")
def sla_target(
    target_id: str,
    get_sla_stats: Annotated[GetSlaStats, Depends(provide_get_sla_stats)],
    days: int = Query(default=30, ge=1, le=90),
) -> dict[str, Any]:
    """SLA-Statistik eines Targets (Null-Stats bei fehlenden Samples)."""
    return get_sla_stats(target_id, days)


# ── schedules ─────────────────────────────────────────────────────────────


@router.get("/schedules")
def get_schedules(
    list_schedules: Annotated[GetSchedules, Depends(provide_get_schedules)],
) -> list[dict[str, Any]]:
    """Alle scan_schedules als rohe 9-Spalten-Zeilen, nach id sortiert."""
    return list_schedules()


@router.post("/schedules")
def add_schedule(
    manage_schedules: Annotated[ManageSchedules, Depends(provide_manage_schedules)],
    body: AddScheduleBody,
) -> dict[str, Any]:
    """Legt ein Schedule an. Body-Felder optional mit Altcode-Defaults -> ``{ok, id}``.

    Der ``ScanTriggerCallback`` fuer die Job-Registrierung ist in der ManageSchedules-
    Verdrahtung gebunden (Composition Root) -- der Router reicht nur die Body-Felder
    durch (``add`` hat seit M.9 KEIN callback-Argument mehr).
    """
    schedule_id = manage_schedules.add(
        name=body.name,
        cidr=body.cidr,
        profile_id=body.profile_id,
        schedule=body.schedule,
    )
    return {"ok": True, "id": schedule_id}


@router.patch("/schedules/{schedule_id}")
def patch_schedule(
    schedule_id: int,
    update: Annotated[UpdateSchedule, Depends(provide_update_schedule)],
    body: PatchScheduleBody,
) -> dict[str, bool]:
    """Aktualisiert ``enabled``/``name`` eines Schedules (``None`` = unveraendert)."""
    update(schedule_id, enabled=body.enabled, name=body.name)
    return {"ok": True}


@router.delete("/schedules/{schedule_id}")
def remove_schedule(
    schedule_id: int,
    manage_schedules: Annotated[ManageSchedules, Depends(provide_manage_schedules)],
) -> dict[str, bool]:
    """Loescht ein Schedule (Zeile + Job). Idempotent bei fehlender id."""
    manage_schedules.delete(schedule_id)
    return {"ok": True}


# ── targets (Schreibpfad, M.9-Nachzuegler) ──────────────────────────────────
# POST/DELETE auf die benutzerdefinierten Monitor-Targets. KEINE ``configure``-
# Folge wie im Altcode (main.py:385-408): der RunMonitor laedt pro tick frisch via
# MonitorTargetSource.load(), also wirkt ein hier geschriebenes Target bei der
# naechsten Loop-Iteration automatisch (Live-Reload).


@router.post("/monitor/targets")
def add_monitor_target(
    add_target: Annotated[AddMonitorTarget, Depends(provide_add_monitor_target)],
    body: AddTargetBody,
) -> dict[str, bool]:
    """Fuegt ein benutzerdefiniertes Monitor-Target hinzu -> ``{ok: True}``."""
    add_target(
        target_id=body.id,
        label=body.label,
        host=body.host,
        interface=body.interface,
        enabled=body.enabled,
    )
    return {"ok": True}


@router.delete("/monitor/targets/{target_id}")
def remove_monitor_target(
    target_id: str,
    delete_target: Annotated[DeleteMonitorTarget, Depends(provide_delete_monitor_target)],
) -> dict[str, bool]:
    """Entfernt ein benutzerdefiniertes Monitor-Target nach id. Idempotent -> ``{ok: True}``."""
    delete_target(target_id)
    return {"ok": True}


# ── monitor/logging (Logging-Aufgaben-Lifecycle, B-I Schritt 3) ─────────────
# Steuert die Task-DEFINITIONEN (Anlegen + Lebenszyklus) + liest den Mengen-Befund.
# GETRENNT vom Live-Monitor (status/events/rtt oben). Der Router erzeugt ``id`` (uuid4)
# und ``created_at``/``now`` (time.time()) -- die Use-Cases bleiben uhr-/id-frei. Die
# Lifecycle-Fehler werden HIER auf Statuscodes gemappt: ``LoggingTaskNotFound`` -> 404,
# ``LoggingTaskConflict`` -> 409 (mit Konzept-Meldung aus Ziel + laufender Task),
# ``InvalidTaskTransition`` -> 409.


def _validate_logging_modes(body: CreateLoggingTaskBody) -> None:
    """Prueft Modus-Vokabular + Modus/Feld-Konsistenz (422 bei Verstoss, keine stille Annahme).

    ``capture_mode``/``operation_mode`` muessen zum Vokabular gehoeren; ``SCHEDULED``
    braucht ``planned_start`` + ``planned_end``, ``IMMEDIATE`` braucht
    ``max_duration_s``. Jeder Verstoss -> 422 (kein stiller Fallback, Finding S3).
    """
    if body.capture_mode not in _CAPTURE_MODES:
        raise HTTPException(
            422,
            detail=f"Unbekannter capture_mode {body.capture_mode!r}",
        )
    if body.operation_mode not in _OPERATION_MODES:
        raise HTTPException(
            422,
            detail=f"Unbekannter operation_mode {body.operation_mode!r}",
        )
    if body.operation_mode == "scheduled" and (
        body.planned_start is None or body.planned_end is None
    ):
        raise HTTPException(
            422,
            detail="operation_mode 'scheduled' braucht planned_start und planned_end",
        )
    if body.operation_mode == "immediate" and body.max_duration_s is None:
        raise HTTPException(
            422,
            detail="operation_mode 'immediate' braucht max_duration_s",
        )
    # RECURRING (3b): braucht ein Tagesfenster (beide Minuten-Grenzen) -- kein stiller
    # Fallback (Finding S3). Zusaetzlich: end > start (halb-offenes Fenster) und beide
    # Grenzen im Tagesbereich 0..1440 (Minuten seit Mitternacht).
    if body.operation_mode == "recurring":
        if body.recur_start_minute is None or body.recur_end_minute is None:
            raise HTTPException(
                422,
                detail="operation_mode 'recurring' braucht recur_start_minute und recur_end_minute",
            )
        if body.recur_end_minute <= body.recur_start_minute:
            raise HTTPException(
                422,
                detail="recur_end_minute muss groesser als recur_start_minute sein",
            )
        if not (0 <= body.recur_start_minute <= 1440) or not (0 <= body.recur_end_minute <= 1440):
            raise HTTPException(
                422,
                detail="recur_start_minute und recur_end_minute muessen im Bereich 0..1440 liegen",
            )
    # Mess-Intervall (C-2): wenn gesetzt, muss es eine der erlaubten Stufen sein --
    # sonst 422 (kein stiller Fallback, Finding S3). ``None`` ist erlaubt (= nicht
    # gesetzt -> Use-Case-Default 5).
    if body.interval_s is not None and body.interval_s not in _INTERVAL_STUFEN:
        raise HTTPException(
            422,
            detail=f"interval_s {body.interval_s!r} ist keine erlaubte Stufe "
            f"{sorted(_INTERVAL_STUFEN)}",
        )
    # Schwellwert (Schnitt 4): nur pruefen, wenn der Client einen gesendet hat.
    if body.threshold is not None:
        _validate_threshold(body.threshold)


def _validate_threshold(threshold: ThresholdBody) -> None:
    """Prueft die rohen Schwellwert-Werte am Router-Rand (422 bei Verstoss, kein 500/Drift).

    Reine Wert-Validierung des Wire-Objekts (Stil wie die interval_s-Pruefung): das
    ``condition``-Vokabular gegen ``_THRESHOLD_CONDITIONS``, ``consecutive_n >= 1``
    (Hysterese braucht mindestens eine Messung), ``limit_ms >= 0`` (kein negativer
    Grenzwert). Die autoritative str -> ``ThresholdCondition``-Hebung + der
    ``LatencyThreshold``-Bau passieren NICHT hier, sondern im Use-Case (Muster
    ``capture_mode``); diese Pruefung ist nur die Frueh-Validierung (422 statt 500).
    """
    if threshold.condition not in _THRESHOLD_CONDITIONS:
        raise HTTPException(
            422,
            detail=f"Unbekannte threshold.condition {threshold.condition!r} "
            f"(erlaubt: {sorted(_THRESHOLD_CONDITIONS)})",
        )
    if threshold.consecutive_n < 1:
        raise HTTPException(
            422,
            detail="threshold.consecutive_n muss >= 1 sein",
        )
    if threshold.limit_ms < 0:
        raise HTTPException(
            422,
            detail="threshold.limit_ms muss >= 0 sein",
        )


@router.post("/monitor/logging", status_code=status.HTTP_201_CREATED)
def create_logging_task(
    create_task: Annotated[CreateLoggingTask, Depends(provide_create_logging_task)],
    body: CreateLoggingTaskBody,
) -> dict[str, Any]:
    """Legt eine Logging-Aufgabe an (Zustand CREATED) -> 201 mit der Wire-Form.

    Der Router erzeugt ``id`` (uuid4-hex) + ``created_at`` (time.time()); die Modus-/
    Feld-Konsistenz prueft ``_validate_logging_modes`` (422 bei Verstoss).
    """
    _validate_logging_modes(body)
    # Schwellwert (Schnitt 4): die ROHEN Wire-Felder durchreichen -- der Use-Case hebt
    # ``condition`` zu ``ThresholdCondition`` und baut den ``LatencyThreshold`` (Muster
    # ``capture_mode``; der api-Ring importiert KEINE Domaenen-Typen). ``threshold_condition``
    # ist das EINE "kein Schwellwert"-Signal: bei ``None`` baut der Use-Case keinen
    # Threshold (Default ``threshold=None``) und ignoriert die uebrigen threshold-Felder.
    threshold_condition = body.threshold.condition if body.threshold is not None else None

    # interval_s (C-2): nur durchreichen, wenn der Client es gesetzt hat -- sonst greift
    # der Use-Case-/Domaenen-Default (5). So bleibt der Default an EINER Stelle (Domaene),
    # der Router setzt keine eigene 5. Seit den ``recur_*``-Parametern (3b) ist ``interval_s``
    # NICHT mehr das letzte Keyword-Argument; ein ``**dict[str, int]``-Unpack liesse sich
    # gegen die gemischt typisierten Folgeparameter (``recur_weekdays: frozenset[int]``) nicht
    # mehr typsicher unpacken. Darum die beiden Pfade explizit (Muster threshold-Durchreichung):
    # mit gesetztem ``interval_s`` ODER ganz ohne (dann greift der Domaenen-Default).
    common_kwargs: dict[str, Any] = {
        "task_id": uuid.uuid4().hex,
        "target_id": body.target_id,
        "label": body.label,
        "purpose": body.purpose,
        "capture_mode": body.capture_mode,
        "operation_mode": body.operation_mode,
        "created_at": time.time(),
        "planned_start": body.planned_start,
        "planned_end": body.planned_end,
        "max_duration_s": body.max_duration_s,
        "threshold_condition": threshold_condition,
        "threshold_limit_ms": body.threshold.limit_ms if body.threshold is not None else 0.0,
        "threshold_consecutive_n": (
            body.threshold.consecutive_n if body.threshold is not None else 3
        ),
        "threshold_notify_desktop": (
            body.threshold.notify_desktop if body.threshold is not None else True
        ),
        "threshold_notify_email": (
            body.threshold.notify_email if body.threshold is not None else False
        ),
        # RECURRING-Tagesfenster (3b): roh durchgereicht (Muster planned_start etc.); die
        # Modus-Konsistenz prueft ``_validate_logging_modes``, der Use-Case hebt nichts.
        # ``recur_weekdays`` als ``frozenset`` (Domaenen-Form ``LoggingTask.recur_weekdays``).
        "recur_start_minute": body.recur_start_minute,
        "recur_end_minute": body.recur_end_minute,
        "recur_weekdays": frozenset(body.recur_weekdays),
        "recur_from": body.recur_from,
        "recur_until": body.recur_until,
    }
    if body.interval_s is not None:
        task = create_task(interval_s=body.interval_s, **common_kwargs)
    else:
        task = create_task(**common_kwargs)
    return _logging_task_to_dict(task)


@router.get("/monitor/logging")
def list_logging_tasks(
    list_tasks: Annotated[ListLoggingTasks, Depends(provide_list_logging_tasks)],
) -> list[dict[str, Any]]:
    """Alle Logging-Aufgaben-Definitionen als Wire-Form. Leer -> ``[]``."""
    return [_logging_task_to_dict(t) for t in list_tasks()]


@router.get("/monitor/logging/volume")
def logging_volume(
    check_volume: Annotated[CheckLogVolume, Depends(provide_check_log_volume)],
) -> dict[str, Any]:
    """Mengen-Befund der Logging-RTT-Messdaten -> ``{count, over_threshold}``."""
    result = check_volume()
    return {"count": result.count, "over_threshold": result.over_threshold}


@router.get("/monitor/logging/{task_id}")
def get_logging_task(
    task_id: str,
    get_detail: Annotated[GetLoggingTaskDetail, Depends(provide_get_logging_task_detail)],
) -> dict[str, Any]:
    """EINE Logging-Aufgaben-Definition. 404 bei unbekannter id."""
    try:
        task = get_detail(task_id)
    except LoggingTaskNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return _logging_task_to_dict(task)


@router.get("/monitor/logging/{task_id}/sla")
def logging_task_sla(
    task_id: str,
    get_sla: Annotated[GetLoggingTaskSla, Depends(provide_get_logging_task_sla)],
    since: Annotated[float | None, Query()] = None,
    until: Annotated[float | None, Query()] = None,
) -> dict[str, Any]:
    """SLA-Kennzahlen EINER Logging-Aufgabe (uptime/avg-RTT/ca.-Downtime). 404 bei unbekannter id.

    Reicht das stats-dict durch (``uptime_pct`` kann ``None`` sein -> as-is; das
    Frontend zeigt dann "noch keine Auswertung"). EIGENER Logging-SLA-Pfad neben
    ``/api/sla/{id}`` -- der bleibt unberuehrt.

    ``since``/``until`` sind OPTIONALE Query-Floats (Unix-ts), Default ``None`` (offener
    Zeitraum = der gesamte Task) -- EXAKT das Muster des Export-Endpunkts
    ``/api/export/logging`` (``Annotated[float | None, Query()] = None``). Sie werden als
    kwargs durchgereicht; der Use-Case waehlt ``all_for`` (beide ``None``) bzw. den
    ``range``-Ausschnitt (mind. eine Grenze gesetzt). ``days`` bleibt sein Default.
    """
    try:
        return get_sla(task_id, since=since, until=until)
    except LoggingTaskNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/monitor/logging/{task_id}/events")
def logging_task_events(
    task_id: str,
    get_events: Annotated[GetLoggingTaskEvents, Depends(provide_get_logging_task_events)],
    since: Annotated[float | None, Query()] = None,
    until: Annotated[float | None, Query()] = None,
) -> list[dict[str, Any]]:
    """Ereignis-/Anomalie-Flanken EINER Logging-Aufgabe als Liste. 404 bei unbekannter id.

    Speist die Event-Liste der Detailansicht. Signatur exakt wie ``logging_task_sla``:
    ``since``/``until`` sind OPTIONALE Query-Floats (Unix-ts), Default ``None`` (offener
    Zeitraum = alle Flanken des Tasks). Der Use-Case gibt rohe ``LoggingEventRow``-Objekte,
    dieser Rand projiziert je Zeile in das Wire-dict ``{event_type, rtt_ms, ts}`` (Muster
    ``monitor_events``: der Use-Case liefert Domaenen-Daten, der Router die Wire-Form).
    Keine Flanken -> ``[]``.
    """
    try:
        rows = get_events(task_id, since=since, until=until)
    except LoggingTaskNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return [_logging_event_to_dict(row) for row in rows]


def _enrich_outages_local(outages: list[OutageInterval]) -> list[OutageInterval]:
    """Setzt je Outage ``minute_of_day`` + ``day_key`` aus ``start_ts`` in LOKALER Zeit.

    Die Aggregation (``series_analysis``) rechnet bewusst KEINE Wanduhr (zeitfrei, ADR
    0002) -- die Umrechnung Unix-ts -> Tagesfenster-Minute/lokales Datum gehoert an den
    Router-Rand, der die Server-Zeitzone nutzen DARF. ``datetime.fromtimestamp`` ohne
    ``tz`` ist die lokale Zeit. ``minute_of_day`` = lokale Stunde*60 + Minute (0..1439),
    ``day_key`` = ISO-Datum ``yyyy-mm-dd``. ``OutageInterval`` ist frozen -> neue
    Instanzen ueber ``dataclasses.replace`` (die uebrigen Felder bleiben unveraendert).
    """
    enriched: list[OutageInterval] = []
    for outage in outages:
        local = datetime.fromtimestamp(outage.start_ts)
        enriched.append(
            replace(
                outage,
                minute_of_day=local.hour * 60 + local.minute,
                day_key=local.date().isoformat(),
            )
        )
    return enriched


def _enrich_rtt_local(rtt: list[Any]) -> list[EnrichedRttSample]:
    """Reichert je RTT-Sample die lokale ``minute_of_day`` aus ``ts`` an (Latenz-Achse).

    Zwillings-Naht zu ``_enrich_outages_local``: die Aggregation (``series_analysis``)
    rechnet bewusst KEINE Wanduhr (zeitfrei, ADR 0002) -- die Umrechnung Unix-``ts`` ->
    Tagesfenster-Minute gehoert an den Router-Rand, der die Server-Zeitzone nutzen DARF.
    ``datetime.fromtimestamp`` ohne ``tz`` ist die lokale Zeit; ``minute_of_day`` =
    lokale Stunde*60 + Minute (0..1439). ``rtt_ms``/``alive`` werden roh durchgereicht
    (Sentinel ``-1.0`` bleibt erhalten) -- die Gueltigkeitspruefung macht
    ``build_latency_slots``. Die Samples kommen als rohe Domaenen-Objekte herein (Typ
    ``Any``, wie ``_rtt_to_dict`` -- der api-Ring importiert keine ``domain``-Typen).
    """
    enriched: list[EnrichedRttSample] = []
    for sample in rtt:
        local = datetime.fromtimestamp(sample.ts)
        enriched.append(
            EnrichedRttSample(
                rtt_ms=sample.rtt_ms,
                alive=sample.alive,
                minute_of_day=local.hour * 60 + local.minute,
            )
        )
    return enriched


@router.get("/monitor/logging/{task_id}/series")
def logging_task_series(
    task_id: str,
    get_detail: Annotated[GetLoggingTaskDetail, Depends(provide_get_logging_task_detail)],
    get_events: Annotated[GetLoggingTaskEvents, Depends(provide_get_logging_task_events)],
    get_rtt: Annotated[GetLoggingTaskRtt, Depends(provide_get_logging_task_rtt)],
    since: Annotated[float | None, Query()] = None,
    until: Annotated[float | None, Query()] = None,
    slot_minutes: Annotated[int, Query(ge=1, le=60)] = 10,
) -> dict[str, Any]:
    """Serien-Auswertung EINER Logging-Aufgabe (Block 3c). 404 bei unbekannter id.

    Laedt Task (fuer ``capture_mode`` + 404), Event-Flanken und die dichten RTT-Samples
    (``since``/``until`` analog ``logging_task_events``) und reicht sie in die reine,
    zeitfreie ``analyze_series``. Die lokale Anreicherung der Outages (``minute_of_day``/
    ``day_key`` aus ``start_ts``) gibt der Router ueber ``_enrich_outages_local`` herein
    (die Aggregation rechnet keine Wanduhr). Das Ergebnis projiziert dieser Rand ueber
    ``_series_analysis_to_dict`` in die Wire-Form (Felder roh, keine Rundung).
    """
    try:
        task = get_detail(task_id)
    except LoggingTaskNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    events = get_events(task_id, since=since, until=until)
    rtt = get_rtt(task_id, since=since, until=until)
    # Latenz-Achse: die rohen RTT-Samples lokal anreichern (minute_of_day), damit die
    # zeitfreie Aggregation die Latenz-Spitzen je Tageszeit-Slot bucketet (Naht wie
    # ``_enrich_outages_local`` bei den Outages). Als NEUES letztes Argument durchgereicht.
    enriched_rtt = _enrich_rtt_local(rtt)
    analysis = analyze_series(
        task.capture_mode,
        rtt,
        events,
        slot_minutes,
        _enrich_outages_local,
        enriched_rtt,
    )
    return _series_analysis_to_dict(analysis)


@router.post("/monitor/logging/{task_id}/start")
def start_logging_task(
    task_id: str,
    start_task: Annotated[StartLoggingTask, Depends(provide_start_logging_task)],
) -> dict[str, Any]:
    """Startet eine Aufgabe (CREATED -> ACTIVE). 404/409 bei Fehler.

    ``LoggingTaskConflict`` -> 409 mit der Konzept-Meldung (Ziel + laufende Task);
    ``InvalidTaskTransition`` -> 409 (falscher Ausgangszustand).
    """
    try:
        task = start_task(task_id, now=time.time())
    except LoggingTaskNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (LoggingTaskConflict, InvalidTaskTransition) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _logging_task_to_dict(task)


@router.post("/monitor/logging/{task_id}/pause")
def pause_logging_task(
    task_id: str,
    pause_task: Annotated[PauseLoggingTask, Depends(provide_pause_logging_task)],
) -> dict[str, Any]:
    """Pausiert eine Aufgabe (ACTIVE -> PAUSED). 404/409 (InvalidTaskTransition)."""
    try:
        task = pause_task(task_id)
    except LoggingTaskNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InvalidTaskTransition as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _logging_task_to_dict(task)


@router.post("/monitor/logging/{task_id}/resume")
def resume_logging_task(
    task_id: str,
    resume_task: Annotated[ResumeLoggingTask, Depends(provide_resume_logging_task)],
) -> dict[str, Any]:
    """Setzt eine Aufgabe fort (PAUSED -> ACTIVE). 404/409 (Konflikt/Transition).

    Fortsetzen aus Pause ist im Konzept ein Start (pro Ziel nur einer aktiv) -> ein
    ``LoggingTaskConflict`` ist hier ebenso moeglich wie beim ``start``.
    """
    try:
        task = resume_task(task_id)
    except LoggingTaskNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (LoggingTaskConflict, InvalidTaskTransition) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _logging_task_to_dict(task)


@router.post("/monitor/logging/{task_id}/stop")
def stop_logging_task(
    task_id: str,
    stop_task: Annotated[StopLoggingTask, Depends(provide_stop_logging_task)],
) -> dict[str, Any]:
    """Beendet eine Aufgabe ({ACTIVE,PAUSED} -> FINISHED). 404/409 (InvalidTaskTransition)."""
    try:
        task = stop_task(task_id)
    except LoggingTaskNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InvalidTaskTransition as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _logging_task_to_dict(task)


@router.delete("/monitor/logging/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_logging_task(
    task_id: str,
    delete_task: Annotated[DeleteLoggingTask, Depends(provide_delete_logging_task)],
) -> None:
    """Loescht eine Aufgaben-DEFINITION. Idempotent (unbekannte id ist kein Fehler) -> 204."""
    delete_task(task_id)
