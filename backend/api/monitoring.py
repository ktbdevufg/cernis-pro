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
    GetAllSlaStats,
    GetLoggingTaskDetail,
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
    PauseLoggingTask,
    ResumeLoggingTask,
    StartLoggingTask,
    StopLoggingTask,
    UpdateSchedule,
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
_OPERATION_MODES = frozenset({"scheduled", "immediate"})

# Erlaubte Mess-Intervall-Stufen in Sekunden (C-2). Wie die Modus-Mengen oben nur die
# Frueh-Validierung am Rand (422 statt 500/stiller Drift); den Default 5 setzt NICHT
# der Router, sondern die Domaene/der Use-Case (interval_s: int = 5) -- der Router
# reicht ``None`` als "nicht gesetzt" durch, dann greift der Use-Case-Default.
_INTERVAL_STUFEN = frozenset({5, 15, 30, 60, 300})


class CreateLoggingTaskBody(BaseModel):
    """POST /api/monitor/logging -- Anlage einer Logging-Aufgabe.

    ``target_id``/``label``/``purpose``/``capture_mode``/``operation_mode`` sind
    Pflicht (kein sinnvoller Default). Die Zeitfenster-Felder sind optional und
    modus-abhaengig: ``SCHEDULED`` braucht ``planned_start`` + ``planned_end``,
    ``IMMEDIATE`` braucht ``max_duration_s`` -- die Konsistenz prueft der Endpunkt
    (422 bei Verstoss), nicht das Modell (Pydantic kann die Kreuz-Bedingung nicht
    ausdruecken, ohne sie zu verstecken). ``id``/``created_at`` setzt der Router
    (uuid4/time.time()), nicht der Client.
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
    # Mess-Intervall (C-2): wenn gesetzt, muss es eine der erlaubten Stufen sein --
    # sonst 422 (kein stiller Fallback, Finding S3). ``None`` ist erlaubt (= nicht
    # gesetzt -> Use-Case-Default 5).
    if body.interval_s is not None and body.interval_s not in _INTERVAL_STUFEN:
        raise HTTPException(
            422,
            detail=f"interval_s {body.interval_s!r} ist keine erlaubte Stufe "
            f"{sorted(_INTERVAL_STUFEN)}",
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
    # interval_s (C-2): nur durchreichen, wenn der Client es gesetzt hat -- sonst greift
    # der Use-Case-/Domaenen-Default (5). So bleibt der Default an EINER Stelle (Domaene),
    # der Router setzt keine eigene 5.
    interval_kwargs: dict[str, int] = (
        {"interval_s": body.interval_s} if body.interval_s is not None else {}
    )
    task = create_task(
        task_id=uuid.uuid4().hex,
        target_id=body.target_id,
        label=body.label,
        purpose=body.purpose,
        capture_mode=body.capture_mode,
        operation_mode=body.operation_mode,
        created_at=time.time(),
        planned_start=body.planned_start,
        planned_end=body.planned_end,
        max_duration_s=body.max_duration_s,
        **interval_kwargs,
    )
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
) -> dict[str, Any]:
    """SLA-Kennzahlen EINER Logging-Aufgabe (uptime/avg-RTT/ca.-Downtime). 404 bei unbekannter id.

    Reicht das stats-dict durch (``uptime_pct`` kann ``None`` sein -> as-is; das
    Frontend zeigt dann "noch keine Auswertung"). EIGENER Logging-SLA-Pfad neben
    ``/api/sla/{id}`` -- der bleibt unberuehrt.
    """
    try:
        return get_sla(task_id)
    except LoggingTaskNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


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
