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

from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from application.monitoring import (
    GetAllSlaStats,
    GetMonitorEvents,
    GetRttHistory,
    GetSchedules,
    GetSlaStats,
    ManageSchedules,
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
