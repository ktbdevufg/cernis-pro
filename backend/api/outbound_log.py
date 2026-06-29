"""FastAPI-Router der Aussenkontakte-Aufzeichnung (E4) -- die REST-Lifecycle-/Lese-Pfade.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich Use-Cases aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter, Ports und
``domain``-Typen werden hier NICHT importiert -- die Use-Cases kommen per
FastAPI-Dependency herein (Verdrahtung im Composition Root ``app.py``), und
Domaenen-Objekte werden ueber Attribut-Zugriff zu JSON serialisiert (Typ ``Any``, exakt
wie der monitoring-Router das haelt).

EIGENER Pfad-Zweig ``/api/outbound/recordings`` -- getrennt vom bestehenden
``/api/outbound/contacts`` (``api/outbound.py``), der die Live-Kontaktsicht liefert. Hier
geht es um die AUFZEICHNUNGS-DEFINITIONEN (Anlegen + Lebenszyklus) und ihren verdichteten
bzw. rohen Lesebefund.

``mode``/``depth`` reicht der Router als ROHE ``str`` durch -- die ``str`` -> Enum-Hebung
passiert NICHT hier, sondern autoritativ im Use-Case (``CreateOutboundRecording``, Muster
``capture_mode`` in ``CreateLoggingTask``); so importiert der api-Ring KEINE
Domaenen-Enums (CI-harter import-linter-Contract). Ein Fehlwert wirft im Use-Case einen
``ValueError`` (StrEnum-Konstruktor / Domaenen-``__post_init__``), den der Create-Endpunkt
auf 422 mappt.

Fehler-Mapping (gespiegelt von den monitoring-Logging-Endpunkten, ``api/monitoring.py``):
``RecordingNotFound`` -> 404, ``RecordingConflict`` -> 409 (mit der ``running_id`` im
Bezug ueber ``str(exc)``), ``InvalidRecordingTransition`` -> 409 (falscher
Ausgangszustand). ``InvalidRecordingTransition`` wird im monitoring-Bestand als
Domaenen-Exception ueber den application-Ring RE-EXPORTIERT und dort DIREKT gefangen
(``api/monitoring.py``: ``from application.monitoring import InvalidTaskTransition`` +
``except (LoggingTaskConflict, InvalidTaskTransition)``) -- exakt diesen Weg spiegeln wir
hier (``from application.outbound_log import InvalidRecordingTransition``), darum bleibt
der import-linter-Contract gewahrt (der Name kommt aus ``application``, nicht aus
``domain``). Zusaetzlich beim Create: ``ValueError`` (Enum-Hebung / Domaenen-Invarianten:
ungueltiger mode/depth/interval_s/DETAIL-Deckel) -> 422.
"""

import time
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from application.outbound_log import (
    CreateOutboundRecording,
    DeleteOutboundRecording,
    EditOutboundRecording,
    GetOutboundAggregate,
    GetOutboundDetailRange,
    GetOutboundRecording,
    InvalidRecordingTransition,
    ListOutboundRecordings,
    PauseOutboundRecording,
    RecordingConfigLocked,
    RecordingConflict,
    RecordingNotFound,
    ResumeOutboundRecording,
    StartOutboundRecording,
    StopOutboundRecording,
)

router = APIRouter(prefix="/api/outbound/recordings", tags=["outbound_log"])


# ── Provider-Marker (im Composition Root ``app.py`` per dependency_overrides ersetzt) ──
# Jeder Marker wirft im ungebundenen Zustand -- keine stillen Fallbacks (Finding S3).


def provide_create_outbound_recording() -> CreateOutboundRecording:
    raise NotImplementedError("CreateOutboundRecording wird in app.py verdrahtet")


def provide_start_outbound_recording() -> StartOutboundRecording:
    raise NotImplementedError("StartOutboundRecording wird in app.py verdrahtet")


def provide_pause_outbound_recording() -> PauseOutboundRecording:
    raise NotImplementedError("PauseOutboundRecording wird in app.py verdrahtet")


def provide_resume_outbound_recording() -> ResumeOutboundRecording:
    raise NotImplementedError("ResumeOutboundRecording wird in app.py verdrahtet")


def provide_stop_outbound_recording() -> StopOutboundRecording:
    raise NotImplementedError("StopOutboundRecording wird in app.py verdrahtet")


def provide_edit_outbound_recording() -> EditOutboundRecording:
    raise NotImplementedError("EditOutboundRecording wird in app.py verdrahtet")


def provide_delete_outbound_recording() -> DeleteOutboundRecording:
    raise NotImplementedError("DeleteOutboundRecording wird in app.py verdrahtet")


def provide_list_outbound_recordings() -> ListOutboundRecordings:
    raise NotImplementedError("ListOutboundRecordings wird in app.py verdrahtet")


def provide_get_outbound_recording() -> GetOutboundRecording:
    raise NotImplementedError("GetOutboundRecording wird in app.py verdrahtet")


def provide_get_outbound_aggregate() -> GetOutboundAggregate:
    raise NotImplementedError("GetOutboundAggregate wird in app.py verdrahtet")


def provide_get_outbound_detail_range() -> GetOutboundDetailRange:
    raise NotImplementedError("GetOutboundDetailRange wird in app.py verdrahtet")


# ── Wire-Modelle (eigene Wire-Form, KEINE application/domain-Typen) ───────────


class CreateRecordingBody(BaseModel):
    """Anlage-Body einer Aufzeichnung. ``mode``/``depth`` als rohe ``str`` (Wire).

    ``mode``/``depth`` reicht der Router roh durch -- die Vokabular-Validierung +
    Enum-Hebung macht der Use-Case (422 bei Fehlwert). ``interval_s`` Default 60
    (Domaenen-Default), ``max_duration_s`` optional (nur DETAIL-relevant; AGGREGATE
    erzwingt der Use-Case ohnehin auf ``None``).
    """

    label: str
    purpose: str = ""
    mode: str
    depth: str
    interval_s: int = 60
    max_duration_s: int | None = None


class EditRecordingBody(BaseModel):
    """Aenderungs-Body einer Aufzeichnung -- gleiche Felder wie ``CreateRecordingBody``.

    ``label``/``purpose`` sind in jedem Zustand aenderbar; die Konfig-Felder
    ``mode``/``depth``/``interval_s``/``max_duration_s`` nur im Zustand CREATED (sonst
    409 via ``RecordingConfigLocked``). ``mode``/``depth`` als rohe ``str`` (Enum-Hebung
    im Use-Case, 422 bei Fehlwert).
    """

    label: str
    purpose: str = ""
    mode: str
    depth: str
    interval_s: int = 60
    max_duration_s: int | None = None


# ── Serialisierungs-Helfer (Domaenen-Objekt -> Wire-dict am api-Rand) ─────────


def _recording_to_dict(rec: Any) -> dict[str, Any]:
    """``OutboundRecording`` -> Wire-dict. Die StrEnums (``mode``/``depth``/``state``)
    als ihr ``str``-Wert (``str(...)`` ergibt den Vokabular-String); die Zeitfelder roh
    durchgereicht (Unix-ts bzw. ``None``).
    """
    return {
        "id": rec.id,
        "label": rec.label,
        "purpose": rec.purpose,
        "mode": str(rec.mode),
        "depth": str(rec.depth),
        "state": str(rec.state),
        "interval_s": rec.interval_s,
        "created_at": rec.created_at,
        "effective_start": rec.effective_start,
        "max_duration_s": rec.max_duration_s,
    }


def _aggregate_to_dict(c: Any) -> dict[str, Any]:
    """``AggregatedContact`` -> Wire-dict. Alle Felder roh durchgereicht (Werte oder ``None``)."""
    return {
        "remote_ip": c.remote_ip,
        "first_seen": c.first_seen,
        "last_seen": c.last_seen,
        "total_count": c.total_count,
        "peak_count": c.peak_count,
        "remote_port": c.remote_port,
        "hostname": c.hostname,
        "country": c.country,
        "operator": c.operator,
        "asn": c.asn,
        "app_name": c.app_name,
    }


def _detail_to_dict(r: Any) -> dict[str, Any]:
    """``OutboundDetailRow`` -> Wire-dict. Alle Felder roh durchgereicht (Werte oder ``None``)."""
    return {
        "ts": r.ts,
        "remote_ip": r.remote_ip,
        "remote_port": r.remote_port,
        "hostname": r.hostname,
        "country": r.country,
        "operator": r.operator,
        "asn": r.asn,
        "app_name": r.app_name,
        "pid": r.pid,
        "connection_count": r.connection_count,
    }


# ── Lifecycle-/Lese-Endpunkte ────────────────────────────────────────────────


@router.post("", status_code=status.HTTP_201_CREATED)
def create_recording(
    body: CreateRecordingBody,
    create_recording_uc: Annotated[
        CreateOutboundRecording, Depends(provide_create_outbound_recording)
    ],
) -> dict[str, Any]:
    """Legt eine Aufzeichnung an (Zustand CREATED) -> 201 mit der Wire-Form.

    Der Router erzeugt ``id`` (uuid4-hex) + ``now`` (time.time()) und reicht ``mode``/
    ``depth`` roh durch; die Enum-Hebung + Wert-Invarianten (interval_s/DETAIL-Deckel)
    pruefen Use-Case/Domaene -- ein ``ValueError`` daraus -> 422 (kein 500/stiller Fallback).
    """
    try:
        rec = create_recording_uc(
            recording_id=uuid.uuid4().hex,
            label=body.label,
            purpose=body.purpose,
            mode=body.mode,
            depth=body.depth,
            interval_s=body.interval_s,
            now=time.time(),
            max_duration_s=body.max_duration_s,
        )
    except ValueError as exc:
        # 422 als nacktes Literal (Bestandsmuster ``api/monitoring.py``); das
        # ``status.HTTP_422_*``-Symbol ist in starlette inzwischen deprecation-markiert.
        raise HTTPException(422, detail=str(exc)) from exc
    return _recording_to_dict(rec)


@router.get("")
def list_recordings(
    list_uc: Annotated[ListOutboundRecordings, Depends(provide_list_outbound_recordings)],
) -> list[dict[str, Any]]:
    """Alle Aufzeichnungs-Definitionen als Wire-Form. Leer -> ``[]``."""
    return [_recording_to_dict(r) for r in list_uc()]


@router.get("/{recording_id}")
def get_recording(
    recording_id: str,
    get_uc: Annotated[GetOutboundRecording, Depends(provide_get_outbound_recording)],
) -> dict[str, Any]:
    """EINE Aufzeichnungs-Definition. 404 bei unbekannter id."""
    try:
        rec = get_uc(recording_id)
    except RecordingNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return _recording_to_dict(rec)


@router.post("/{recording_id}/start")
def start_recording(
    recording_id: str,
    start_uc: Annotated[StartOutboundRecording, Depends(provide_start_outbound_recording)],
) -> dict[str, Any]:
    """Startet eine Aufzeichnung (CREATED -> ACTIVE). 404/409 bei Fehler.

    ``RecordingConflict`` -> 409 (host-weit nur eine aktiv, ``running_id`` im Bezug);
    ``InvalidRecordingTransition`` -> 409 (falscher Ausgangszustand).
    """
    try:
        rec = start_uc(recording_id, time.time())
    except RecordingNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (RecordingConflict, InvalidRecordingTransition) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _recording_to_dict(rec)


@router.post("/{recording_id}/pause")
def pause_recording(
    recording_id: str,
    pause_uc: Annotated[PauseOutboundRecording, Depends(provide_pause_outbound_recording)],
) -> dict[str, Any]:
    """Pausiert eine Aufzeichnung (ACTIVE -> PAUSED). 404/409 (InvalidRecordingTransition)."""
    try:
        rec = pause_uc(recording_id)
    except RecordingNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InvalidRecordingTransition as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _recording_to_dict(rec)


@router.post("/{recording_id}/resume")
def resume_recording(
    recording_id: str,
    resume_uc: Annotated[ResumeOutboundRecording, Depends(provide_resume_outbound_recording)],
) -> dict[str, Any]:
    """Setzt eine Aufzeichnung fort (PAUSED -> ACTIVE). 404/409 (Konflikt/Transition).

    Fortsetzen aus Pause ist im Konzept ein Start (host-weit nur eine aktiv) -> ein
    ``RecordingConflict`` ist hier ebenso moeglich wie beim ``start``.
    """
    try:
        rec = resume_uc(recording_id)
    except RecordingNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (RecordingConflict, InvalidRecordingTransition) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _recording_to_dict(rec)


@router.post("/{recording_id}/stop")
def stop_recording(
    recording_id: str,
    stop_uc: Annotated[StopOutboundRecording, Depends(provide_stop_outbound_recording)],
) -> dict[str, Any]:
    """Beendet eine Aufzeichnung ({ACTIVE,PAUSED} -> FINISHED). 404/409 (Transition)."""
    try:
        rec = stop_uc(recording_id)
    except RecordingNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InvalidRecordingTransition as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _recording_to_dict(rec)


@router.put("/{recording_id}")
def edit_recording(
    recording_id: str,
    body: EditRecordingBody,
    edit_uc: Annotated[EditOutboundRecording, Depends(provide_edit_outbound_recording)],
) -> dict[str, Any]:
    """Aendert eine Aufzeichnungs-DEFINITION. 404/409/422 bei Fehler.

    ``label``/``purpose`` sind in jedem Zustand aenderbar; die vier Konfig-Felder nur im
    Zustand CREATED. ``RecordingNotFound`` -> 404, ``RecordingConfigLocked`` -> 409
    (Konfig-Aenderung ausserhalb CREATED), ``ValueError`` -> 422 (Enum-Hebung /
    Domaenen-Invarianten: ungueltiger mode/depth/interval_s/DETAIL-Deckel).
    """
    try:
        rec = edit_uc(
            recording_id=recording_id,
            label=body.label,
            purpose=body.purpose,
            mode=body.mode,
            depth=body.depth,
            interval_s=body.interval_s,
            max_duration_s=body.max_duration_s,
        )
    except RecordingNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RecordingConfigLocked as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        # 422 als nacktes Literal (Bestandsmuster wie ``create_recording``).
        raise HTTPException(422, detail=str(exc)) from exc
    return _recording_to_dict(rec)


@router.delete("/{recording_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_recording(
    recording_id: str,
    delete_uc: Annotated[DeleteOutboundRecording, Depends(provide_delete_outbound_recording)],
) -> None:
    """Loescht eine Aufzeichnungs-DEFINITION. Idempotent (unbekannte id ist kein Fehler) -> 204."""
    delete_uc(recording_id)


@router.get("/{recording_id}/aggregate")
def get_aggregate(
    recording_id: str,
    get_aggregate_uc: Annotated[GetOutboundAggregate, Depends(provide_get_outbound_aggregate)],
) -> list[dict[str, Any]]:
    """Verdichteter Stand einer Aufzeichnung als Wire-Liste. Leer/unbekannte id -> ``[]``."""
    return [_aggregate_to_dict(c) for c in get_aggregate_uc(recording_id)]


@router.get("/{recording_id}/detail")
def get_detail(
    recording_id: str,
    get_detail_range_uc: Annotated[
        GetOutboundDetailRange, Depends(provide_get_outbound_detail_range)
    ],
    since: Annotated[float, Query()],
    until: Annotated[float, Query()],
) -> list[dict[str, Any]]:
    """Roher DETAIL-Zeitverlauf einer Aufzeichnung im Fenster ``[since, until)`` als Wire-Liste.

    ``since``/``until`` sind ABSOLUTE Query-Floats (Unix-ts) -- der Use-Case haelt keine
    Uhr, das Fenster kommt vom Client. Keine Daten / unbekannte id -> ``[]``.
    """
    return [_detail_to_dict(r) for r in get_detail_range_uc(recording_id, since, until)]
