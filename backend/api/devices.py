"""FastAPI-Router der devices-Domaene (v2), prefix ``/api/devices``.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich Use-Cases aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter und
auch ``domain``-Typen werden hier NICHT importiert -- die Use-Cases kommen per
FastAPI-Dependency herein (Verdrahtung im Composition Root ``app.py``), und
Domaenen-Objekte werden ueber Attribut-Zugriff zu JSON serialisiert (Typ ``Any``,
genau wie der settings-Router das haelt).

Serialisierungs-Vertrag fuers Frontend: ``tags``/``open_ports`` als JSON-Listen
(Domaene fuehrt tuples), ``is_known`` als bool, Zeitstempel als ISO-String. Der
``stats``-Zaehler ``active`` heisst im Response ``active_24h`` (kompatibel zum
Altcode-Shape).

HTTP-Mapping: ``DeviceNotFoundError`` (aus application importierbar) -> 404 hier
im Router. Loeschen ist idempotent -> kein 404.
"""

from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from application.devices import (
    AnswerArchivePrompt,
    ArchiveDevice,
    CreateDevice,
    DeleteDevice,
    DeviceAlreadyExistsError,
    DeviceNotFoundError,
    DismissDeviceFromWatch,
    GetArchivedDevices,
    GetDevice,
    GetDevices,
    GetDeviceStats,
    GetUnclassifiedDevices,
    InvalidTrustStateError,
    RecordScannedHost,
    RestoreDevice,
    UpdateDeviceMeta,
)

router = APIRouter(prefix="/api/devices", tags=["devices"])


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit
# echten Adaptern verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler.
def provide_get_device_stats() -> GetDeviceStats:
    raise NotImplementedError("GetDeviceStats wird in app.py verdrahtet")


def provide_get_devices() -> GetDevices:
    raise NotImplementedError("GetDevices wird in app.py verdrahtet")


def provide_get_device() -> GetDevice:
    raise NotImplementedError("GetDevice wird in app.py verdrahtet")


def provide_update_device_meta() -> UpdateDeviceMeta:
    raise NotImplementedError("UpdateDeviceMeta wird in app.py verdrahtet")


def provide_delete_device() -> DeleteDevice:
    raise NotImplementedError("DeleteDevice wird in app.py verdrahtet")


def provide_record_scanned_host() -> RecordScannedHost:
    # Kein Endpunkt in D.6: dieser Use-Case wird in app.py verdrahtet und
    # bereitgestellt, damit die spaeter migrierte scanning-Domaene ihn konsumiert.
    raise NotImplementedError("RecordScannedHost wird in app.py verdrahtet")


def provide_get_unclassified_devices() -> GetUnclassifiedDevices:
    raise NotImplementedError("GetUnclassifiedDevices wird in app.py verdrahtet")


def provide_dismiss_device_from_watch() -> DismissDeviceFromWatch:
    raise NotImplementedError("DismissDeviceFromWatch wird in app.py verdrahtet")


def provide_create_device() -> CreateDevice:
    raise NotImplementedError("CreateDevice wird in app.py verdrahtet")


def provide_archive_device() -> ArchiveDevice:
    raise NotImplementedError("ArchiveDevice wird in app.py verdrahtet")


def provide_restore_device() -> RestoreDevice:
    raise NotImplementedError("RestoreDevice wird in app.py verdrahtet")


def provide_get_archived_devices() -> GetArchivedDevices:
    raise NotImplementedError("GetArchivedDevices wird in app.py verdrahtet")


def provide_get_archive_candidates() -> Callable[[], list[Any]]:
    # Liefert ein fertig parametriertes Callable (Schwelle aus dem Setting im
    # Composition Root eingesetzt), das der Endpunkt argumentlos aufruft -- der
    # api-Ring kennt weder den domain-Device-Typ noch die Tage-Schwelle.
    raise NotImplementedError("get_archive_candidates wird in app.py verdrahtet")


def provide_answer_archive_prompt() -> AnswerArchivePrompt:
    raise NotImplementedError("AnswerArchivePrompt wird in app.py verdrahtet")


class DeviceMetaBody(BaseModel):
    """Partielles Update der User-Metadaten -- alle Felder optional (None = nicht aendern)."""

    label: str | None = None
    tags: list[str] | None = None
    notes: str | None = None
    category: str | None = None
    is_known: bool | None = None
    # Als roher str entgegengenommen (kein domain-Import im api-Ring). Die
    # Validierung gegen die erlaubten Werte und die Hebung str->TrustState macht
    # der Use-Case; ein ungueltiger Wert wird unten auf HTTP 422 abgebildet.
    trust_state: str | None = None
    # Wache-Wegleg-Flag ueber den generischen Update-Pfad (None = nicht aendern).
    watch_dismissed: bool | None = None


class DismissBody(BaseModel):
    """Body von POST /{mac}/dismiss: ``dismissed`` legt weg (True) bzw. holt zurueck (False)."""

    dismissed: bool


class CreateDeviceBody(BaseModel):
    """Body von POST "": ein Geraet von Hand anlegen (``mac`` Pflicht, Rest optional)."""

    mac: str
    label: str = ""
    notes: str = ""
    category: str = ""
    tags: list[str] | None = None


class ArchivePromptBody(BaseModel):
    """Body von POST /{mac}/archive-prompt: ``archive`` -> Ja (True) / Nein (False)."""

    archive: bool


def _device_to_dict(device: Any) -> dict[str, Any]:
    # device ist ein domain.Device; bewusst als Any behandelt, damit api den
    # domain-Ring nicht importiert (import-linter). tuple -> list, datetime -> ISO.
    return {
        "mac": device.mac,
        "vendor": device.vendor,
        "label": device.label,
        "notes": device.notes,
        "category": device.category,
        "is_known": device.is_known,
        "trust_state": device.trust_state.value,
        "source": device.source.value,
        "watch_dismissed": device.watch_dismissed,
        "hostname": device.hostname,
        "os_guess": device.os_guess,
        "tags": list(device.tags),
        "open_ports": list(device.open_ports),
        "last_ip": device.last_ip,
        "times_seen": device.times_seen,
        "first_seen": device.first_seen.isoformat(),
        "last_seen": device.last_seen.isoformat(),
    }


def _ip_history_to_list(entries: Any) -> list[dict[str, Any]]:
    return [{"ip": entry.ip, "seen_at": entry.seen_at.isoformat()} for entry in entries]


# /stats VOR /{mac} deklarieren, sonst faengt der Pfad-Parameter "stats".
@router.get("/stats")
def device_stats(
    get_device_stats: Annotated[GetDeviceStats, Depends(provide_get_device_stats)],
) -> dict[str, Any]:
    """Zaehler ueber den Geraetebestand; ``active`` -> ``active_24h`` im Response."""
    stats = get_device_stats()
    return {
        "total": stats.total,
        "known": stats.known,
        "unknown": stats.unknown,
        "active_24h": stats.active,
    }


@router.get("")
def list_devices(
    get_devices: Annotated[GetDevices, Depends(provide_get_devices)],
    known_only: bool = False,
) -> list[dict[str, Any]]:
    """Alle Geraete; ``?known_only=true`` filtert auf bekannte."""
    return [_device_to_dict(device) for device in get_devices(known_only)]


@router.post("")
def create_device(
    body: CreateDeviceBody,
    create_device: Annotated[CreateDevice, Depends(provide_create_device)],
) -> dict[str, Any]:
    """Legt ein Geraet von Hand an; bekannte MAC -> 409, ungueltige MAC -> 422."""
    try:
        created = create_device(
            body.mac,
            label=body.label,
            notes=body.notes,
            category=body.category,
            tags=body.tags,
        )
    except DeviceAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Geraet existiert bereits. (E-506)",
        ) from exc
    except ValueError as exc:
        # Ungueltige MAC aus normalize_mac im Use-Case. Bare 422 wie der
        # InvalidTrustState-Pfad (vermeidet den deprecateten status-Alias).
        raise HTTPException(status_code=422, detail="Ungueltige MAC. (E-506)") from exc
    return _device_to_dict(created)


# /unclassified VOR /{mac} deklarieren, sonst faengt der Pfad-Parameter
# "unclassified" als MAC.
@router.get("/unclassified")
def list_unclassified_devices(
    get_unclassified: Annotated[GetUnclassifiedDevices, Depends(provide_get_unclassified_devices)],
) -> list[dict[str, Any]]:
    """Die Gaeste-/Unbekannt-Wache: noch nicht eingeordnete, nicht weggelegte Geraete."""
    return [_device_to_dict(device) for device in get_unclassified()]


# /archived VOR /{mac} deklarieren, sonst faengt der Pfad-Parameter "archived".
@router.get("/archived")
def list_archived_devices(
    get_archived: Annotated[GetArchivedDevices, Depends(provide_get_archived_devices)],
) -> list[dict[str, Any]]:
    """Die Archiv-Liste: alle archivierten Geraete (``last_seen`` absteigend)."""
    return [_device_to_dict(device) for device in get_archived()]


# /archive-candidates VOR /{mac} deklarieren, sonst faengt der Pfad-Parameter
# "archive-candidates" als MAC.
@router.get("/archive-candidates")
def archive_candidates(
    get_archive_candidates: Annotated[
        Callable[[], list[Any]], Depends(provide_get_archive_candidates)
    ],
) -> list[dict[str, Any]]:
    """Nachfrage-Kandidaten: lange nicht gesehene Geraete (Schwelle aus dem Setting).

    Passiver Lese-Endpunkt, den das Frontend nach Scan-Abschluss abfragt; es wird
    nichts automatisch archiviert. Die Schwelle ist im Composition Root eingesetzt,
    daher argumentloser Aufruf.
    """
    candidates = get_archive_candidates()
    return [_device_to_dict(device) for device in candidates]


@router.get("/{mac}")
def get_device(
    mac: str,
    get_device: Annotated[GetDevice, Depends(provide_get_device)],
) -> dict[str, Any]:
    """Ein Geraet samt IP-Historie; unbekannte MAC -> 404."""
    try:
        result = get_device(mac)
    except DeviceNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Geraet nicht gefunden. (E-505)",
        ) from exc
    return {
        **_device_to_dict(result.device),
        "ip_history": _ip_history_to_list(result.ip_history),
    }


@router.put("/{mac}")
def put_device(
    mac: str,
    body: DeviceMetaBody,
    update_device_meta: Annotated[UpdateDeviceMeta, Depends(provide_update_device_meta)],
) -> dict[str, Any]:
    """Partielles Meta-Update; unbekannte MAC -> 404 (bewusste Abweichung vom Altcode-No-op)."""
    try:
        updated = update_device_meta(
            mac,
            label=body.label,
            tags=body.tags,
            notes=body.notes,
            category=body.category,
            is_known=body.is_known,
            trust_state=body.trust_state,
            watch_dismissed=body.watch_dismissed,
        )
    except DeviceNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Geraet nicht gefunden. (E-505)",
        ) from exc
    except InvalidTrustStateError as exc:
        # Bare 422 wie der uebrige Router (monitoring/analysis): vermeidet die
        # Deprecation des status.HTTP_422_*-Alias der installierten Starlette.
        raise HTTPException(
            status_code=422,
            detail=f"Ungueltiger trust_state: {exc.value!r}. (E-506)",
        ) from exc
    return _device_to_dict(updated)


@router.delete("/{mac}")
def delete_device(
    mac: str,
    delete_device: Annotated[DeleteDevice, Depends(provide_delete_device)],
) -> dict[str, bool]:
    """Loescht ein Geraet (inkl. IP-History). Idempotent -> kein 404."""
    delete_device(mac)
    return {"ok": True}


@router.post("/{mac}/dismiss")
def dismiss_device(
    mac: str,
    body: DismissBody,
    dismiss_from_watch: Annotated[
        DismissDeviceFromWatch, Depends(provide_dismiss_device_from_watch)
    ],
) -> dict[str, Any]:
    """Legt ein Geraet aus der Wache weg (``dismissed=true``) bzw. holt es zurueck;
    unbekannte MAC -> 404. Anders als DELETE bleibt das Geraet im Bestand."""
    try:
        updated = dismiss_from_watch(mac, body.dismissed)
    except DeviceNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Geraet nicht gefunden. (E-505)",
        ) from exc
    return _device_to_dict(updated)


@router.post("/{mac}/archive")
def archive_device(
    mac: str,
    archive_device: Annotated[ArchiveDevice, Depends(provide_archive_device)],
) -> dict[str, Any]:
    """Archiviert ein Geraet direkt; unbekannte MAC -> 404."""
    try:
        updated = archive_device(mac)
    except DeviceNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Geraet nicht gefunden. (E-505)",
        ) from exc
    return _device_to_dict(updated)


@router.post("/{mac}/restore")
def restore_device(
    mac: str,
    restore_device: Annotated[RestoreDevice, Depends(provide_restore_device)],
) -> dict[str, Any]:
    """Holt ein archiviertes Geraet zurueck in den aktiven Bestand; unbekannte MAC -> 404."""
    try:
        updated = restore_device(mac)
    except DeviceNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Geraet nicht gefunden. (E-505)",
        ) from exc
    return _device_to_dict(updated)


@router.post("/{mac}/archive-prompt")
def answer_archive_prompt(
    mac: str,
    body: ArchivePromptBody,
    answer_archive_prompt: Annotated[AnswerArchivePrompt, Depends(provide_answer_archive_prompt)],
) -> dict[str, Any]:
    """Nutzerantwort auf die Scan-Nachfrage: Ja -> archivieren, Nein -> Zaehler hoch;
    unbekannte MAC -> 404."""
    try:
        updated = answer_archive_prompt(mac, body.archive)
    except DeviceNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Geraet nicht gefunden. (E-505)",
        ) from exc
    return _device_to_dict(updated)
