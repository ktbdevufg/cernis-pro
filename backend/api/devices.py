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

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from application.devices import (
    DeleteDevice,
    DeviceNotFoundError,
    GetDevice,
    GetDevices,
    GetDeviceStats,
    RecordScannedHost,
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


class DeviceMetaBody(BaseModel):
    """Partielles Update der User-Metadaten -- alle Felder optional (None = nicht aendern)."""

    label: str | None = None
    tags: list[str] | None = None
    notes: str | None = None
    category: str | None = None
    is_known: bool | None = None


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
            status_code=status.HTTP_404_NOT_FOUND, detail="Geraet nicht gefunden."
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
        )
    except DeviceNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Geraet nicht gefunden."
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
