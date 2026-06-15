"""FastAPI-Router der fritz-Domaene (v2), prefix ``/api/fritz``.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich Use-Cases aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter und
``domain``-Typen werden hier NICHT importiert -- der Use-Case kommt per
FastAPI-Dependency herein (Verdrahtung im Composition Root ``app.py``), und das
Domaenen-Aggregat wird ueber Attribut-Zugriff zu JSON serialisiert (Typ ``Any``,
genau wie der devices-/scanning-Router das haelt).

Der Auth-Fehler kommt als APPLICATION-Typ ``FritzDetailAuthError`` herein -- NICHT
als ``infrastructure``-``FritzAuthError`` (anders als die scanning-Doku nahelegt:
dort wird der Adapter-Fehler erst im Composition Root ``ws_scan`` gefangen, weil
scanning keinen REST-Endpunkt hat). Der api-Ring darf ``infrastructure`` laut
import-linter NICHT importieren ("api ruft nur application"); darum uebersetzt der
Composition Root (``app.py``) die Adapter-``FritzAuthError`` in den application-
eigenen ``FritzDetailAuthError``, den dieser Router sauber fangen kann.

HTTP-Mapping:
* ``FritzDetailAuthError`` (falsche Credentials) -> 502 Bad Gateway. Das
  Upstream-Geraet lehnt die Anmeldung ab -- aus Sicht unseres Dienstes ist das ein
  Gateway-Problem, kein 4xx-Client-Fehler unserer API. Klare Message.
* ``reachable=False`` (Box nicht konfiguriert/erreichbar) ist KEIN Fehler ->
  200 mit ``reachable: false`` im Body.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from application.fritz_detail import FritzDetailAuthError, GetFritzDetail

router = APIRouter(prefix="/api/fritz", tags=["fritz"])


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit
# echtem Adapter verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler.
def provide_get_fritz_detail() -> GetFritzDetail:
    raise NotImplementedError("GetFritzDetail wird in app.py verdrahtet")


def _device_to_dict(device: Any) -> dict[str, Any]:
    return {
        "model": device.model,
        "firmware": device.firmware,
        "is_fiber": device.is_fiber,
        "total_hosts": device.total_hosts,
    }


def _wan_to_dict(wan: Any) -> dict[str, Any]:
    return {
        "connected": wan.connected,
        "uptime_secs": wan.uptime_secs,
        "ip_external": wan.ip_external,
        "ip_external_v6": wan.ip_external_v6,
        "upstream_kbps": wan.upstream_kbps,
        "downstream_kbps": wan.downstream_kbps,
        "bytes_sent": wan.bytes_sent,
        "bytes_recv": wan.bytes_recv,
    }


def _dsl_to_dict(dsl: Any) -> dict[str, Any]:
    return {
        "sync": dsl.sync,
        "downstream_kbps": dsl.downstream_kbps,
        "upstream_kbps": dsl.upstream_kbps,
        "snr_downstream": dsl.snr_downstream,
        "snr_upstream": dsl.snr_upstream,
        "attn_downstream": dsl.attn_downstream,
        "attn_upstream": dsl.attn_upstream,
    }


def _band_to_dict(band: Any) -> dict[str, Any]:
    return {
        "enabled": band.enabled,
        "ssid": band.ssid,
        "channel": band.channel,
        "clients": band.clients,
    }


def _client_to_dict(client: Any) -> dict[str, Any]:
    return {
        "mac": client.mac,
        "ip": client.ip,
        "hostname": client.hostname,
        "signal_dbm": client.signal_dbm,
        "speed_mbps": client.speed_mbps,
        "band": client.band,
    }


def _log_to_dict(entry: Any) -> dict[str, Any]:
    return {"id": entry.id, "timestamp": entry.timestamp, "message": entry.message}


def _forwarding_to_dict(fwd: Any) -> dict[str, Any]:
    return {
        "enabled": fwd.enabled,
        "description": fwd.description,
        "protocol": fwd.protocol,
        "external_port": fwd.external_port,
        "internal_ip": fwd.internal_ip,
        "internal_port": fwd.internal_port,
    }


def _detail_to_dict(detail: Any) -> dict[str, Any]:
    # detail ist ein domain.FritzDetail; bewusst als Any behandelt, damit api den
    # domain-Ring nicht importiert. tuple -> list, Sub-Objekte verschachtelt.
    return {
        "reachable": detail.reachable,
        "host": detail.host,
        "auth_error": detail.auth_error,
        "device": _device_to_dict(detail.device),
        "wan": _wan_to_dict(detail.wan),
        "dsl": _dsl_to_dict(detail.dsl),
        "wlan_24": _band_to_dict(detail.wlan_24),
        "wlan_5": _band_to_dict(detail.wlan_5),
        "wlan_clients": [_client_to_dict(c) for c in detail.wlan_clients],
        "log": [_log_to_dict(e) for e in detail.log],
        "port_forwardings": [_forwarding_to_dict(f) for f in detail.port_forwardings],
    }


@router.get("/detail")
async def get_fritz_detail(
    get_fritz_detail: Annotated[GetFritzDetail, Depends(provide_get_fritz_detail)],
) -> dict[str, Any]:
    """Voller FRITZ!Box-Detailstatus.

    ``reachable: false`` (nicht konfiguriert/erreichbar) -> 200; falsche
    Credentials (``FritzDetailAuthError``) -> 502.
    """
    try:
        detail = await get_fritz_detail()
    except FritzDetailAuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="FRITZ!Box-Authentifizierung gescheitert (Credentials pruefen).",
        ) from exc
    return _detail_to_dict(detail)
