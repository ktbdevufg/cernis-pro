"""FastAPI-Router der scanning-Domaene (v2) -- die REST-Lese-Pfade.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich Use-Cases aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter, Ports
und ``domain``-Typen werden hier NICHT importiert -- die Use-Cases kommen per
FastAPI-Dependency herein (Verdrahtung im Composition Root ``app.py``), und
Domaenen-Objekte werden ueber Attribut-Zugriff zu JSON serialisiert (Typ ``Any``,
genau wie der devices-/settings-Router das haelt).

Endpunkte (Shapes am S.1-Characterization-Contract):

* ``GET /api/history``       -> Liste der Scans (id/scanned_at/cidr/host_count).
* ``GET /api/history/{id}``  -> ein Scan mit vollen Hosts; unbekannte ID -> 404.
* ``GET /api/vendor/{mac}``  -> ``{"mac": ..., "vendor": ...}``.

BEWUSST NICHT hier (S.7): ``GET /api/arp``. Es braucht einen ``ArpTablePort`` +
Adapter (im Altcode ``modules.get_arp_table`` direkt), der zum ARP-Merge-Block
gehoert -- dieser ist zusammen mit FritzHosts-Merge + devices-Projektion nach S.7
verschoben. ``/api/arp`` kommt mit dem ARP-Port in S.7 (NICHT als Luecke
uebersehen).

Der WS-Endpunkt ``/ws/scan`` liegt NICHT hier, sondern im Composition Root
(``backend/ws_scan.py``): seine Event->Frame-Uebersetzung braucht die
``domain``-Event-Typen (``match``/``assert_never``) und die Adapter-Exceptions
(``NmapScanError``/``FritzAuthError`` aus ``infrastructure``) -- beides darf der
api-Ring laut Contract nicht importieren, der Composition Root schon.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from application.scanning import GetScanDetail, GetScanHistory, LookupVendor

router = APIRouter(prefix="/api", tags=["scanning"])


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit
# echten Adaptern verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler.
def provide_get_scan_history() -> GetScanHistory:
    raise NotImplementedError("GetScanHistory wird in app.py verdrahtet")


def provide_get_scan_detail() -> GetScanDetail:
    raise NotImplementedError("GetScanDetail wird in app.py verdrahtet")


def provide_lookup_vendor() -> LookupVendor:
    raise NotImplementedError("LookupVendor wird in app.py verdrahtet")


def _summary_to_dict(summary: Any) -> dict[str, Any]:
    # summary ist ein domain.ScanSummary; als Any behandelt, damit api den
    # domain-Ring nicht importiert. Shape wie S.1-Contract (id/scanned_at/...).
    return {
        "id": summary.scan_id,
        "scanned_at": summary.scanned_at,
        "cidr": summary.cidr,
        "host_count": summary.host_count,
    }


def _port_to_dict(port: Any) -> dict[str, Any]:
    return {"port": port.port, "state": port.state, "service": port.service}


def _mdns_to_dict(svc: Any) -> dict[str, Any]:
    return {
        "name": svc.name,
        "type": svc.type,
        "port": svc.port,
        "hostname": svc.hostname,
        "is_ndi": svc.is_ndi,
        "properties": [list(pair) for pair in svc.properties],
        "ip": svc.ip,
    }


def _ssdp_to_dict(svc: Any) -> dict[str, Any]:
    return {"server": svc.server, "st": svc.st, "location": svc.location, "ip": svc.ip}


def _host_to_dict(host: Any) -> dict[str, Any]:
    # host ist ein domain.EnrichedHost; verschachtelte Domaenen-Objekte werden
    # ebenfalls per Attribut-Zugriff serialisiert (kein domain-Import, tuple->list).
    return {
        "ip": host.ip,
        "mac": host.mac,
        "vendor": host.vendor,
        "rtt_ms": host.rtt_ms,
        "hostname": host.hostname,
        "smb_name": host.smb_name,
        "smb_domain": host.smb_domain,
        "ipv6": host.ipv6,
        "ipv6_all": list(host.ipv6_all),
        "os_guess": host.os_guess,
        "os_accuracy": host.os_accuracy,
        "scan_method": host.scan_method,
        "ports": [_port_to_dict(p) for p in host.ports],
        "mdns_services": [_mdns_to_dict(s) for s in host.mdns_services],
        "ssdp_services": [_ssdp_to_dict(s) for s in host.ssdp_services],
        "is_ndi": host.is_ndi,
        "is_unknown": host.is_unknown,
        "category": host.category,
        "label": host.label,
        "tags": list(host.tags),
        "notes": host.notes,
    }


@router.get("/history")
def list_history(
    get_scan_history: Annotated[GetScanHistory, Depends(provide_get_scan_history)],
    limit: int = Query(default=20, ge=1, le=100),
) -> list[dict[str, Any]]:
    """Letzte Scans als Listen-View (ohne Host-Blob), neueste zuerst."""
    return [_summary_to_dict(s) for s in get_scan_history(limit)]


@router.get("/history/{scan_id}")
def get_history_detail(
    scan_id: int,
    get_scan_detail: Annotated[GetScanDetail, Depends(provide_get_scan_detail)],
) -> dict[str, Any]:
    """Ein Scan mit seinen vollen Hosts; unbekannte ID -> 404."""
    record = get_scan_detail(scan_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nicht gefunden.")
    return {
        "id": record.scan_id,
        "scanned_at": record.scanned_at,
        "cidr": record.cidr,
        "host_count": record.host_count,
        "hosts": [_host_to_dict(h) for h in record.hosts],
    }


@router.get("/vendor/{mac}")
def get_vendor(
    mac: str,
    lookup_vendor: Annotated[LookupVendor, Depends(provide_lookup_vendor)],
) -> dict[str, str]:
    """Hersteller zur OUI einer MAC; ``""`` wenn nicht gefunden."""
    return {"mac": mac, "vendor": lookup_vendor(mac)}
