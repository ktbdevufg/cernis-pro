"""WebSocket-Handler ``/ws/scan`` -- lebt im Composition Root, NICHT im api-Ring.

Warum hier und nicht in ``api/``: Die Event->Frame-Uebersetzung braucht die
``domain``-Event-Typen (``match``/``assert_never`` ueber die ``ScanEvent``-Union)
UND die Adapter-Exceptions (``NmapScanError``/``FritzAuthError`` aus
``infrastructure``). Beide Importe sind dem api-Ring per import-linter verboten
(api -> nur application, nicht domain/ports/infrastructure). ``backend/ws_scan.py``
liegt flach in ``backend/`` -- kein Submodul eines ``root_package`` -, ist also
wie ``app.py`` von den Contracts ausgenommen (Composition-Root-Ausnahme).

Der Handler bekommt die ``RunNetworkScan``-Factory injiziert (gebaut in
``app.py`` mit den konkreten Adaptern) -- er konstruiert den Use-Case NICHT selbst,
haelt aber keinen api-Ring-Reinheitsanspruch (er IST Composition Root).

Frame-Protokoll: exakt der S.1-Characterization-Contract (``test_ws_scan_contract``).
Die ``ScanEvent``-Union wird per ``match`` + ``assert_never`` erschoepfend in
JSON-Frames uebersetzt -- ein neuer Event-Typ ohne ``case`` bricht in mypy.

Fehlerpfad (S.5-Entscheidung 3 / S.6-Merkposten 2): ``NmapScanError`` /
``FritzAuthError`` propagieren aus ``RunNetworkScan.run`` (der Use-Case faengt sie
bewusst NICHT). HIER werden sie gefangen und in einen sauberen ``error``-Frame
uebersetzt -- KEIN roher 500er/WS-Abbruch. Beide zusammen behandelt.

HostFound-Timing (S.6-Merkposten 1): Der HostDiscoveryAdapter (Variante A)
buendelt die ``HostFound`` nach den Ticks; der Use-Case gibt das unveraendert
weiter. Dieser Handler uebernimmt die Reihenfolge der Events 1:1 -- er sortiert
NICHT um. Die v1-interleaved-Reihenfolge wird bewusst NICHT wiederhergestellt:
Frame-Reihenfolge folgt dem Event-Strom des Use-Case. (Dokumentiert, nicht
stillschweigend.)
"""

from collections.abc import Awaitable, Callable
from typing import Any, assert_never

from fastapi import WebSocket

from domain.scanning import (
    HostEnriched,
    HostFound,
    Info,
    PhaseChanged,
    Progress,
    ScanCompleted,
    ScanConfig,
    ScanError,
    ScanEvent,
    ScanStarted,
)
from infrastructure.scanning.fritz_hosts import FritzAuthError
from infrastructure.scanning.port_scanner import NmapScanError

# Adapter-Exceptions, die der Use-Case bewusst durchwirft (S.5) und die hier in
# einen ``error``-Frame uebersetzt werden -- statt eines rohen 500ers/Abbruchs.
_ADAPTER_ERRORS = (NmapScanError, FritzAuthError)

# Factory-Typ: app.py liefert eine Funktion, die pro Verbindung einen frischen
# RunNetworkScan-Use-Case baut (mit den konkreten Adaptern verdrahtet).
RunScanFactory = Callable[[], Any]


def _event_to_frame(event: ScanEvent) -> dict[str, Any]:
    """Uebersetzt ein ``ScanEvent`` in seinen WS-Frame (S.1-Contract-Shapes)."""
    match event:
        case ScanStarted(cidr=cidr, total_hosts=total_hosts):
            return {"type": "scan_started", "cidr": cidr, "total_hosts": total_hosts}
        case PhaseChanged(phase=phase, status="running", total=total):
            return {"type": "phase", "phase": phase, "status": "running", "total": total}
        case PhaseChanged(phase=phase, status="done", alive_count=alive_count):
            return {"type": "phase", "phase": phase, "status": "done", "alive_count": alive_count}
        case PhaseChanged(phase=phase, status=other_status):
            # Defensiv: jeder andere phase-Status -> minimaler Frame (kein S.1-Fall,
            # aber vollstaendig statt KeyError).
            return {"type": "phase", "phase": phase, "status": other_status}
        case HostFound(ip=ip, mac=mac, vendor=vendor, rtt_ms=rtt_ms, is_unknown=is_unknown):
            # Shape exakt wie S.1: KEIN source-Feld (das trugen v1 nur Fritz/ARP-
            # Hosts, die in S.6 noch nicht gemerged werden -> S.7).
            return {
                "type": "host_found",
                "ip": ip,
                "rtt_ms": rtt_ms,
                "mac": mac,
                "vendor": vendor,
                "is_unknown": is_unknown,
            }
        case Progress(phase=phase, completed=completed, total=total, pct=pct):
            return {
                "type": "progress",
                "phase": phase,
                "completed": completed,
                "total": total,
                "pct": pct,
            }
        case HostEnriched(host=host):
            return _host_detail_frame(host)
        case Info(message=message):
            return {"type": "info", "message": message}
        case ScanCompleted(total_found=total_found):
            return {"type": "scan_complete", "total_found": total_found}
        case ScanError(message=message):
            return {"type": "error", "message": message}
        case _:
            assert_never(event)


def _host_detail_frame(host: Any) -> dict[str, Any]:
    """``EnrichedHost`` -> ``host_detail``-Frame (20 Keys, S.1-Contract).

    ``host`` ist ein ``domain.EnrichedHost``; verschachtelte Domaenen-Objekte
    werden per Attribut-Zugriff serialisiert (tuple -> list).
    """
    return {
        "type": "host_detail",
        "ip": host.ip,
        "mac": host.mac,
        "vendor": host.vendor,
        "rtt_ms": host.rtt_ms,
        "hostname": host.hostname,
        "smb_name": host.smb_name,
        "smb_domain": host.smb_domain,
        "os_guess": host.os_guess,
        "os_accuracy": host.os_accuracy,
        "scan_method": host.scan_method,
        "ports": [{"port": p.port, "state": p.state, "service": p.service} for p in host.ports],
        "mdns_services": [
            {
                "name": s.name,
                "type": s.type,
                "port": s.port,
                "hostname": s.hostname,
                "is_ndi": s.is_ndi,
                "properties": [list(pair) for pair in s.properties],
            }
            for s in host.mdns_services
        ],
        "ssdp_services": [
            {"server": s.server, "st": s.st, "location": s.location} for s in host.ssdp_services
        ],
        "is_ndi": host.is_ndi,
        "is_unknown": host.is_unknown,
        "category": host.category,
        "label": host.label,
        "tags": list(host.tags),
        "notes": host.notes,
    }


def _build_config(raw: dict[str, Any]) -> ScanConfig:
    """Baut ``ScanConfig`` aus dem WS-JSON (Multi-CIDR comma-split, wie Altcode).

    Ungueltige Werte (leeres/kaputtes CIDR) wirft ``ScanConfig.__post_init__`` als
    ``ValueError`` -- der Aufrufer uebersetzt das in einen ``error``-Frame.
    """
    cidr_raw = str(raw.get("cidr", "192.168.1.0/24"))
    cidrs = tuple(c.strip() for c in cidr_raw.split(",") if c.strip())
    return ScanConfig(
        cidrs=cidrs,
        ping_timeout=float(raw.get("ping_timeout", 1.5)),
        port_scan=bool(raw.get("port_scan", True)),
        port_mode=str(raw.get("port_mode", "socket")),
        mdns_scan=bool(raw.get("mdns_scan", True)),
        mdns_duration=float(raw.get("mdns_duration", 8.0)),
        resolve_hostnames=bool(raw.get("resolve_hostnames", True)),
        smb_scan=bool(raw.get("smb_scan", False)),
        ssdp_scan=bool(raw.get("ssdp_scan", True)),
        max_concurrent_ping=int(raw.get("max_concurrent_ping", 64)),
        max_concurrent_ports=int(raw.get("max_concurrent_ports", 100)),
        custom_ports=tuple(raw["custom_ports"]) if raw.get("custom_ports") else None,
    )


def make_ws_scan(run_scan_factory: RunScanFactory) -> Callable[[WebSocket], Awaitable[None]]:
    """Baut den ``/ws/scan``-Handler mit injizierter ``RunNetworkScan``-Factory.

    ``run_scan_factory()`` liefert pro Verbindung einen frischen, mit den
    konkreten Adaptern verdrahteten ``RunNetworkScan``-Use-Case (gebaut in app.py).
    """

    async def ws_scan(websocket: WebSocket) -> None:
        await websocket.accept()

        # 1. Config aus dem WS-JSON. Kaputtes JSON ODER ungueltiges CIDR
        #    (ValueError aus ScanConfig) -> error-Frame, dann Ende.
        try:
            raw = await websocket.receive_json()
            config = _build_config(raw)
        except ValueError as exc:
            await websocket.send_json({"type": "error", "message": str(exc)})
            return
        except Exception as exc:
            await websocket.send_json({"type": "error", "message": str(exc)})
            return

        # 2. Scan ausfuehren, jedes Event als Frame senden. Adapter-Exceptions
        #    (NmapScanError/FritzAuthError) propagieren aus dem Generator -> hier
        #    in einen error-Frame uebersetzt, KEIN roher 500er (S.6-Merkposten 2).
        use_case = run_scan_factory()
        try:
            async for event in use_case.run(config):
                await websocket.send_json(_event_to_frame(event))
        except _ADAPTER_ERRORS as exc:
            await websocket.send_json({"type": "error", "message": str(exc)})

    return ws_scan
