"""FastAPI-Router der capture-Domaene (v2) -- die pcap/lldp-REST-Pfade.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich Use-Cases aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter, Ports
und ``domain``-Typen werden hier NICHT importiert -- die Use-Cases kommen per
FastAPI-Dependency herein (Verdrahtung im Composition Root ``app.py``), und
Domaenen-Objekte werden ueber Attribut-Zugriff zu JSON serialisiert (Typ ``Any``,
genau wie der monitoring-/scanning-Router das haelt).

Endpunkte (Shapes am C.0-Characterization-Contract ``test_capture_contract`` --
RegressionSSCHUTZ: die Wire-Form bleibt 1:1, AUSSER der EINEN bewussten Heilung):

* ``GET  /api/pcap/available`` -> ``{available, permission_error}``.
* ``POST /api/pcap/start``     -> ``{ok, error, available}`` (Erfolg) / 403 ``{ok,error}``.
* ``POST /api/pcap/stop``      -> ``{ok: True}``.
* ``GET  /api/pcap/status``    -> ``{running, packets, stats, pcap_available, pcap_path, error}``.
* ``GET  /api/pcap/packets``   -> Liste der letzten Pakete (limit 1..1000, default 100).
* ``POST /api/pcap/save``      -> 404 ``{error}`` ohne pcap / 200 ``{ok, path, size}`` (GEHEILT).
* ``GET  /api/lldp/neighbors`` -> Liste mit ``age_secs``/``expired``.
* ``POST /api/lldp/capture``   -> Nachbar-Liste / 503 bei Fehler/Timeout.
* ``GET  /api/topology``       -> radialer Heimnetz-Graph ``{nodes, edges}`` (ADR 0035).

BEWUSSTE HEILUNG ggue. C.0 (der einzige Umschlag): ``/api/pcap/save`` lieferte im
Altcode bei vorhandener Capture-Datei einen 500er (``os.path.basename`` auf ein nie
gebundenes ``os`` -- ``main.py`` importiert nur ``os as _os``). Hier 200 mit
``{ok, path, size}`` -- Dateiname ueber ``Path(path).name`` (kein ``os``-Import, kein
``os.path.basename``). Der C.0-Test bleibt UNVERAENDERT (friert v1 gegen ``main.py``
ein); diese geheilte Form lebt im v2-eigenen ``test_capture_api``.

Tote Route WEGGELASSEN (vom C.0-Contract bewusst nicht festgenagelt): ``/api/pcap/
download``. Die fruehere tote ``/api/lldp/topology`` ist NICHT reaktiviert, sondern
durch den sauber neu gebauten ``/api/topology`` ERSETZT (ADR 0035) -- Gateway-
zentrierter Graph mit measured/assumed-Kanten statt des dangling-edge-Altcodes.

Shape-Naht: Die Use-Cases geben ROHE Domaenen-Objekte / Wire-nahe dicts; dieser Rand
baut die endgueltige Wire-Form (``_packet_to_dict`` / ``_neighbor_to_dict`` mit
``age_secs``/``expired`` aus ``enrich_neighbor``). Der ``start``-Callable
(``provide_start_capture``) kapselt das ``asyncio.create_task`` + ``app.state`` im
Composition Root -- der Router kennt kein ``create_task``/``app.state``.
"""

import asyncio
import time
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from application.capture import (
    BuildTopology,
    CaptureLldp,
    GetLldpNeighbors,
    StartCapture,
    enrich_neighbor,
)

router = APIRouter(prefix="/api", tags=["capture"])


# Body-Modelle (Hausmuster api/monitoring.AddScheduleBody): optionale Felder mit
# Altcode-Defaults -- ein leerer Body ist gueltig. Kein rohes Body(dict) (B008).
class StartCaptureBody(BaseModel):
    """POST /api/pcap/start -- alle Felder optional mit Altcode-Defaults."""

    interface: str = ""
    filter: str = ""
    max_packets: int = 5000


class LldpCaptureBody(BaseModel):
    """POST /api/lldp/capture -- interface optional, duration default 30.0."""

    interface: str = ""
    duration: float = 30.0


# Liefert ``{available, permission_error}``-Bausteine fuer /available. Der
# StartCapture-Use-Case kapselt is_available + check_permission (kein infra-Import).
def provide_start_capture_uc() -> StartCapture:
    raise NotImplementedError("StartCapture wird in app.py verdrahtet")


# Composition-Root-Callable: prueft (StartCapture) und startet bei ok=True den
# RunCapture-Loop als Task (create_task + app.state) -- das kennt nur app.py. Gibt
# das ``{ok, error}``-Ergebnis zurueck (der Router formt 200/403 daraus).
type StartCaptureRunner = Callable[[str | None, str, int], dict[str, Any]]


def provide_start_capture() -> StartCaptureRunner:
    raise NotImplementedError("StartCaptureRunner wird in app.py verdrahtet")


# Composition-Root-Callable: stoppt den laufenden Capture (RunCapture.stop()).
type StopCaptureRunner = Callable[[], None]


def provide_stop_capture() -> StopCaptureRunner:
    raise NotImplementedError("StopCaptureRunner wird in app.py verdrahtet")


# Liefert den Capture-Status (RunCapture.status(now)). Als Callable injiziert, weil
# ``now`` der Rand reicht und der Singleton-State im Composition Root lebt.
type CaptureStatusProvider = Callable[[float], dict[str, Any]]


def provide_capture_status() -> CaptureStatusProvider:
    raise NotImplementedError("CaptureStatusProvider wird in app.py verdrahtet")


# Liefert die letzten Pakete (RunCapture.recent_packets(limit)) als rohe PacketSummary.
type RecentPacketsProvider = Callable[[int], list[Any]]


def provide_recent_packets() -> RecentPacketsProvider:
    raise NotImplementedError("RecentPacketsProvider wird in app.py verdrahtet")


# Liefert den Pfad der zuletzt geschriebenen temp-pcap (RunCapture.pcap_path()).
type PcapPathProvider = Callable[[], str | None]


def provide_pcap_path() -> PcapPathProvider:
    raise NotImplementedError("PcapPathProvider wird in app.py verdrahtet")


# Waehlt das Ziel-Verzeichnis fuer ``save`` (Desktop/Downloads/Home). Filesystem-
# Policy -> Composition Root, NICHT Use-Case (der bleibt domain-/ports-rein).
type SaveDirProvider = Callable[[], Path]


def provide_save_dir() -> SaveDirProvider:
    raise NotImplementedError("SaveDirProvider wird in app.py verdrahtet")


def provide_capture_lldp() -> CaptureLldp:
    raise NotImplementedError("CaptureLldp wird in app.py verdrahtet")


def provide_get_lldp_neighbors() -> GetLldpNeighbors:
    raise NotImplementedError("GetLldpNeighbors wird in app.py verdrahtet")


# Waehlbare Host-Quelle der Topologie (Nutzer-Wahl, kein fester Default):
#   * "last_scan"  -> nur die Hosts des juengsten gespeicherten Scans (Live-Bild),
#   * "all_known"  -> der gesamte device_repository-Bestand (bisheriges Verhalten).
# Als ``Literal`` am Query-Rand (Hausmuster api/export.export_scan / api/process.
# list_processes): FastAPI lehnt einen ungueltigen Wert selbst mit 422 ab -- keine
# eigene Validierung, kein domain-Import. Die Hebung str -> Projektion macht der
# Composition Root: die Factory unten waehlt anhand dieses Werts den Host-Provider.
type TopologySource = Literal["last_scan", "all_known"]


# Composition-Root-Factory: liefert einen ``BuildTopology`` mit der zur ``source``
# passenden Host-Projektion. WARUM Factory statt fertigem Use-Case: die Quelle-
# Unterscheidung gehoert in die Verdrahtung (Regel 5), NICHT in die Use-Case-Logik
# -- ``BuildTopology`` bleibt quellen-agnostisch (bekommt nur EINEN Host-Provider).
type BuildTopologyFactory = Callable[[TopologySource], BuildTopology]


def provide_build_topology() -> BuildTopologyFactory:
    raise NotImplementedError("BuildTopology-Factory wird in app.py verdrahtet")


# ── Serialisierungs-Helfer (Domaenen-Objekt -> Wire-dict am api-Rand) ─────────


def _packet_to_dict(ps: Any) -> dict[str, Any]:
    """``PacketSummary`` -> Wire-dict (Feldsatz wie Altcode ``PacketSummary.to_dict``)."""
    return {
        "timestamp": ps.timestamp,
        "src_ip": ps.src_ip,
        "dst_ip": ps.dst_ip,
        "src_mac": ps.src_mac,
        "dst_mac": ps.dst_mac,
        "protocol": ps.protocol,
        "src_port": ps.src_port,
        "dst_port": ps.dst_port,
        "length": ps.length,
        "info": ps.info,
        "is_ipv6": ps.is_ipv6,
    }


def _neighbor_to_dict(neighbor: Any, now: float) -> dict[str, Any]:
    """``LLDPNeighbor`` -> Wire-dict + ``age_secs``/``expired`` (Altcode ``get_neighbors``).

    ``age_secs``/``expired`` kommen aus ``enrich_neighbor`` (application-Wrapper um
    ``neighbor_age``) -- der Rand importiert die domain-Funktion nicht direkt.
    """
    age_secs, expired = enrich_neighbor(neighbor, now)
    return {
        "source_mac": neighbor.source_mac,
        "chassis_id": neighbor.chassis_id,
        "port_id": neighbor.port_id,
        "system_name": neighbor.system_name,
        "system_desc": neighbor.system_desc,
        "port_desc": neighbor.port_desc,
        "protocol": neighbor.protocol,
        "vlans": list(neighbor.vlans),
        "capabilities": list(neighbor.capabilities),
        "mgmt_ip": neighbor.mgmt_ip,
        "ttl": neighbor.ttl,
        "last_seen": neighbor.last_seen,
        "age_secs": age_secs,
        "expired": expired,
    }


# ── pcap ────────────────────────────────────────────────────────────────────


@router.get("/pcap/available")
def pcap_available(
    start_capture: Annotated[StartCapture, Depends(provide_start_capture_uc)],
) -> dict[str, Any]:
    """``{available, permission_error}`` -- scapy da? + Rechte-Begruendung (oder "")."""
    if not start_capture.is_available():
        return {
            "available": False,
            "permission_error": (
                "Scapy is not available -- Packet Capture requires libpcap.\n"
                "Install via: sudo apt install libpcap-dev (Debian/Ubuntu) "
                "or sudo dnf install libpcap-devel (Fedora).\n"
                "Then restart CERNIS PRO."
            ),
        }
    return {"available": True, "permission_error": start_capture.check_permission() or ""}


@router.post("/pcap/start")
def pcap_start(
    body: StartCaptureBody,
    start_capture: Annotated[StartCaptureRunner, Depends(provide_start_capture)],
    start_capture_uc: Annotated[StartCapture, Depends(provide_start_capture_uc)],
) -> Any:
    """Startet den Capture. Erfolg -> ``{ok, error, available}``; sonst 403 ``{ok, error}``.

    Der ``start_capture``-Callable (Composition Root) prueft + startet den Loop und
    gibt ``{ok, error}`` zurueck. Bei Erfolg haengt der Rand ``available`` an (wie
    C.0); bei ``ok=False`` -> 403 mit dem Body UNVERAENDERT (KEIN ``available``-Key).
    """
    result = start_capture(body.interface or None, body.filter, body.max_packets)
    if not result["ok"]:
        return JSONResponse(status_code=403, content=result)
    return {**result, "available": start_capture_uc.is_available()}


@router.post("/pcap/stop")
def pcap_stop(
    stop_capture: Annotated[StopCaptureRunner, Depends(provide_stop_capture)],
) -> dict[str, bool]:
    """Stoppt den Capture (schreibt temp-pcap). Immer ``{ok: True}`` (kein Zustands-Check)."""
    stop_capture()
    return {"ok": True}


@router.get("/pcap/status")
def pcap_status(
    status_provider: Annotated[CaptureStatusProvider, Depends(provide_capture_status)],
) -> dict[str, Any]:
    """Aktueller Status: ``{running, packets, stats, pcap_available, pcap_path, error}``."""
    return status_provider(time.time())


@router.get("/pcap/packets")
def pcap_packets(
    recent_packets: Annotated[RecentPacketsProvider, Depends(provide_recent_packets)],
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    """Die letzten ``limit`` erfassten Pakete (default 100, Grenzen 1..1000)."""
    return [_packet_to_dict(ps) for ps in recent_packets(limit)]


@router.post("/pcap/save")
def pcap_save(
    pcap_path: Annotated[PcapPathProvider, Depends(provide_pcap_path)],
    save_dir: Annotated[SaveDirProvider, Depends(provide_save_dir)],
) -> Any:
    """Kopiert die temp-pcap ins Ziel-Verzeichnis. 404 ohne pcap, sonst ``{ok, path, size}``.

    GEHEILT ggue. Altcode (os-NameError -> 500): Dateiname ueber ``Path(path).name``,
    Ziel-Verzeichnis aus dem ``save_dir``-Callable (Composition Root: Desktop/
    Downloads/Home-Fallback). Kein ``os``-Import, kein ``os.path.basename``.
    """
    import shutil

    path = pcap_path()
    if not path:
        return JSONResponse(
            status_code=404,
            content={"error": "No capture file available. Start and stop a capture first."},
        )
    dest = save_dir() / Path(path).name
    shutil.copy2(path, dest)
    return {"ok": True, "path": str(dest), "size": dest.stat().st_size}


# ── lldp ────────────────────────────────────────────────────────────────────


@router.get("/lldp/neighbors")
def lldp_neighbors(
    get_neighbors: Annotated[GetLldpNeighbors, Depends(provide_get_lldp_neighbors)],
) -> list[dict[str, Any]]:
    """Aktuelle LLDP/CDP-Nachbartabelle mit ``age_secs``/``expired`` (frische ``now``)."""
    now = time.time()
    return [_neighbor_to_dict(n, now) for n in get_neighbors()]


@router.post("/lldp/capture")
async def lldp_capture(
    body: LldpCaptureBody,
    capture_lldp: Annotated[CaptureLldp, Depends(provide_capture_lldp)],
) -> Any:
    """Zeitbegrenzter LLDP/CDP-Sniff. Erfolg -> Nachbar-Liste; Fehler/Timeout -> 503.

    ``timeout=duration+5`` (Altcode-Vertrag): der Sniff selbst laeuft ``duration``
    Sekunden, der Wrapper-Timeout gibt 5 s Puffer. ``interface`` ``""`` -> ``None``.
    Jeder Fehler ODER ein Timeout -> 503 ``{error}`` (kein roher 500er).
    """
    interface = body.interface or None
    duration = float(body.duration)
    try:
        neighbors = await asyncio.wait_for(capture_lldp(interface, duration), timeout=duration + 5)
        return [_neighbor_to_dict(n, time.time()) for n in neighbors]
    except Exception as exc:
        # Jeder Sniff-Fehler ODER Timeout -> 503 (Altcode-Naht, kein roher 500er).
        return JSONResponse(status_code=503, content={"error": str(exc)})


# ── topology ──────────────────────────────────────────────────────────────────


@router.get("/topology")
async def topology(
    build_topology_for: Annotated[BuildTopologyFactory, Depends(provide_build_topology)],
    source: TopologySource = "last_scan",
) -> dict[str, list[dict[str, Any]]]:
    """Radialer Heimnetz-Graph ``{nodes, edges}`` (Gateway-Zentrum, ADR 0035).

    ``?source=last_scan`` (Default) zeigt nur die Hosts des juengsten gespeicherten
    Scans (aktuelles Live-Bild); ``?source=all_known`` den gesamten device_repository-
    Bestand (alle je gesehenen Geraete, auch offline). Ein ungueltiger Wert -> 422
    (FastAPI-``Literal``-Validierung). Die Factory liefert den ``BuildTopology`` mit
    der passenden Host-Projektion -- die Use-Case-Logik kennt die Quelle nicht.

    Der Use-Case gibt rohe Domaenen-dicts (nodes/edges); dieser Rand baut die
    endgueltige Wire-Form. Ehrlicher Leerzustand: ohne Scan-Hosts/LLDP-Daten ist
    der Graph leer (``{"nodes": [], "edges": []}``) -- kein erfundener Inhalt.
    """
    graph = await build_topology_for(source)()
    return {
        "nodes": [_topology_node_to_dict(n) for n in graph["nodes"]],
        "edges": [
            {"source": e["source"], "target": e["target"], "kind": e["kind"]}
            for e in graph["edges"]
        ],
    }


def _topology_node_to_dict(node: dict[str, str]) -> dict[str, Any]:
    """Knoten-Roh-dict -> Wire-dict. Host-/Gateway-Knoten und Switch-/Netzwerk-
    Knoten tragen unterschiedliche Felder; der Rand reicht die vorhandenen durch
    (``.get`` mit Default), damit beide Formen stabil serialisieren.
    """
    return {
        "id": node.get("id", ""),
        "type": node.get("type", "host"),
        "ip": node.get("ip", ""),
        "mac": node.get("mac", ""),
        "hostname": node.get("hostname", ""),
        "vendor": node.get("vendor", ""),
        "description": node.get("description", ""),
        "port": node.get("port", ""),
        "protocol": node.get("protocol", ""),
    }
