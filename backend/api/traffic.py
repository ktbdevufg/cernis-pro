"""FastAPI-Router der traffic-Domaene (v2, T.3), Routen ``GET /api/traffic`` +
``GET /api/traffic/permission``.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich die Use-Cases aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter und
``domain``-Typen werden hier NICHT importiert -- die Use-Cases kommen per
FastAPI-Dependency herein (Verdrahtung im Composition Root ``app.py``), und die
Domaenen-Aggregate werden ueber Attribut-Zugriff zu JSON serialisiert (Typ ``Any``,
Muster wie ``api/scanning._host_to_dict`` fuer verschachtelte Aggregate).

``GET /api/traffic`` liefert die App-Uebersicht: eine Liste von Apps, jede mit den
eingebetteten Verbindungen. Nicht zuordenbare Verbindungen (rootless) erscheinen als
App mit ``app_name=null`` (die ehrliche None-Gruppe). Die Durchsatz-Felder
(``*_rate_bps``) sind ``null``, solange kein Poller laeuft; mit laufendem Poller
(``POST /traffic/poll/start`` oder AUTO) traegt der Composition-Root-Runner die
Raten je Socket nach (``current_rates`` -> ``ListAppTraffic``).

``POST /api/traffic/poll/start`` + ``/stop`` steuern den Durchsatz-Poller on-demand
(MANUELL, Muster capture ``/pcap/start``). ``GET /api/traffic/permission`` liefert
die ``{ok, error}``-Rechte-Naht (``CheckTrafficPermission``): ``ok=false`` + Hinweis,
wenn der Durchsatz aller Apps erhoehte Rechte braucht.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends

from application.traffic import CheckTrafficPermission

router = APIRouter(prefix="/api", tags=["traffic"])


# Composition-Root-Callable (Muster capture ``StartCaptureRunner``): kombiniert die
# Raten des laufenden Pollers (``PollThroughput.current_rates`` ueber ``app.state``)
# mit ``ListAppTraffic`` und liefert die angereicherte Domaenen-AppTraffic-Liste
# (der Router serialisiert sie weiter -- die Wire-Projektion bleibt am Rand). Als
# Callable injiziert, weil die Kombination app.state-State kennt (das kennt NUR der
# Composition Root, nicht der api-Ring). Ohne laufenden Poller -> Raten None
# (ehrliche Stufe 1). ``list[Any]`` -- die AppTraffic-Objekte bleiben dem Router als
# ``Any`` (kein domain-Import im api-Ring).
type ListAppTrafficRunner = Callable[[], Awaitable[list[Any]]]

# Composition-Root-Callables fuer den MANUELL-Poll-Lebenszyklus (Muster capture
# ``StartCaptureRunner``/``StopCaptureRunner``): das ``asyncio.create_task`` + den
# ``app.state``-Task kapselt der Composition Root, nicht der api-Ring.
type StartPollRunner = Callable[[], dict[str, Any]]
type StopPollRunner = Callable[[], None]


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit den
# echten Callables/Use-Cases verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler.
def provide_list_app_traffic() -> ListAppTrafficRunner:
    raise NotImplementedError("ListAppTrafficRunner wird in app.py verdrahtet")


def provide_check_traffic_permission() -> CheckTrafficPermission:
    raise NotImplementedError("CheckTrafficPermission wird in app.py verdrahtet")


def provide_start_poll() -> StartPollRunner:
    raise NotImplementedError("StartPollRunner wird in app.py verdrahtet")


def provide_stop_poll() -> StopPollRunner:
    raise NotImplementedError("StopPollRunner wird in app.py verdrahtet")


def _endpoint_to_dict(endpoint: Any) -> dict[str, Any] | None:
    # endpoint ist ein domain.Endpoint oder None; abwesend bleibt null (kein leeres
    # Objekt-Sentinel -- die Wire-Form spiegelt den ehrlichen None-Zustand).
    if endpoint is None:
        return None
    return {"ip": endpoint.ip, "port": endpoint.port}


def _conn_to_dict(conn: Any) -> dict[str, Any]:
    # conn ist eine domain.Connection; per Attribut-Zugriff serialisiert (kein
    # domain-Import). Stufe-2-Felder sind in Stufe 1 null.
    return {
        "l4": conn.l4,
        "status": conn.status,
        "local": _endpoint_to_dict(conn.local),
        "remote": _endpoint_to_dict(conn.remote),
        "pid": conn.pid,
        "app_name": conn.app_name,
        "bytes_sent": conn.bytes_sent,
        "bytes_received": conn.bytes_received,
        "send_rate_bps": conn.send_rate_bps,
        "recv_rate_bps": conn.recv_rate_bps,
    }


def _app_to_dict(app: Any) -> dict[str, Any]:
    # app ist ein domain.AppTraffic mit eingebetteten Connections; Muster
    # _host_to_dict (verschachtelte Liste, tuple->list). app_name=None bleibt null
    # (die ehrliche "nicht zuordenbar"-Gruppe).
    return {
        "app_name": app.app_name,
        "pids": list(app.pids),
        "connection_count": app.connection_count,
        "total_send_rate_bps": app.total_send_rate_bps,
        "total_recv_rate_bps": app.total_recv_rate_bps,
        "connections": [_conn_to_dict(c) for c in app.connections],
    }


@router.get("/traffic")
async def list_app_traffic(
    list_app_traffic: Annotated[ListAppTrafficRunner, Depends(provide_list_app_traffic)],
) -> list[dict[str, Any]]:
    """Per-App-Verbindungssicht: Apps mit eingebetteten Verbindungen + Durchsatz.

    Nicht zuordenbare Verbindungen (rootless, ``pid=None``) erscheinen als App mit
    ``app_name=null`` (ehrliche None-Gruppe). Die Durchsatz-Felder (``*_rate_bps``)
    sind ``null``, solange kein Poller laeuft -- sobald ``POST /traffic/poll/start``
    (oder AUTO) den Poller gestartet hat, traegt der Runner die Raten je Socket nach.
    """
    apps = await list_app_traffic()
    return [_app_to_dict(app) for app in apps]


@router.post("/traffic/poll/start")
async def start_traffic_poll(
    start_poll: Annotated[StartPollRunner, Depends(provide_start_poll)],
) -> dict[str, Any]:
    """Startet den Durchsatz-Poller (MANUELL). Idempotent -> ``{ok: True}``.

    Ab dem zweiten tick (Default 1s) traegt ``GET /api/traffic`` die Raten. Ein
    bereits laufender Poller wird nicht doppelt gestartet (Muster capture).

    BEWUSST ``async``: der ``start_poll``-Callable ruft ``asyncio.create_task`` --
    das braucht einen laufenden Event-Loop. Ein synchroner Endpunkt liefe im
    Starlette-Threadpool OHNE Loop (``RuntimeError: no running event loop``). Der
    ``async``-Endpunkt laeuft im Loop, der Callable selbst bleibt synchron.
    """
    return start_poll()


@router.post("/traffic/poll/stop")
def stop_traffic_poll(
    stop_poll: Annotated[StopPollRunner, Depends(provide_stop_poll)],
) -> dict[str, bool]:
    """Stoppt den Durchsatz-Poller. Immer ``{ok: True}`` (kein Zustands-Check)."""
    stop_poll()
    return {"ok": True}


@router.get("/traffic/permission")
def get_traffic_permission(
    check_permission_uc: Annotated[
        CheckTrafficPermission, Depends(provide_check_traffic_permission)
    ],
) -> dict[str, Any]:
    """Rechte-Status fuer den Durchsatz aller Apps (Stufe 2).

    ``{ok, error}``-Form: ``ok=true`` bei voller Sicht (Root/CAP_NET_ADMIN), sonst
    ``ok=false`` + handlungsorientierter Hinweis (Stufe 1 bleibt nutzbar).
    """
    return check_permission_uc()
