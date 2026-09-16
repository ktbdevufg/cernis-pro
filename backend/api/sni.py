"""FastAPI-Router der sni-Domaene (v2) -- der passive SNI-Mitschnitt als REST.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich Use-Cases aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter, Ports und
``domain``-Typen werden hier NICHT importiert -- die Use-Cases/Callables kommen per
FastAPI-Dependency herein (Verdrahtung im Composition Root ``app.py``), und Domaenen-
Objekte werden ueber Attribut-Zugriff zu JSON serialisiert (Typ ``Any``, Muster wie
``api/capture._packet_to_dict``).

Endpunkte (Router prefix ``/api``, tags ``["sni"]``):

* ``POST /api/sni/start``    -> startet den Mitschnitt MANUELL. ok=false -> 403
  (Muster ``pcap/start``); Erfolg -> ``{ok, error, available}``.
* ``POST /api/sni/stop``     -> stoppt; idempotent ``{ok: True}``.
* ``GET  /api/sni/status``   -> ``{running, count, available, permission_error,
  stopped_reason}``.
* ``GET  /api/sni/observed`` -> Liste der erfassten + zugeordneten SNIs als Wire-dicts
  ``[{hostname, remote_ip, remote_port, app_name|null, pid|null, delta_ms|null, age_secs}]``.

Permission-/Verfuegbarkeitsfehler: der ``start``-Callable (Composition Root) prueft
ueber ``StartSniCapture`` und gibt ``{ok,error}``; ``ok=false`` -> 403 (Muster
``pcap/start``). Ein echter Start-Fehler des Adapters (``SniError``) wird am
Composition Root auf 503 gemappt (Muster ``DiagnosticsToolMissing``); der api-Ring
kennt diese Exception NICHT.

Wire-Projektion (``_observed_to_dict``) am api-Rand: ``age_secs`` aus dem monotonen
Erfassungs-Zeitstempel relativ zur hereingereichten ``now`` (``time.monotonic()``) --
die Domaene fuehrt nur ``monotonic_ts``, das "wie alt" rechnet der Rand.
"""

import time
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from application.sni import GetObservedSni, StartSniCapture

router = APIRouter(prefix="/api", tags=["sni"])


# Body-Modell (Muster ``api/capture.StartCaptureBody``): interface optional, leerer
# Body gueltig. Kein rohes Body(dict) (B008).
class StartSniBody(BaseModel):
    """POST /api/sni/start -- interface optional (leer -> Adapter waehlt selbst)."""

    interface: str = ""


# Composition-Root-Callable: prueft (StartSniCapture) und startet bei ok=True den
# Sniff als Task an app.state (create_task + app.state -- das kennt nur app.py). Gibt
# das ``{ok, error}``-Ergebnis zurueck (der Router formt 200/403 daraus).
type StartSniRunner = Callable[[str | None], dict[str, Any]]


def provide_start_sni() -> StartSniRunner:
    raise NotImplementedError("StartSniRunner wird in app.py verdrahtet")


# Composition-Root-Callable: stoppt den laufenden Sniff (RunSniCapture.stop()).
type StopSniRunner = Callable[[], None]


def provide_stop_sni() -> StopSniRunner:
    raise NotImplementedError("StopSniRunner wird in app.py verdrahtet")


# StartSniCapture-Use-Case (fuer status: running-naher Verfuegbarkeits-/Rechte-Check
# + available-Flag bei start-Erfolg). Im Composition Root mit dem Adapter verdrahtet.
def provide_start_sni_uc() -> StartSniCapture:
    raise NotImplementedError("StartSniCapture wird in app.py verdrahtet")


# Liefert den laufend-Zustand (RunSniCapture.is_running()) als Callable -- der
# Singleton-State lebt im Composition Root.
type SniRunningProvider = Callable[[], bool]


def provide_sni_running() -> SniRunningProvider:
    raise NotImplementedError("SniRunningProvider wird in app.py verdrahtet")


def provide_get_observed_sni() -> GetObservedSni:
    raise NotImplementedError("GetObservedSni wird in app.py verdrahtet")


# ── Serialisierungs-Helfer (Domaenen-Objekt -> Wire-dict am api-Rand) ─────────


def _observed_to_dict(obs: Any, now_monotonic: float) -> dict[str, Any]:
    """``ObservedSni`` -> Wire-dict + ``age_secs`` (relativ zur monotonen ``now``).

    ``age_secs`` = ``now_monotonic - obs.monotonic_ts`` (auf ganze Sekunden gerundet,
    nie negativ) -- der monotone Zeitstempel bleibt intern, der Rand liefert das
    Mensch-lesbare Alter. ``monotonic_ts`` selbst geht NICHT auf die Wire (es ist eine
    prozesslokale Uhr ohne Aussenbedeutung).
    """
    age_secs = max(0, round(now_monotonic - obs.monotonic_ts))
    return {
        "hostname": obs.hostname,
        "remote_ip": obs.remote_ip,
        "remote_port": obs.remote_port,
        "app_name": obs.app_name,
        "pid": obs.pid,
        "delta_ms": obs.delta_ms,
        "age_secs": age_secs,
    }


@router.post("/sni/start")
async def sni_start(
    start_sni: Annotated[StartSniRunner, Depends(provide_start_sni)],
    start_sni_uc: Annotated[StartSniCapture, Depends(provide_start_sni_uc)],
    body: StartSniBody | None = None,
) -> Any:
    """Startet den passiven SNI-Mitschnitt (MANUELL). Erfolg -> ``{ok, error, available}``;
    sonst 403 ``{ok, error}``.

    BEWUSST ``async`` (Muster ``traffic/poll/start``): der ``start_sni``-Callable ruft
    ``asyncio.create_task`` -- das braucht einen laufenden Event-Loop. Der Callable
    selbst bleibt synchron; er prueft (StartSniCapture) + startet bei ok=True und gibt
    ``{ok, error}`` zurueck. Bei Erfolg haengt der Rand ``available`` an (Muster
    ``pcap/start``); bei ``ok=False`` -> 403 mit dem Body UNVERAENDERT.

    Der Body ist OPTIONAL (Muster pcap/start: alle Felder optional): ein ``curl`` ganz
    OHNE Body laeuft (interface -> None, der Adapter waehlt das Interface selbst). Ein
    leerer Body ``{}`` oder ``{"interface": "ens33"}`` funktioniert genauso.
    """
    interface = (body.interface or None) if body is not None else None
    result = start_sni(interface)
    if not result["ok"]:
        return JSONResponse(status_code=403, content=result)
    return {**result, "available": start_sni_uc.is_available()}


@router.post("/sni/stop")
def sni_stop(
    stop_sni: Annotated[StopSniRunner, Depends(provide_stop_sni)],
) -> dict[str, bool]:
    """Stoppt den Mitschnitt. Immer ``{ok: True}`` (idempotent, kein Zustands-Check)."""
    stop_sni()
    return {"ok": True}


@router.get("/sni/status")
def sni_status(
    running_provider: Annotated[SniRunningProvider, Depends(provide_sni_running)],
    get_observed: Annotated[GetObservedSni, Depends(provide_get_observed_sni)],
    start_sni_uc: Annotated[StartSniCapture, Depends(provide_start_sni_uc)],
) -> dict[str, Any]:
    """Aktueller Status: ``{running, count, available, permission_error, stopped_reason}``.

    ``count`` ist die Anzahl der bisher erfassten SNIs (Laenge der Momentaufnahme).
    ``available``/``permission_error`` kommen aus ``StartSniCapture`` (scapy da? +
    Rechte-Begruendung oder ``null``).

    ``stopped_reason`` (Befund 30) kommt ueber DENSELBEN Weg wie ``permission_error``
    (``StartSniCapture`` -> Port) und traegt den stabilen Marker, falls die Aufzeichnung
    von SELBST endete -- sonst ``null``. Zusammen mit ``running`` ergibt das die bis
    dahin fehlende Aussage: ``running=false`` UND ein gesetzter ``stopped_reason``
    heisst "der Mitschnitt ist abgebrochen", nicht "er wurde nie gestartet".
    """
    return {
        "running": running_provider(),
        "count": len(get_observed()),
        "available": start_sni_uc.is_available(),
        "permission_error": start_sni_uc.check_permission(),
        "stopped_reason": start_sni_uc.stopped_reason(),
    }


@router.get("/sni/observed")
def sni_observed(
    get_observed: Annotated[GetObservedSni, Depends(provide_get_observed_sni)],
) -> list[dict[str, Any]]:
    """Die erfassten + zugeordneten SNIs als Wire-dicts (mit ``age_secs``).

    Nicht zuordenbare Hits (rootless / kein Match) tragen ``app_name``/``pid``/
    ``delta_ms`` ``null`` (ehrliche Luecke, kein Verwerfen). ``now`` einmal frisch
    gegriffen, damit alle Eintraege gegen denselben Bezugspunkt altern.
    """
    now_monotonic = time.monotonic()
    return [_observed_to_dict(obs, now_monotonic) for obs in get_observed()]
