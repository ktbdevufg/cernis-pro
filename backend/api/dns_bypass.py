"""FastAPI-Router des netzweiten DNS-Umgehungs-Waechters (ADR 0042, Etappe 4b), prefix
``/api/dns-bypass``.

Aeusserer Ring: nimmt HTTP entgegen. Wie ``api/dns_watch.py`` (und ``api/outbound.py``)
kennt dieser Router WEDER ``application`` NOCH ``infrastructure`` NOCH ``modules``
(Regel 4): die injizierten Runner kommen als schmale lokale Vertraege per Dependency
herein, verdrahtet im Composition Root (``app.py``).

Damit der api-Ring application-frei bleibt UND der Aufruf trotzdem typsicher ist (mypy
strict), beschreibt je ein schmales lokales ``Protocol``/``Callable`` den Vertrag der
injizierten Runner (Lesen der verdichteten Sicht, billiger Status-Poll, Start/Stop der
Aufzeichnung). Der api-Ring definiert eigene schmale pydantic-Response-Modelle
(``DnsBypassFindingOut``/``DnsBypassOverviewOut``/``DnsBypassStatusOut``); die Projektion
vom application-Typ ``DnsBypassOverview`` auf diese Wire-Form UND die Geraete-/DoH-
Zuordnung machen die Composition-Root-Runner in ``app.py``, NICHT der Router -- so nennt
der api-Ring den application-Typ nie.

Endpunkte:

* ``GET /api/dns-bypass`` -> die verdichtete netzweite Umgehungs-Sicht (je Umgehung ein
  Befund mit best-effort Geraetename + DoH-Bewertung, plus Zaehler und ``recording``).
* ``GET /api/dns-bypass/status`` -> billiger Status-Poll (laeuft die Aufzeichnung? wie
  viele Anfragen sind gesammelt?), ohne die teure Verdichtung.
* ``POST /api/dns-bypass/start`` -> startet die Aufzeichnung ON-DEMAND (Body
  ``{interface?}``). Der Helfer-Start kann legitim scheitern (z. B. keine Rechte): ein
  Fehlertext wird als ``{"ok": false, "error": <text>}`` mit HTTP 200 ehrlich
  durchgereicht (kein 500 -- S3, kein stiller Fallback).
* ``POST /api/dns-bypass/stop`` -> stoppt die Aufzeichnung. ``{"ok": true}``.
"""

from collections.abc import Callable
from typing import Annotated, Protocol

from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter(prefix="/api/dns-bypass", tags=["dns_bypass"])


# ── schmale api-Response-Modelle (eigene Wire-Form, KEIN application-Typ) ──────
# Die Felder spiegeln ``application.dns_bypass.DnsBypassFinding``/``DnsBypassOverview``,
# ohne diese Typen zu importieren. Der Composition-Root-Runner projiziert die
# application-Sicht auf genau diese Form und reichert sie um Geraetename + DoH-Bewertung
# an (Regel 4/5: api kennt application nicht; die Zuordnung faellt nur im Root).


class DnsBypassFindingOut(BaseModel):
    """Ein aggregierter Umgehungs-Befund = EINE (``src_ip``, ``dst_ip``)-Gruppe.

    ``device_name`` ist der best-effort im Bestand gefundene Anzeigename der Quell-IP
    (``None`` wenn keine IP passt -- Option 2, kein harter Identitaets-Anspruch);
    ``is_doh``/``doh_source_name`` sind die im Composition Root ueber die eigene
    DoH-Lookup-Naht ermittelte Bewertung des Ziels (Quellenname der treffenden aktiven
    DOH-Quelle, sonst ``None``).
    """

    src_ip: str
    device_name: str | None
    dst_ip: str
    is_doh: bool
    doh_source_name: str | None
    query_count: int
    sample_qnames: list[str]


class DnsBypassOverviewOut(BaseModel):
    """Die verdichtete netzweite Umgehungs-Sicht: alle Befunde + Zaehler + ``recording``.

    ``expected_servers`` ist die zur Klassifikation genutzte erwartete-Resolver-Menge
    (ehrlicher Beleg, was der Befund bedeutet). ``recording`` sagt ehrlich, ob die
    Aufzeichnung gerade laeuft (ein Leerbefund bei ``recording=false`` bedeutet: es wird
    nicht mitgelesen, nicht "alles sauber").
    """

    findings: list[DnsBypassFindingOut]
    expected_servers: list[str]
    queries_total: int
    bypass_total: int
    expected_total: int
    bypass_devices: int
    recording: bool


class DnsBypassStatusOut(BaseModel):
    """Billiger Status-Poll: laeuft die Aufzeichnung? wie viele Anfragen sind gesammelt?

    Bewusst OHNE die teure Verdichtung (``BuildDnsBypass``) -- nur der laufende Zustand
    des Recorders, damit die UI guenstig pollen kann.
    """

    recording: bool
    collected_queries: int


# ── injizierte Composition-Root-Runner ────────────────────────────────────────
# Provider-Marker: in app.py per dependency_overrides mit den echten Root-Runnern
# verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (kein stiller Fallback, S3).


class DnsBypassViewRunner(Protocol):
    """Schmaler Vertrag des injizierten Lese-Runners (liefert die fertige Sicht)."""

    async def __call__(self) -> DnsBypassOverviewOut:
        """Baut die verdichtete netzweite Umgehungs-Sicht und liefert sie api-fertig."""
        ...


def provide_dns_bypass_view() -> DnsBypassViewRunner:
    raise NotImplementedError("DnsBypassViewRunner wird in app.py verdrahtet")


# Start-Runner: startet die Aufzeichnung ON-DEMAND fuer ein optionales Interface und gibt
# ``None`` bei Erfolg oder einen ehrlichen Fehlertext zurueck (der Helfer-Start kann
# legitim scheitern). Synchron -- der Recorder-Start ist ein lokaler Steuerbefehl.
type DnsBypassStartRunner = Callable[[str | None], str | None]


def provide_dns_bypass_start() -> DnsBypassStartRunner:
    raise NotImplementedError("DnsBypassStartRunner wird in app.py verdrahtet")


# Stop-Runner: stoppt die Aufzeichnung (idempotent/best-effort) -> None.
type DnsBypassStopRunner = Callable[[], None]


def provide_dns_bypass_stop() -> DnsBypassStopRunner:
    raise NotImplementedError("DnsBypassStopRunner wird in app.py verdrahtet")


class DnsBypassStatusRunner(Protocol):
    """Schmaler Vertrag des injizierten Status-Runners (billiger Poll, keine Verdichtung)."""

    def __call__(self) -> DnsBypassStatusOut:
        """Liefert den laufenden Zustand des Recorders (recording + collected_queries)."""
        ...


def provide_dns_bypass_status() -> DnsBypassStatusRunner:
    raise NotImplementedError("DnsBypassStatusRunner wird in app.py verdrahtet")


class StartBody(BaseModel):
    """POST /api/dns-bypass/start -- optionales Interface fuer die Aufzeichnung.

    ``interface`` ist ``None`` -> der Helfer waehlt sein Default-Interface (netzweiter
    Sniff mit ``promisc=True``, ADR 0042).
    """

    interface: str | None = None


# ── Routen ───────────────────────────────────────────────────────────────────


@router.get("")
async def get_dns_bypass(
    runner: Annotated[DnsBypassViewRunner, Depends(provide_dns_bypass_view)],
) -> DnsBypassOverviewOut:
    """Liefert die verdichtete netzweite DNS-Umgehungs-Sicht (Befunde + Zaehler + Status)."""
    return await runner()


@router.get("/status")
def get_dns_bypass_status(
    runner: Annotated[DnsBypassStatusRunner, Depends(provide_dns_bypass_status)],
) -> DnsBypassStatusOut:
    """Billiger Status-Poll: laeuft die Aufzeichnung? wie viele Anfragen sind gesammelt?"""
    return runner()


@router.post("/start")
async def start_dns_bypass(
    body: StartBody,
    runner: Annotated[DnsBypassStartRunner, Depends(provide_dns_bypass_start)],
) -> dict[str, object]:
    """Startet die Aufzeichnung ON-DEMAND (Muster pcap-Capture): Task erst bei Bedarf.

    Der Helfer-Start kann legitim scheitern (z. B. keine Rechte): ein Fehlertext wird
    ehrlich als ``{"ok": false, "error": <text>}`` mit HTTP 200 durchgereicht -- KEIN 500,
    kein stiller Fallback (S3). Erfolg (``None``) -> ``{"ok": true}``.

    BEWUSST ``async`` (Muster ``traffic.start_traffic_poll``): der Composition-Root-
    Runner ruft ``asyncio.create_task`` -- das braucht einen laufenden Event-Loop. Ein
    synchroner Endpunkt liefe im Starlette-Threadpool OHNE Loop (``RuntimeError: no
    running event loop``). Der ``async``-Endpunkt laeuft im Loop; der ``runner``-Callable
    selbst bleibt synchron und wird weiterhin OHNE ``await`` aufgerufen.
    """
    error = runner(body.interface)
    if error is not None:
        return {"ok": False, "error": error}
    return {"ok": True}


@router.post("/stop")
def stop_dns_bypass(
    runner: Annotated[DnsBypassStopRunner, Depends(provide_dns_bypass_stop)],
) -> dict[str, bool]:
    """Stoppt die Aufzeichnung (idempotent/best-effort). ``{"ok": true}``."""
    runner()
    return {"ok": True}
