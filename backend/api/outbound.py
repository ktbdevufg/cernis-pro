"""FastAPI-Router der outbound-Domaene (v2), prefix ``/api/outbound``.

Aeusserer Ring: nimmt HTTP entgegen. Wie ``api/maintenance.py`` (NICHT wie die
domaenen-Router, die ihre Use-Case-Klassen aus ``application`` importieren) kennt
dieser Router WEDER ``application`` NOCH ``infrastructure`` NOCH ``modules``
(Regel 4): der Aussenkontakt-Runner kommt als schmales lokales ``Protocol`` per
Dependency herein, verdrahtet im Composition Root (``app.py``).

Damit der api-Ring application-frei bleibt UND der Router-Aufruf trotzdem
typsicher ist (mypy strict), beschreibt ein schmales lokales ``Protocol`` den
Vertrag des injizierten Runners: ein Objekt mit genau einer ``async``-Methode, die
die fertig projizierte Sicht liefert. Anders als bei maintenance ist die Form hier
REICHER als ein ``{"ok": true}`` -- der api-Ring definiert deshalb eigene schmale
pydantic-Response-Modelle (``OutboundContactOut``/``OutboundOverviewOut``), und der
Runner liefert genau diese ``OutboundOverviewOut`` zurueck. Die Projektion vom
application-Typ ``OutboundOverview`` auf diese api-Form macht der
Composition-Root-Runner in ``app.py``, NICHT der Router -- so nennt der api-Ring den
application-Typ nie und bleibt application-frei.

Endpunkt:

* ``GET /api/outbound/contacts`` -> die ``OutboundOverview`` DIESES Hosts als JSON
  (Aussenkontakte + ``host_scope``-Marker). NUR die Verbindungen DIESES CERNIS-Hosts,
  nichts Netzweites (S3-ehrlich; der Scope-Marker traegt das als reines Datum).
"""

from typing import Annotated, Protocol

from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter(prefix="/api/outbound", tags=["outbound"])


# ── schmale api-Response-Modelle (eigene Wire-Form, KEIN application-Typ) ──────
# Die Felder spiegeln ``application.outbound.OutboundContact``/``OutboundOverview``,
# ohne diese Typen zu importieren. Der Composition-Root-Runner projiziert die
# application-Sicht auf genau diese Form (Regel 4: api kennt application nicht).


class OutboundContactOut(BaseModel):
    """Ein aggregierter Aussenkontakt DIESES Hosts (eine Remote-IP, angereichert)."""

    remote_ip: str
    remote_port: int | None
    hostname: str | None
    country: str | None
    operator: str | None
    asn: str | None
    app_name: str | None
    pid: int | None
    connection_count: int


class OutboundOverviewOut(BaseModel):
    """Die Gesamtsicht: alle Aussenkontakte DIESES Hosts + der Scope-Marker.

    ``host_scope`` ist ein FESTER Marker-Schluessel (z. B. ``"local_host"``), der
    ehrlich festhaelt, dass dies die Kontakte DIESES Rechners sind und NICHT netzweit.
    """

    contacts: list[OutboundContactOut]
    host_scope: str


# ── injizierter Composition-Root-Runner ───────────────────────────────────────
# Provider-Marker: in app.py per dependency_overrides mit dem echten Root-Runner
# verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (kein stiller Fallback,
# S3). Das ``...Runner``-Protocol beschreibt strukturell die eine ``async``-Methode,
# ohne dass der api-Ring ``application`` importiert. Der Runner liefert die bereits
# projizierte ``OutboundOverviewOut`` (api-Typ) -- die Projektion macht der Root.


class OutboundContactsRunner(Protocol):
    """Schmaler Vertrag des injizierten Root-Runners (liefert die fertige Sicht)."""

    async def __call__(self) -> OutboundOverviewOut:
        """Baut die Aussenkontakt-Sicht DIESES Hosts und liefert sie api-fertig."""
        ...


def provide_outbound_contacts() -> OutboundContactsRunner:
    raise NotImplementedError("OutboundContactsRunner wird in app.py verdrahtet")


# ── Routen ───────────────────────────────────────────────────────────────────


@router.get("/contacts")
async def get_outbound_contacts(
    runner: Annotated[OutboundContactsRunner, Depends(provide_outbound_contacts)],
) -> OutboundOverviewOut:
    """Liefert die ``OutboundOverview`` DIESES Hosts (Aussenkontakte + ``host_scope``)."""
    return await runner()
