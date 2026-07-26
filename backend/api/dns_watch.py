"""FastAPI-Router des DNS-Waechters (Block 2, Etappe 2d-3), prefix ``/api/dns-watch``.

Aeusserer Ring: nimmt HTTP entgegen. Wie ``api/outbound.py`` (und ``api/maintenance.py``)
kennt dieser Router WEDER ``application`` NOCH ``infrastructure`` NOCH ``modules``
(Regel 4): die injizierten Runner kommen als schmale lokale Vertraege per Dependency
herein, verdrahtet im Composition Root (``app.py``).

Damit der api-Ring application-frei bleibt UND der Aufruf trotzdem typsicher ist (mypy
strict), beschreibt ein schmales lokales ``Protocol`` den Vertrag des injizierten
Lese-Runners (eine ``async``-Methode, die die fertig projizierte Sicht liefert), und ein
``Callable`` den des Schreib-Runners (ack/unack). Der api-Ring definiert eigene schmale
pydantic-Response-Modelle (``DnsContactOut``/``DnsWatchOverviewOut``); die Projektion vom
application-Typ ``DnsWatchOverview`` auf diese Wire-Form macht der Composition-Root-Runner
in ``app.py``, NICHT der Router -- so nennt der api-Ring den application-Typ nie.

Endpunkte:

* ``GET /api/dns-watch`` -> die ``DnsWatchOverview`` DIESES Hosts (DNS-relevante
  Aussenkontakte + Listen + Scope-Marker). NUR die Verbindungen DIESES CERNIS-Hosts,
  nichts Netzweites (S3-ehrlich; der Scope-Marker traegt das als reines Datum).
* ``POST /api/dns-watch/acknowledge`` -> quittiert (oder entquittiert) einen Befund
  pro (remote_ip, category) ueber den injizierten Schreib-Runner. ``{"ok": true}``.

Der Settings-Key-Name der DoH-Liste lebt hier als Modulkonstante (der Composition Root
liest diese editierbare Liste ueber die bestehende Settings-Naht; es ist ein normales
Listen-Setting, KEINE Aenderung an ``domain/settings``). Er steht im api-Ring, weil hier
der DNS-Waechter-Vertrag liegt; ``app.py`` re-importiert ihn an der Lesestelle.

Die frueher daneben stehende erwartete-Server-Liste hat KEINEN eigenen Settings-Key mehr
(S62 L7a): die erwartete Menge kommt aus dem Vertrauensmodell (``dns_trust``), nicht aus
einer separat gepflegten Einstellung. Der Altbestand des entfallenen Schluessels wird
beim Start einmalig in die Vertrauens-Tabelle uebernommen
(``infrastructure/_dns_expected_migration.py``).
"""

from collections.abc import Callable
from typing import Annotated, Literal, Protocol

from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter(prefix="/api/dns-watch", tags=["dns_watch"])

# ── Settings-Key-Name (normales Listen-Setting, value = JSON-Liste von IP-Strings) ──
# Die EINE verbliebene editierbare Liste des DNS-Waechters (bekannte DoH-Anbieter) liegt
# ueber die bestehende Settings-Naht (value=Any). KEINE Settings-Domaenen-Aenderung --
# nur der Name.
DNS_DOH_PROVIDERS_KEY = "dns_doh_providers"


# ── schmale api-Response-Modelle (eigene Wire-Form, KEIN application-Typ) ──────
# Die Felder spiegeln ``application.dns_watch.DnsContact``/``DnsWatchOverview``, ohne
# diese Typen zu importieren. Der Composition-Root-Runner projiziert die
# application-Sicht auf genau diese Form (Regel 4: api kennt application nicht).


class DnsContactOut(BaseModel):
    """Ein aggregierter DNS-relevanter Befund DIESES Hosts (eine Remote-IP + Kategorie)."""

    remote_ip: str
    remote_port: int | None
    category: str
    hostname: str | None
    app_name: str | None
    pid: int | None
    connection_count: int
    acknowledged: bool


class DnsWatchOverviewOut(BaseModel):
    """Die Gesamtsicht: alle DNS-relevanten Befunde DIESES Hosts + Marker und Listen.

    ``host_scope`` ist ein FESTER Marker-Schluessel (z. B. ``"local_host"``), der
    ehrlich festhaelt, dass dies die Befunde DIESES Rechners sind und NICHT netzweit.
    ``expected_servers``/``doh_providers`` sind die zur Klassifikation genutzten,
    editierbaren Listen (ehrlicher Beleg, was der Befund bedeutet).
    """

    contacts: list[DnsContactOut]
    host_scope: str
    counts: dict[str, int]
    expected_servers: list[str]
    doh_providers: list[str]


# ── injizierte Composition-Root-Runner ────────────────────────────────────────
# Provider-Marker: in app.py per dependency_overrides mit den echten Root-Runnern
# verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (kein stiller Fallback, S3).


class DnsWatchRunner(Protocol):
    """Schmaler Vertrag des injizierten Lese-Runners (liefert die fertige Sicht)."""

    async def __call__(self) -> DnsWatchOverviewOut:
        """Baut die DNS-Waechter-Sicht DIESES Hosts und liefert sie api-fertig."""
        ...


def provide_dns_watch() -> DnsWatchRunner:
    raise NotImplementedError("DnsWatchRunner wird in app.py verdrahtet")


# Schreib-Runner: quittiert/entquittiert einen Befund (remote_ip, category, action) ->
# None. Der api-Ring kennt das Repository (``SqliteDnsWatchAcknowledgementRepository``)
# NICHT direkt (api -> nur Dependency); das Callable wird im Composition Root
# verdrahtet. Synchron (lokaler SQLite-Schreibzugriff).
type DnsWatchAcknowledgeRunner = Callable[[str, str, str], None]


def provide_dns_watch_acknowledge() -> DnsWatchAcknowledgeRunner:
    raise NotImplementedError("DnsWatchAcknowledgeRunner wird in app.py verdrahtet")


class AcknowledgeBody(BaseModel):
    """POST /api/dns-watch/acknowledge -- ein Quittier-Befehl pro (remote_ip, category).

    ``action`` ist ein ``Literal``-Feld: ein anderer Wert -> HTTP 422 (pydantic-
    Validierung), nicht ein leiser Durchlauf (S3). ``ack`` markiert den Befund als
    bekannt (nimmt die Faerbung weg), ``unack`` stellt ihn wieder scharf -- KEIN
    Loeschen, die History bleibt vollstaendig (append-only Log im Repository).
    """

    remote_ip: str
    category: str
    action: Literal["ack", "unack"]


# ── Routen ───────────────────────────────────────────────────────────────────


@router.get("")
async def get_dns_watch(
    runner: Annotated[DnsWatchRunner, Depends(provide_dns_watch)],
) -> DnsWatchOverviewOut:
    """Liefert die ``DnsWatchOverview`` DIESES Hosts (Befunde + Listen + ``host_scope``)."""
    return await runner()


@router.post("/acknowledge")
def acknowledge(
    body: AcknowledgeBody,
    record: Annotated[DnsWatchAcknowledgeRunner, Depends(provide_dns_watch_acknowledge)],
) -> dict[str, bool]:
    """Quittiert (oder entquittiert) einen DNS-Waechter-Befund pro (remote_ip, category).

    Schreibt EINE append-only Log-Zeile (ack/unack) ueber den Composition-Root-Runner;
    der effektive Status eines (remote_ip, category) ergibt sich aus dem jeweils
    JUENGSTEN Eintrag. ``ack`` nimmt die Faerbung dauerhaft weg, ``unack`` stellt den
    Befund wieder scharf -- KEIN Loeschen. ``action`` per Body-Constraint erzwungen
    (Muell -> 422). Erfolg -> 200 ``{"ok": true}``.
    """
    record(body.remote_ip, body.category, body.action)
    return {"ok": True}
