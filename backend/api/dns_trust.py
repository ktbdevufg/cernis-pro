"""FastAPI-Router des DNS-Server-Vertrauensmodells (ADR 0043, Etappe 5), prefix ``/api/dns-trust``.

Aeusserer Ring: nimmt HTTP entgegen. Wie ``api/dns_watch.py`` (Vorbild dieses Blocks)
kennt dieser Router WEDER ``application`` NOCH ``infrastructure`` NOCH ``modules``
(Regel 4): die injizierten Runner kommen als schmale lokale Vertraege per Dependency
herein, verdrahtet im Composition Root (``app.py``).

Damit der api-Ring application-frei bleibt UND der Aufruf trotzdem typsicher ist (mypy
strict), beschreibt ein schmales lokales ``Protocol`` den Vertrag des injizierten
Lese-Runners (liefert die fertig projizierte Sicht), und ein ``Callable`` den des
Schreib-Runners (trust/reject/reset). Der api-Ring definiert eigene schmale pydantic-
Response-Modelle (``TrustedDnsServerOut``/``DnsServerPlausibilityOut``); die Projektion vom
application-Typ (``TrustedDnsServer`` + ``DnsServerPlausibility``) auf diese Wire-Form macht
der Composition-Root-Runner in ``app.py``, NICHT der Router -- so nennt der api-Ring den
application-Typ nie.

Endpunkte:

* ``GET /api/dns-trust`` -> die kuratierten DNS-Server (``ListDnsTrustServers``), je Server
  Kategorie + Vertrauens-Zustand + best-effort Bestands-Indizien (Plausibilitaet). Die
  Reihenfolge ist die des Use-Case/Repos: nach ``first_seen`` AUFSTEIGEND -- deterministisch
  (aeltester zuerst), ohne Re-Sortierung im Router.
* ``POST /api/dns-trust/decision`` -> vertraut/lehnt ab/setzt zurueck EINEN Server pro ``ip``
  ueber den injizierten Schreib-Runner (``SetDnsServerTrust``). ``{"ok": true}``. KEIN Loeschen
  hier (Loeschen kommt spaeter in der Wartungsrubrik).

Die ``now``-Uhr faellt NICHT im Router, sondern am Rand (Composition Root / Runner-Wrapper);
der Router reicht nur ``ip`` + ``decision`` durch.
"""

from collections.abc import Callable
from typing import Annotated, Literal, Protocol

from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter(prefix="/api/dns-trust", tags=["dns_trust"])


# ── schmale api-Response-Modelle (eigene Wire-Form, KEIN application-Typ) ──────
# Die Felder spiegeln ``application.dns_trust.DnsServerPlausibility`` bzw.
# ``domain.dns_trust.TrustedDnsServer``, ohne diese Typen zu importieren. Der
# Composition-Root-Runner projiziert die application-Sicht auf genau diese Form
# (Regel 4: api kennt application/domain nicht).


class DnsServerPlausibilityOut(BaseModel):
    """Rein deskriptive Bestands-Indizien zu EINER DNS-Server-IP (Wire-Form).

    Spiegelt ``application.dns_trust.DnsServerPlausibility``: ``in_inventory`` (die IP
    ist ein bekanntes Geraet), ``first_seen_days`` (Alter in ganzen Tagen, ``None`` wenn
    unbekannt), ``vendor``/``display_name`` (best-effort Namen, ``""`` moeglich),
    ``open_ports`` (bekannte offene Ports). KEINE Wertung -- die traegt ``trust_state``.
    """

    in_inventory: bool
    first_seen_days: int | None
    vendor: str
    open_ports: list[int]
    display_name: str


class TrustedDnsServerOut(BaseModel):
    """Ein kuratierter DNS-Server samt Kategorie, Vertrauens-Zustand und Indizien (Wire-Form).

    Spiegelt ``domain.dns_trust.TrustedDnsServer``: ``category`` (faktische Einordnung)
    und ``trust_state`` (Nutzer-Wertung) sind ihre ``str``-Werte. ``plausibility`` ist die
    beigestellte Bestands-Sicht -- ``None``, wenn die IP kein bekanntes Geraet ist.
    """

    ip: str
    category: str
    trust_state: str
    first_seen: float
    last_seen: float
    display_name: str
    notes: str
    plausibility: DnsServerPlausibilityOut | None


# ── injizierte Composition-Root-Runner ────────────────────────────────────────
# Provider-Marker: in app.py per dependency_overrides mit den echten Root-Runnern
# verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (kein stiller Fallback, S3).


class DnsTrustListRunner(Protocol):
    """Schmaler Vertrag des injizierten Lese-Runners (liefert die fertige Server-Liste).

    Synchron (rein lesend, lokaler SQLite-Zugriff -- ``ListDnsTrustServers`` ist sync);
    die Projektion application -> Wire-Form macht der Composition Root, nicht der Router.
    """

    def __call__(self) -> list[TrustedDnsServerOut]:
        """Liest die kuratierten Server und liefert sie api-fertig (nach first_seen sortiert)."""
        ...


def provide_dns_trust_list() -> DnsTrustListRunner:
    raise NotImplementedError("DnsTrustListRunner wird in app.py verdrahtet")


# Schreib-Runner: vertraut/lehnt ab/setzt zurueck (ip, decision) -> None. Der api-Ring
# kennt das Repository/den Use-Case NICHT direkt; das Callable wird im Composition Root
# verdrahtet (die ``now``-Uhr faellt dort). Synchron (lokaler SQLite-Schreibzugriff).
type DnsTrustDecisionRunner = Callable[[str, str], None]


def provide_dns_trust_decision() -> DnsTrustDecisionRunner:
    raise NotImplementedError("DnsTrustDecisionRunner wird in app.py verdrahtet")


class TrustDecisionBody(BaseModel):
    """POST /api/dns-trust/decision -- eine Vertrauens-Entscheidung pro ``ip``.

    ``decision`` ist ein ``Literal``-Feld: ein anderer Wert -> HTTP 422 (pydantic-
    Validierung), nicht ein leiser Durchlauf (S3). ``trust`` markiert den Server als
    vertraut, ``reject`` als abgelehnt, ``reset`` stellt ihn NEUTRAL -- KEIN Loeschen.
    """

    ip: str
    decision: Literal["trust", "reject", "reset"]


# ── Routen ───────────────────────────────────────────────────────────────────


@router.get("")
def get_dns_trust_servers(
    runner: Annotated[DnsTrustListRunner, Depends(provide_dns_trust_list)],
) -> list[TrustedDnsServerOut]:
    """Liefert die kuratierten DNS-Server (Kategorie + Vertrauens-Zustand + Indizien).

    Reihenfolge: nach ``first_seen`` aufsteigend (Use-Case/Repo-Ordnung, deterministisch).
    """
    return runner()


@router.post("/decision")
def set_dns_trust_decision(
    body: TrustDecisionBody,
    record: Annotated[DnsTrustDecisionRunner, Depends(provide_dns_trust_decision)],
) -> dict[str, bool]:
    """Vertraut/lehnt ab/setzt EINEN DNS-Server pro ``ip`` zurueck (ueber den Root-Runner).

    ``decision`` per Body-Constraint erzwungen (Muell -> 422). Eine unbekannte ``ip`` ist
    ein definierter No-Op im Use-Case (kein 500). Erfolg -> 200 ``{"ok": true}``.
    """
    record(body.ip, body.decision)
    return {"ok": True}
