"""FastAPI-Router des DNS-Server-Vertrauensmodells (ADR 0043, Etappe 5), prefix ``/api/dns-trust``.

Aeusserer Ring: nimmt HTTP entgegen. ``infrastructure``/``domain``/``ports`` bleiben
draussen (Regel 4): die injizierten Runner kommen als schmale lokale Vertraege per
Dependency herein, verdrahtet im Composition Root (``app.py``).

Aus ``application`` wird GENAU EINES importiert: die beiden Fehlertypen des
Vertrauensmodells (``application/dns_trust/errors.py``). Dieser Router war urspruenglich
zusaetzlich application-frei gebaut (lokale Stilkonvention nach dem Vorbild
``api/dns_watch.py``/``api/blocklist.py``, KEIN Contract -- der Architektur-Contract
erlaubt api -> application ausdruecklich und 18 Router nutzen das). Die Konvention wird
hier bewusst aufgegeben, weil die beiden Nichtvollzuege fachlich verschieden sind
(Adresse nicht erfasst -> 404 vs. Server nicht bestaetigt -> 409) und stdlib-Ausnahmen
diesen Unterschied nicht tragen koennen: fuer 404 gibt es das belegte ``KeyError``-Muster
(``api/blocklist.py``), fuer 409 kein stdlib-Gegenstueck im Projekt.

Alles UEBRIGE bleibt application-frei: ein schmales lokales ``Protocol`` beschreibt den
Vertrag des injizierten Lese-Runners (liefert die fertig projizierte Sicht), ein
``Callable`` den des Schreib-Runners (trust/reject/reset). Der api-Ring definiert eigene
schmale pydantic-Response-Modelle (``TrustedDnsServerOut``/``DnsServerPlausibilityOut``);
die Projektion vom application-Typ (``TrustedDnsServer`` + ``DnsServerPlausibility``) auf
diese Wire-Form macht der Composition-Root-Runner in ``app.py``, NICHT der Router -- so
nennt der api-Ring die application-DATENtypen weiterhin nie.

Endpunkte:

* ``GET /api/dns-trust`` -> die kuratierten DNS-Server (``ListDnsTrustServers``), je Server
  Kategorie + Vertrauens-Zustand + best-effort Bestands-Indizien (Plausibilitaet). Die
  Reihenfolge ist die des Use-Case/Repos: nach ``first_seen`` AUFSTEIGEND -- deterministisch
  (aeltester zuerst), ohne Re-Sortierung im Router.
* ``POST /api/dns-trust/decision`` -> vertraut/lehnt ab/setzt zurueck EINEN Server pro ``ip``
  ueber den injizierten Schreib-Runner (``SetDnsServerTrust``). ``{"ok": true}``. KEIN Loeschen
  hier (Loeschen kommt spaeter in der Wartungsrubrik). Eine ``ip``, zu der kein Server
  erfasst ist -> 404 (frueher ein stiller No-Op mit Erfolgsmeldung).
* ``POST /api/dns-trust/rank`` -> setzt die erwartete Prioritaet EINES Servers pro ``ip``
  (``SetDnsServerRank``; ``rank == 0`` = unrangiert). ``{"ok": true}``. Unbekannte ``ip``
  -> 404; ein ``rank > 0`` fuer einen weder bestaetigten noch bereits rangierten Server
  -> 409 (frueher fiel der Wunsch still weg, gemeldet wurde Erfolg).

Die ``now``-Uhr faellt NICHT im Router, sondern am Rand (Composition Root / Runner-Wrapper);
der Router reicht nur ``ip`` + ``decision`` durch.
"""

from collections.abc import Callable
from typing import Annotated, Literal, Protocol

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from application.dns_trust import (
    DnsTrustServerNotConfirmedError,
    DnsTrustServerNotFoundError,
)

router = APIRouter(prefix="/api/dns-trust", tags=["dns_trust"])


# ── schmale api-Response-Modelle (eigene Wire-Form, KEIN application-Datentyp) ──
# Die Felder spiegeln ``application.dns_trust.DnsServerPlausibility`` bzw.
# ``domain.dns_trust.TrustedDnsServer``, ohne diese Typen zu importieren. Der
# Composition-Root-Runner projiziert die application-Sicht auf genau diese Form.
# Importiert wird aus ``application`` NUR das Fehler-Vokabular (s. Modul-Docstring),
# nie ein Datentyp; ``domain`` bleibt ganz draussen (Regel 4).


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
    ``is_platform_placeholder`` kennzeichnet einen funktionslosen Windows-Platzhalter-DNS-
    Server (fec0:0:0:ffff::1..3) -- eine andere Achse als ``category``.
    """

    ip: str
    category: str
    trust_state: str
    first_seen: float
    last_seen: float
    display_name: str
    notes: str
    is_platform_placeholder: bool
    # Nutzergesetzte erwartete Prioritaet (1..N, kleiner = hoeher); 0 = kein Rang.
    expected_rank: int
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


# Rang-Runner: setzt die erwartete Prioritaet (ip, rank) -> None. Muster des
# Decision-Runners: das Callable wird im Composition Root verdrahtet (now-Uhr dort).
type DnsTrustRankRunner = Callable[[str, int], None]


def provide_dns_trust_rank() -> DnsTrustRankRunner:
    raise NotImplementedError("DnsTrustRankRunner wird in app.py verdrahtet")


class RankBody(BaseModel):
    """POST /api/dns-trust/rank -- die erwartete Prioritaet EINER ``ip`` setzen.

    ``rank >= 0`` per Body-Constraint (pydantic ``Field(ge=0)``, Muell -> 422);
    ``rank == 0`` entfernt die ``ip`` aus der Rangordnung (unrangiert).
    """

    ip: str
    rank: int = Field(ge=0)


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

    ``decision`` per Body-Constraint erzwungen (Muell -> 422). Eine ``ip``, zu der kein
    Server erfasst ist -> 404 (Muster ``api/devices.py``): frueher schrieb der Weg dort
    nichts und meldete trotzdem Erfolg. Erfolg -> 200 ``{"ok": true}``.
    """
    try:
        record(body.ip, body.decision)
    except DnsTrustServerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Diese Adresse ist noch nicht bekannt und kann darum nicht bewertet werden. (E-503)"
            ),
        ) from exc
    return {"ok": True}


@router.post("/rank")
def set_dns_trust_rank(
    body: RankBody,
    record: Annotated[DnsTrustRankRunner, Depends(provide_dns_trust_rank)],
) -> dict[str, bool]:
    """Setzt die erwartete Prioritaet EINES DNS-Servers pro ``ip`` (ueber den Root-Runner).

    ``rank >= 0`` per Body-Constraint erzwungen (Muell -> 422); ``rank == 0`` entfernt
    die ``ip`` aus der Rangordnung. Eine ``ip`` ohne erfassten Server -> 404; ein
    ``rank > 0`` fuer einen weder bestaetigten noch bereits rangierten Server -> 409
    (Zustand laesst die Aktion nicht zu, Muster ``api/outbound_log.py``) -- frueher fiel
    der Wunsch dort still weg. Erfolg -> 200 ``{"ok": true}``.
    """
    try:
        record(body.ip, body.rank)
    except DnsTrustServerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Diese Adresse ist noch nicht bekannt und kann darum nicht bewertet werden. (E-503)"
            ),
        ) from exc
    except DnsTrustServerNotConfirmedError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Eine Reihenfolge laesst sich nur fuer bestaetigte Server vergeben. (E-503)",
        ) from exc
    return {"ok": True}
