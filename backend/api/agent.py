"""FastAPI-Router der agent-Domaene (v2) -- die Client-seitigen REST-Pfade.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich Use-Cases aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter, Ports
und ``infrastructure``-Exceptions werden hier NICHT importiert -- die Use-Cases
kommen per FastAPI-Dependency herein (Verdrahtung im Composition Root ``app.py``).

Endpunkte (Wire-Form 1:1 am A.0-Characterization-Contract
``test_agent_rest_contract`` -- der friert die v1-``main.py``-Routen ein; dieser
v2-Rand muss dieselbe Wire-Form treffen, festgenagelt im v2-eigenen
``test_agent_api``):

* ``GET    /api/agents``             -> Liste maskierter Agent-Wire-dicts.
* ``POST   /api/agents``             -> ``{ok: True}`` (roher dict-Body, AS-IS).
* ``DELETE /api/agents/{id}``        -> ``{ok: True}`` (idempotent, kein 404).
* ``GET    /api/agents/{id}/ping``   -> Ping-Info / 404 bei unbekanntem Agenten.
* ``POST   /api/agents/{id}/scan``   -> Host-Liste / 404 / 503 (Exception/Timeout).

WIRE-NAHT (Masken-Replikation am Rand): ``RemoteAgent`` ist v2-seitig TOKENLOS und
traegt KEINE toten Altcode-Felder (``last_seen``/``version``/``platform``). Der
A.0-Vertrag verlangt sie aber im GET-Body. Darum baut ``_agent_to_wire`` die
Altcode-Wire-Form am Rand wieder auf: konstante Token-Maske ``"••..."``
(NICHT aus domain -- man kann nicht maskieren, was nicht da ist), tote Felder als
Leerstrings, ``enabled`` zurueck zu ``int``, ``cidrs`` als Liste. Diese Maske/die
toten Felder leben NUR hier, nie in domain/application.

SAVE-500 (AS-IS, Finding S1, Heilung = Phase 4): KEIN BaseModel. Der Rand liest
die Pflichtfelder hart aus dem rohen Body (``body["id"]`` etc.) -- ein fehlendes
Pflichtfeld ist ein ``KeyError`` -> 500 (genau wie der Altcode, der ``agent["id"]``
hart las). Eine saubere 422-Heilung waere api-Haertung in Phase 4.

EXCEPTION-MAPPING: ``AgentNotFoundError`` (application) -> 404 am Rand. Der
scan-Pfad faengt sonst JEDE Exception -> 503 (altcode-treu: ``proxy_scan``-Fehler
ODER ``wait_for``-Timeout). Bewusst KEIN Import der ``AgentScanError``
(infrastructure) -- der api-Ring darf infrastructure nicht kennen (Regel 4); das
breite ``except Exception`` deckt sie ohnehin ab. ``SecretStoreUnavailableError``
faengt der globale 503-Handler im Composition Root ab.
"""

import asyncio
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse

from application.agent import (
    AgentNotFoundError,
    DeleteAgent,
    ListAgents,
    PingAgent,
    SaveAgent,
    ScanViaAgent,
)

router = APIRouter(prefix="/api", tags=["agent"])

# Konstante Token-Maske am api-Rand (NICHT aus domain -- der v2-RemoteAgent ist
# tokenlos). Acht U+2022 BULLET, exakt wie der Altcode (``to_dict``/``get_agents``).
_TOKEN_MASK = "•" * 8


# ── Provider-Marker (im Composition Root ``app.py`` per dependency_overrides verdrahtet) ──


def provide_list_agents() -> ListAgents:
    raise NotImplementedError("ListAgents wird in app.py verdrahtet")


def provide_save_agent() -> SaveAgent:
    raise NotImplementedError("SaveAgent wird in app.py verdrahtet")


def provide_delete_agent() -> DeleteAgent:
    raise NotImplementedError("DeleteAgent wird in app.py verdrahtet")


def provide_ping_agent() -> PingAgent:
    raise NotImplementedError("PingAgent wird in app.py verdrahtet")


def provide_scan_via_agent() -> ScanViaAgent:
    raise NotImplementedError("ScanViaAgent wird in app.py verdrahtet")


# ── Serialisierungs-Helfer (Domaenen-Objekt -> Wire-dict am api-Rand) ─────────


def _agent_to_wire(agent: Any) -> dict[str, Any]:
    """``RemoteAgent`` -> Altcode-Wire-dict (maskiert, tote Felder leer).

    Duck-typing (``: Any``, Hausmuster monitoring/capture): KEIN domain-Import am
    api-Rand (Schichtungs-Regel api -> nur application). Maske + tote Felder
    (``last_seen``/``version``/``platform``) leben NUR hier: der v2-RemoteAgent
    traegt sie nicht. ``enabled`` zurueck zu ``int`` (Altcode-Form), ``cidrs`` als
    Liste (nicht tuple, nicht JSON-String).
    """
    return {
        "id": agent.id,
        "name": agent.name,
        "url": agent.url,
        "token": _TOKEN_MASK,
        "enabled": int(agent.enabled),
        "last_seen": "",
        "version": "",
        "platform": "",
        "cidrs": list(agent.cidrs),
    }


def _ping_to_wire(result: Any) -> dict[str, Any]:
    """``AgentPingResult`` -> Altcode-Wire-dict, KONDITIONAL nach ``reachable``.

    Der Altcode reichte die rohe ``ping_agent``-Rueckgabe durch: bei Erfolg
    ``{reachable, version, platform, hostname}`` OHNE ``error``-Key, bei
    Unerreichbarkeit ``{error, reachable: False}``. Das v2-Wertobjekt traegt immer
    alle Felder -- darum hier konditional auf genau die zwei Altcode-Formen.
    """
    if result.reachable:
        return {
            "reachable": True,
            "version": result.version,
            "platform": result.platform,
            "hostname": result.hostname,
        }
    return {"error": result.error, "reachable": False}


# ── Routen ────────────────────────────────────────────────────────────────────


@router.get("/agents")
def get_agents(
    list_agents: Annotated[ListAgents, Depends(provide_list_agents)],
) -> list[dict[str, Any]]:
    """Aktive (enabled) Agenten als maskierte Wire-dicts."""
    return [_agent_to_wire(agent) for agent in list_agents()]


@router.post("/agents")
def add_agent(
    save_agent: Annotated[SaveAgent, Depends(provide_save_agent)],
    body: Annotated[dict[str, Any], Body(...)],
) -> dict[str, bool]:
    """Legt einen Agenten an/aktualisiert ihn. ``{ok: True}``.

    AS-IS (kein BaseModel): die Pflichtfelder werden hart aus dem rohen Body
    gelesen -- ein fehlendes Feld ist ein ``KeyError`` -> 500 (Altcode-Form,
    saubere 422 = Phase 4). Der Rand baut KEIN domain-Objekt (Schichtungs-Regel
    api -> nur application): er reicht PRIMITIVE durch, das ``RemoteAgent`` baut
    der ``SaveAgent``-Use-Case. Der Token geht getrennt in den SecretStore (der
    Use-Case verwahrt ihn), ``cidrs`` defaulten auf ``[]``.
    """
    save_agent(
        body["id"],
        body["name"],
        body["url"],
        bool(body.get("enabled", True)),
        body.get("cidrs", []),
        body.get("token"),
    )
    return {"ok": True}


@router.delete("/agents/{agent_id}")
def delete_agent(
    agent_id: str,
    delete_agent_uc: Annotated[DeleteAgent, Depends(provide_delete_agent)],
) -> dict[str, bool]:
    """Loescht einen Agenten. Idempotent -- immer ``{ok: True}``, kein 404."""
    delete_agent_uc(agent_id)
    return {"ok": True}


@router.get("/agents/{agent_id}/ping")
async def ping_agent(
    agent_id: str,
    ping_agent_uc: Annotated[PingAgent, Depends(provide_ping_agent)],
) -> Any:
    """Erreichbarkeits-Check. 404 bei unbekanntem Agenten, sonst 200 mit Ping-Info.

    Unerreichbarkeit ist KEIN HTTP-Fehler: 200 mit ``{error, reachable: False}``
    (so liefert der Pinger bei einer I/O-Stoerung). Nur ein nicht (aktiv)
    registrierter Agent -> 404.
    """
    try:
        result = await ping_agent_uc(agent_id)
    except AgentNotFoundError:
        return JSONResponse(status_code=404, content={"error": "Agent not found"})
    return _ping_to_wire(result)


@router.post("/agents/{agent_id}/scan")
async def agent_scan(
    agent_id: str,
    scan_via_agent: Annotated[ScanViaAgent, Depends(provide_scan_via_agent)],
    body: Annotated[dict[str, Any], Body(...)],
) -> Any:
    """Proxy-Scan ueber den Agenten. 404 unbekannt, Host-Liste / 503 (Exception/Timeout).

    ``timeout=300.0`` (Altcode-Vertrag): laeuft der Scan in den Timeout ODER wirft
    der Scan-Client (AgentScanError u.a.), wird das zu 503 ``{error}`` -- ein
    breites ``except Exception`` (KEIN infrastructure-Import noetig). Nur der nicht
    (aktiv) registrierte Agent -> 404.
    """
    try:
        return await asyncio.wait_for(scan_via_agent(agent_id, body), timeout=300.0)
    except AgentNotFoundError:
        return JSONResponse(status_code=404, content={"error": "Agent not found"})
    except Exception as exc:
        return JSONResponse(status_code=503, content={"error": str(exc)})
