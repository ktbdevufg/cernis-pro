"""FastAPI-Router der System-/Glue-Endpunkte (v2, ADR-0004 P.1).

Aeusserer Ring: nimmt HTTP entgegen. Self-contained Glue-Routen, die KEINER
Domaene gehoeren (Tauri-Ready-Probe, URL-Oeffnen, Dependency-Report). Der api-Ring
kennt KEIN ``infrastructure`` und KEIN ``modules`` (Regel 4): wo eine Route
Infrastruktur braucht (System-Info, Browser-Oeffnen), kommt sie als ``Callable``
per Dependency herein -- verdrahtet im Composition Root (``app.py``). Muster wie
``MonitorStatusProvider`` (api/monitoring) und die capture-Runner.

Endpunkte:

* ``GET  /api/status``       -> ``{status, version}`` (HTTP 200; Tauri-Ready-Probe).
* ``POST /api/open-url``     -> oeffnet eine http/https-URL im Default-Browser.
* ``GET  /api/system/info``  -> Verfuegbarkeit der real genutzten v2-Deps + nmap.

``GET /api/interfaces`` ist KEIN System-Glue mehr: der fruhere Uebergangs-Endpunkt
ist durch die vollwertige interfaces-Domaene abgeloest (eigener Router
``api/interfaces.py``, I.3).

ABWEICHUNGEN ggue. dem Altcode (main.py, der unangetastet weiterlaeuft):

* ``/api/system/info`` ist REDUZIERT: nur ``version`` + ``nmap`` + die Deps, die v2
  real nutzt (``scapy`` fuer capture). Die mit ``main.py`` sterbenden Quer-Deps
  (pysnmp/reportlab/fritzconnection/dnspython/apscheduler/cryptography/websockets)
  sind RAUS. ``/api/system/install`` (pip-Installer fuer eben jene Deps) wird in v2
  NICHT gebaut.
"""

from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter(prefix="/api", tags=["system"])


# ── injizierte Composition-Root-Callables ────────────────────────────────────
# Provider-Marker: in app.py per dependency_overrides mit den echten Closures
# verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (kein stiller Fallback).

# Liefert die Versionsnummer (aus infrastructure.config -- darf api nicht kennen).
type VersionProvider = Callable[[], str]


def provide_version() -> VersionProvider:
    raise NotImplementedError("VersionProvider wird in app.py verdrahtet")


# Liefert den reduzierten Dependency-/nmap-Report (system-nahes Probing, infra).
type SystemInfoProvider = Callable[[], dict[str, Any]]


def provide_system_info() -> SystemInfoProvider:
    raise NotImplementedError("SystemInfoProvider wird in app.py verdrahtet")


# Oeffnet eine URL im Default-Browser. Als Callable injiziert, damit der Test einen
# Spy einhaengt (kein echter Browser-Start). Default-Verdrahtung: webbrowser.open.
type UrlOpener = Callable[[str], None]


def provide_url_opener() -> UrlOpener:
    raise NotImplementedError("UrlOpener wird in app.py verdrahtet")


class OpenUrlBody(BaseModel):
    """POST /api/open-url -- die zu oeffnende URL (leer als Default = ungueltig)."""

    url: str = ""


# ── Routen ───────────────────────────────────────────────────────────────────


@router.get("/status")
def status(
    version_provider: Annotated[VersionProvider, Depends(provide_version)],
) -> dict[str, str]:
    """Ready-Probe (HTTP 200) -- Tauri wartet hierauf beim Backend-Start.

    Eigene Semantik neben ``/health`` (das ``service`` traegt): ``/api/status`` ist
    der Altcode-Pfad, den das Frontend/Tauri kennt, und liefert ``{status, version}``.
    """
    return {"status": "ok", "version": version_provider()}


@router.post("/open-url")
def open_url(
    body: OpenUrlBody,
    opener: Annotated[UrlOpener, Depends(provide_url_opener)],
) -> dict[str, Any]:
    """Oeffnet eine http/https-URL im Default-Browser.

    GUARD (altcode-treu): nur ``http://``/``https://`` erlaubt -- jedes andere Schema
    (z. B. ``file:``, ``javascript:``) wird abgewiesen, OHNE den Opener zu rufen
    (Schutz vor URL-/Command-Injection). Abweisung -> ``{"ok": False, "error": ...}``,
    kein HTTP-Fehler (Altcode-Vertrag).
    """
    if not body.url.startswith(("https://", "http://")):
        return {"ok": False, "error": "Invalid URL"}
    opener(body.url)
    return {"ok": True}


@router.get("/system/info")
def system_info(
    info_provider: Annotated[SystemInfoProvider, Depends(provide_system_info)],
) -> dict[str, Any]:
    """Reduzierter Verfuegbarkeits-Report: ``version`` + ``nmap`` + real genutzte Deps."""
    return info_provider()
