"""FastAPI-Router der maintenance-Domaene (v2), prefix ``/api/maintenance``.

Aeusserer Ring: nimmt HTTP entgegen. Wie ``api/system.py`` (NICHT wie die
domaenen-Router, die ihre Use-Case-Klassen aus ``application`` importieren) kennt
dieser Router WEDER ``application`` NOCH ``infrastructure`` NOCH ``modules``
(Regel 4): die zwei Wartungs-Runner kommen als ``Callable`` per Dependency
herein, verdrahtet im Composition Root (``app.py``).

Damit der api-Ring application-frei bleibt UND der Router-Aufruf trotzdem
typsicher ist (mypy strict), beschreibt ein schmales lokales ``Protocol`` den
Vertrag des injizierten Runners: ein Objekt mit genau einer ``run``-Methode --
exakt die Form der Use-Case-Instanzen ``ResetScanData``/``FactoryReset``, die der
Composition Root via ``dependency_overrides`` als Instanz hereinreicht (Muster
wie die devices-POST-Use-Cases, die ebenfalls als Instanz injiziert und im Router
gerufen werden). So bleibt der konkrete Use-Case-Typ dem api-Ring verborgen.

Endpunkte (Daten-Loeschung, zwei Stufen + granularer Baukasten -- s. application/maintenance):

* ``POST /api/maintenance/reset-scan-data`` -> leert NUR Scan-/CVE-/ARP-/Analyse-
  Befunde (Stufe 1) -> ``{"ok": true}``.
* ``POST /api/maintenance/reset-selected``  -> granularer Baukasten; Body
  ``{items: list[str]}`` -> ``{"ok": true}``. Die rohen Posten-Strings hebt der
  Use-Case autoritativ in den Domaenen-Enum (der api-Ring kennt ihn NICHT, Regel 4);
  ein nicht zum Vokabular passender String -> 422.
* ``POST /api/maintenance/factory-reset``  -> Werkszustand (Stufe 2); Body
  ``{include_secrets: bool = false}`` -> ``{"ok": true}``.
"""

from collections.abc import Callable
from typing import Annotated, Protocol

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/maintenance", tags=["maintenance"])


# ── injizierte Composition-Root-Callables ────────────────────────────────────
# Provider-Marker: in app.py per dependency_overrides mit den echten Use-Case-
# Instanzen verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (kein stiller
# Fallback). Die ``...Runner``-Protocols beschreiben strukturell die ``run``-
# Methode der jeweiligen Use-Case-Instanz, ohne dass der api-Ring ``application``
# importiert.


class ResetScanDataRunner(Protocol):
    """Schmaler Vertrag der injizierten Stufe-1-Instanz (``application.ResetScanData``)."""

    def run(self) -> None:
        """Leert die Scan-/CVE-/ARP-/Analyse-Befunde (Stufe 1)."""
        ...


class DeleteSelectedRunner(Protocol):
    """Schmaler Vertrag der injizierten Baukasten-Instanz (``application.DeleteSelectedData``).

    Der Router reicht die rohen Posten-Strings durch (``items: list[str]``) -- die
    ``str`` -> Enum-Hebung passiert AUTORITATIV im Use-Case (``run_from_wire``), darum
    importiert der api-Ring den Domaenen-Enum NICHT (import-linter Regel 4). Ein nicht
    zum Vokabular passender String wirft ``ValueError``, den der Endpunkt auf 422 mappt.
    """

    def run_from_wire(self, items: list[str]) -> None:
        """Loescht die uebergebene Menge roher Posten-Strings (Hebung im Use-Case)."""
        ...


class FactoryResetRunner(Protocol):
    """Schmaler Vertrag der injizierten Stufe-2-Instanz (``application.FactoryReset``)."""

    def run(self, *, include_secrets: bool = False) -> None:
        """Setzt alles auf Werkszustand zurueck (Stufe 2); optional inkl. Secrets."""
        ...


# Liefert den Stufe-1-Runner (ResetScanData-Instanz) aus dem Composition Root.
type ResetScanDataProvider = Callable[[], ResetScanDataRunner]


def provide_reset_scan_data() -> ResetScanDataProvider:
    raise NotImplementedError("ResetScanDataProvider wird in app.py verdrahtet")


# Liefert den Baukasten-Runner (DeleteSelectedData-Instanz) aus dem Composition Root.
type DeleteSelectedProvider = Callable[[], DeleteSelectedRunner]


def provide_delete_selected() -> DeleteSelectedProvider:
    raise NotImplementedError("DeleteSelectedProvider wird in app.py verdrahtet")


# Liefert den Stufe-2-Runner (FactoryReset-Instanz) aus dem Composition Root.
type FactoryResetProvider = Callable[[], FactoryResetRunner]


def provide_factory_reset() -> FactoryResetProvider:
    raise NotImplementedError("FactoryResetProvider wird in app.py verdrahtet")


class DeleteSelectedBody(BaseModel):
    """POST /api/maintenance/reset-selected -- ``items`` als Liste roher Posten-Strings.

    Die Vokabular-Validierung + Enum-Hebung macht der Use-Case (422 bei Fehlwert); der
    Router reicht die Strings roh durch (kennt den Domaenen-Enum NICHT).
    """

    items: list[str]


class FactoryResetBody(BaseModel):
    """POST /api/maintenance/factory-reset -- ``include_secrets`` (Default: nicht loeschen)."""

    include_secrets: bool = False


# ── Routen ───────────────────────────────────────────────────────────────────


@router.post("/reset-scan-data")
def reset_scan_data(
    runner: Annotated[ResetScanDataRunner, Depends(provide_reset_scan_data)],
) -> dict[str, bool]:
    """Stufe 1: leert die Scan-/CVE-/ARP-/Analyse-Befunde."""
    runner.run()
    return {"ok": True}


@router.post("/reset-selected")
def reset_selected(
    body: DeleteSelectedBody,
    runner: Annotated[DeleteSelectedRunner, Depends(provide_delete_selected)],
) -> dict[str, bool]:
    """Granularer Baukasten: loescht die ausgewaehlten Posten (rohe Strings).

    Die ``str`` -> Enum-Hebung passiert im Use-Case; ein nicht zum Vokabular passender
    String wirft dort ``ValueError`` -> 422 (kein 500/stiller Fallback). 422 als nacktes
    Literal (Bestandsmuster ``api/monitoring.py``).
    """
    try:
        runner.run_from_wire(body.items)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    return {"ok": True}


@router.post("/factory-reset")
def factory_reset(
    body: FactoryResetBody,
    runner: Annotated[FactoryResetRunner, Depends(provide_factory_reset)],
) -> dict[str, bool]:
    """Stufe 2 (Werkszustand): die ganze Stufe 1 plus alles Uebrige; optional inkl. Secrets."""
    runner.run(include_secrets=body.include_secrets)
    return {"ok": True}
