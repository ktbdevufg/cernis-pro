"""FastAPI-Router der Capture-Rechteeinrichtung, prefix ``/api/capture-access``.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich Use-Cases aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter und
``domain``-Typen werden hier NICHT importiert -- die Use-Cases kommen per
FastAPI-Dependency herein (Verdrahtung im Composition Root ``app.py``).

Drei Endpunkte:

* ``GET /api/capture-access`` -- ist der rohe Mitschnitt-Zugriff eingerichtet?
* ``POST /api/capture-access/grant`` -- Einrichtung anstossen (loest auf macOS die
  native Systemabfrage aus; der Aufruf dauert, solange der Dialog offen ist).
* ``POST /api/capture-access/revoke`` -- Einrichtung zuruecknehmen, ebenfalls mit
  Systemabfrage. Der Rumpf waehlt, ob nur die eigene Mitgliedschaft entfernt oder
  vollstaendig abgeraeumt wird.

WIRE-FORM: beide Antworten tragen ein ``state``- bzw. ``outcome``-Feld mit dem
STRING des jeweiligen Domaenen-Enums. Die drei Ausgaenge der Einrichtung --
``granted`` / ``cancelled`` / ``failed`` (plus ``not_applicable``) -- kommen damit
im Frontend UNTERSCHEIDBAR an, statt in einem ``{ok: bool}`` zusammenzufallen: ein
Abbruch durch den Nutzer ist kein Fehler und darf dort keine Fehleroptik ausloesen
(S3). Die Enum-Werte werden als ``str`` serialisiert -- der api-Ring nennt den
``domain``-Typ nicht (Regel 4), sondern deklariert schlicht ``str``.

HTTP-Status ist in ALLEN Faellen 200: auch "abgebrochen", "fehlgeschlagen" und
"trifft hier nicht zu" sind gueltige, erwartete Auskuenfte ueber den Systemzustand,
keine HTTP-Fehler. Der Grund steht im Feld ``detail`` bzw. ``reason``.
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from application.capture_access import (
    GetCaptureAccessStatus,
    GrantCaptureAccess,
    RevokeCaptureAccess,
)

router = APIRouter(prefix="/api/capture-access", tags=["capture-access"])


# ── schmale api-Response-Modelle (eigene Wire-Form) ───────────────────────────


class CaptureAccessStatusOut(BaseModel):
    """Status des rohen Mitschnitt-Zugriffs.

    ``state``: ``"granted"`` (Zugriff steht), ``"missing"`` (fehlt, einrichtbar) oder
    ``"not_applicable"`` (auf dieser Plattform gibt es diese Einrichtung nicht).
    ``detail`` traegt bei den letzten beiden den ehrlichen Klartext-Grund, bei
    ``granted`` ist es leer.

    ``members`` sind die Login-Namen der Mitglieder der Capture-Gruppe (leer, wenn es
    sie nicht gibt). Wire-Form ist eine LISTE -- JSON kennt kein Tuple; das
    Domaenen-Tuple wird im Router konvertiert. Die Oberflaeche zeigt daran vor einem
    Widerruf, wer sonst noch betroffen waere: die Geraete sind eine systemweite,
    geteilte Ressource.
    """

    state: str
    detail: str
    members: list[str]


class CaptureAccessResultOut(BaseModel):
    """Ergebnis eines Einrichtungsversuchs.

    ``outcome``: ``"granted"``, ``"cancelled"`` (Nutzer hat die Systemabfrage
    abgebrochen -- KEIN Fehler, jederzeit nachholbar), ``"failed"`` (mit Grund in
    ``reason``) oder ``"not_applicable"``.
    """

    outcome: str
    reason: str


class CaptureAccessRevokeResultOut(BaseModel):
    """Ergebnis eines Widerrufsversuchs.

    ``outcome``: ``"revoked"``, ``"cancelled"`` (Nutzer hat die Systemabfrage
    abgebrochen -- KEIN Fehler), ``"failed"`` (mit Grund in ``reason``) oder
    ``"not_applicable"``. Bewusst ein EIGENES Modell mit eigenen Werten: ein
    Widerruf kann nicht "granted" ausgehen (siehe ``domain.CaptureAccessRevokeOutcome``).
    """

    outcome: str
    reason: str


class CaptureAccessRevokeIn(BaseModel):
    """Rumpf des Widerrufs: welcher Umfang soll zurueckgenommen werden.

    ``nur_mitgliedschaft=True`` entfernt allein die Gruppenmitgliedschaft des
    aufrufenden Nutzers; ``False`` (Default) raeumt die systemweite Einrichtung
    vollstaendig ab. Der Default ist bewusst der vollstaendige Widerruf: er ist der
    Normalfall (ein Nutzer, der als einziger Zugriff hat) und entspricht dem, was der
    Einwilligungs-Dialog als "rueckgaengig machen" zusagt.
    """

    nur_mitgliedschaft: bool = False


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit den
# echten Use-Cases verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (S3).
def provide_get_capture_access_status() -> GetCaptureAccessStatus:
    raise NotImplementedError("GetCaptureAccessStatus wird in app.py verdrahtet")


def provide_grant_capture_access() -> GrantCaptureAccess:
    raise NotImplementedError("GrantCaptureAccess wird in app.py verdrahtet")


def provide_revoke_capture_access() -> RevokeCaptureAccess:
    raise NotImplementedError("RevokeCaptureAccess wird in app.py verdrahtet")


# ── Routen ───────────────────────────────────────────────────────────────────


@router.get("")
def get_capture_access(
    status_uc: Annotated[GetCaptureAccessStatus, Depends(provide_get_capture_access_status)],
) -> CaptureAccessStatusOut:
    """Liefert, ob der rohe Mitschnitt-Zugriff eingerichtet ist (ohne Systemabfrage)."""
    status = status_uc()
    return CaptureAccessStatusOut(
        state=str(status.state), detail=status.detail, members=list(status.members)
    )


@router.post("/grant")
async def grant_capture_access(
    grant_uc: Annotated[GrantCaptureAccess, Depends(provide_grant_capture_access)],
) -> CaptureAccessResultOut:
    """Stoesst die Einrichtung an; antwortet erst, wenn die Systemabfrage beendet ist.

    Die drei Ausgaenge kommen im ``outcome``-Feld unterscheidbar an (siehe
    Modul-Docstring); der HTTP-Status ist auch bei ``cancelled``/``failed`` 200.
    """
    result = await grant_uc()
    return CaptureAccessResultOut(outcome=str(result.outcome), reason=result.reason)


@router.post("/revoke")
async def revoke_capture_access(
    daten: CaptureAccessRevokeIn,
    revoke_uc: Annotated[RevokeCaptureAccess, Depends(provide_revoke_capture_access)],
) -> CaptureAccessRevokeResultOut:
    """Nimmt die Einrichtung zurueck; antwortet erst, wenn die Systemabfrage beendet ist.

    Der HTTP-Status ist auch bei ``cancelled``/``failed`` 200 -- aus demselben Grund
    wie bei ``grant``: beides sind gueltige Auskuenfte ueber den Systemzustand, keine
    HTTP-Fehler. Ein Abbruch darf in der Oberflaeche keine Fehleroptik ausloesen (S3).
    """
    result = await revoke_uc(daten.nur_mitgliedschaft)
    return CaptureAccessRevokeResultOut(outcome=str(result.outcome), reason=result.reason)
