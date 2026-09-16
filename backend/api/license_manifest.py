"""FastAPI-Router der Lizenzaufstellung, prefix ``/api/lizenzen``.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich Use-Cases aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter, ``ports``
und ``domain`` werden hier NICHT importiert -- die Use-Cases kommen per
FastAPI-Dependency herein (Verdrahtung im Composition Root ``app.py``).

Zwei LESENDE Endpunkte:

* ``GET /api/lizenzen`` -- die Aufstellung OHNE Lizenztexte (Kopf, ``werk``,
  ``bestandteile``, ``luecken``, ``ebene_nativ``), in einem Zug.
* ``GET /api/lizenzen/text?schluessel=...`` -- EIN Lizenztext auf Abruf.

WARUM DER SCHLUESSEL EIN ABFRAGEPARAMETER IST und kein Pfadsegment: die Schluessel
tragen Doppelpunkt UND Schraegstrich (``paket:python/anyio``, ``spdx:MIT``,
``werk:<id>``). Als Pfadsegment zerfiele ``paket:python/anyio`` in zwei Segmente;
ein ``:path``-Konverter faenge zwar wieder alles ein, doch Proxies und Clients
normalisieren Pfade (``//``, ``%2F``) unterschiedlich. Der Abfrageparameter ist die
verlaessliche Form -- der Wert wird als Ganzes uebertragen und nicht am Trennzeichen
zerlegt.

ZWEITEILUNG DER AUSLIEFERUNG: 75,6 Prozent der Datei sind Lizenztexte (720349 B
gesamt, 175664 B ohne). Die Liste kommt darum ohne sie; ein Volltext wird einzeln
geholt (Median 1344 B, groesster 69949 B).

FEHLERBILD (Aufgabe 3c, Finding S3) -- nie eine leere Antwort mit 200:

* unbekannter Schluessel -> ``404`` mit verstaendlicher Meldung,
* fehlende oder unlesbare Aufstellung -> ``503``: nicht die Anfrage ist falsch,
  sondern die Auslieferung ist unvollstaendig. Die Meldung des Use-Case traegt bei
  einem Nichtfund die vollstaendige Liste der geprueften Pfade weiter.

Muster wie ``api/interfaces.py``: ``provide_*``-Marker mit ``NotImplementedError``,
Rueckgabe ``dict[str, Any]``, KEIN ``response_model`` -- die Wire-Form ist die der
Aufstellung selbst (ein erzeugtes Bau-Artefakt mit eigenem ``schema_version``), sie
wird hier nicht in ein zweites Schema uebersetzt.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from application.license_manifest import (
    GetLicenseManifest,
    GetLicenseText,
    LicenseManifestUnavailable,
    LicenseTextUnknown,
)

router = APIRouter(prefix="/api/lizenzen", tags=["lizenzen"])


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit den
# echten Use-Cases verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (S3).
def provide_get_license_manifest() -> GetLicenseManifest:
    raise NotImplementedError("GetLicenseManifest wird in app.py verdrahtet")


def provide_get_license_text() -> GetLicenseText:
    raise NotImplementedError("GetLicenseText wird in app.py verdrahtet")


# Die laufende Plattform wird im Composition Root ermittelt und hier hereingereicht
# (Aufgabe 3d) -- weder Router noch Use-Case fragen selbst ``sys.platform``.
def provide_laufende_plattform() -> str:
    raise NotImplementedError("Die laufende Plattform wird in app.py verdrahtet")


@router.get("")
def get_license_manifest(
    manifest_uc: Annotated[GetLicenseManifest, Depends(provide_get_license_manifest)],
    plattform: Annotated[str, Depends(provide_laufende_plattform)],
) -> dict[str, Any]:
    """Die Lizenzaufstellung OHNE Lizenztexte.

    Traegt den Kopf (``schema_version``/``erzeugt_am``/``produktversion``/
    ``plattform``) und die vier Abschnitte ``werk``, ``bestandteile``, ``luecken``,
    ``ebene_nativ``. Je Bestandteil ADDITIV ``lizenz_id_normalisiert`` (Filterindex;
    ``lizenz_id`` bleibt roh) und -- nur fuer die Ebene ``programme`` --
    ``vorhanden`` mit ``vorhanden``/``fehlt``/``nicht_zutreffend``.

    Fehlt die Aufstellung, ist das ``503`` mit den geprueften Pfaden in der Meldung,
    KEINE leere Antwort mit 200.
    """
    try:
        return manifest_uc(plattform=plattform)
    except LicenseManifestUnavailable as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.get("/text")
def get_license_text(
    text_uc: Annotated[GetLicenseText, Depends(provide_get_license_text)],
    schluessel: Annotated[
        str,
        Query(
            min_length=1,
            description=(
                "Schluessel des Lizenztextes, z. B. 'spdx:MIT' oder "
                "'paket:python/anyio'. Als Abfrageparameter, weil Schluessel "
                "Doppelpunkt und Schraegstrich tragen."
            ),
        ),
    ],
) -> dict[str, Any]:
    """EIN Lizenztext, zeichengleich wie in der Aufstellung.

    Der Text wird NICHT veraendert -- nicht gekuerzt, nicht umbrochen, nicht
    uebersetzt. Unbekannter Schluessel -> ``404``; fehlende/unlesbare Aufstellung ->
    ``503``. In keinem Fall ein leerer Text mit 200.
    """
    try:
        text = text_uc(schluessel)
    except LicenseTextUnknown as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except LicenseManifestUnavailable as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    return {"schluessel": schluessel, "text": text}
