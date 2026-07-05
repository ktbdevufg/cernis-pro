"""FastAPI-Router der usage-Zaehlung (Nutzungs-Ranking des Startseiten-Schnellzugriffs).

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich ``application/`` -- konkret
ueber Composition-Root-Runner, die per FastAPI-Dependency hereinkommen (Verdrahtung in
``app.py``). Der api-Ring kennt WEDER ``domain``/``application``-Typen noch die Adapter
(import-linter: api -> nur application); die Ergebnis-Objekte (``UsageRecord``) werden per
Attribut-Zugriff zu JSON serialisiert (Typ ``Any``, Muster ``api/analysis``).

* ``POST /api/usage/record`` -- Body ``{feature_id: str}`` -> ``{ok: true}``. Zaehlt EINE
  nutzer-ausgeloeste Funktions-Oeffnung (ruft ``RecordFeatureUsage`` ueber den Runner).
* ``GET  /api/usage/top?limit=5`` -> ``[{feature_id, count, last_used}]`` (absteigend nach
  count; ruft ``GetTopFeatures``). Leerer Stand -> ``[]`` (kein Fehler).

``feature_id`` ist ein STABILER Frontend-Schluessel (z. B. ``"observe:scan"``); der Rand
validiert ihn NICHT gegen eine feste Liste -- das Backend zaehlt nur. ``limit`` wird per
``Query``-Constraint auf 1-50 begrenzt (KEIN stiller Fallback, S3): ein Wert ausserhalb ->
HTTP 422.
"""

from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api", tags=["usage"])


class RecordUsageBody(BaseModel):
    """POST /api/usage/record -- ein schmales Request-DTO (api-eigenes Modell).

    Traegt genau den stabilen ``feature_id``-Schluessel, den das Frontend beim Oeffnen einer
    Funktion sendet (z. B. ``"observe:scan"``, ``"investigate:cve"``, ``"reporting"``).
    """

    feature_id: str


# Composition-Root-Callable: reicht ``RecordFeatureUsage`` herein (feature_id -> None). Der
# api-Ring kennt den Use-Case NICHT direkt (api -> nur application); das Callable wird im
# Composition Root verdrahtet. Synchron (der Store ist lokaler SQLite-Zugriff).
type RecordUsageRunner = Callable[[str], None]


# Composition-Root-Callable: reicht ``GetTopFeatures`` herein (limit -> rohe UsageRecord-
# Objekte als ``list[Any]``). Der api-Ring kennt weder ``GetTopFeatures`` noch
# ``UsageRecord``, daher ``Any``. Synchron (lokaler SQLite-Zugriff).
type TopFeaturesRunner = Callable[[int], list[Any]]


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit dem echten
# Callable verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (Muster provide_analyze).
def provide_record_usage() -> RecordUsageRunner:
    raise NotImplementedError("RecordUsageRunner wird in app.py verdrahtet")


def provide_top_features() -> TopFeaturesRunner:
    raise NotImplementedError("TopFeaturesRunner wird in app.py verdrahtet")


def _record_to_dict(record: Any) -> dict[str, Any]:
    # record ist ein ports.usage.UsageRecord; per Attribut-Zugriff serialisiert (kein
    # domain/application-Import). last_used ist ISO-UTC-Text oder None.
    return {
        "feature_id": record.feature_id,
        "count": record.count,
        "last_used": record.last_used,
    }


@router.post("/usage/record")
def record_usage(
    body: RecordUsageBody,
    record: Annotated[RecordUsageRunner, Depends(provide_record_usage)],
) -> dict[str, bool]:
    """Zaehlt EINE nutzer-ausgeloeste Funktions-Oeffnung (Upsert im Store).

    Der Runner reicht den ``feature_id`` an ``RecordFeatureUsage`` durch. Erfolg -> 200
    ``{"ok": true}``. Die Zaehlung ist Nebensache; der Aufrufer (Frontend) darf einen Fehler
    still schlucken -- der Endpunkt selbst meldet echte Fehler aber ehrlich (kein stiller
    Fallback im Backend, S3).
    """
    record(body.feature_id)
    return {"ok": True}


@router.get("/usage/top")
def top_features(
    top: Annotated[TopFeaturesRunner, Depends(provide_top_features)],
    limit: Annotated[int, Query(ge=1, le=50)] = 5,
) -> list[dict[str, Any]]:
    """Liefert die ``limit`` meistgeoeffneten Funktionen (absteigend nach count).

    Der Runner liefert die rohen ``UsageRecord``-Objekte; dieser Rand serialisiert sie ueber
    Attribut-Zugriff. Ein leerer Stand -> ``[]`` (kein Fehler). ``limit`` 1-50 (Query-
    Constraint) -- ausserhalb -> HTTP 422 (KEIN stiller Fallback).
    """
    return [_record_to_dict(record) for record in top(limit)]
