"""FastAPI-Router der analysis-Domaene (v2, AN.3), Route ``GET /api/analysis``.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich ``application/`` (import-linter:
api -> nur application). Konkrete Adapter und ``domain``/``application``-Typen werden hier
NICHT importiert -- der Runner kommt per FastAPI-Dependency herein (Verdrahtung im Composition
Root ``app.py``), und die Ergebnis-Objekte werden ueber Attribut-Zugriff zu JSON serialisiert
(Typ ``Any``, Muster wie ``api/process._process_to_dict``).

``GET /api/analysis`` liefert die aktuellen Beobachtungen der Lage (ZEIGEN + EINORDNEN, NIE
URTEILEN). Der Runner baut den Snapshot frisch aus traffic+process (Projektion im Composition
Root), wertet ihn aus und liefert die rohen ResolvedObservation-Objekte; dieser Rand
serialisiert sie. Eine leere Lage -> ``[]`` (kein Fehler).
"""

from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends

router = APIRouter(prefix="/api", tags=["analysis"])


# Composition-Root-Callable: baut den Snapshot frisch, ruft AnalyzeSnapshot und liefert die
# rohen ResolvedObservation-Objekte als ``list[Any]`` -- der api-Ring kennt keine domain/
# application-Typen, daher ``Any``. Async, weil die Projektion traffic/process (async) aufruft.
type AnalyzeRunner = Callable[[], Awaitable[list[Any]]]


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit dem echten
# Callable verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (Muster
# provide_list_processes).
def provide_analyze() -> AnalyzeRunner:
    raise NotImplementedError("AnalyzeRunner wird in app.py verdrahtet")


def _resolved_to_dict(r: Any) -> dict[str, Any]:
    # r ist eine application.ResolvedObservation (.observation + .help_url); per
    # Attribut-Zugriff serialisiert (kein domain/application-Import). Die eingebettete
    # Observation traegt rule_id/severity/title/detail/help_kind/subject.
    return {
        "rule_id": r.observation.rule_id,
        "severity": r.observation.severity,
        "title": r.observation.title,
        "detail": r.observation.detail,
        "help_kind": r.observation.help_kind,
        "subject": r.observation.subject,
        "help_url": r.help_url,
    }


@router.get("/analysis")
async def get_analysis(
    analyze: Annotated[AnalyzeRunner, Depends(provide_analyze)],
) -> list[dict[str, Any]]:
    """Aktuelle Beobachtungen der Lage (ZEIGEN + EINORDNEN, NIE URTEILEN).

    Der Runner baut den Snapshot frisch (Projektion aus traffic+process im Composition Root),
    wertet ihn aus und liefert die rohen Beobachtungen; dieser Rand serialisiert sie ueber
    Attribut-Zugriff. Eine leere Lage -> ``[]`` (kein Fehler).
    """
    items = await analyze()
    return [_resolved_to_dict(r) for r in items]
