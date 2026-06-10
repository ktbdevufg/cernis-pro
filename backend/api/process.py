"""FastAPI-Router der process-Domaene (v2, P.3), Routen ``GET /api/processes`` +
``GET /api/processes/permission``.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich die Use-Cases aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter und
``domain``-Typen werden hier NICHT importiert -- die Use-Cases/Runner kommen per
FastAPI-Dependency herein (Verdrahtung im Composition Root ``app.py``), und die
Domaenen-Objekte werden ueber Attribut-Zugriff zu JSON serialisiert (Typ ``Any``,
Muster wie ``api/traffic._conn_to_dict``).

``GET /api/processes?view=flat|tree`` liefert die Prozess-Sicht -- flach (eine Liste
von Prozessen) ODER als Baum (Wald aus Knoten mit ``info``/``children``). ``view`` ist
ein PFLICHT-Parameter mit genau zwei erlaubten Werten (FastAPI lehnt fehlende/ungueltige
Werte selbst mit 422 ab -- kein Raten, bewusste Nutzerwahl).

``GET /api/processes/permission`` liefert die ``{ok, error}``-Rechte-Naht
(``CheckProcessPermission``): ``ok=false`` + handlungsorientierter Hinweis, wenn die
Detailfelder fremder Prozesse Root brauchen (eigene Prozesse bleiben sichtbar).

HINWEIS ``kind``: Das ``classify_kind``-Ergebnis (kernel/userland) wird in P.3 NICHT in
die Wire-Form aufgenommen -- der api-Ring darf ``domain`` nicht importieren, und eine
kuenstliche Anreicherung im Runner waere ueber das Spezifizierte hinaus. ``classify_kind``
ist gebaut und getestet (P.1); die Nutzung im Wire folgt, wenn das Frontend sie braucht.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends

from application.process import CheckProcessPermission

router = APIRouter(prefix="/api", tags=["process"])


# Composition-Root-Callable: bekommt den ``view``-Parameter und liefert die rohen
# Domaenen-Objekte als ``list[Any]`` (flat: ``ProcessInfo``-Liste; tree: ``ProcessNode``-
# Wald als Liste). Die Wire-Projektion bleibt am Rand (dieser Router) -- der Runner
# serialisiert NICHT. ``list[Any]``, weil der api-Ring keine domain-Typen kennt.
type ListProcessesRunner = Callable[[str], Awaitable[list[Any]]]


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit den
# echten Callables/Use-Cases verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler.
def provide_list_processes() -> ListProcessesRunner:
    raise NotImplementedError("ListProcessesRunner wird in app.py verdrahtet")


def provide_check_process_permission() -> CheckProcessPermission:
    raise NotImplementedError("CheckProcessPermission wird in app.py verdrahtet")


def _process_to_dict(p: Any) -> dict[str, Any]:
    # p ist ein domain.ProcessInfo; per Attribut-Zugriff serialisiert (kein
    # domain-Import). Nicht lesbare Felder sind null (ppid/owner/status/create_time)
    # bzw. leere Liste (cmdline) -- die ehrliche rootless-Naht spiegelt sich im Wire.
    return {
        "pid": p.pid,
        "ppid": p.ppid,
        "name": p.name,
        "owner": p.owner,
        "status": p.status,
        "create_time": p.create_time,
        "cmdline": list(p.cmdline),
    }


def _node_to_dict(n: Any) -> dict[str, Any]:
    # n ist ein domain.ProcessNode (.info + .children); rekursiv serialisiert (Muster
    # _host_to_dict fuer verschachtelte Aggregate). Ein Blatt hat children=[].
    return {
        "info": _process_to_dict(n.info),
        "children": [_node_to_dict(child) for child in n.children],
    }


@router.get("/processes")
async def list_processes(
    view: Literal["flat", "tree"],
    list_processes: Annotated[ListProcessesRunner, Depends(provide_list_processes)],
) -> list[dict[str, Any]]:
    """Prozess-Sicht: flach (``view=flat``) ODER als Baum (``view=tree``).

    ``view`` ist Pflicht mit genau zwei erlaubten Werten -- FastAPI lehnt fehlende/
    ungueltige Werte selbst mit 422 ab (bewusste Nutzerwahl, kein Raten). Der Runner
    liefert anhand ``view`` die passenden Domaenen-Objekte; der Router serialisiert sie
    entsprechend (flach ueber ``_process_to_dict``, Baum rekursiv ueber ``_node_to_dict``).
    Nicht lesbare Felder fremder Prozesse erscheinen als ``null``/``[]`` (rootless-Naht).
    """
    items = await list_processes(view)
    if view == "tree":
        return [_node_to_dict(node) for node in items]
    return [_process_to_dict(proc) for proc in items]


@router.get("/processes/permission")
def get_process_permission(
    check_permission_uc: Annotated[
        CheckProcessPermission, Depends(provide_check_process_permission)
    ],
) -> dict[str, Any]:
    """Rechte-Status fuer die Detailfelder fremder Prozesse.

    ``{ok, error}``-Form: ``ok=true`` bei voller Sicht (Root), sonst ``ok=false`` +
    handlungsorientierter Hinweis (eigene Prozesse bleiben sichtbar).
    """
    return check_permission_uc()
