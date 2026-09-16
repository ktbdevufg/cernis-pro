"""FastAPI-Router des v2-Schedulers (Block 3a, Etappe 3b), prefix ``/api/scheduler``.

Aeusserer Ring: nimmt HTTP entgegen. Wie ``api/dns_watch.py`` (und ``api/cve.py``)
kennt dieser Router WEDER ``application`` NOCH ``infrastructure`` NOCH ``modules``
(Regel 4): die injizierten Runner kommen als schmale lokale Vertraege per Dependency
herein, verdrahtet im Composition Root (``app.py``).

Damit der api-Ring application-frei bleibt UND der Aufruf trotzdem typsicher ist (mypy
strict), beschreiben schmale lokale ``Protocol``s die Vertraege der injizierten Lese-/
Schreib-Runner (``SchedulerCreateRunner``/``SchedulerListRunner``) und ``Callable``s die
der Zustands-Runner (pause/resume/delete). Der api-Ring definiert eigene schmale pydantic-
Wire-Modelle (``DailyWindowBody``/``CreateJobBody``/``ScheduledJobOut``); die Projektion
vom application-/domain-Typ ``ScheduledJob`` auf die flache Wire-Form macht der
Composition-Root-Runner in ``app.py``, NICHT der Router -- so nennt der api-Ring den
application-/domain-Typ nie.

Endpunkte:

* ``POST   /api/scheduler/jobs``              -> legt einen Job an, liefert ``{"id": <int>}``.
* ``GET    /api/scheduler/jobs``              -> alle geplanten Jobs (flache Wire-Form).
* ``POST   /api/scheduler/jobs/{job_id}/pause``  -> haelt einen Job an. ``{"ok": true}``.
* ``POST   /api/scheduler/jobs/{job_id}/resume`` -> setzt einen Job fort. ``{"ok": true}``.
* ``DELETE /api/scheduler/jobs/{job_id}``     -> loescht einen Job. ``{"ok": true}``.

Alle Routen synchron (lokaler SQLite-Zugriff, Muster ``dns_watch`` acknowledge-Route).
Noch ist nichts sichtbar (kein Frontend) -- der Worker laeuft ohne Handler-Registry und
tut nichts (ehrlicher Leerzustand, S3); diese Routen verwalten nur die Jobs.
"""

from collections.abc import Callable
from typing import Annotated, Protocol

from fastapi import APIRouter, Depends, Path
from pydantic import BaseModel

router = APIRouter(prefix="/api/scheduler", tags=["scheduler"])


# ── schmale api-Wire-Modelle (eigene Wire-Form, KEIN domain/application-Typ) ────
# Die Felder spiegeln ``domain.scheduler.DailyWindow``/``ScheduledJob``, ohne diese
# Typen zu importieren. Der Composition-Root-Runner baut aus ``CreateJobBody`` den
# domain-``DailyWindow`` und projiziert den ``ScheduledJob`` auf ``ScheduledJobOut``
# (Regel 4: api kennt domain/application nicht).


class DailyWindowBody(BaseModel):
    """Eingabe-Form des wiederkehrenden Tagesfensters eines Jobs.

    ``weekdays`` als Liste (0=Montag .. 6=Sonntag); die LEERE Liste bedeutet "alle Tage"
    (keine Wochentags-Einschraenkung, Domaenen-Konvention ``DailyWindow.weekdays``).
    ``until_epoch`` ``0.0`` ist der ehrliche "kein Ende"-Leerzustand (unbegrenzt gueltig).
    """

    start_minute: int
    end_minute: int
    weekdays: list[int]
    from_epoch: float
    until_epoch: float


class CreateJobBody(BaseModel):
    """POST /api/scheduler/jobs -- der Anlege-Befehl.

    ``params`` als Liste von 2er-Tupeln (pydantic nimmt das als ``list[tuple[str, str]]``
    an); leere Liste = keine Parameter. ``job_type`` ist die OPAQUE Typ-Kennung, die der
    Composition Root einem registrierten Handler zuordnet (in Etappe 3b noch keiner).
    """

    job_type: str
    params: list[tuple[str, str]] = []
    window: DailyWindowBody


class ScheduledJobOut(BaseModel):
    """Flache Wire-Form eines geplanten Jobs (``window`` flach ausgerollt, ``state`` als str).

    Spiegelt ``ScheduledJob`` + ``DailyWindow`` flach: das verschachtelte Tagesfenster
    liegt als einzelne Felder (``start_minute``/``end_minute``/``weekdays``/``from_epoch``/
    ``until_epoch``) direkt am Job. Die Projektion vom domain-Typ faellt im Composition Root.
    """

    id: int
    job_type: str
    params: list[tuple[str, str]]
    start_minute: int
    end_minute: int
    weekdays: list[int]
    from_epoch: float
    until_epoch: float
    state: str


# ── injizierte Composition-Root-Runner ────────────────────────────────────────
# Provider-Marker: in app.py per dependency_overrides mit den echten Root-Runnern
# verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (kein stiller Fallback, S3).


class SchedulerCreateRunner(Protocol):
    """Schmaler Vertrag des injizierten Anlege-Runners (Body -> neue id)."""

    def __call__(self, body: CreateJobBody) -> int:
        """Legt den Job an (Wire-Body -> domain-Anlage) und liefert die neue id."""
        ...


def provide_scheduler_create() -> SchedulerCreateRunner:
    raise NotImplementedError("SchedulerCreateRunner wird in app.py verdrahtet")


class SchedulerListRunner(Protocol):
    """Schmaler Vertrag des injizierten Lese-Runners (liefert die fertige flache Sicht)."""

    def __call__(self) -> list[ScheduledJobOut]:
        """Liefert alle geplanten Jobs api-fertig (flache Wire-Form)."""
        ...


def provide_scheduler_list() -> SchedulerListRunner:
    raise NotImplementedError("SchedulerListRunner wird in app.py verdrahtet")


# Zustands-Runner: pause/resume/delete je ein eigenes Callable (job_id -> None). Der
# api-Ring kennt das Repository/die Use-Cases NICHT direkt; die Callables werden im
# Composition Root verdrahtet. Synchron (lokaler SQLite-Zugriff).
type SchedulerPauseRunner = Callable[[int], None]
type SchedulerResumeRunner = Callable[[int], None]
type SchedulerDeleteRunner = Callable[[int], None]


def provide_scheduler_pause() -> SchedulerPauseRunner:
    raise NotImplementedError("SchedulerPauseRunner wird in app.py verdrahtet")


def provide_scheduler_resume() -> SchedulerResumeRunner:
    raise NotImplementedError("SchedulerResumeRunner wird in app.py verdrahtet")


def provide_scheduler_delete() -> SchedulerDeleteRunner:
    raise NotImplementedError("SchedulerDeleteRunner wird in app.py verdrahtet")


# ── Routen ───────────────────────────────────────────────────────────────────


@router.post("/jobs")
def create_job(
    body: CreateJobBody,
    create: Annotated[SchedulerCreateRunner, Depends(provide_scheduler_create)],
) -> dict[str, int]:
    """Legt einen neuen geplanten Job an und liefert seine neue id.

    Der Composition-Root-Runner baut aus dem flachen ``CreateJobBody`` den domain-
    ``DailyWindow`` und die ``params``-Tupel und legt den Job ueber den Use-Case an
    (``state`` startet ``active``). Erfolg -> 200 ``{"id": <int>}``.
    """
    return {"id": create(body)}


@router.get("/jobs")
def list_jobs(
    runner: Annotated[SchedulerListRunner, Depends(provide_scheduler_list)],
) -> list[ScheduledJobOut]:
    """Liefert alle geplanten Jobs ueber alle Zustaende (flache Wire-Form). Keine -> ``[]``."""
    return runner()


@router.post("/jobs/{job_id}/pause")
def pause_job(
    job_id: Annotated[int, Path()],
    pause: Annotated[SchedulerPauseRunner, Depends(provide_scheduler_pause)],
) -> dict[str, bool]:
    """Haelt einen Job an (``active`` -> ``paused``). Erfolg -> ``{"ok": true}``."""
    pause(job_id)
    return {"ok": True}


@router.post("/jobs/{job_id}/resume")
def resume_job(
    job_id: Annotated[int, Path()],
    resume: Annotated[SchedulerResumeRunner, Depends(provide_scheduler_resume)],
) -> dict[str, bool]:
    """Setzt einen pausierten Job fort (``paused`` -> ``active``). Erfolg -> ``{"ok": true}``."""
    resume(job_id)
    return {"ok": True}


@router.delete("/jobs/{job_id}")
def delete_job(
    job_id: Annotated[int, Path()],
    delete: Annotated[SchedulerDeleteRunner, Depends(provide_scheduler_delete)],
) -> dict[str, bool]:
    """Loescht einen Job (unbekannte id ist ein No-Op, kein Fehler). Erfolg -> ``{"ok": true}``."""
    delete(job_id)
    return {"ok": True}
