"""Ports (Vertraege) der scheduler-Domaene -- Persistenz + entkoppelnder Job-Handler.

Ein Persistenz-Vertrag (``sync`` -- lokaler SQLite-Zugriff, Muster der uebrigen Repos)
und EIN Handler-Vertrag, der die scheduler-Domaene vom Aufgaben-INHALT entkoppelt:

* ``ScheduledJobRepository`` -- Job-Persistenz (Anlegen + Lese-Views + Zustand/Loeschen).
* ``JobHandler``             -- die ENTKOPPELNDE Naht (analog ``CveLookupProvider``): der
  Scheduler ruft ``run(params)`` auf, OHNE den Inhalt zu kennen; was der Handler tut,
  lebt im Composition Root.

``ports/`` kennt nur ``domain/scheduler``-Typen + stdlib (import-linter "ports kennen
hoechstens domain"). KEIN Bezug auf monitoring/scanning/irgendeine andere Domaene
(independence). KEIN ``@runtime_checkable`` (Muster der uebrigen Domaenen, statische
Pruefung ueber mypy + Verdrahtung im Composition Root).
"""

from typing import Protocol

from domain.scheduler.models import DailyWindow, JobState, ScheduledJob

__all__ = [
    "DailyWindow",
    "JobHandler",
    "JobState",
    "ScheduledJob",
    "ScheduledJobRepository",
]


# ── Persistenz-Vertrag ────────────────────────────────────────────────────────


class ScheduledJobRepository(Protocol):
    """Persistenz der geplanten Jobs -- Anlegen + Lese-Views + Zustand/Loeschen.

    ``sync`` (lokaler SQLite-Zugriff). ``CREATE TABLE IF NOT EXISTS`` im Adapter
    (idempotentes Schema, injizierter db_path -- Muster der uebrigen Repos).
    """

    def add(self, job_type: str, params: tuple[tuple[str, str], ...], window: DailyWindow) -> int:
        """Legt einen neuen Job an (``state`` startet ``ACTIVE``) und liefert die neue id."""
        ...

    def get(self, job_id: int) -> ScheduledJob | None:
        """Job zur id, oder ``None`` wenn die id unbekannt ist (legitimer Leerzustand)."""
        ...

    def list_active(self) -> list[ScheduledJob]:
        """Alle Jobs mit ``state == ACTIVE`` (Worker-Sicht). Keine -> ``[]``."""
        ...

    def list_all(self) -> list[ScheduledJob]:
        """Alle Jobs ueber alle Zustaende (Verwaltungs-Sicht). Keine -> ``[]``."""
        ...

    def update_state(self, job_id: int, state: JobState) -> None:
        """Setzt den Lebenszyklus-Zustand eines Jobs (z. B. ACTIVE -> PAUSED/FINISHED)."""
        ...

    def delete(self, job_id: int) -> None:
        """Loescht einen Job (unbekannte id ist ein No-Op, kein Fehler)."""
        ...

    def clear_all(self) -> None:
        """Leert alle geplanten Jobs (nur die eigene Tabelle)."""
        ...


# ── Entkoppelnder Handler-Vertrag ─────────────────────────────────────────────


class JobHandler(Protocol):
    """Fuehrt die eigentliche Aufgabe eines Jobs aus -- die ENTKOPPELNDE Naht (Weg 2).

    Jeder Handler bedient genau EINEN ``job_type`` (Attribut ``job_type``). Der Scheduler
    waehlt anhand des Typs den Handler und ruft ``run(params)`` -- OHNE den Inhalt zu
    kennen. Die Bedeutung von ``job_type``/``params`` lebt im Composition Root, nicht hier.
    """

    job_type: str

    async def run(self, params: tuple[tuple[str, str], ...]) -> None:
        """Fuehrt die Aufgabe aus; bekommt nur die OPAQUEN ``params``.

        ``async`` -- die Aufgabe kann I/O treiben. FEHLERTOLERANT zu implementieren: ein
        Fehler darf den Worker-Loop NICHT killen (der Loop faengt, S3 -- keine stillen
        Fallbacks, aber auch kein Loop-Tod durch einen einzelnen Handler).
        """
        ...
