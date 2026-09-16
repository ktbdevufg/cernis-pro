"""Application-Ring der scheduler-Domaene -- der Lifespan-Worker + die Verwaltungs-Use-Cases.

Kennt ``domain/scheduler`` und ``ports/scheduler``, NIE ``infrastructure/`` oder
``modules/`` (import-linter). Der Worker ist vom Aufgaben-INHALT entkoppelt (Weg 2): er
waehlt per ``job_type`` den registrierten ``JobHandler`` und ruft ``run(params)``, ohne
zu wissen, WAS der Job tut. Die Handler-Registry wird im Composition Root befuellt.
"""

from application.scheduler.use_cases import (
    DEFAULT_TICK_INTERVAL_SECONDS,
    CreateScheduledJob,
    DeleteScheduledJob,
    ListScheduledJobs,
    PauseScheduledJob,
    ResumeScheduledJob,
    RunScheduler,
)

__all__ = [
    "DEFAULT_TICK_INTERVAL_SECONDS",
    "CreateScheduledJob",
    "DeleteScheduledJob",
    "ListScheduledJobs",
    "PauseScheduledJob",
    "ResumeScheduledJob",
    "RunScheduler",
]
