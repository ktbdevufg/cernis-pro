"""Infrastructure-Adapter der monitoring-Domaene.

Zweites Paket der neuen Ringe (nach ``infrastructure.scanning``), das ``modules/``
importieren darf -- ENG eingezaeunt via ADR 0007 (in M.4 erweitert) und SCOPED:
nur ``pinger`` und ``notifier`` nutzen ``modules`` (``_ping_burst`` /
``_notify_macos``); ``target_source`` nutzt zusaetzlich ``modules.interfaces``
(unmigriertes Hilfsmodul). Die sqlite-Repos (``rtt_history`` / ``monitor_events`` /
``sla_samples``) kommen bewusst OHNE ``modules`` aus (eigenes Schema), und Settings
liest ``target_source`` ueber den migrierten ``ports/settings``-Port. Auch die M.6-
Adapter (``schedule_repository`` SQLite, ``job_scheduler`` APScheduler-direkt) und
der M.7-Lese-Adapter ``sla_samples`` (SQLite) sind ``modules``-frei. Der M.9-WS-
Fan-out (``broadcaster``, FastAPI-WebSocket) ist ebenfalls ``modules``-frei.
"""

from infrastructure.monitoring.broadcaster import WebSocketMonitorBroadcaster
from infrastructure.monitoring.job_scheduler import ApschedulerJobScheduler
from infrastructure.monitoring.logging_events import SqliteLoggingEventRepository
from infrastructure.monitoring.logging_rtt import SqliteLoggingRttRepository
from infrastructure.monitoring.logging_sink import MonitorLoggingSink
from infrastructure.monitoring.logging_tasks import SqliteLoggingTaskRepository
from infrastructure.monitoring.monitor_events import SqliteMonitorEventRepository
from infrastructure.monitoring.notifier import MonitorNotifierAdapter
from infrastructure.monitoring.pinger import MonitorPingerAdapter
from infrastructure.monitoring.rtt_history import SqliteRttHistoryRepository
from infrastructure.monitoring.schedule_repository import SqliteScheduleRepository
from infrastructure.monitoring.sla_samples import SqliteSlaSampleRepository
from infrastructure.monitoring.target_source import CompositeTargetSource

__all__ = [
    "ApschedulerJobScheduler",
    "CompositeTargetSource",
    "MonitorLoggingSink",
    "MonitorNotifierAdapter",
    "MonitorPingerAdapter",
    "SqliteLoggingEventRepository",
    "SqliteLoggingRttRepository",
    "SqliteLoggingTaskRepository",
    "SqliteMonitorEventRepository",
    "SqliteRttHistoryRepository",
    "SqliteScheduleRepository",
    "SqliteSlaSampleRepository",
    "WebSocketMonitorBroadcaster",
]
