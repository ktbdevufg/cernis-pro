"""Infrastructure-Adapter der monitoring-Domaene.

Zweites Paket der neuen Ringe (nach ``infrastructure.scanning``), das ``modules/``
importieren darf -- ENG eingezaeunt via ADR 0007 (in M.4 erweitert) und SCOPED:
nur ``pinger`` und ``notifier`` nutzen ``modules`` (``_ping_burst`` /
``_notify_macos``); ``target_source`` nutzt zusaetzlich ``modules.interfaces``
(unmigriertes Hilfsmodul). Die sqlite-Repos (``rtt_history`` / ``monitor_events``)
kommen bewusst OHNE ``modules`` aus (eigenes Schema), und Settings liest
``target_source`` ueber den migrierten ``ports/settings``-Port.
"""

from infrastructure.monitoring.monitor_events import SqliteMonitorEventRepository
from infrastructure.monitoring.notifier import MonitorNotifierAdapter
from infrastructure.monitoring.pinger import MonitorPingerAdapter
from infrastructure.monitoring.rtt_history import SqliteRttHistoryRepository
from infrastructure.monitoring.target_source import CompositeTargetSource

__all__ = [
    "CompositeTargetSource",
    "MonitorNotifierAdapter",
    "MonitorPingerAdapter",
    "SqliteMonitorEventRepository",
    "SqliteRttHistoryRepository",
]
