"""Application-Ring der blocklist-Domaene -- Quellen verwalten, laden, abgleichen, pruefen.

Kennt ``ports/`` + ``domain/`` + stdlib, NIE ``infrastructure/``/``api/``/``modules/``
(import-linter). Die Netz-NAHT ist das ``BlocklistFetcher``-Protocol (echte Impl in
``infrastructure``); alle Ports/der Fetcher kommen per Constructor-Injection herein.

Re-exportiert die Use-Cases, die Ergebnis-/Eingangs-Datentraeger, den Fetcher-Vertrag,
den Scheduler-Handler, die Wire-Hebung, die Application-Exceptions und die Settings-Key-
Konstanten -- so zieht der Composition Root alles aus ``application.blocklist``.
"""

from application.blocklist.constants import (
    DEFAULT_GROUP_THREAT_ENABLED,
    DEFAULT_GROUP_TRACKER_ADS_ENABLED,
    DEFAULT_REFRESH_DAYS,
    DEFAULT_STRICTNESS,
    SETTING_GROUP_THREAT,
    SETTING_GROUP_TRACKER_ADS,
    SETTING_REFRESH_DAYS,
    SETTING_STRICTNESS,
)
from application.blocklist.errors import (
    BlocklistError,
    BlocklistFetchError,
    UnknownStrictnessError,
)
from application.blocklist.parsing import parse_blocklist
from application.blocklist.scheduler_handler import BlocklistRefreshHandler
from application.blocklist.use_cases import (
    AddSourceResult,
    AddUserSource,
    BlocklistFetcher,
    CheckBlocklistHealth,
    ContactInput,
    DeleteUserSource,
    HealthIssue,
    ImportResult,
    ImportUploadedSource,
    ListBlocklistSources,
    MatchContacts,
    RefreshDueSources,
    RefreshResult,
    RefreshSource,
    ResetSourcesToDefaults,
    SeedBuiltinDohContent,
    SeedDefaultSources,
    UpdateUserSource,
    strictness_from_wire,
)

__all__ = [
    "DEFAULT_GROUP_THREAT_ENABLED",
    "DEFAULT_GROUP_TRACKER_ADS_ENABLED",
    "DEFAULT_REFRESH_DAYS",
    "DEFAULT_STRICTNESS",
    "SETTING_GROUP_THREAT",
    "SETTING_GROUP_TRACKER_ADS",
    "SETTING_REFRESH_DAYS",
    "SETTING_STRICTNESS",
    "AddSourceResult",
    "AddUserSource",
    "BlocklistError",
    "BlocklistFetchError",
    "BlocklistFetcher",
    "BlocklistRefreshHandler",
    "CheckBlocklistHealth",
    "ContactInput",
    "DeleteUserSource",
    "HealthIssue",
    "ImportResult",
    "ImportUploadedSource",
    "ListBlocklistSources",
    "MatchContacts",
    "RefreshDueSources",
    "RefreshResult",
    "RefreshSource",
    "ResetSourcesToDefaults",
    "SeedBuiltinDohContent",
    "SeedDefaultSources",
    "UnknownStrictnessError",
    "UpdateUserSource",
    "parse_blocklist",
    "strictness_from_wire",
]
