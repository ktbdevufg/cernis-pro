"""Adapter der security-Domaene: ARP-Guard-Persistenz + drei Inspektoren.

``SqliteArpGuardRepository`` ist reine Struktur-Migration (AS-IS, SEC.1). Die drei
Inspektor-Adapter (``CveLookupAdapter``/``TlsInspectorAdapter``/
``DefaultCredsCheckerAdapter``) sind v2-stdlib-Reimplementierungen (DF2) mit den
S3-Heilungen (Muster i: Warn-Log + Ergebnis behalten). KEIN ``modules``-Import ->
kein ADR-0007 fuer security.
"""

from infrastructure.security.arp_repository import SqliteArpGuardRepository
from infrastructure.security.cve import CveLookupAdapter
from infrastructure.security.default_creds import DefaultCredsCheckerAdapter
from infrastructure.security.default_creds_history_db import (
    CorruptDefaultCredsHistoryError,
    SqliteDefaultCredsHistoryRepository,
)
from infrastructure.security.default_creds_list_db import (
    CorruptDefaultCredsError,
    SqliteDefaultCredsListRepository,
)
from infrastructure.security.net_scope import is_private_target
from infrastructure.security.tls import TlsInspectorAdapter

__all__ = [
    "CorruptDefaultCredsError",
    "CorruptDefaultCredsHistoryError",
    "CveLookupAdapter",
    "DefaultCredsCheckerAdapter",
    "SqliteArpGuardRepository",
    "SqliteDefaultCredsHistoryRepository",
    "SqliteDefaultCredsListRepository",
    "TlsInspectorAdapter",
    "is_private_target",
]
