"""Infrastructure-Adapter der agent-Domaene (NUR Client-Seite).

Drei Adapter hinter den ``ports/agent``-Vertraegen:

* ``SqliteAgentRepository`` -- reine Persistenz der Agent-Stammdaten, TOKEN-FREI.
  Schreibt ausschliesslich ``id/name/url/enabled/cidrs``; der Token lebt im
  ``SecretStore`` (Variante B, wie settings), nicht in der DB.
* ``UrllibAgentPinger`` -- ausgehender Erreichbarkeits-Check (urllib GET
  ``/agent/info``, blockierend in ``asyncio.to_thread``).
* ``WebsocketsAgentScanClient`` -- ausgehender Proxy-Scan (WebSocket).

Bewusst KEIN ``modules/``-Import (kein ADR 0007 fuer agent, siehe ADR 0008): der
alte Fernet-Krypto-Pfad ist durch den ``SecretStore`` ersetzt, die ausgehende I/O
ist nativ ueber ``urllib``/``websockets`` reimplementiert (keine systemnahe
Wegwerf-Schicht wie bei scanning/monitoring).
"""

from infrastructure.agent.errors import AgentScanError, CorruptAgentError
from infrastructure.agent.pinger import UrllibAgentPinger
from infrastructure.agent.repository import SqliteAgentRepository
from infrastructure.agent.scan_client import WebsocketsAgentScanClient

__all__ = [
    "AgentScanError",
    "CorruptAgentError",
    "SqliteAgentRepository",
    "UrllibAgentPinger",
    "WebsocketsAgentScanClient",
]
