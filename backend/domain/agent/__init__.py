"""Modelle und Key-Schema der agent-Domaene (NUR Client-Seite)."""

from domain.agent.keys import token_key
from domain.agent.models import AgentPingResult, RemoteAgent

__all__ = [
    "AgentPingResult",
    "RemoteAgent",
    "token_key",
]
