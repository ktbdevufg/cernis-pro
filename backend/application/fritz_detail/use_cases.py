"""Use-Cases der fritz_detail-Domaene.

Orchestriert ausschliesslich den Port (``FritzDetailPort``) -- kennt ``domain/``
und ``ports/``, NIEMALS ``infrastructure/`` (import-linter). Der Port kommt per
Constructor-Injection als Protocol-Typ herein, nie ein konkreter Adapter. Kein
State ueber Aufrufe, keine Framework-Imports (Muster wie ``GetDevices``).
"""

from domain.fritz_detail import FritzDetail
from ports.fritz_detail import FritzDetailPort


class GetFritzDetail:
    """Liefert den read-only Detail-Schnappschuss der konfigurierten FRITZ!Box.

    Reine Delegation an den Port: "nicht erreichbar" kommt als
    ``FritzDetail(reachable=False)`` zurueck (Leer-Zustand, kein Fehler); ein
    Auth-Fehler fliegt als Exception aus dem Adapter und wird hier NICHT gefangen
    (das HTTP-Mapping passiert im api-Ring).
    """

    def __init__(self, port: FritzDetailPort) -> None:
        self._port = port

    async def __call__(self) -> FritzDetail:
        return await self._port.get_detail()
