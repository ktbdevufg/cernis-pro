"""Application-Exceptions der agent-Use-Cases.

Eigene Fehlerklasse OHNE HTTP-Details -- das Mapping auf Statuscodes passiert
spaeter in ``api/`` (Folgeschritt). Der Altcode prueft die Existenz heute in der
Route (``next((a for a in agents if a["id"] == agent_id), None)`` ->
``404 {"error": "Agent not found"}``); v2 zieht diese Logik in den Use-Case.
"""


class AgentApplicationError(Exception):
    """Basis fuer Fehler der agent-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""


class AgentNotFoundError(AgentApplicationError):
    """Ein Agent ist nicht (sichtbar) registriert.

    Wird geworfen, wenn ``ping``/``scan`` auf eine id treffen, die in der
    enabled-gefilterten Sicht nicht existiert. Altcode-treu (Finding-frei): ein
    DEAKTIVIERTER Agent ist fuer ping/scan unsichtbar -- der Altcode las
    ausschliesslich ``WHERE enabled=1`` und lieferte fuer alles andere 404.
    """

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        super().__init__(f"Agent {agent_id!r} ist nicht (aktiv) registriert.")
