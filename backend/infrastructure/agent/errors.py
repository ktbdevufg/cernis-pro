"""Infrastructure-Exceptions der agent-Adapter.

Zwei Fehlerklassen, beide im Geiste von ADR 0001 (keine stillen Fallbacks):

* ``CorruptAgentError`` -- eine gespeicherte JSON-Spalte (``cidrs``) ist kein
  gueltiges JSON. Muster ``CorruptDeviceError``: ein kaputter Wert ist ein
  Fehler MIT id-Bezug, kein leiser Roh-/Leer-Fallback.
* ``AgentScanError`` -- der ausgehende WebSocket-Proxy-Scan ist fehlgeschlagen.
  Ersetzt den stillen Altcode-Fallback, der einen Verbindungsfehler als
  Pseudo-Host (``{"error": ...}``) in die Ergebnisliste schmuggelte (Finding
  S3): ein Scan-Fehler ist ein Fehler, kein als Ergebnis getarnter Fehlschlag.
"""


class CorruptAgentError(Exception):
    """Die gespeicherte ``cidrs``-Spalte eines Agenten ist kein gueltiges JSON.

    Ersetzt einen stillen Roh-/Leer-Fallback: ein kaputter Wert ist ein Fehler
    MIT id-Bezug (Muster ``CorruptDeviceError`` bei devices).
    """

    def __init__(self, agent_id: str, raw_value: str) -> None:
        self.agent_id = agent_id
        self.raw_value = raw_value
        super().__init__(
            f"Agent {agent_id!r}: Spalte 'cidrs' enthaelt kein gueltiges JSON: {raw_value!r}"
        )


class AgentScanError(Exception):
    """Der ausgehende Proxy-Scan gegen einen Remote-Agenten ist fehlgeschlagen.

    Wird vom ``WebsocketsAgentScanClient`` geworfen, wenn der WebSocket-Aufbau
    oder die Uebertragung scheitert. Ersetzt den stillen Altcode-Fallback
    (``results.append({"error": str(e)})``), der den Fehler als Pseudo-Host in
    die Ergebnisliste gab. Die api-Schicht mappt diesen Fehler spaeter auf einen
    Statuscode; das Mapping ist NICHT Sache des Adapters.
    """

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"Proxy-Scan gegen {url!r} fehlgeschlagen: {reason}")
