"""Die EINE Quelle des Keystore-Key-Schemas der agent-Domaene.

Reine Funktion (stdlib-only), analog zu ``normalize_mac`` in ``domain/devices``:
ein einziger Ort, der festlegt, unter welchem Key der Agent-Token im
``SecretStore`` liegt. So koennen Use-Case (Schreiben), Ping/Scan (Lesen) und
Loeschen nie auseinanderlaufen.
"""


def token_key(agent_id: str) -> str:
    """Keystore-Key fuer den Token eines Agenten: ``"agent_token:<id>"``.

    Deterministisch und kollisionsfrei pro ``agent_id``. Das Schema ist die
    EINE Quelle -- wird es hier geaendert, ziehen alle Aufrufstellen mit.
    """
    return f"agent_token:{agent_id}"
