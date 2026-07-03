"""Escaping fuer die Einbettung von Werten in AppleScript-String-Literale (stdlib-only).

Reine Hilfsfunktion ohne Abhaengigkeiten: title/message/subtitle fliessen in den
``osascript``-Programmtext der Desktop-Notifier; ein ``"`` im Wert wuerde sonst aus dem
String-Literal ausbrechen (AppleScript-Injection, nur macOS wirksam). Die Funktion
escaped fuer ein DOUBLE-QUOTED-String-Literal.
"""


def escape_applescript_literal(value: str) -> str:
    """Escaped ``value`` fuer die Einbettung in ein AppleScript-Double-Quoted-Literal.

    Zuerst der Backslash (``\\`` -> ``\\\\``), dann der Doublequote (``"`` -> ``\\"``) --
    die Reihenfolge ist wichtig, damit ein spaeter eingefuegter Escape-Backslash nicht
    erneut verdoppelt wird. Ein Wert ohne diese Zeichen bleibt unveraendert.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')
