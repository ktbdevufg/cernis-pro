"""Origin-Pruefung gegen die CORS-Allowlist (Finding F-01, Etappe 1).

Reine, zeitfreie Prueffunktion ohne FastAPI/starlette-Abhaengigkeit -- damit ohne
laufenden Server testbar. Sie schliesst die Angriffsflaeche "fremde Webseite im
lokalen Browser triggert die localhost-API": ein boeser Tab kann zwar einen Request
an ``http://localhost:...`` absetzen, aber der Browser setzt dabei zwingend den
``Origin``-Header auf die Herkunft des Tabs -- und der steht nicht in der Allowlist.

EINE Quelle der Wahrheit fuer erlaubte Origins ist ``cfg.cors_allow_origins``
(``infrastructure.config``). Diese Funktion liest NICHT selbst aus der Umgebung --
die Allowlist wird ihr vom Aufrufer (Composition Root) injiziert. So bleibt der
Origin-Guard deckungsgleich mit der CORS-Semantik (exakter String-Vergleich, kein
Wildcard-Matching) und an EINER Stelle konfigurierbar.
"""


def is_origin_allowed(origin: str | None, allowed: list[str]) -> bool:
    """Ist der ``Origin`` eines Requests gegen die Allowlist erlaubt?

    Regeln (bewusst schlicht, deckungsgleich zur CORS-Allowlist-Semantik):

    * ``origin is None`` -> ``True``. Same-origin-Requests und Nicht-Browser-Clients
      (Tauri-WebView same-origin, curl, der Agent) senden KEINEN ``Origin``-Header.
      Das ist kein Cross-Origin-Angriff, den CORS/Origin adressiert -- der lokale
      Fremdprozess ohne Origin ist Sache von Etappe 2 (Token). Hier durchlassen.
    * ``origin in allowed`` -> ``True`` (exakter String-Vergleich).
    * sonst -> ``False`` (fremde Browser-Herkunft -> abgewiesen).

    KEIN Wildcard-/Praefix-Matching: identisch zur CORS-Allowlist hier, die ebenfalls
    exakt vergleicht (kein ``*``).
    """
    if origin is None:
        return True
    return origin in allowed
