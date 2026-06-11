"""Application-Exceptions der diagnostics-Use-Cases.

Eigene Fehlerklasse OHNE HTTP-Details -- das Mapping auf Statuscodes passiert am Rand
(Composition Root / api, spaeterer Schnitt). Die Basisklasse folgt dem Projektmuster
(scanning/devices/interfaces/traffic/process/agent fuehren je eine
``*ApplicationError``-Basis) und dient als gemeinsamer Aufhaenger der diagnostics-
Use-Cases.

``DiagnosticsToolMissingError`` benennt den Fall "benoetigtes System-Binary fehlt"
(``dig``/``traceroute`` nicht im PATH). NUR eine neutrale Meldung -- KEIN distro-
spezifischer Install-Befehl (das reichert Block 1b an).

WICHTIG (Ring-Realitaet, vom Auftrag vorgesehene Abweichung): Der import-linter-Contract
"infrastructure kennt nicht application/api" (pyproject.toml) verbietet dem
Infrastruktur-Ring, diese application-Exception zu importieren oder zu werfen. Der
etablierte Repo-Weg fuer einen infrastruktur-erkannten Ausfall ist daher das Vorbild
``infrastructure.secret_store.SecretStoreUnavailableError``: die Adapter werfen eine
INFRASTRUKTUR-eigene Tool-fehlt-Exception (``infrastructure.diagnostics_linux``), die der
Composition Root (``app.py``) ueber einen globalen ``exception_handler`` auf 503 abbildet
-- genau wie ``SecretStoreUnavailableError``. Diese application-Klasse bleibt der
domaenen-konforme Aufhaenger (jede Domaene fuehrt ihre ``*ApplicationError``-Basis); sie
wird vom api-Ring importiert und ist die kanonische Tool-fehlt-Bedeutung der Domaene.
"""


class DiagnosticsApplicationError(Exception):
    """Basis fuer Fehler der diagnostics-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""


class DiagnosticsToolMissingError(DiagnosticsApplicationError):
    """Ein benoetigtes System-Binary (``dig``/``traceroute``) wurde nicht gefunden.

    NUR neutrale Meldung ("Programm 'dig' wurde nicht gefunden.") -- KEIN distro-
    spezifischer Install-Befehl (Block 1b reichert die Erkennung+den Install-Hinweis an).
    """
