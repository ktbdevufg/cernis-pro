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


class RogueDhcpPermissionError(DiagnosticsApplicationError):
    """Rogue-DHCP wurde ohne Root angefragt -- ehrliche Sperre, kein Fallback (Block 3).

    Anders als die Tool-fehlt-Naht (eine infra-EIGENE Exception, weil der Adapter den
    Ausfall erkennt) ist DIES ein APPLICATION-Zustand: der Use-Case wertet den Rechte-Port
    aus und sperrt VOR dem Discovery, wenn nmap fehlt ODER kein Root vorliegt. Rogue-DHCP
    braucht rohe DHCP-Pakete -> Root, es gibt KEINE rootless Alternative (anders als
    traceroute, das eine ungenauere rootless-Methode hat). Darum eine ehrliche Sperre statt
    eines stillen Fallbacks (S3); keine Selbst-Eskalation (CLAUDE.md).

    ``message`` traegt die nutzerseitige Begruendung (vom Rechte-Port). Der api-Rand bildet
    diese Exception auf **403** ab (Muster der process/traffic-Permission-403, ueber einen
    globalen ``exception_handler`` im Composition Root) -- die Discovery ist nicht erlaubt,
    nicht der Dienst kaputt. Der Probe wird in diesem Fall NICHT gerufen.
    """

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class ExternalCheckError(DiagnosticsApplicationError):
    """Der externe cpnetcheck-Dienst war nicht erreichbar/lieferte einen Fehler (2b).

    Analog ``DiagnosticsToolMissingError`` der kanonische application-Aufhaenger fuer den
    Dienst-Ausfall des externen IP/Port-Checks (HTTP 4xx/5xx, Netzfehler, Timeout, JSON-
    Parsefehler). Der INFRASTRUKTUR-Adapter wirft diese Exception (anders als die
    Tool-fehlt-Naht, die eine infra-EIGENE Exception wirft -- ``ExternalCheckError`` traegt
    KEINEN application-internen Zustand, nur eine neutrale Meldung, darf also vom
    infrastructure-Ring NICHT importiert werden; siehe unten). Der Composition Root
    (``app.py``) bildet sie ueber einen globalen ``exception_handler`` auf **502** ab
    (Bad Gateway -- der Fehler liegt im externen Dienst, nicht in CERNIS).

    NUR neutrale Meldung -- NIE den Token, NIE interne Details (Sicherheitsnaht, ADR 0014
    Block 2b). 401 vom Dienst -> "Authentifizierung am externen Dienst fehlgeschlagen".

    WICHTIG (Ring-Realitaet, wie die Tool-fehlt-Naht): Der import-linter-Contract
    "infrastructure kennt nicht application/api" verbietet dem Adapter, diese
    application-Exception zu werfen. Darum wirft der Adapter -- exakt wie bei
    ``DiagnosticsToolMissing`` -- eine INFRASTRUKTUR-eigene Exception
    (``infrastructure.diagnostics_linux.ExternalCheckFailed``), die der Composition Root auf
    502 abbildet. Diese application-Klasse bleibt der domaenen-konforme Aufhaenger und wird
    vom api-Ring NICHT gebraucht (das Mapping sitzt am Composition Root) -- sie ist die
    kanonische Bedeutung "externer Check fehlgeschlagen" der Domaene und steht den
    Use-Case-Tests als Durchwurf-/Mapping-Typ zur Verfuegung.
    """
