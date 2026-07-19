"""macOS-Adapter fuer ``CaptureAccessPort``: BPF-Zugriff pruefen + einrichten.

Erfuellt den ``CaptureAccessPort`` strukturell. Zwei Operationen:

* ``status`` -- sind die BPF-Geraete fuer den aktuellen Nutzer lesbar? Die Frage
  beantwortet bereits ``sniffd.sniff_core.check_raw_permission`` (Etappe 1, dort
  die ``/dev/bpf*``-Probe). Sie wird HIER WIEDERVERWENDET und NICHT ein zweites Mal
  nachgebaut -- eine zweite Probe koennte abweichen und dann zwei verschiedene
  "Wahrheiten" ueber dieselbe Frage liefern.
* ``grant`` -- fuehrt die Einrichtung mit Administratorrechten aus. Die
  Passwortabfrage ist der NATIVE macOS-Dialog (Touch ID moeglich), nicht eine
  Terminal-Eingabe: ``osascript`` mit ``do shell script ... with administrator
  privileges``.

SICHERHEIT 1 -- DER INHALT WIRD UEBERGEBEN, NICHT EIN DATEIPFAD (Etappe 2b):
Frueher startete ``grant`` das Einrichtungsskript als DATEI (``/bin/bash <pfad>``).
Das setzte voraus, dass die Datei im Bundle vor Veraenderung geschuetzt ist. AM
LAUFENDEN ARTEFAKT GEMESSEN trifft das nachweislich NICHT zu::

    ls -la /Applications/CernisPro.app/Contents/Resources/
      -> Eigentuemer karlbach:admin, NICHT root
    codesign -dv /Applications/CernisPro.app
      -> Signature=adhoc, Sealed Resources=none, TeamIdentifier=not set

Die Bundle-Ressource ist also weder durch Dateirechte noch durch eine Signatur
geschuetzt: ein Nutzer mit Admin-Rechten koennte sie austauschen und beim naechsten
Einrichten eigenen Code als root ausfuehren lassen.

Darum wird der Skript-INHALT zur Laufzeit gelesen und ueber ``stdin`` an
``/bin/bash`` uebergeben, statt einen Dateipfad als Argument zu reichen. Das Lesen
selbst ist unkritisch (nichts wird dabei ausgefuehrt), und zwischen Pruefung und
Ausfuehrung existiert kein Zeitfenster mehr, in dem die Datei getauscht werden
koennte -- die klassische TOCTOU-Luecke entfaellt, weil der Inhalt bereits im
Speicher liegt.

BEWUSSTE ABWEICHUNG -- ``infrastructure/bundle_paths.py`` wird hier ABSICHTLICH NICHT
benutzt (bitte nicht spaeter "vereinheitlichen"): jener Helfer kapselt ``sys._MEIPASS``,
und ``_MEIPASS`` ist ein TEMPORAERES Verzeichnis. Als Quelle fuer Root-Code ist es
ungeeignet -- wird die Datei zwischen Entpacken und Ausfuehrung ausgetauscht, ist das
eine lokale Rechteausweitung. Auch ein FALLBACK auf ``_MEIPASS`` ist ausgeschlossen:
ein Angreifer koennte den bevorzugten Pfad gezielt scheitern lassen und so den
unsicheren Zweig erzwingen. Diese Begruendung gilt unveraendert weiter.

SICHERHEIT 2 -- PRUEFUNG DER QUELLDATEI: ``_verify_script_safe`` bleibt erhalten und
prueft, was jetzt noch sinnvoll pruefbar ist: die Datei existiert, ist eine regulaere
Datei und ist NICHT weltschreibbar. Die fruehere root-Eigentuemer-Bedingung ist
ENTFALLEN -- nicht als Aufweichung, sondern weil sie fuer eine Bundle-Ressource
nachweislich NIE zutrifft (siehe Messbefund oben) und die Einrichtung dadurch
dauerhaft unmoeglich waere. Der eigentliche Schutz liegt jetzt in der Uebergabe des
Inhalts (SICHERHEIT 1), nicht mehr im Dateieigentuemer.

SICHERHEIT 3 -- KEINE INJECTION: In den ``osascript``-Programmtext fliessen NUR
projektintern bestimmte Werte (der Skriptinhalt aus der mitgelieferten Datei, der
Login-Name aus ``getpass.getuser``), niemals Fremd- oder Netzdaten. Beide
Escaping-Ebenen bleiben zwingend: ``quote`` fuer die von ``do shell script``
gestartete Shell und ``escape_applescript_literal`` fuer das umgebende
AppleScript-Double-Quoted-Literal -- beide, weil ``do shell script`` seinen String an
``/bin/sh`` uebergibt (AppleScript-Injection war ein v1-Finding, siehe
``desktop_notifier.py``). Der Skriptinhalt wird als EIN ``quote``-geschuetztes
Shell-Wort an ``printf '%s'`` uebergeben und von dort nach ``stdin`` gepipet -- er
kann damit nicht aus dem Wort ausbrechen, egal was in der Datei steht. Ein
Here-Dokument waere hier falsch: dessen Ende-Marker ist Teil des Shell-Texts, und ein
Inhalt mit einer Marker-Zeile wuerde das Heredoc vorzeitig schliessen, sodass der Rest
in der AEUSSEREN Shell liefe (real nachgestellt und bestaetigt).
"""

import getpass
import os
import re
import stat
import subprocess
import sys
from shlex import quote

import structlog

from domain.capture_access import (
    CaptureAccessOutcome,
    CaptureAccessResult,
    CaptureAccessState,
    CaptureAccessStatus,
)
from infrastructure.osascript_escape import escape_applescript_literal
from infrastructure.sniffd.sniff_core import check_raw_permission

_logger = structlog.get_logger(__name__)

# Dateiname des Einrichtungsskripts -- projektintern fest, NIE aus Nutzereingabe.
_SCRIPT_NAME = "setup-bpf-access.sh"

# Unterverzeichnis der Ressource im Bundle. Tauri bildet das fuehrende ``..`` des
# resources-Eintrags auf das Segment ``_up_`` ab (siehe _resolve_script_path).
_BUNDLE_SUBDIR = os.path.join("_up_", "scripts")

# Zweck-Text fuer die geteilte Rechteprobe (``check_raw_permission``): benennt den
# konkreten Aufrufer, damit die Meldung ehrlich ist (kein "SNI capture" fuer eine
# reine Status-Abfrage).
_PROBE_PURPOSE = "Packet capture"

# Der Einrichtungsdialog wartet auf eine menschliche Eingabe (Passwort/Touch ID).
# Grosszuegiges Zeitlimit, damit ein langsamer Nutzer nicht als Fehler endet -- aber
# ein endliches, damit ein haengender Dialog den Aufruf nicht ewig blockiert.
_OSASCRIPT_TIMEOUT = 300

# AppleScript meldet den Nutzer-Abbruch als Fehlernummer -128 ("User cancelled").
# Die TEXT-Meldung ist lokalisiert ("Von Benutzer:in abgebrochen") und darum als
# Merkmal unbrauchbar; die NUMMER ist sprachunabhaengig und stabil.
_CANCEL_PATTERN = re.compile(r"-128\b")

_NOT_APPLICABLE_DETAIL = (
    "Diese Einrichtung gilt nur fuer macOS. Auf anderen Plattformen wird der "
    "Zugriff anders geregelt (Linux: CAP_NET_RAW ueber das Paket-Postinstall)."
)


def _resolve_script_path() -> str:
    """Loest den Pfad der Skript-QUELLE auf: Bundle-Resources, sonst Repo.

    Bundle: ``sys.executable`` liegt im ``.app`` unter ``Contents/MacOS/``, die
    Ressourcen also eine Ebene hoeher unter ``Contents/Resources/``. Der Eintrag in
    ``tauri.conf.json`` lautet ``../scripts/setup-bpf-access.sh``; Tauri uebersetzt
    das fuehrende ``..`` deterministisch in das Segment ``_up_``
    (``tauri-utils::resources::resource_relpath``), die Datei landet also unter
    ``Contents/Resources/_up_/scripts/``. AM GEBAUTEN BUNDLE VERIFIZIERT::

        /Applications/CernisPro.app/Contents/Resources/_up_/scripts/setup-bpf-access.sh

    Dev: das Repo-Verzeichnis ``scripts/`` (diese Datei liegt in
    ``backend/infrastructure/``, von dort zwei Ebenen hoch zum Repo-Root).

    Der Pfad dient NUR dem LESEN des Inhalts -- aus dieser Datei wird nichts als root
    gestartet (siehe Modul-Docstring, SICHERHEIT 1). Bewusst OHNE
    ``bundle_paths.resolve_bundle_path`` und ohne ``_MEIPASS``-Fallback.
    """
    resources = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "..", "Resources")
    )
    bundle_script = os.path.join(resources, _BUNDLE_SUBDIR, _SCRIPT_NAME)
    if os.path.isfile(bundle_script):
        return bundle_script
    return os.path.normpath(
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts", _SCRIPT_NAME
        )
    )


def _verify_script_safe(path: str) -> str | None:
    """Prueft die Skript-QUELLE; ``None`` = brauchbar, sonst der Grund fuer ``FAILED``.

    Drei Bedingungen (SICHERHEIT 2): die Datei existiert, ist eine regulaere Datei und
    ist NICHT weltschreibbar. Eine weltschreibbare Quelle koennte jeder Nutzer der
    Maschine veraendern -- ihr Inhalt darf nicht als root ausgefuehrt werden.

    BEWUSST ENTFALLEN ist die fruehere Bedingung "gehoert root". Das ist KEINE
    Aufweichung, sondern die Korrektur einer falschen Annahme: am gebauten Bundle
    gemessen gehoert die Ressource ``karlbach:admin``, nicht root (und das Bundle ist
    adhoc-signiert, ``Sealed Resources=none``). Die Bedingung traf also nie zu und
    machte die Einrichtung dauerhaft unmoeglich. Der Schutz gegen einen Austausch der
    Datei liegt jetzt woanders: der INHALT wird gelesen und ueber stdin uebergeben, es
    wird nichts aus dieser Datei heraus gestartet (Modul-Docstring, SICHERHEIT 1).

    Die Gruppen-Schreibbarkeit wird ebenfalls NICHT mehr geprueft: die Bundle-Ressource
    liegt gemessen in der Gruppe ``admin`` mit Standardrechten, und eine
    Gruppen-Schreibbarkeit waere dort der Normalfall, kein Angriffsmerkmal.
    """
    try:
        info = os.stat(path)
    except OSError as fehler:
        return f"Einrichtungsskript nicht gefunden oder nicht lesbar ({path}): {fehler}"
    if not stat.S_ISREG(info.st_mode):
        return f"Einrichtungsskript ist keine regulaere Datei: {path}"
    if info.st_mode & stat.S_IWOTH:
        return (
            f"Einrichtungsskript ist weltschreibbar: {path}. "
            "Sein Inhalt wird aus Sicherheitsgruenden nicht mit Administratorrechten "
            "ausgefuehrt."
        )
    return None


def _read_script(path: str) -> str:
    """Liest den Skriptinhalt als Text; wirft ``OSError``, wenn das nicht geht.

    Reines Lesen -- es wird NICHTS ausgefuehrt (siehe Modul-Docstring, SICHERHEIT 1).
    Danach liegt der Inhalt im Speicher; ein spaeterer Austausch der Datei kann die
    bereits gelesene Fassung nicht mehr veraendern (kein TOCTOU).
    """
    with open(path, encoding="utf-8") as datei:
        return datei.read()


class CaptureAccessAdapter:
    """Erfuellt ``CaptureAccessPort`` auf macOS (BPF-Zugriff pruefen/einrichten)."""

    def status(self) -> CaptureAccessStatus:
        """``GRANTED``, wenn die BPF-Geraete lesbar sind, sonst ``MISSING`` + Grund.

        Nutzt die geteilte Probe aus Etappe 1 (``check_raw_permission``): ``None``
        heisst "Zugriff moeglich" (das schliesst den inconclusive-Fall ein -- dann
        darf der Sniff es selbst versuchen, statt hier eine Einrichtung zu fordern,
        die vielleicht gar nicht fehlt). Ein Text ist der ehrliche Rechte-Grund.
        """
        if sys.platform != "darwin":
            return CaptureAccessStatus(
                state=CaptureAccessState.NOT_APPLICABLE, detail=_NOT_APPLICABLE_DETAIL
            )
        hinweis = check_raw_permission(_PROBE_PURPOSE)
        if hinweis is None:
            return CaptureAccessStatus(state=CaptureAccessState.GRANTED)
        return CaptureAccessStatus(state=CaptureAccessState.MISSING, detail=hinweis)

    def grant(self) -> CaptureAccessResult:
        """Fuehrt das Einrichtungsskript als root aus (nativer Dialog, Touch ID moeglich).

        Blockiert, solange der Systemdialog offen ist (der Use-Case kapselt das ueber
        ``run_in_executor``). Drei unterscheidbare Ausgaenge: ``GRANTED``,
        ``CANCELLED`` (Nutzer hat abgebrochen -- kein Fehler) und ``FAILED`` mit Grund.
        """
        if sys.platform != "darwin":
            return CaptureAccessResult(
                outcome=CaptureAccessOutcome.NOT_APPLICABLE, reason=_NOT_APPLICABLE_DETAIL
            )

        script_path = _resolve_script_path()
        unsicher = _verify_script_safe(script_path)
        if unsicher is not None:
            # KEIN Ausfuehren bei verletzter Vorbedingung (S3): lieber ein ehrlicher
            # Fehlschlag als ein Root-Aufruf mit einem zweifelhaften Inhalt.
            _logger.warning("capture_access.script_unsafe", path=script_path, reason=unsicher)
            return CaptureAccessResult(outcome=CaptureAccessOutcome.FAILED, reason=unsicher)

        try:
            inhalt = _read_script(script_path)
        except OSError as fehler:
            return CaptureAccessResult(
                outcome=CaptureAccessOutcome.FAILED,
                reason=f"Einrichtungsskript nicht lesbar ({script_path}): {fehler}",
            )

        benutzer = getpass.getuser()
        # Zwei Escaping-Ebenen (SICHERHEIT 3), beide zwingend: ``quote`` fuer die von
        # ``do shell script`` gestartete Shell, ``escape_applescript_literal`` fuer das
        # umgebende AppleScript-Double-Quoted-Literal.
        #
        # Der INHALT geht ueber stdin an /bin/bash -- KEIN Dateipfad als Argument
        # (SICHERHEIT 1: kein TOCTOU-Fenster). Er wird als EIN ``quote``-geschuetztes
        # Shell-Wort an ``printf '%s'`` uebergeben und von dort gepipet.
        #
        # Bewusst KEIN Here-Dokument: dessen Ende-Marker ist Teil des Shell-Texts, und
        # ein Inhalt, der zufaellig eine Marker-Zeile enthaelt, wuerde das Heredoc
        # vorzeitig beenden -- der Rest liefe dann in der AEUSSEREN Shell (real
        # nachgestellt und bestaetigt). Mit ``quote`` ueber den GESAMTEN Inhalt gibt es
        # dieses Ausbruchsfenster nicht, unabhaengig davon, was in der Datei steht.
        #
        # ``/bin/bash -s -- <benutzer>``: ``-s`` liest das Programm von stdin, alles nach
        # ``--`` sind Positionsargumente des Skripts (der Benutzername bleibt Argument).
        befehl = f"printf '%s' {quote(inhalt)} | /bin/bash -s -- {quote(benutzer)}"
        script = (
            f'do shell script "{escape_applescript_literal(befehl)}" with administrator privileges'
        )

        try:
            ergebnis = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
                timeout=_OSASCRIPT_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return CaptureAccessResult(
                outcome=CaptureAccessOutcome.FAILED,
                reason="Die Systemabfrage wurde nicht rechtzeitig beantwortet.",
            )
        except OSError as fehler:
            # z. B. kein osascript vorhanden -- lauter Fehler statt stillem no-op.
            return CaptureAccessResult(
                outcome=CaptureAccessOutcome.FAILED,
                reason=f"Die Systemabfrage konnte nicht gestartet werden: {fehler}",
            )

        if ergebnis.returncode == 0:
            _logger.info("capture_access.granted", script=script_path)
            return CaptureAccessResult(outcome=CaptureAccessOutcome.GRANTED)

        stderr = (ergebnis.stderr or "").strip()
        if _CANCEL_PATTERN.search(stderr):
            # Abbruch ist ein EIGENER Zustand, kein Fehler -- ohne Begruendungstext,
            # damit die Oberflaeche keine Fehleroptik zeigt.
            _logger.info("capture_access.cancelled")
            return CaptureAccessResult(outcome=CaptureAccessOutcome.CANCELLED)

        _logger.warning("capture_access.failed", returncode=ergebnis.returncode, stderr=stderr)
        return CaptureAccessResult(
            outcome=CaptureAccessOutcome.FAILED,
            reason=stderr or "Die Einrichtung ist ohne Meldung fehlgeschlagen.",
        )
