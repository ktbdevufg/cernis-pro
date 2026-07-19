"""macOS-Adapter fuer ``CaptureAccessPort``: BPF-Zugriff pruefen + einrichten.

Erfuellt den ``CaptureAccessPort`` strukturell. Zwei Operationen:

* ``status`` -- sind die BPF-Geraete fuer den aktuellen Nutzer lesbar? Die Frage
  beantwortet bereits ``sniffd.sniff_core.check_raw_permission`` (Etappe 1, dort
  die ``/dev/bpf*``-Probe). Sie wird HIER WIEDERVERWENDET und NICHT ein zweites Mal
  nachgebaut -- eine zweite Probe koennte abweichen und dann zwei verschiedene
  "Wahrheiten" ueber dieselbe Frage liefern.
* ``grant`` -- fuehrt das Einrichtungsskript mit Administratorrechten aus. Die
  Passwortabfrage ist der NATIVE macOS-Dialog (Touch ID moeglich), nicht eine
  Terminal-Eingabe: ``osascript`` mit ``do shell script ... with administrator
  privileges``.

SICHERHEIT 1 -- HERKUNFT DES ROOT-SKRIPTS: Ein Skript, das per ``osascript`` mit
Root-Rechten ausgefuehrt wird, darf ausschliesslich aus einem Verzeichnis geladen
werden, das fuer unprivilegierte Prozesse NICHT schreibbar ist. Darum wird der Pfad
hier ueber ``sys.executable`` auf ``<app>/Contents/Resources/`` aufgeloest (im
Bundle root-eigen) bzw. im Dev auf ``<repo>/scripts/``.

BEWUSSTE ABWEICHUNG -- ``infrastructure/bundle_paths.py`` wird hier ABSICHTLICH NICHT
benutzt (bitte nicht spaeter "vereinheitlichen"): jener Helfer kapselt ``sys._MEIPASS``,
und ``_MEIPASS`` ist ein TEMPORAERES Verzeichnis. Als Quelle fuer Root-Code ist es
ungeeignet -- wird die Datei zwischen Entpacken und Ausfuehrung ausgetauscht, ist das
eine lokale Rechteausweitung. Auch ein FALLBACK auf ``_MEIPASS`` ist ausgeschlossen:
ein Angreifer koennte den bevorzugten Pfad gezielt scheitern lassen und so den
unsicheren Zweig erzwingen.

SICHERHEIT 2 -- PRUEFUNG VOR DER AUSFUEHRUNG: Vor dem Aufruf wird geprueft, dass das
Skript existiert, ``root`` gehoert und WEDER gruppen- NOCH weltschreibbar ist. Trifft
das nicht zu, wird NICHT ausgefuehrt, sondern ``FAILED`` mit klarem Grund gemeldet
(S3: kein stiller Fallback auf unsicheres Verhalten).

SICHERHEIT 3 -- KEINE INJECTION: In den ``osascript``-Programmtext fliessen NUR
projektintern bestimmte Werte (der Skriptpfad, der Login-Name aus ``getpass.getuser``),
niemals Fremd- oder Netzdaten. Sie werden zusaetzlich ueber
``escape_applescript_literal`` fuer das Double-Quoted-Literal escaped und ueber
``quote`` fuer die von ``do shell script`` gestartete Shell -- beide Ebenen, weil
``do shell script`` seinen String an ``/bin/sh`` uebergibt (AppleScript-Injection war
ein v1-Finding, siehe ``desktop_notifier.py``).
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
    """Loest den Pfad des Einrichtungsskripts auf: Bundle-Resources, sonst Repo.

    Bundle: ``sys.executable`` liegt im ``.app`` unter ``Contents/MacOS/``; die per
    ``tauri.conf.json`` mitgelieferten ``resources`` landen in ``Contents/Resources/``
    -- also vom Binary-Verzeichnis eine Ebene hoch und nach ``Resources``. Dev: das
    Repo-Verzeichnis ``scripts/`` (diese Datei liegt in ``backend/infrastructure/``,
    von dort zwei Ebenen hoch zum Repo-Root).

    Bewusst OHNE ``bundle_paths.resolve_bundle_path`` und ohne ``_MEIPASS``-Fallback
    (siehe Modul-Docstring, SICHERHEIT 1).
    """
    resources = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "..", "Resources")
    )
    bundle_script = os.path.join(resources, _SCRIPT_NAME)
    if os.path.isfile(bundle_script):
        return bundle_script
    return os.path.normpath(
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts", _SCRIPT_NAME
        )
    )


def _verify_script_safe(path: str) -> str | None:
    """Prueft, ob ``path`` als Root-Skript sicher ist; ``None`` = sicher, sonst Grund.

    Drei Bedingungen (SICHERHEIT 2): die Datei existiert, gehoert ``root`` (uid 0) und
    ist weder gruppen- noch weltschreibbar. Waere eine davon verletzt, koennte ein
    unprivilegierter Prozess den Inhalt vor der Root-Ausfuehrung austauschen. Der
    Rueckgabetext ist der Grund fuer ``FAILED`` -- er wird benannt, nicht verschluckt.
    """
    try:
        info = os.stat(path)
    except OSError as fehler:
        return f"Einrichtungsskript nicht gefunden oder nicht lesbar ({path}): {fehler}"
    if not stat.S_ISREG(info.st_mode):
        return f"Einrichtungsskript ist keine regulaere Datei: {path}"
    if info.st_uid != 0:
        return (
            f"Einrichtungsskript gehoert nicht root (uid {info.st_uid}): {path}. "
            "Es wird aus Sicherheitsgruenden nicht mit Administratorrechten ausgefuehrt."
        )
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return (
            f"Einrichtungsskript ist gruppen- oder weltschreibbar: {path}. "
            "Es wird aus Sicherheitsgruenden nicht mit Administratorrechten ausgefuehrt."
        )
    return None


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
            # Fehlschlag als ein Root-Aufruf auf einer moeglicherweise manipulierten Datei.
            _logger.warning("capture_access.script_unsafe", path=script_path, reason=unsicher)
            return CaptureAccessResult(outcome=CaptureAccessOutcome.FAILED, reason=unsicher)

        benutzer = getpass.getuser()
        # Zwei Escaping-Ebenen (SICHERHEIT 3): ``quote`` fuer die von ``do shell script``
        # gestartete /bin/sh, ``escape_applescript_literal`` fuer das umgebende
        # AppleScript-Double-Quoted-Literal. Beide Werte sind projektintern bestimmt.
        befehl = f"/bin/bash {quote(script_path)} {quote(benutzer)}"
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
