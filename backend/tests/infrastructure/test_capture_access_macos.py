"""Tests des macOS-Capture-Rechte-Adapters (Etappe 2) -- PLATTFORMFREI.

Laeuft auf der Linux-CI: ``sys.platform``, die Rechteprobe, ``subprocess.run`` und die
Skript-Pruefung werden per ``monkeypatch`` ersetzt. Es wird NIE ein echtes
``osascript`` gestartet und NIE das Einrichtungsskript ausgefuehrt -- ein Test darf
keinen Passwortdialog oeffnen und keine Systemrechte veraendern.

Schwerpunkt ist die S3-Dreiteilung des Ergebnisses: Erfolg, ABBRUCH DURCH DEN NUTZER
und Fehlschlag muessen drei unterscheidbare Ausgaenge bleiben. Dazu kommen die beiden
Sicherheits-Vorbedingungen (Skript gehoert root, nicht gruppen-/weltschreibbar), die
eine Ausfuehrung verhindern MUESSEN, statt sie stillschweigend zuzulassen.
"""

import getpass
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from domain.capture_access import CaptureAccessOutcome, CaptureAccessState
from infrastructure import capture_access_macos as adapter_modul
from infrastructure.capture_access_macos import CaptureAccessAdapter

# ── Helfer: die Umgebung eines geglueckten macOS-Laufs herstellen ────────────


# Stellvertretender Skriptinhalt. Enthaelt bewusst eine markante Zeile, an der sich
# im Test nachweisen laesst, dass der INHALT uebergeben wird und nicht ein Dateipfad.
_SKRIPT_INHALT = '#!/bin/bash\necho "richte BPF-Zugriff ein fuer $1"\n'

# Referenz auf das ECHTE ``subprocess.run``, VOR jedem monkeypatch festgehalten. Der
# Ausfuehrungs-Test unten braucht den echten Aufruf, waehrend das Modul gemockt ist.
subprocess_run_echt = subprocess.run


class _FakeStat:
    """Minimaler ``os.stat``-Ersatz: nur die geprueften Felder."""

    def __init__(self, uid: int = 501, mode: int = 0o100755) -> None:
        self.st_uid = uid
        self.st_mode = mode


class _FakeCompleted:
    """Minimaler ``subprocess.run``-Rueckgabewert (returncode + stderr)."""

    def __init__(self, returncode: int, stderr: str = "") -> None:
        self.returncode = returncode
        self.stderr = stderr


def _als_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    """Versetzt den Adapter in den darwin-Zweig (ohne echtes macOS)."""
    monkeypatch.setattr(sys, "platform", "darwin")


def _mit_sicherem_skript(monkeypatch: pytest.MonkeyPatch, inhalt: str = _SKRIPT_INHALT) -> None:
    """Quelldatei existiert, ist regulaer, nicht weltschreibbar -- und liefert ``inhalt``.

    Der Adapter LIEST die Datei jetzt (Etappe 2b) und uebergibt den Inhalt; darum wird
    hier auch ``_read_script`` ersetzt. Es wird nie eine echte Datei angefasst.
    """
    monkeypatch.setattr(
        adapter_modul, "_resolve_script_path", lambda: "/bundle/setup-bpf-access.sh"
    )
    monkeypatch.setattr(os, "stat", lambda _p: _FakeStat())
    monkeypatch.setattr(adapter_modul, "_read_script", lambda _p: inhalt)


def _osascript_liefert(monkeypatch: pytest.MonkeyPatch, ergebnis: Any) -> list[list[str]]:
    """Ersetzt ``subprocess.run``; gibt die Liste der tatsaechlichen Aufrufe zurueck.

    ``ergebnis`` ist entweder ein ``_FakeCompleted`` oder eine zu werfende Exception.
    """
    aufrufe: list[list[str]] = []

    def _run(cmd: list[str], **_kwargs: Any) -> Any:
        aufrufe.append(cmd)
        if isinstance(ergebnis, BaseException):
            raise ergebnis
        return ergebnis

    monkeypatch.setattr(subprocess, "run", _run)
    return aufrufe


# ── status(): die Rechteprobe aus Etappe 1 wird wiederverwendet ──────────────


def test_status_granted_when_probe_reports_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """Probe liefert ``None`` (Zugriff moeglich) -> ``GRANTED``, ohne Begruendung."""
    _als_macos(monkeypatch)
    monkeypatch.setattr(adapter_modul, "check_raw_permission", lambda _zweck: None)

    status = CaptureAccessAdapter().status()

    assert status.state is CaptureAccessState.GRANTED
    assert status.detail == ""


def test_status_missing_passes_probe_reason_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """Probe liefert einen Text -> ``MISSING`` mit GENAU diesem Grund (nicht neu erfunden)."""
    _als_macos(monkeypatch)
    grund = "Permission denied -- Packet capture requires root or CAP_NET_RAW; /dev/bpf*"
    monkeypatch.setattr(adapter_modul, "check_raw_permission", lambda _zweck: grund)

    status = CaptureAccessAdapter().status()

    assert status.state is CaptureAccessState.MISSING
    assert status.detail == grund


def test_status_not_applicable_off_darwin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nicht-macOS -> ``NOT_APPLICABLE`` mit Begruendung, KEIN Fehler und kein Probe-Aufruf."""

    def _keine_probe(_zweck: str) -> str | None:
        raise AssertionError("ausserhalb von darwin darf nicht geprobt werden")

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(adapter_modul, "check_raw_permission", _keine_probe)

    status = CaptureAccessAdapter().status()

    assert status.state is CaptureAccessState.NOT_APPLICABLE
    assert "macOS" in status.detail


# ── grant(): die S3-Dreiteilung Erfolg / Abbruch / Fehlschlag ────────────────


def test_grant_success_returns_granted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exit 0 -> ``GRANTED`` ohne Begruendung; der Aufruf geht ueber ``osascript``."""
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch)
    aufrufe = _osascript_liefert(monkeypatch, _FakeCompleted(returncode=0))

    result = CaptureAccessAdapter().grant()

    assert result.outcome is CaptureAccessOutcome.GRANTED
    assert result.reason == ""
    assert len(aufrufe) == 1
    assert aufrufe[0][0] == "osascript"
    # Der native Rechte-Dialog (Touch ID moeglich) -- KEINE Terminal-Passworteingabe.
    assert "with administrator privileges" in aufrufe[0][2]


def test_grant_user_cancel_is_its_own_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Abbruch (AppleScript -128) -> ``CANCELLED``, NICHT ``FAILED`` und ohne Fehlertext.

    Das ist der Kern der S3-Vorgabe: ein Abbruch ist kein Fehler. Die Oberflaeche soll
    dafuer keine Fehleroptik zeigen, darum bleibt ``reason`` leer.
    """
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch)
    _osascript_liefert(
        monkeypatch,
        _FakeCompleted(returncode=1, stderr="execution error: Von Benutzer:in abgebrochen. (-128)"),
    )

    result = CaptureAccessAdapter().grant()

    assert result.outcome is CaptureAccessOutcome.CANCELLED
    assert result.reason == ""


def test_grant_cancel_detected_language_independently(monkeypatch: pytest.MonkeyPatch) -> None:
    """Der Abbruch wird an der NUMMER -128 erkannt, nicht am lokalisierten Text.

    Die Meldung ist auf einem englischen System anders ("User canceled") -- haenge die
    Erkennung nie am Text, sonst gilt ein Abbruch dort faelschlich als Fehler.
    """
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch)
    _osascript_liefert(
        monkeypatch,
        _FakeCompleted(returncode=1, stderr="execution error: User canceled. (-128)"),
    )

    assert CaptureAccessAdapter().grant().outcome is CaptureAccessOutcome.CANCELLED


def test_grant_failure_reports_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    """Echter Fehlschlag -> ``FAILED`` MIT Grund (benannt, nicht verschluckt)."""
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch)
    _osascript_liefert(
        monkeypatch,
        _FakeCompleted(returncode=1, stderr="FEHLER: Gruppe konnte nicht angelegt werden."),
    )

    result = CaptureAccessAdapter().grant()

    assert result.outcome is CaptureAccessOutcome.FAILED
    assert "Gruppe konnte nicht angelegt werden" in result.reason


def test_grant_failure_without_stderr_still_names_something(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fehlschlag ohne stderr -> ``FAILED`` mit ehrlichem Ersatztext (nie leer)."""
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch)
    _osascript_liefert(monkeypatch, _FakeCompleted(returncode=2, stderr=""))

    result = CaptureAccessAdapter().grant()

    assert result.outcome is CaptureAccessOutcome.FAILED
    assert result.reason != ""


def test_grant_timeout_is_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zeitueberschreitung -> ``FAILED`` mit Grund, kein haengender Aufruf."""
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch)
    _osascript_liefert(monkeypatch, subprocess.TimeoutExpired(cmd="osascript", timeout=300))

    result = CaptureAccessAdapter().grant()

    assert result.outcome is CaptureAccessOutcome.FAILED
    assert result.reason != ""


def test_grant_missing_osascript_is_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Kein ``osascript`` vorhanden -> ``FAILED``, KEIN stilles No-op."""
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch)
    _osascript_liefert(monkeypatch, OSError("kein osascript"))

    result = CaptureAccessAdapter().grant()

    assert result.outcome is CaptureAccessOutcome.FAILED
    assert result.reason != ""


def test_grant_not_applicable_off_darwin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nicht-macOS -> ``NOT_APPLICABLE``; es wird NICHTS ausgefuehrt."""
    monkeypatch.setattr(sys, "platform", "linux")

    def _kein_subprocess(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("ausserhalb von darwin darf nichts ausgefuehrt werden")

    monkeypatch.setattr(subprocess, "run", _kein_subprocess)

    result = CaptureAccessAdapter().grant()

    assert result.outcome is CaptureAccessOutcome.NOT_APPLICABLE
    assert "macOS" in result.reason


# ── Sicherheit: unsichere Skript-Herkunft verhindert die Root-Ausfuehrung ────


def test_grant_accepts_script_not_owned_by_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Eine NICHT root-eigene Quelldatei ist zulaessig -- das ist der reale Bundle-Fall.

    Etappe 2b: am gebauten Bundle gemessen gehoert die Ressource ``karlbach:admin``,
    nicht root. Die fruehere root-Bedingung machte die Einrichtung dauerhaft unmoeglich.
    Der Schutz liegt jetzt darin, dass der INHALT uebergeben wird und nichts aus dieser
    Datei heraus gestartet wird -- nicht mehr am Eigentuemer.
    """
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch)
    monkeypatch.setattr(os, "stat", lambda _p: _FakeStat(uid=501))
    aufrufe = _osascript_liefert(monkeypatch, _FakeCompleted(returncode=0))

    result = CaptureAccessAdapter().grant()

    assert result.outcome is CaptureAccessOutcome.GRANTED
    assert len(aufrufe) == 1


def test_grant_refuses_world_writable_script(monkeypatch: pytest.MonkeyPatch) -> None:
    """Weltschreibbare Quelldatei -> ``FAILED`` ohne Ausfuehrung.

    Was jeder Nutzer der Maschine veraendern kann, darf nicht als root laufen -- auch
    dann nicht, wenn nur der Inhalt uebergeben wird.
    """
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch)
    monkeypatch.setattr(os, "stat", lambda _p: _FakeStat(mode=0o100777))
    aufrufe = _osascript_liefert(monkeypatch, _FakeCompleted(returncode=0))

    result = CaptureAccessAdapter().grant()

    assert result.outcome is CaptureAccessOutcome.FAILED
    assert "weltschreibbar" in result.reason
    assert aufrufe == []


def test_grant_allows_group_writable_script(monkeypatch: pytest.MonkeyPatch) -> None:
    """Gruppenschreibbar allein ist KEIN Ablehnungsgrund mehr (Gruppe ``admin``).

    Gegenstueck zum weltschreibbaren Fall: die Bundle-Ressource liegt gemessen in der
    Gruppe ``admin``; Gruppen-Schreibbarkeit ist dort der Normalfall.
    """
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch)
    monkeypatch.setattr(os, "stat", lambda _p: _FakeStat(mode=0o100775))
    aufrufe = _osascript_liefert(monkeypatch, _FakeCompleted(returncode=0))

    assert CaptureAccessAdapter().grant().outcome is CaptureAccessOutcome.GRANTED
    assert len(aufrufe) == 1


def test_grant_refuses_missing_script(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skript nicht vorhanden -> ``FAILED`` mit Grund, keine Ausfuehrung."""
    _als_macos(monkeypatch)
    monkeypatch.setattr(adapter_modul, "_resolve_script_path", lambda: "/weg/setup-bpf-access.sh")

    def _fehlt(_p: str) -> Any:
        raise FileNotFoundError("nicht da")

    monkeypatch.setattr(os, "stat", _fehlt)
    aufrufe = _osascript_liefert(monkeypatch, _FakeCompleted(returncode=0))

    result = CaptureAccessAdapter().grant()

    assert result.outcome is CaptureAccessOutcome.FAILED
    assert aufrufe == []


def test_verify_script_safe_accepts_regular_non_world_writable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Positivprobe: regulaer und nicht weltschreibbar -> ``None`` (Eigentuemer egal).

    Gegenstueck zu den Ablehnungs-Tests: ohne diesen Fall koennte die Pruefung
    pauschal alles ablehnen und die Negativ-Tests waeren trotzdem gruen.
    """
    monkeypatch.setattr(os, "stat", lambda _p: _FakeStat(uid=501, mode=stat.S_IFREG | 0o755))

    assert adapter_modul._verify_script_safe("/bundle/setup-bpf-access.sh") is None


def test_verify_script_safe_rejects_non_regular_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein Verzeichnis/Symlink-Ziel statt einer regulaeren Datei -> abgelehnt."""
    monkeypatch.setattr(os, "stat", lambda _p: _FakeStat(mode=stat.S_IFDIR | 0o755))

    grund = adapter_modul._verify_script_safe("/bundle")

    assert grund is not None
    assert "regulaere Datei" in grund


# ── Etappe 2b: der INHALT wird uebergeben, nicht ein Dateipfad ──────────────


def test_grant_passes_script_content_not_a_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Der Skript-INHALT steht im Root-Befehl -- der Dateipfad ist KEIN Argument.

    Das ist der Kern von Etappe 2b: waere der Pfad das Argument, koennte die Datei
    zwischen Pruefung und Root-Ausfuehrung getauscht werden (TOCTOU). Weil der Inhalt
    bereits gelesen im Befehl steckt, gibt es dieses Zeitfenster nicht.
    """
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch)
    aufrufe = _osascript_liefert(monkeypatch, _FakeCompleted(returncode=0))

    CaptureAccessAdapter().grant()

    script = aufrufe[0][2]
    # (a) der Inhalt ist da ...
    assert "richte BPF-Zugriff ein fuer" in script
    # (b) ... und der Pfad wird NICHT als auszufuehrendes Argument gereicht.
    assert "/bin/bash /bundle/setup-bpf-access.sh" not in script
    assert "/bundle/setup-bpf-access.sh" not in script
    # (c) der Weg ist stdin, nicht eine Datei.
    assert "/bin/bash -s --" in script


def test_grant_content_cannot_break_out_of_the_shell_word(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ein Inhalt mit Quotes/Metazeichen bleibt EIN Shell-Wort -- kein Ausbruch.

    Bewusst mit einer Zeile, die ein Here-Dokument beenden wuerde: genau daran ist die
    Heredoc-Variante gescheitert (real nachgestellt), die ``quote``-Variante nicht.
    """
    boesartig = "echo drin\nCERNIS_BPF_SETUP_EOF\n'; echo AUSGEBROCHEN; '\n"
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch, inhalt=boesartig)
    aufrufe = _osascript_liefert(monkeypatch, _FakeCompleted(returncode=0))

    CaptureAccessAdapter().grant()

    befehl = aufrufe[0][2]
    # Der Inhalt steckt vollstaendig drin (er soll ja als Programm laufen) ...
    assert "echo drin" in befehl
    # ... aber als EIN Shell-Wort: jedes Single-Quote des Angreifers ist durch
    # shlex.quote in die Sequenz '"'"' entwertet, kann das Wort also nicht schliessen.
    # Im AppleScript-Text sind die Doublequotes zusaetzlich als \" escaped -- geprueft
    # wird darum die Form NACH beiden Ebenen.
    assert "'\\\"'\\\"'" in befehl
    # Gegenprobe auf die Struktur: genau EIN printf-Wort, dann die Pipe in bash.
    assert befehl.count(" | /bin/bash -s -- ") == 1
    assert befehl.startswith("do shell script \"printf '%s' '")


def test_grant_command_really_confines_content_when_executed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Der erzeugte Shell-Befehl wird WIRKLICH ausgefuehrt -- der Inhalt bleibt drinnen.

    Kein osascript und kein root: nur der innere Shell-Teil des Befehls laeuft, so wie
    ``do shell script`` ihn an ``/bin/sh`` gaebe. Der Inhalt versucht auszubrechen und
    eine Datei ausserhalb anzulegen; entsteht sie, waere der Schutz gebrochen.

    Plattformfrei: ``/bin/sh`` und ``/bin/bash`` gibt es auch auf der Linux-CI.
    """
    beute = tmp_path / "ausgebrochen.txt"
    beleg = tmp_path / "innen-gelaufen.txt"
    # Erste Zeile belegt, dass der Inhalt ueberhaupt als Programm laeuft (sonst waere
    # der Test auch gruen, wenn gar nichts passiert). Die zweite versucht auszubrechen.
    boesartig = f"touch {beleg}\n'; touch {beute}; '\n"
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch, inhalt=boesartig)
    aufrufe = _osascript_liefert(monkeypatch, _FakeCompleted(returncode=0))

    CaptureAccessAdapter().grant()

    # Aus dem AppleScript-Text den inneren Shell-Befehl zurueckgewinnen (die Ebene,
    # die ``do shell script`` an /bin/sh reicht).
    applescript = aufrufe[0][2]
    innerer_befehl = applescript[len('do shell script "') : -len('" with administrator privileges')]
    # Rueckwaerts zum Escaping in ``escape_applescript_literal``: dort erst Backslash,
    # dann Quote -- hier also erst Quote, dann Backschlash zuruecknehmen. Die falsche
    # Reihenfolge zerlegt die '"'"'-Sequenzen und taeuscht einen Ausbruch vor.
    innerer_befehl = innerer_befehl.replace('\\"', '"').replace("\\\\", "\\")

    # WICHTIG: ``_mit_sicherem_skript`` hat ``os.stat`` global ersetzt -- damit wuerde
    # ``Path.exists()`` fuer JEDE Datei ``True`` liefern und die Messung unten waere
    # wertlos. Vor dem Messen also den echten ``os.stat`` zurueckholen.
    monkeypatch.undo()

    # subprocess ist im Modul gemockt gewesen -- hier bewusst der ECHTE Aufruf.
    subprocess_run_echt(["/bin/sh", "-c", innerer_befehl], capture_output=True, check=False)

    # (a) Der Inhalt wurde tatsaechlich als Programm ausgefuehrt ...
    assert beleg.exists(), "Der Inhalt wurde gar nicht ausgefuehrt -- Test waere wertlos."
    # (b) ... aber der Ausbruchsversuch blieb in der inneren Shell stecken.
    assert not beute.exists(), "Der Inhalt ist aus dem Shell-Wort ausgebrochen!"


def test_resolve_script_path_prefers_bundle_up_scripts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Im Bundle wird ``Contents/Resources/_up_/scripts/`` bevorzugt (gemessene Ablage).

    Tauri bildet das fuehrende ``..`` des resources-Eintrags auf ``_up_`` ab; am
    gebauten ``.app`` verifiziert. Der Test stellt die Bundle-Struktur in ``tmp_path``
    nach, statt sie anzunehmen.
    """
    macos_dir = tmp_path / "CernisPro.app" / "Contents" / "MacOS"
    macos_dir.mkdir(parents=True)
    ziel = tmp_path / "CernisPro.app" / "Contents" / "Resources" / "_up_" / "scripts"
    ziel.mkdir(parents=True)
    (ziel / "setup-bpf-access.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    monkeypatch.setattr(sys, "executable", str(macos_dir / "cernis-backend"))

    assert adapter_modul._resolve_script_path() == str(ziel / "setup-bpf-access.sh")


def test_resolve_script_path_falls_back_to_repo_scripts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Ohne Bundle-Ressource gilt der Dev-Pfad ``<repo>/scripts/`` -- er bleibt bestehen."""
    macos_dir = tmp_path / "CernisPro.app" / "Contents" / "MacOS"
    macos_dir.mkdir(parents=True)  # KEINE Resources/_up_/scripts angelegt
    monkeypatch.setattr(sys, "executable", str(macos_dir / "cernis-backend"))

    pfad = adapter_modul._resolve_script_path()

    assert pfad.endswith(os.path.join("scripts", "setup-bpf-access.sh"))
    assert "_up_" not in pfad


def test_bundled_repo_script_passes_the_source_check() -> None:
    """Das MITGELIEFERTE Repo-Skript besteht die Quellpruefung tatsaechlich.

    Kein Mock: prueft die echte Datei unter ``scripts/``. Schlaegt dieser Test fehl,
    waere die Einrichtung im Dev-Betrieb blockiert -- genau der Fehler, den Etappe 2b
    behebt.
    """
    pfad = adapter_modul._resolve_script_path()

    assert os.path.isfile(pfad)
    assert adapter_modul._verify_script_safe(pfad) is None


def test_grant_reports_unreadable_script(monkeypatch: pytest.MonkeyPatch) -> None:
    """Quelldatei besteht die Pruefung, ist aber nicht lesbar -> ``FAILED``, kein Start."""
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch)

    def _nicht_lesbar(_p: str) -> str:
        raise PermissionError("keine Leserechte")

    monkeypatch.setattr(adapter_modul, "_read_script", _nicht_lesbar)
    aufrufe = _osascript_liefert(monkeypatch, _FakeCompleted(returncode=0))

    result = CaptureAccessAdapter().grant()

    assert result.outcome is CaptureAccessOutcome.FAILED
    assert "nicht lesbar" in result.reason
    assert aufrufe == []


# ── Injection-Schutz: nur projektinterne Werte im AppleScript-Text ───────────


def test_grant_quotes_user_with_spaces(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein Benutzername mit Leerzeichen wird gequotet, bleibt also EIN Argument.

    ``shlex.quote`` quotet nur, WO es noetig ist -- ein harmloser Pfad bleibt darum
    unquotiert. Geprueft wird deshalb die Wirkung (der Wert bleibt ein Argument), nicht
    das Vorhandensein von Anfuehrungszeichen. Beide Werte sind projektintern bestimmt;
    das Quoten ist die zweite Verteidigung (AppleScript-Injection, v1-Finding).
    """
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch)
    monkeypatch.setattr(getpass, "getuser", lambda: "karl bach")
    aufrufe = _osascript_liefert(monkeypatch, _FakeCompleted(returncode=0))

    CaptureAccessAdapter().grant()

    script = aufrufe[0][2]
    assert "'karl bach'" in script
    # Der Benutzername bleibt Positionsargument des ueber stdin gelesenen Skripts.
    assert "/bin/bash -s -- 'karl bach'" in script


def test_grant_neutralises_shell_metacharacters_in_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ein Name mit Shell-Metazeichen kann keinen zweiten Befehl anhaengen.

    Konstruierter Extremfall (der Login-Name ist projektintern, nicht fremdbestimmt):
    das ``;`` darf nicht als Befehlstrenner wirksam werden.
    """
    _als_macos(monkeypatch)
    _mit_sicherem_skript(monkeypatch)
    monkeypatch.setattr(getpass, "getuser", lambda: "karl; rm -rf /")
    aufrufe = _osascript_liefert(monkeypatch, _FakeCompleted(returncode=0))

    CaptureAccessAdapter().grant()

    script = aufrufe[0][2]
    # Der gefaehrliche Teil steckt vollstaendig IM gequoteten Argument, steht also
    # nicht als eigener Befehl da.
    assert "'karl; rm -rf /'" in script
