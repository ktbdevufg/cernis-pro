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
from typing import Any

import pytest

from domain.capture_access import CaptureAccessOutcome, CaptureAccessState
from infrastructure import capture_access_macos as adapter_modul
from infrastructure.capture_access_macos import CaptureAccessAdapter

# ── Helfer: die Umgebung eines geglueckten macOS-Laufs herstellen ────────────


class _FakeStat:
    """Minimaler ``os.stat``-Ersatz: nur die drei geprueften Felder."""

    def __init__(self, uid: int = 0, mode: int = 0o100755) -> None:
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


def _mit_sicherem_skript(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skriptpfad existiert, gehoert root, ist nicht gruppen-/weltschreibbar."""
    monkeypatch.setattr(
        adapter_modul, "_resolve_script_path", lambda: "/bundle/setup-bpf-access.sh"
    )
    monkeypatch.setattr(os, "stat", lambda _p: _FakeStat())


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


def test_grant_refuses_script_not_owned_by_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skript gehoert NICHT root -> ``FAILED``, und es wird NICHT ausgefuehrt.

    Ein nicht-root-eigenes Skript koennte vor der Root-Ausfuehrung ausgetauscht werden
    (lokale Rechteausweitung). Der Adapter muss hier abbrechen, nicht "trotzdem".
    """
    _als_macos(monkeypatch)
    monkeypatch.setattr(adapter_modul, "_resolve_script_path", lambda: "/tmp/setup-bpf-access.sh")
    monkeypatch.setattr(os, "stat", lambda _p: _FakeStat(uid=501))
    aufrufe = _osascript_liefert(monkeypatch, _FakeCompleted(returncode=0))

    result = CaptureAccessAdapter().grant()

    assert result.outcome is CaptureAccessOutcome.FAILED
    assert "root" in result.reason
    assert aufrufe == []  # nichts gestartet


@pytest.mark.parametrize(
    ("mode", "label"),
    [(0o100775, "gruppenschreibbar"), (0o100777, "weltschreibbar")],
)
def test_grant_refuses_writable_script(
    monkeypatch: pytest.MonkeyPatch, mode: int, label: str
) -> None:
    """Gruppen-/weltschreibbares Skript -> ``FAILED`` ohne Ausfuehrung.

    Auch bei root-Eigentum: ist die Datei fuer andere schreibbar, ist ihr Inhalt vor
    der Root-Ausfuehrung manipulierbar.
    """
    _als_macos(monkeypatch)
    monkeypatch.setattr(
        adapter_modul, "_resolve_script_path", lambda: "/bundle/setup-bpf-access.sh"
    )
    monkeypatch.setattr(os, "stat", lambda _p: _FakeStat(uid=0, mode=mode))
    aufrufe = _osascript_liefert(monkeypatch, _FakeCompleted(returncode=0))

    result = CaptureAccessAdapter().grant()

    assert result.outcome is CaptureAccessOutcome.FAILED, label
    assert "schreibbar" in result.reason
    assert aufrufe == []


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


def test_verify_script_safe_accepts_root_owned_non_writable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Positivprobe: root-eigen, regulaer und nicht gruppen-/weltschreibbar -> ``None``.

    Gegenstueck zu den Ablehnungs-Tests: ohne diesen Fall koennte die Pruefung
    pauschal alles ablehnen und die Negativ-Tests waeren trotzdem gruen.
    """
    monkeypatch.setattr(os, "stat", lambda _p: _FakeStat(uid=0, mode=stat.S_IFREG | 0o755))

    assert adapter_modul._verify_script_safe("/bundle/setup-bpf-access.sh") is None


def test_verify_script_safe_rejects_non_regular_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein Verzeichnis/Symlink-Ziel statt einer regulaeren Datei -> abgelehnt."""
    monkeypatch.setattr(os, "stat", lambda _p: _FakeStat(uid=0, mode=stat.S_IFDIR | 0o755))

    grund = adapter_modul._verify_script_safe("/bundle")

    assert grund is not None
    assert "regulaere Datei" in grund


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
    assert "/bin/bash /bundle/setup-bpf-access.sh" in script


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
