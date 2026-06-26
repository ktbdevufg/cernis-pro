"""Tests fuer ``SubprocessSniffHelper`` -- NUR die Pfade ohne echten Subprozess.

Ein echter Spawn braucht den Helfer + CAP_NET_RAW + scapy/Raw-Socket -- das wird hier
bewusst NICHT gefahren (Constraint: kein echter scapy/Raw-Socket/Subprozess in Tests).
Geprueft werden die deterministischen Naht-Punkte:

* Spawn schlaegt fehl (Kommando zeigt auf nicht-existierendes Programm) -> ``start()``
  gibt einen EHRLICHEN Fehlertext zurueck (kein Crash, S3-frei);
* das Spawn-Kommando-Muster (frozen vs. dev);
* ``poll_hits`` ist ohne Lauf leer; ``stop``/``is_running`` sind idempotent/ehrlich.
"""

import sys
from pathlib import Path

import pytest

from infrastructure.sni import helper_channel
from infrastructure.sni.helper_channel import SubprocessSniffHelper, _spawn_command


def test_start_returns_honest_error_when_spawn_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zeigt das Spawn-Kommando auf ein nicht-existierendes Programm, faellt ``Popen``
    mit ``FileNotFoundError`` (OSError) -- ``start()`` faengt das und gibt einen
    ehrlichen Fehlertext zurueck (kein Crash, keine stille Leer-Erfassung)."""
    monkeypatch.setattr(
        helper_channel,
        "_spawn_command",
        lambda socket_path: ["/nonexistent/cernis-sniffd-does-not-exist", socket_path],
    )
    helper = SubprocessSniffHelper()
    error = helper.start(None)
    assert error is not None
    assert "nicht gestartet" in error
    assert helper.is_running() is False
    # stop() nach gescheitertem Start ist ein No-op (kein Crash, idempotent).
    helper.stop()


def test_spawn_command_dev_points_at_sniffd_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    """dev (nicht frozen): ``[python, <repo>/backend/sniffd.py, socket]``."""
    monkeypatch.setattr(helper_channel, "_is_frozen", lambda: False)
    cmd = _spawn_command("/run/x.sock")
    assert cmd[1].endswith("sniffd.py")
    assert cmd[2] == "/run/x.sock"
    # Der dev-Entry-Pfad zeigt real auf backend/sniffd.py (existiert im Repo).
    assert Path(cmd[1]).name == "sniffd.py"


def test_spawn_command_frozen_points_next_to_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    """frozen: ``[<exe-dir>/cernis-sniffd, socket]`` -- Binary neben sys.executable."""
    monkeypatch.setattr(helper_channel, "_is_frozen", lambda: True)
    monkeypatch.setattr(sys, "executable", "/opt/cernis/cernis-backend")
    cmd = _spawn_command("/run/x.sock")
    assert cmd[0] == "/opt/cernis/cernis-sniffd"
    assert cmd[1] == "/run/x.sock"


def test_poll_hits_empty_without_run() -> None:
    assert SubprocessSniffHelper().poll_hits() == []


def test_is_running_false_without_run() -> None:
    assert SubprocessSniffHelper().is_running() is False


def test_stop_idempotent_without_run() -> None:
    helper = SubprocessSniffHelper()
    helper.stop()
    helper.stop()  # zweimal -> kein Crash
