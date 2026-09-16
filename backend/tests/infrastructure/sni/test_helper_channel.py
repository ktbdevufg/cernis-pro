"""Tests fuer ``SubprocessSniffHelper`` (Alias auf ``SniHelperClient``) -- nur Pfade
ohne echten Subprozess.

Ein echter Spawn braucht den Helfer + CAP_NET_RAW + scapy/Raw-Socket -- das wird hier
bewusst NICHT gefahren (Constraint: kein echter scapy/Raw-Socket/Subprozess in Tests).
Geprueft werden die deterministischen Naht-Punkte:

* Spawn schlaegt fehl (Kommando zeigt auf nicht-existierendes Programm) -> ``start()``
  gibt einen EHRLICHEN Fehlertext zurueck (kein Crash, S3-frei);
* das Spawn-Kommando-Muster (frozen vs. dev);
* ``poll_hits`` ist ohne Lauf leer; ``stop``/``is_running`` sind idempotent/ehrlich.

ETAPPE 3b: Der Spawn-/Connect-Kern wohnt jetzt in ``infrastructure.sniffd_client.base``
(``_spawn_command``/``_is_frozen`` werden DORT aufgeloest) -- die Monkeypatches zielen
darum auf ``base``, nicht mehr auf ``helper_channel``. ``SubprocessSniffHelper`` bleibt
ueber ``helper_channel`` importierbar (Alias auf ``SniHelperClient``).
"""

import sys
from pathlib import Path

import pytest

from infrastructure.sni.helper_channel import SubprocessSniffHelper
from infrastructure.sniffd_client import base
from infrastructure.sniffd_client.base import _spawn_command


def test_start_returns_honest_error_when_spawn_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zeigt das Spawn-Kommando auf ein nicht-existierendes Programm, faellt ``Popen``
    mit ``FileNotFoundError`` (OSError) -- ``start()`` faengt das und gibt einen
    ehrlichen Fehlertext zurueck (kein Crash, keine stille Leer-Erfassung)."""
    monkeypatch.setattr(
        base,
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
    monkeypatch.setattr(base, "_is_frozen", lambda: False)
    cmd = _spawn_command("/run/x.sock")
    assert cmd[1].endswith("sniffd.py")
    assert cmd[2] == "/run/x.sock"
    # Der dev-Entry-Pfad zeigt real auf backend/sniffd.py (existiert im Repo).
    assert Path(cmd[1]).name == "sniffd.py"


def test_spawn_command_frozen_points_next_to_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    """frozen: ``[<exe-dir>/cernis-sniffd, adresse]`` -- Binary neben sys.executable.

    Die Aussage bleibt unveraendert scharf: das Kommando zeigt auf GENAU die
    Helfer-Datei im Verzeichnis von ``sys.executable``, und die Adresse wird
    unveraendert durchgereicht. Nur der ERWARTETE Pfad wird plattformrichtig
    gebildet (``Path``) statt als Zeichenkette mit fest verdrahtetem ``/``:
    ``Path(...).parent / name`` liefert auf Windows ``\\`` als Trenner, worauf
    der frueher fest erwartete Text ``/opt/cernis/cernis-sniffd`` scheiterte.
    Der Vergleich laeuft ueber ``Path``-Gleichheit -- das prueft dieselbe
    Zusammensetzung, nur ohne Annahme ueber das Trennzeichen.
    """
    monkeypatch.setattr(base, "_is_frozen", lambda: True)
    exe = Path("/opt/cernis/cernis-backend")
    monkeypatch.setattr(sys, "executable", str(exe))
    cmd = _spawn_command("/run/x.sock")
    assert Path(cmd[0]) == exe.parent / base._HELPER_BINARY_NAME
    # Die Datei liegt WIRKLICH neben sys.executable (nicht irgendwo darunter).
    assert Path(cmd[0]).parent == exe.parent
    assert cmd[1] == "/run/x.sock"


def test_helper_binary_name_carries_platform_suffix() -> None:
    """Der Helfer-Name traegt die plattformuebliche Endung -- an genau EINER Stelle.

    Windows legt die Binary als ``cernis-sniffd.exe`` ab (``build.ps1``),
    Linux/macOS ohne Endung. Frueher bildete ``base.py`` den Namen IMMER ohne
    Endung -- im eingefrorenen Windows-Bau zeigte das Spawn-Kommando damit auf
    einen Pfad, den es nicht gibt.
    """
    if sys.platform == "win32":
        assert base._HELPER_BINARY_NAME == "cernis-sniffd.exe"
    else:
        assert base._HELPER_BINARY_NAME == "cernis-sniffd"


def test_spawn_command_frozen_finds_binary_with_platform_suffix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Der frozen-Pfad findet eine Datei, die wie im echten Bau abgelegt ist.

    Kern des Befunds: die Ablage (``build.ps1``: ``cernis-sniffd.exe``) und die
    Suche mussten auseinanderlaufen koennen. Hier wird die Binary GENAU so
    hingelegt, wie der jeweilige Bau sie ablegt -- und geprueft, dass das
    Spawn-Kommando sie tatsaechlich trifft.
    """
    exe = tmp_path / "cernis-backend"
    exe.write_bytes(b"")
    # So legt der Bau die Helfer-Datei ab (Windows mit .exe, sonst ohne).
    (tmp_path / base._HELPER_BINARY_NAME).write_bytes(b"")

    monkeypatch.setattr(base, "_is_frozen", lambda: True)
    monkeypatch.setattr(sys, "executable", str(exe))

    cmd = _spawn_command("adresse")
    assert Path(cmd[0]).exists(), f"frozen-Kommando trifft die abgelegte Binary nicht: {cmd[0]}"


def test_poll_hits_empty_without_run() -> None:
    assert SubprocessSniffHelper().poll_hits() == []


def test_is_running_false_without_run() -> None:
    assert SubprocessSniffHelper().is_running() is False


def test_stop_idempotent_without_run() -> None:
    helper = SubprocessSniffHelper()
    helper.stop()
    helper.stop()  # zweimal -> kein Crash
