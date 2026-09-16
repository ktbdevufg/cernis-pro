"""Tests fuer den reinen Mapping-Helfer ``_to_process_info`` (P.5, exe_path-Naht).

Kein echtes psutil/proc-I/O -- ein ``_FakeProc`` liefert pro Feld entweder einen Wert
oder wirft ``psutil.AccessDenied`` (fremder Prozess). Belegt die ROOTLESS-Naht: ein
lesbares ``exe()`` wird zu ``exe_path``, ein ``AccessDenied`` faellt ehrlich auf ``None``
zurueck (analog ``owner``/``status``), der Prozess wird NICHT weggeworfen.
"""

from typing import Any

import psutil

from infrastructure.process_linux import _to_process_info


class _FakeProc:
    """Minimaler psutil-``Process``-Stand-in -- pro Feld Wert ODER ``AccessDenied``.

    Felder, die auf ``_DENIED`` gesetzt sind, werfen beim Aufruf ``AccessDenied`` (so
    wie psutil bei fremden Prozessen) -- der Adapter faengt das ueber ``_safe`` ab.
    """

    _DENIED = object()

    def __init__(self, *, pid: int, exe: Any) -> None:
        self.pid = pid
        self._exe = exe

    def name(self) -> str:
        return "foo"

    def ppid(self) -> int:
        return 1

    def username(self) -> str:
        return "kbach"

    def status(self) -> str:
        return "sleeping"

    def create_time(self) -> float:
        return 123.0

    def cmdline(self) -> list[str]:
        return ["/usr/bin/foo"]

    def exe(self) -> str:
        if self._exe is self._DENIED:
            raise psutil.AccessDenied(self.pid)
        return str(self._exe)


def test_to_process_info_exe_path_lesbar() -> None:
    """Lesbares ``exe()`` -> ``exe_path`` gesetzt (absoluter Programmpfad)."""
    info = _to_process_info(_FakeProc(pid=42, exe="/usr/bin/foo"))
    assert info.exe_path == "/usr/bin/foo"


def test_to_process_info_exe_path_accessdenied_ist_none() -> None:
    """``AccessDenied`` bei ``exe()`` -> ``exe_path`` ehrlich ``None`` (rootless-Naht)."""
    info = _to_process_info(_FakeProc(pid=42, exe=_FakeProc._DENIED))
    assert info.exe_path is None
    # Der Prozess wird NICHT weggeworfen -- die uebrigen Felder bleiben lesbar.
    assert info.pid == 42
    assert info.name == "foo"
