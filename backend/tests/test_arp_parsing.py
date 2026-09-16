"""Tests des ARP-Cache-Parsings (``modules/discovery.get_arp_table``) -- PLATTFORMFREI.

Laeuft auf der Linux-CI: ``platform.system`` und ``subprocess.run`` werden per
``monkeypatch`` ersetzt, es wird nie ein echtes ``arp``/``ip`` gebraucht.

Hintergrund (D8): macOS' ``arp -a`` gibt MAC-Oktette OHNE fuehrende Null aus
("at b0:f2:8:dc:c1:e7" = 16 Zeichen). Der fruehere starre ``{17}``-Regex verwarf
jede solche Zeile -- auf dem Referenz-Mac gingen 24 von 36 Eintraegen verloren,
darunter das Gateway. Diese Tests halten das unpadded-tolerante Parsing und die
kanonische Normalisierung (zweistellig gepolstert, lowercase, ':'-getrennt) fest.
"""

import platform
import subprocess
from typing import Any

import pytest

from modules.discovery import get_arp_table, normalize_arp_mac

# Reale macOS-Ausgabe (gemessen): unpadded Gateway-MAC, gepolsterte MAC,
# incomplete-Eintrag ohne MAC.
_MACOS_ARP_OUT = """\
fritzbox.mysticplace.de (172.18.0.1) at b0:f2:8:dc:c1:e7 on en12 ifscope [ethernet]
homematic.mysticplace.de (172.18.1.111) at dc:a6:32:28:97:37 on en12 ifscope [ethernet]
? (172.18.1.99) at (incomplete) on en12 ifscope [ethernet]
"""

_WINDOWS_ARP_OUT = """\
Interface: 172.18.1.50 --- 0xb
  Internet Address      Physical Address      Type
  172.18.0.1            b0-f2-8-dc-c1-e7      dynamic
  172.18.1.111          DC-A6-32-28-97-37     dynamic
"""

_LINUX_NEIGH_OUT = """\
172.18.0.1 dev eth0 lladdr b0:f2:08:dc:c1:e7 REACHABLE
172.18.1.99 dev eth0 FAILED
"""


def _fake_run(stdout: str) -> Any:
    """Ersatz fuer ``subprocess.run``: liefert nur das vorgegebene stdout."""

    class _Completed:
        def __init__(self) -> None:
            self.stdout = stdout

    def _run(*_args: Any, **_kwargs: Any) -> Any:
        return _Completed()

    return _run


# ── Normalisierungs-Helfer ───────────────────────────────────────────────────


def test_normalize_pads_unpadded_octet() -> None:
    assert normalize_arp_mac("b0:f2:8:dc:c1:e7") == "b0:f2:08:dc:c1:e7"


def test_normalize_dash_and_uppercase() -> None:
    assert normalize_arp_mac("B0-F2-08-DC-C1-E7") == "b0:f2:08:dc:c1:e7"


def test_normalize_padded_is_idempotent() -> None:
    assert normalize_arp_mac("dc:a6:32:28:97:37") == "dc:a6:32:28:97:37"


def test_normalize_rejects_wrong_octet_count() -> None:
    assert normalize_arp_mac("b0:f2:08:dc:c1") == ""  # 5 Oktette -> verworfen


def test_normalize_rejects_non_hex() -> None:
    assert normalize_arp_mac("zz:f2:08:dc:c1:e7") == ""


# ── macOS-Zweig ──────────────────────────────────────────────────────────────


def test_macos_parses_unpadded_and_padded_skips_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(subprocess, "run", _fake_run(_MACOS_ARP_OUT))
    table = get_arp_table()
    assert table["172.18.0.1"] == "b0:f2:08:dc:c1:e7"  # unpadded -> gepolstert
    assert table["172.18.1.111"] == "dc:a6:32:28:97:37"  # gepolstert -> unveraendert
    assert "172.18.1.99" not in table  # incomplete ohne MAC -> nicht aufgenommen
    assert len(table) == 2


# ── Windows-Zweig ────────────────────────────────────────────────────────────


def test_windows_parses_unpadded_and_uppercase(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(subprocess, "run", _fake_run(_WINDOWS_ARP_OUT))
    table = get_arp_table()
    assert table["172.18.0.1"] == "b0:f2:08:dc:c1:e7"
    assert table["172.18.1.111"] == "dc:a6:32:28:97:37"


# ── Linux-Zweig ──────────────────────────────────────────────────────────────


def test_linux_normalizes_and_skips_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(subprocess, "run", _fake_run(_LINUX_NEIGH_OUT))
    table = get_arp_table()
    assert table == {"172.18.0.1": "b0:f2:08:dc:c1:e7"}  # FAILED-Zeile fehlt
