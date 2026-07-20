"""Tests des TrafficPermissionAdapter -- reine Capability-/Rechte-Logik.

Prueft die reine ``_has_cap_net_admin``-Bit-Pruefung (Bit 12, defensiv gegen
ungueltigen Hex) und die ``check_permission``-Naht (Root / CAP_NET_ADMIN / kein
Recht) ueber Monkeypatch von ``os.geteuid`` und der gekapselten ``_read_cap_eff``-
I/O-Stelle. Kein echtes ``/proc`` noetig.
"""

import os
import sys

import pytest

import infrastructure.traffic_permission as tp
from domain.traffic import TrafficPermissionState
from infrastructure.traffic_macos import (
    TrafficPermissionAdapter as MacosTrafficPermissionAdapter,
)
from infrastructure.traffic_permission import TrafficPermissionAdapter, _has_cap_net_admin

# ── _has_cap_net_admin (reine Bit-Pruefung) ──────────────────────────────────


def test_has_cap_net_admin_bit_set() -> None:
    # Bit 12 gesetzt -> True. (1 << 12) == 0x1000.
    assert _has_cap_net_admin("0000000000001000") is True
    # voller Root-Capset enthaelt Bit 12 ebenfalls.
    assert _has_cap_net_admin("000001ffffffffff") is True


def test_has_cap_net_admin_bit_unset() -> None:
    assert _has_cap_net_admin("0000000000000000") is False
    # Bits 0..11 gesetzt, aber NICHT 12 -> False.
    assert _has_cap_net_admin("0000000000000fff") is False


def test_has_cap_net_admin_invalid_hex_defensive() -> None:
    assert _has_cap_net_admin("nicht-hex") is False
    assert _has_cap_net_admin("") is False


# ── check_permission (Root / Capability / kein Recht) ────────────────────────


def test_check_permission_root_full_view(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert TrafficPermissionAdapter().check_permission() is None


def test_check_permission_cap_net_admin_full_view(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(tp, "_read_cap_eff", lambda: "0000000000001000")  # Bit 12
    assert TrafficPermissionAdapter().check_permission() is None


def test_check_permission_no_rights_returns_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(tp, "_read_cap_eff", lambda: "0000000000000000")  # kein Bit 12
    result = TrafficPermissionAdapter().check_permission()
    assert result is not None
    assert "Root" in result  # handlungsorientierter Hinweis


def test_check_permission_proc_unreadable_falls_back_to_geteuid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # /proc nicht lesbar -> _read_cap_eff None; nicht-root -> Hinweis (kein stiller
    # Fallback auf "volle Sicht", S3).
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(tp, "_read_cap_eff", lambda: None)
    assert TrafficPermissionAdapter().check_permission() is not None


# ── is_available (Plattform-Riegel) ──────────────────────────────────────────


def test_is_available_on_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert TrafficPermissionAdapter().is_available() is True


def test_is_available_non_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    assert TrafficPermissionAdapter().is_available() is False


# ── permission_state: Rechte-Problem vs. Plattformgrenze (A3) ────────────────
# Die Kernunterscheidung dieser Naht. Beide Faelle liefern in der schmalen
# Text-Naht ``ok=False`` samt Begruendung -- fachlich sind sie aber verschieden:
# auf Linux BEHEBBAR (Rechte erlangbar), auf macOS NICHT (die Plattform bietet die
# Messung gar nicht an). Faellt die Trennung je zusammen, raet die Oberflaeche auf
# macOS zu erhoehten Rechten, die dort nichts bewirken.


def test_permission_state_linux_granted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Root -> ``GRANTED`` ohne Begruendung (es gibt nichts zu erklaeren)."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    result = TrafficPermissionAdapter().permission_state()

    assert result.state is TrafficPermissionState.GRANTED
    assert result.reason == ""


def test_permission_state_linux_missing_rights_is_behebbar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kein Recht auf Linux -> ``NEEDS_PRIVILEGES`` MIT Weg, NIE ``NOT_APPLICABLE``.

    Auf Linux ist die Messung moeglich; fehlt sie, liegt es an den Rechten des
    Prozesses. Der handlungsorientierte Hinweis ist hier RICHTIG.
    """
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(tp, "_read_cap_eff", lambda: "0000000000000000")

    result = TrafficPermissionAdapter().permission_state()

    assert result.state is TrafficPermissionState.NEEDS_PRIVILEGES
    assert "Root" in result.reason


def test_permission_state_macos_is_not_applicable() -> None:
    """macOS -> ``NOT_APPLICABLE``: Plattformgrenze, KEIN Rechteproblem."""
    result = MacosTrafficPermissionAdapter().permission_state()

    assert result.state is TrafficPermissionState.NOT_APPLICABLE


def test_permission_state_macos_gives_no_privilege_advice() -> None:
    """Der macOS-Text raet NICHT zu erhoehten Rechten -- dort waere das wirkungslos.

    Kernforderung von A3: keine Handlungsaufforderung, die auf dieser Plattform
    nichts bewirkt. Geprueft wird der Text BEIDER Nahtstellen (Zustand und die
    schmale Text-Naht), damit der Rat nicht durch eine Hintertuer zurueckkehrt.
    """
    result = MacosTrafficPermissionAdapter().permission_state()
    text_naht = MacosTrafficPermissionAdapter().check_permission() or ""

    for text in (result.reason, text_naht):
        gesenkt = text.lower()
        for verboten in ("root", "sudo", "administrator", "erhoehte rechte"):
            assert verboten not in gesenkt, f"Rechte-Rat '{verboten}' im macOS-Text"


def test_permission_state_macos_names_what_still_works() -> None:
    """Der Text benennt WAS fehlt, WARUM es fehlt und WAS trotzdem funktioniert."""
    reason = MacosTrafficPermissionAdapter().permission_state().reason

    assert "macOS" in reason  # warum: diese Plattform
    assert "Stufe 1" in reason or "Programme" in reason  # was trotzdem geht
    assert reason.strip() != ""
