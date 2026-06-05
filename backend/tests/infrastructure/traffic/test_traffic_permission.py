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
