"""Tests des TrafficPermissionAdapter -- Verfuegbarkeit der Durchsatz-Quelle.

Der Durchsatz je Programm braucht auf Linux KEINE erhoehten Rechte (gemessen:
``ss -tin`` liefert die Byte-Zaehler als gewoehnlicher Benutzer). Geprueft wird
darum die einzige Bedingung, die ihn wirklich verhindern kann: ob das Werkzeug
``ss`` vorhanden ist. Der Test faelscht die gekapselte Pruefstelle
``_ss_vorhanden`` -- kein echtes PATH-Gefummel noetig.

Der macOS-Pfad (Plattformgrenze, ``NOT_APPLICABLE``) bleibt unveraendert
mitgeprueft: er darf durch die Linux-Aenderung nicht mitkippen.
"""

import sys

import pytest

import infrastructure.traffic_permission as tp
from domain.traffic import TrafficPermissionState
from infrastructure.traffic_macos import (
    TrafficPermissionAdapter as MacosTrafficPermissionAdapter,
)
from infrastructure.traffic_permission import TrafficPermissionAdapter

# ── check_permission (Werkzeug vorhanden / fehlt) ────────────────────────────


def test_check_permission_ohne_root_messbar(monkeypatch: pytest.MonkeyPatch) -> None:
    """KERN (Finding 5): als gewoehnlicher Benutzer ist der Durchsatz messbar.

    Frueher meldete diese Naht ohne Root einen Rechte-Hinweis; sie darf es nicht
    mehr -- die Rechte-Annahme war messbar falsch.
    """
    monkeypatch.setattr(tp, "_ss_vorhanden", lambda: True)

    assert TrafficPermissionAdapter().check_permission() is None


def test_check_permission_werkzeug_fehlt_nennt_grund(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fehlendes ``ss`` -> benannter Grund (kein stilles Nichts, S3)."""
    monkeypatch.setattr(tp, "_ss_vorhanden", lambda: False)

    result = TrafficPermissionAdapter().check_permission()

    assert result is not None
    assert "ss" in result
    assert "iproute2" in result


def test_check_permission_raet_nie_zu_erhoehten_rechten(monkeypatch: pytest.MonkeyPatch) -> None:
    """Kein Rechte-Rat, kein Terminal-Befehl im Text (Karls Entscheidung S57).

    Auch im Fehlerfall: ein fehlendes Paket ist kein Rechteproblem, und ein
    ``sudo``-Rat waere dort schlicht falsch.
    """
    monkeypatch.setattr(tp, "_ss_vorhanden", lambda: False)

    text = (TrafficPermissionAdapter().check_permission() or "").lower()

    for verboten in ("root", "sudo", "administrator", "erhoehte rechte", "erhöhte rechte"):
        assert verboten not in text, f"Rechte-Rat '{verboten}' im Linux-Text"


# ── is_available (Plattform-Riegel) ──────────────────────────────────────────


def test_is_available_on_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert TrafficPermissionAdapter().is_available() is True


def test_is_available_non_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    assert TrafficPermissionAdapter().is_available() is False


# ── permission_state: messbar vs. Quelle fehlt vs. Plattformgrenze ───────────


def test_permission_state_linux_granted_ohne_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """KERN (Finding 5): rootless -> ``GRANTED`` ohne Begruendung.

    Genau hier sass die falsche Annahme: dieser Fall lieferte frueher
    ``NEEDS_PRIVILEGES`` samt sudo-Rat, obwohl die Messung laeuft.
    """
    monkeypatch.setattr(tp, "_ss_vorhanden", lambda: True)

    result = TrafficPermissionAdapter().permission_state()

    assert result.state is TrafficPermissionState.GRANTED
    assert result.reason == ""


def test_permission_state_werkzeug_fehlt_ist_fehler_mit_grund(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fehlendes Werkzeug -> ``NEEDS_PRIVILEGES`` MIT Grund, nie ``GRANTED``.

    Der echte Fehlerfall bleibt sichtbar -- er darf nicht zur stillen Null werden.
    """
    monkeypatch.setattr(tp, "_ss_vorhanden", lambda: False)

    result = TrafficPermissionAdapter().permission_state()

    assert result.state is TrafficPermissionState.NEEDS_PRIVILEGES
    assert result.reason.strip() != ""


def test_permission_state_linux_nie_not_applicable(monkeypatch: pytest.MonkeyPatch) -> None:
    """``NOT_APPLICABLE`` gehoert Plattformen ohne Messung -- Linux vergibt ihn nie."""
    for vorhanden in (True, False):
        monkeypatch.setattr(tp, "_ss_vorhanden", lambda v=vorhanden: v)
        state = TrafficPermissionAdapter().permission_state().state
        assert state is not TrafficPermissionState.NOT_APPLICABLE


def test_permission_state_macos_is_not_applicable() -> None:
    """macOS -> ``NOT_APPLICABLE``: Plattformgrenze, KEIN Rechteproblem (unveraendert)."""
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
