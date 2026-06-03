"""Charakterisierung der monitoring-Uebergangs-Logik ``classify_transition`` /
``should_notify``.

Die vollstaendige Wahrheitstabelle aus dem Altcode (``modules/monitor.py``
Z.250-262) als parametrisierte Faelle -- besonders die zwei nicht-offensichtlichen
Regeln: ``degraded`` NUR bei prev=True/now=True/loss>30, und False/False -> None
(dauerhaft-ab erzeugt KEIN Event). ``should_notify`` gegen die Inline-Notify-Regel
des Altcodes (nur up->down- und down->up-Flanken, NICHT Erstmessung/degraded).
"""

import pytest

from domain.monitoring import MonitorEventType, classify_transition, should_notify

UP = MonitorEventType.UP
DOWN = MonitorEventType.DOWN
DEGRADED = MonitorEventType.DEGRADED


@pytest.mark.parametrize(
    ("prev", "now", "loss_pct", "expected"),
    [
        # Erstmessung (prev is None): up wenn lebendig, sonst down. loss irrelevant.
        (None, True, 0.0, UP),
        (None, True, 50.0, UP),
        (None, False, 0.0, DOWN),
        (None, False, 50.0, DOWN),
        # Flanke up -> down.
        (True, False, 0.0, DOWN),
        (True, False, 50.0, DOWN),
        # Flanke down -> up: ueberschattet degraded auch bei loss>30.
        (False, True, 0.0, UP),
        (False, True, 50.0, UP),
        # Stabil up: ohne Degradation kein Event, mit loss>30 -> degraded.
        (True, True, 0.0, None),
        (True, True, 30.0, None),  # Schwelle ist STRIKT > 30
        (True, True, 50.0, DEGRADED),
        # Dauerhaft down: KEIN Event (auch nicht "down").
        (False, False, 0.0, None),
        (False, False, 50.0, None),
    ],
)
def test_classify_transition_truth_table(
    prev: bool | None,
    now: bool,
    loss_pct: float,
    expected: MonitorEventType | None,
) -> None:
    assert classify_transition(prev, now, loss_pct) == expected


def test_degraded_only_on_stable_up() -> None:
    # Die nicht-offensichtliche Regel explizit: degraded NUR bei prev=True/now=True.
    assert classify_transition(True, True, 50.0) is DEGRADED
    # Bei Recovery (prev=False -> now=True) gewinnt up, auch bei hohem Verlust.
    assert classify_transition(False, True, 50.0) is UP


def test_persistent_down_yields_no_event() -> None:
    # Die zweite nicht-offensichtliche Regel: dauerhaft-ab -> None, kein "down".
    assert classify_transition(False, False, 0.0) is None
    assert classify_transition(False, False, 99.0) is None


def test_degraded_threshold_is_strictly_greater_than_30() -> None:
    assert classify_transition(True, True, 30.0) is None
    assert classify_transition(True, True, 30.001) is DEGRADED


@pytest.mark.parametrize(
    ("prev", "event", "expected"),
    [
        # Erstmessung (prev is None): NIE notify, egal welches Event.
        (None, UP, False),
        (None, DOWN, False),
        (None, None, False),
        # Flanken mit Vorzustand: up/down -> notify.
        (True, DOWN, True),
        (False, UP, True),
        (True, UP, True),
        (False, DOWN, True),
        # degraded -> NIE notify (Altcode rief _notify_macos dort nicht).
        (True, DEGRADED, False),
        (False, DEGRADED, False),
        # kein Event -> kein notify.
        (True, None, False),
        (False, None, False),
    ],
)
def test_should_notify_rule(
    prev: bool | None,
    event: MonitorEventType | None,
    expected: bool,
) -> None:
    assert should_notify(prev, event) is expected


def test_should_notify_never_on_first_measurement() -> None:
    # Auch wenn die Erstmessung up/down klassifiziert, gibt es keine Notification.
    for event in (UP, DOWN, DEGRADED, None):
        assert should_notify(None, event) is False


def test_should_notify_never_on_degraded() -> None:
    assert should_notify(True, DEGRADED) is False
    assert should_notify(False, DEGRADED) is False
