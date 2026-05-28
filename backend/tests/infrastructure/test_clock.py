"""Tests fuer den ``SystemClock``-Adapter.

Prueft nur die strukturellen Eigenschaften (tz-aware, UTC) -- kein konkreter,
flaky Zeitwert.
"""

from datetime import UTC, timedelta

from infrastructure.clock import SystemClock
from ports.devices import Clock


def test_conforms_to_clock_protocol() -> None:
    # Statische Vertragspruefung (mypy), ohne @runtime_checkable.
    _: Clock = SystemClock()


def test_now_is_timezone_aware_utc() -> None:
    now = SystemClock().now()
    assert now.tzinfo is not None  # tz-aware
    assert now.utcoffset() == timedelta(0)  # UTC
    assert now.tzinfo == UTC
