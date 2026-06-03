"""Charakterisierung des Schedule-Parsings ``parse_schedule`` (M.6, domain).

Die Wahrheitstabelle aus dem Altcode (``modules/scheduler._parse_trigger``) als
parametrisierte Faelle -- valide interval/cron-Formen + die v2-Fix-Faelle: JEDER
unparsbare String wirft ``ScheduleParseError`` (statt des stillen 24h-Fallbacks /
des rohen ValueError des Altcodes). Empirisch gegen ``_parse_trigger`` belegt.
"""

import pytest

from domain.monitoring import (
    CronSpec,
    IntervalSpec,
    ScheduleParseError,
    ScheduleSpec,
    parse_schedule,
)


@pytest.mark.parametrize(
    ("schedule", "expected"),
    [
        # interval: alle drei Einheiten (m/h/d) -> APScheduler-Argumentnamen.
        ("interval:30m", IntervalSpec(unit="minutes", value=30)),
        ("interval:1h", IntervalSpec(unit="hours", value=1)),
        ("interval:6h", IntervalSpec(unit="hours", value=6)),
        ("interval:1d", IntervalSpec(unit="days", value=1)),
        ("interval:90m", IntervalSpec(unit="minutes", value=90)),
        # cron: genau fuenf Felder, ungeparst durchgereicht.
        ("cron:0 2 * * *", CronSpec(minute="0", hour="2", day="*", month="*", day_of_week="*")),
        (
            "cron:0 */6 * * *",
            CronSpec(minute="0", hour="*/6", day="*", month="*", day_of_week="*"),
        ),
    ],
)
def test_parse_schedule_valid(schedule: str, expected: ScheduleSpec) -> None:
    assert parse_schedule(schedule) == expected


@pytest.mark.parametrize(
    "schedule",
    [
        "",  # leer
        "nonsense",  # kein interval:/cron:-Praefix
        "interval:",  # interval ohne Wert
        "interval:30",  # kein m/h/d-Suffix
        "interval:30x",  # unbekanntes Suffix
        "interval:abcm",  # nicht-numerischer Wert (Altcode: roher ValueError)
        "interval:0m",  # <= 0 ist kein sinnvoller Trigger
        "interval:-5h",  # negativ
        "cron:",  # cron leer
        "cron:0 2 *",  # zu wenig Felder (3)
        "cron:0 2 * * * *",  # zu viele Felder (6)
        "daily",  # weder noch
    ],
)
def test_parse_schedule_invalid_raises(schedule: str) -> None:
    # v2-Fix: KEIN stiller 24h-Fallback -- jeder unparsbare String wirft.
    with pytest.raises(ScheduleParseError):
        parse_schedule(schedule)


def test_parse_error_carries_the_offending_string() -> None:
    with pytest.raises(ScheduleParseError) as exc_info:
        parse_schedule("interval:xyz")
    assert exc_info.value.schedule == "interval:xyz"
    assert "interval:xyz" in str(exc_info.value)


def test_parse_error_is_standalone_not_value_error() -> None:
    # ScheduleParseError ist EIGENSTAENDIG (erbt NICHT von ValueError) -- so kann ein
    # versehentliches ``except ValueError`` es nicht mitfangen (defensiv gegen den
    # Zu-breit-Fang in ManageSchedules, M.6 Schritt 2).
    assert not issubclass(ScheduleParseError, ValueError)
    assert issubclass(ScheduleParseError, Exception)
    # Beleg: ein except ValueError faengt es NICHT.
    caught_as_value_error = False
    try:
        parse_schedule("kaputt")
    except ValueError:
        caught_as_value_error = True
    except ScheduleParseError:
        caught_as_value_error = False
    assert caught_as_value_error is False


def test_parse_error_preserves_int_cause() -> None:
    # Der int()-ValueError bei nicht-numerischem Wert wird zu ScheduleParseError
    # umgewandelt (raise ... from exc) -- die Kausalkette bleibt ueber __cause__.
    with pytest.raises(ScheduleParseError) as exc_info:
        parse_schedule("interval:abcm")
    assert isinstance(exc_info.value.__cause__, ValueError)


def test_interval_minimum_value_accepted() -> None:
    # 1 ist gueltig (Grenze), 0 nicht (vorheriger Test).
    assert parse_schedule("interval:1m") == IntervalSpec(unit="minutes", value=1)
