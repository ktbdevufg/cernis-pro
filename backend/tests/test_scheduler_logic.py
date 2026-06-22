"""Tests fuer die reine Fenster-/Faelligkeits-Logik der scheduler-Domaene.

Belegt ``is_within_window`` (Gesamtzeitraum, Wochentag, Tagesfenster-Grenzen),
``is_expired`` (until==0.0 nie / > until / == until) und ``is_active_job`` (nur
ACTIVE + nicht expired + im Fenster). Zeitfrei -- alle Werte direkt als Argumente,
keine Uhr, keine Mocks.
"""

from domain.scheduler.logic import is_active_job, is_expired, is_within_window
from domain.scheduler.models import DailyWindow, JobState, ScheduledJob

DAY = 24 * 3600.0
# 09:00 .. 17:00 als Minuten seit Mitternacht.
NINE = 9 * 60
FIVE_PM = 17 * 60


def _window(
    *,
    start_minute: int = NINE,
    end_minute: int = FIVE_PM,
    weekdays: set[int] | None = None,
    from_epoch: float = 0.0,
    until_epoch: float = 0.0,
) -> DailyWindow:
    return DailyWindow(
        start_minute=start_minute,
        end_minute=end_minute,
        weekdays=frozenset(weekdays or set()),
        from_epoch=from_epoch,
        until_epoch=until_epoch,
    )


def _job(window: DailyWindow, state: JobState = JobState.ACTIVE) -> ScheduledJob:
    return ScheduledJob(
        id=1,
        job_type="monitoring_window",
        params=(("target", "lan"),),
        window=window,
        state=state,
    )


# ── is_within_window: Grundfall ──────────────────────────────────────────────


def test_innerhalb_aller_bedingungen_ist_true() -> None:
    win = _window(from_epoch=0.0, until_epoch=0.0)
    assert is_within_window(win, now_epoch=1000.0, now_minute=NINE + 30, weekday=2)


# ── is_within_window: Gesamtzeitraum ─────────────────────────────────────────


def test_vor_from_epoch_ist_false() -> None:
    win = _window(from_epoch=5 * DAY)
    assert not is_within_window(win, now_epoch=1 * DAY, now_minute=NINE + 30, weekday=2)


def test_nach_until_epoch_ist_false() -> None:
    win = _window(from_epoch=0.0, until_epoch=5 * DAY)
    assert not is_within_window(win, now_epoch=6 * DAY, now_minute=NINE + 30, weekday=2)


def test_until_null_ist_immer_offen() -> None:
    win = _window(from_epoch=0.0, until_epoch=0.0)
    # Selbst sehr weit in der Zukunft: until==0.0 -> unbegrenzt.
    assert is_within_window(win, now_epoch=10_000 * DAY, now_minute=NINE + 30, weekday=2)


# ── is_within_window: Wochentag ──────────────────────────────────────────────


def test_weekday_nicht_in_weekdays_ist_false() -> None:
    win = _window(weekdays={0, 1, 2, 3, 4})  # Mo-Fr
    assert not is_within_window(win, now_epoch=1000.0, now_minute=NINE + 30, weekday=6)


def test_weekdays_leer_zaehlt_jeder_tag() -> None:
    win = _window(weekdays=set())
    # Sonntag (6) -- leere Menge bedeutet "alle Tage".
    assert is_within_window(win, now_epoch=1000.0, now_minute=NINE + 30, weekday=6)


# ── is_within_window: Tagesfenster-Grenzen (halb-offen) ──────────────────────


def test_now_minute_gleich_start_ist_inklusiv_true() -> None:
    win = _window()
    assert is_within_window(win, now_epoch=1000.0, now_minute=NINE, weekday=2)


def test_now_minute_gleich_end_ist_exklusiv_false() -> None:
    win = _window()
    assert not is_within_window(win, now_epoch=1000.0, now_minute=FIVE_PM, weekday=2)


def test_now_minute_vor_start_ist_false() -> None:
    win = _window()
    assert not is_within_window(win, now_epoch=1000.0, now_minute=NINE - 1, weekday=2)


def test_now_minute_ab_end_ist_false() -> None:
    win = _window()
    assert not is_within_window(win, now_epoch=1000.0, now_minute=FIVE_PM + 1, weekday=2)


# ── is_expired ───────────────────────────────────────────────────────────────


def test_until_null_nie_expired() -> None:
    win = _window(until_epoch=0.0)
    assert not is_expired(win, now_epoch=10_000 * DAY)


def test_now_nach_until_ist_expired() -> None:
    win = _window(until_epoch=5 * DAY)
    assert is_expired(win, now_epoch=5 * DAY + 1.0)


def test_now_gleich_until_ist_nicht_expired() -> None:
    win = _window(until_epoch=5 * DAY)
    assert not is_expired(win, now_epoch=5 * DAY)


# ── is_active_job ────────────────────────────────────────────────────────────


def test_active_im_fenster_nicht_expired_ist_true() -> None:
    job = _job(_window(until_epoch=0.0), state=JobState.ACTIVE)
    assert is_active_job(job, now_epoch=1000.0, now_minute=NINE + 30, weekday=2)


def test_paused_ist_false_trotz_fenster() -> None:
    job = _job(_window(until_epoch=0.0), state=JobState.PAUSED)
    assert not is_active_job(job, now_epoch=1000.0, now_minute=NINE + 30, weekday=2)


def test_finished_ist_false_trotz_fenster() -> None:
    job = _job(_window(until_epoch=0.0), state=JobState.FINISHED)
    assert not is_active_job(job, now_epoch=1000.0, now_minute=NINE + 30, weekday=2)


def test_expired_ist_false_trotz_fenster() -> None:
    # Im Tagesfenster + ACTIVE, aber Gesamtzeitraum abgelaufen -> nicht aktiv.
    job = _job(_window(until_epoch=5 * DAY), state=JobState.ACTIVE)
    assert not is_active_job(job, now_epoch=6 * DAY, now_minute=NINE + 30, weekday=2)


def test_active_aber_ausserhalb_tagesfenster_ist_false() -> None:
    job = _job(_window(until_epoch=0.0), state=JobState.ACTIVE)
    assert not is_active_job(job, now_epoch=1000.0, now_minute=FIVE_PM + 1, weekday=2)
