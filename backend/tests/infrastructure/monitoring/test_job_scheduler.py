"""Tests fuer ``ApschedulerJobScheduler`` (M.6) -- Trigger-Bau + Lifecycle.

Getestet: (1) Port-Konformitaet, (2) ``_build_trigger`` baut die richtigen
APScheduler-Trigger aus der ``ScheduleSpec`` (Interval m/h/d, Cron), (3) ``register``
parst via ``parse_schedule`` und legt den Job an; ein kaputter String propagiert
``ScheduleParseError`` (kein stiller Fallback), (4) ``unregister`` ist idempotent
(nie registrierter Job -> kein Fehler), (5) start/stop-Lifecycle + Doppelstart-Schutz.

``AsyncIOScheduler.start()`` bindet sich an ``asyncio.get_running_loop()`` -- die
start-abhaengigen Tests laufen daher INNERHALB eines ``asyncio.run`` (kein
``pytest-asyncio``, wie ueberall). Ein tickender Loop ist nicht noetig -- es feuert
kein echter Job; nur der Scheduler-/Job-Zustand wird geprueft. Die reinen
``_build_trigger``-Tests laufen ohne Loop (kein ``start``).
"""

import asyncio

import pytest
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from domain.monitoring import CronSpec, IntervalSpec, ScheduleParseError
from infrastructure.monitoring.job_scheduler import (
    ApschedulerJobScheduler,
    _build_trigger,
)
from ports.monitoring import ScanJobScheduler


async def _noop_callback(cidr: str, profile_id: str, schedule_id: int) -> None:
    return None


def test_conforms_to_job_scheduler_protocol() -> None:
    _: ScanJobScheduler = ApschedulerJobScheduler()


# ── _build_trigger: Spec -> APScheduler-Trigger ─────────────────────────────


def test_build_trigger_interval_minutes() -> None:
    trigger = _build_trigger(IntervalSpec(unit="minutes", value=30))
    assert isinstance(trigger, IntervalTrigger)
    assert trigger.interval.total_seconds() == 30 * 60


def test_build_trigger_interval_hours() -> None:
    trigger = _build_trigger(IntervalSpec(unit="hours", value=6))
    assert isinstance(trigger, IntervalTrigger)
    assert trigger.interval.total_seconds() == 6 * 3600


def test_build_trigger_interval_days() -> None:
    trigger = _build_trigger(IntervalSpec(unit="days", value=1))
    assert isinstance(trigger, IntervalTrigger)
    assert trigger.interval.total_seconds() == 86400


def test_build_trigger_cron() -> None:
    trigger = _build_trigger(CronSpec(minute="0", hour="2", day="*", month="*", day_of_week="*"))
    assert isinstance(trigger, CronTrigger)


# ── register / unregister ───────────────────────────────────────────────────


def test_register_adds_job_with_parsed_trigger() -> None:
    async def _run() -> None:
        sched = ApschedulerJobScheduler()
        sched.start(_noop_callback)
        try:
            sched.register(
                {"id": 7, "cidr": "10.0.0.0/24", "profile_id": "p", "schedule": "interval:1h"},
                _noop_callback,
            )
            assert sched._scheduler is not None
            assert sched._scheduler.get_job("scan_7") is not None  # Job unter erwarteter id
        finally:
            sched.stop()

    asyncio.run(_run())


def test_register_parse_error_propagates() -> None:
    # Kaputter Schedule-String -> ScheduleParseError propagiert (kein 24h-Fallback).
    async def _run() -> None:
        sched = ApschedulerJobScheduler()
        sched.start(_noop_callback)
        try:
            with pytest.raises(ScheduleParseError):
                sched.register(
                    {"id": 1, "cidr": "10.0.0.0/24", "profile_id": "p", "schedule": "kaputt"},
                    _noop_callback,
                )
        finally:
            sched.stop()

    asyncio.run(_run())


def test_register_without_start_is_noop() -> None:
    sched = ApschedulerJobScheduler()
    # Kein start() -> register ist No-op (kein Scheduler), kein Fehler, kein Loop noetig.
    sched.register(
        {"id": 1, "cidr": "10.0.0.0/24", "profile_id": "p", "schedule": "interval:1h"},
        _noop_callback,
    )


def test_unregister_idempotent_on_unknown_job() -> None:
    async def _run() -> None:
        sched = ApschedulerJobScheduler()
        sched.start(_noop_callback)
        try:
            sched.unregister(9999)  # nie registriert -> idempotent (Warn-Log)
        finally:
            sched.stop()

    asyncio.run(_run())


def test_unregister_removes_registered_job() -> None:
    async def _run() -> None:
        sched = ApschedulerJobScheduler()
        sched.start(_noop_callback)
        try:
            sched.register(
                {"id": 5, "cidr": "10.0.0.0/24", "profile_id": "p", "schedule": "interval:1h"},
                _noop_callback,
            )
            assert sched._scheduler is not None
            assert sched._scheduler.get_job("scan_5") is not None
            sched.unregister(5)
            assert sched._scheduler.get_job("scan_5") is None
        finally:
            sched.stop()

    asyncio.run(_run())


# ── Lifecycle ───────────────────────────────────────────────────────────────


def test_start_stop_lifecycle() -> None:
    async def _run() -> None:
        sched = ApschedulerJobScheduler()
        assert sched._scheduler is None
        sched.start(_noop_callback)
        assert sched._scheduler is not None
        sched.stop()
        assert sched._scheduler is None

    asyncio.run(_run())


def test_double_start_is_guarded() -> None:
    async def _run() -> None:
        sched = ApschedulerJobScheduler()
        sched.start(_noop_callback)
        first = sched._scheduler
        try:
            sched.start(_noop_callback)  # zweiter start -> No-op
            assert sched._scheduler is first  # dieselbe Instanz, nicht neu gebaut
        finally:
            sched.stop()

    asyncio.run(_run())
