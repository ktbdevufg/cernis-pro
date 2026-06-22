"""Tests fuer ``SqliteScheduledJobRepository`` (Block 3a, Etappe 2) -- gegen tmp_path-DB.

Belegt den Round-trip von Anlegen + Lesen (alle Felder 1:1, inkl. ``weekdays`` als
``frozenset`` und ``params`` als Tupel-Sequenz), die Lese-Views (active/all), den
Zustands-Lebenszyklus (active -> paused/finished, Wirkung auf ``list_active``) und das
Loeschen (delete / clear_all). Muster der uebrigen infrastructure-Repo-Tests
(``tmp_path``-DB, wie ``test_cve_findings_db.py``/``test_dns_watch_acknowledgements_db.py``).
"""

from pathlib import Path

import pytest

from domain.scheduler.models import DailyWindow, JobState, ScheduledJob
from infrastructure.scheduler_jobs_db import SqliteScheduledJobRepository

JOB_TYPE = "monitoring_window"


@pytest.fixture
def repo(tmp_path: Path) -> SqliteScheduledJobRepository:
    return SqliteScheduledJobRepository(tmp_path / "cernis.db")


def _window(
    start_minute: int = 540,
    end_minute: int = 1020,
    weekdays: frozenset[int] = frozenset(),
    from_epoch: float = 100.0,
    until_epoch: float = 0.0,
) -> DailyWindow:
    return DailyWindow(
        start_minute=start_minute,
        end_minute=end_minute,
        weekdays=weekdays,
        from_epoch=from_epoch,
        until_epoch=until_epoch,
    )


# ── Anlegen + ids ─────────────────────────────────────────────────────────────


def test_add_gibt_aufsteigende_ids(repo: SqliteScheduledJobRepository) -> None:
    first = repo.add(JOB_TYPE, (), _window())
    second = repo.add(JOB_TYPE, (), _window())
    assert second > first


# ── Round-trip aller Felder ───────────────────────────────────────────────────


def test_get_liefert_job_1zu1_zurueck(repo: SqliteScheduledJobRepository) -> None:
    window = _window(
        start_minute=540,
        end_minute=1020,
        weekdays=frozenset({0, 2, 4}),
        from_epoch=123.5,
        until_epoch=456.5,
    )
    params = (("interface", "eth0"), ("mode", "deep"))
    job_id = repo.add(JOB_TYPE, params, window)

    got = repo.get(job_id)
    assert got == ScheduledJob(
        id=job_id,
        job_type=JOB_TYPE,
        params=params,
        window=window,
        state=JobState.ACTIVE,
    )


def test_get_unbekannte_id_ist_none(repo: SqliteScheduledJobRepository) -> None:
    assert repo.get(999) is None


# ── weekdays-Round-trip ───────────────────────────────────────────────────────


def test_weekdays_leer_round_trip_ist_frozenset(repo: SqliteScheduledJobRepository) -> None:
    job_id = repo.add(JOB_TYPE, (), _window(weekdays=frozenset()))
    got = repo.get(job_id)
    assert got is not None
    assert got.window.weekdays == frozenset()


def test_weekdays_alle_arbeitstage_round_trip(repo: SqliteScheduledJobRepository) -> None:
    weekdays = frozenset({0, 1, 2, 3, 4})
    job_id = repo.add(JOB_TYPE, (), _window(weekdays=weekdays))
    got = repo.get(job_id)
    assert got is not None
    assert got.window.weekdays == weekdays


# ── params-Round-trip ─────────────────────────────────────────────────────────


def test_params_leer_round_trip_ist_leeres_tupel(repo: SqliteScheduledJobRepository) -> None:
    job_id = repo.add(JOB_TYPE, (), _window())
    got = repo.get(job_id)
    assert got is not None
    assert got.params == ()


def test_params_mehrere_paare_round_trip(repo: SqliteScheduledJobRepository) -> None:
    params = (("a", "1"), ("b", "2"), ("c", "3"))
    job_id = repo.add(JOB_TYPE, params, _window())
    got = repo.get(job_id)
    assert got is not None
    assert got.params == params


# ── Lese-Views + Zustands-Lebenszyklus ────────────────────────────────────────


def test_list_active_liefert_nur_active(repo: SqliteScheduledJobRepository) -> None:
    active_id = repo.add(JOB_TYPE, (), _window())
    paused_id = repo.add(JOB_TYPE, (), _window())
    repo.update_state(paused_id, JobState.PAUSED)

    active_ids = {job.id for job in repo.list_active()}
    assert active_ids == {active_id}


def test_pause_entfernt_aus_active_bleibt_in_all(repo: SqliteScheduledJobRepository) -> None:
    job_id = repo.add(JOB_TYPE, (), _window())
    repo.update_state(job_id, JobState.PAUSED)

    assert job_id not in {job.id for job in repo.list_active()}
    all_jobs = repo.list_all()
    assert job_id in {job.id for job in all_jobs}
    paused = next(job for job in all_jobs if job.id == job_id)
    assert paused.state == JobState.PAUSED


def test_finished_entfernt_aus_active_bleibt_in_all(repo: SqliteScheduledJobRepository) -> None:
    job_id = repo.add(JOB_TYPE, (), _window())
    repo.update_state(job_id, JobState.FINISHED)

    assert job_id not in {job.id for job in repo.list_active()}
    finished = repo.get(job_id)
    assert finished is not None
    assert finished.state == JobState.FINISHED


def test_list_all_ueber_alle_zustaende(repo: SqliteScheduledJobRepository) -> None:
    a = repo.add(JOB_TYPE, (), _window())
    b = repo.add(JOB_TYPE, (), _window())
    c = repo.add(JOB_TYPE, (), _window())
    repo.update_state(b, JobState.PAUSED)
    repo.update_state(c, JobState.FINISHED)
    assert {job.id for job in repo.list_all()} == {a, b, c}


# ── Loeschen ──────────────────────────────────────────────────────────────────


def test_delete_entfernt_job(repo: SqliteScheduledJobRepository) -> None:
    job_id = repo.add(JOB_TYPE, (), _window())
    repo.delete(job_id)
    assert repo.get(job_id) is None


def test_delete_unbekannte_id_wirft_nicht(repo: SqliteScheduledJobRepository) -> None:
    repo.delete(999)  # No-Op, kein Fehler
    assert repo.list_all() == []


def test_clear_all_leert(repo: SqliteScheduledJobRepository) -> None:
    repo.add(JOB_TYPE, (), _window())
    repo.add(JOB_TYPE, (), _window())
    repo.clear_all()
    assert repo.list_all() == []


# ── until_epoch-Leerzustand + gesetzter Wert ──────────────────────────────────


def test_until_epoch_null_round_trip(repo: SqliteScheduledJobRepository) -> None:
    job_id = repo.add(JOB_TYPE, (), _window(until_epoch=0.0))
    got = repo.get(job_id)
    assert got is not None
    assert got.window.until_epoch == 0.0


def test_until_epoch_gesetzt_round_trip(repo: SqliteScheduledJobRepository) -> None:
    job_id = repo.add(JOB_TYPE, (), _window(until_epoch=1750000000.0))
    got = repo.get(job_id)
    assert got is not None
    assert got.window.until_epoch == 1750000000.0
