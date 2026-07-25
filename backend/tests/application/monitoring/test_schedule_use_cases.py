"""Tests fuer die Schedule-Use-Cases (M.6) -- gegen Fake-Ports.

Reine application-Schicht: KEINE echte DB/APScheduler. Aufzeichnende Fakes fuer
``ScheduleRepository`` + ``ScanJobScheduler``.

Schwerpunkte:
* ManageSchedules.add: orchestriert repo.add + jobengine.register. BEST-EFFORT bei
  kaputtem Schedule: DB-Zeile entsteht, Job NICHT, ScheduleParseError GEZIELT
  gefangen (kein Crash).
* ManageSchedules.delete: orchestriert repo.delete + jobengine.unregister.
* GetSchedules: Pass-Through aufs Repo.
* UpdateSchedule (E1b): schreibt die Zeile UND zieht den Job nach -- enabled=False
  entfernt ihn (unregister), enabled=True registriert ihn aus der aktualisierten
  Zeile neu, enabled=None (nur Name) laesst ihn unangetastet; ScheduleParseError
  beim Re-Registrieren wird gezielt gefangen.
* Ausfuehrungszeiten (Finding 3): add zieht next_run aus der Engine nach (last_run
  leer), UpdateSchedule leert next_run bei enabled=False und setzt es bei
  enabled=True wieder (last_run bleibt jeweils erhalten), enabled=None und delete
  ruehren die Zeiten nicht an, RecordScheduleRun setzt last_run aus der Clock +
  zieht next_run nach. BEST-EFFORT: ein Persistenz-Fehler beim Zeit-Schreiben
  wirft NIE (er darf keinen Scan-Lauf verhindern).
"""

import sqlite3
from datetime import UTC, datetime
from typing import Any

import pytest

from application.monitoring import (
    GetSchedules,
    ManageSchedules,
    RecordScheduleRun,
    UpdateSchedule,
)
from domain.monitoring import ScheduleParseError
from ports.monitoring import ScanTriggerCallback


async def _callback(cidr: str, profile_id: str, schedule_id: int) -> None:
    return None


class _FakeRepo:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self._next_id = 1
        # Aufzeichnung der Zeit-Schreibaufrufe (Finding 3): (id, last_run, next_run).
        self.run_time_calls: list[tuple[int, str | None, str | None]] = []

    def list(self) -> list[dict[str, Any]]:
        return list(self.rows)

    def add(self, name: str, cidr: str, profile_id: str, schedule: str) -> int:
        sid = self._next_id
        self._next_id += 1
        self.rows.append(
            {
                "id": sid,
                "name": name,
                "cidr": cidr,
                "profile_id": profile_id,
                "schedule": schedule,
                "enabled": 1,
                "last_run": None,
                "next_run": None,
                "created_at": "2026-06-03 00:00:00",
            }
        )
        return sid

    def update(self, schedule_id: int, enabled: bool | None, name: str | None) -> None:
        for row in self.rows:
            if row["id"] == schedule_id:
                if enabled is not None:
                    row["enabled"] = int(enabled)
                if name is not None:
                    row["name"] = name

    def set_run_times(
        self,
        schedule_id: int,
        last_run: str | None,
        next_run: str | None,
    ) -> None:
        # Wie der SQLite-Adapter: BEIDE Spalten werden gesetzt (None = leer),
        # kein "unveraendert lassen". Zusaetzlich aufgezeichnet, damit die Tests
        # die Aufrufe selbst pruefen koennen.
        self.run_time_calls.append((schedule_id, last_run, next_run))
        for row in self.rows:
            if row["id"] == schedule_id:
                row["last_run"] = last_run
                row["next_run"] = next_run

    def delete(self, schedule_id: int) -> None:
        self.rows = [r for r in self.rows if r["id"] != schedule_id]

    def clear_all(self) -> None:
        """Leert alle Schedule-Zeilen (No-op-Vertrag fuer den Fake)."""
        self.rows.clear()


class _FakeJobScheduler:
    def __init__(
        self,
        *,
        raise_parse_error: bool = False,
        raise_other: Exception | None = None,
        next_run: str | None = "2026-06-03T02:00:00+00:00",
    ) -> None:
        self.registered: list[int] = []
        self.unregistered: list[int] = []
        self._raise = raise_parse_error
        self._raise_other = raise_other
        # Die Feuerzeit, die der Fake fuer registrierte Jobs meldet (Finding 3).
        self._next_run = next_run

    def start(self, callback: ScanTriggerCallback) -> None: ...

    def stop(self) -> None: ...

    def register(self, schedule: dict[str, Any], callback: ScanTriggerCallback) -> None:
        if self._raise_other is not None:
            # Eine ANDERE Exception als ScheduleParseError (z. B. ein CronTrigger-
            # Feld-Syntaxfehler aus add_job) -- darf NICHT als "kaputtes Schedule"
            # durchgehen.
            raise self._raise_other
        if self._raise:
            raise ScheduleParseError(str(schedule.get("schedule", "")))
        self.registered.append(int(schedule["id"]))

    def unregister(self, schedule_id: int) -> None:
        self.unregistered.append(schedule_id)

    def next_run_time(self, schedule_id: int) -> str | None:
        # Wie der echte Adapter: nur ein REGISTRIERTER Job hat eine Feuerzeit --
        # sonst ehrlich None (kein erfundener Wert).
        if schedule_id not in self.registered:
            return None
        return self._next_run


# ── ManageSchedules.add ─────────────────────────────────────────────────────


def test_add_orchestrates_repo_and_job() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler()
    uc = ManageSchedules(repo, jobs, _callback)

    sid = uc.add("Nightly", "192.168.1.0/24", "standard", "cron:0 2 * * *")

    # DB-Zeile angelegt UND Job registriert.
    assert len(repo.list()) == 1
    assert repo.list()[0]["id"] == sid
    assert jobs.registered == [sid]


def test_add_best_effort_keeps_row_skips_job_on_parse_error() -> None:
    # Kaputter Schedule-String: register wirft ScheduleParseError -> gezielt gefangen.
    repo = _FakeRepo()
    jobs = _FakeJobScheduler(raise_parse_error=True)
    uc = ManageSchedules(repo, jobs, _callback)

    sid = uc.add("Broken", "10.0.0.0/24", "p", "kaputt")

    # Zeile DA (sichtbar in der Liste), aber KEIN Job (Warn-geloggt im Use-Case).
    assert len(repo.list()) == 1
    assert repo.list()[0]["id"] == sid
    assert repo.list()[0]["schedule"] == "kaputt"
    assert jobs.registered == []  # kein Job registriert
    # add kehrt regulaer zurueck (kein Crash) -- die id ist gueltig.
    assert sid == 1


def test_add_propagates_non_parse_error() -> None:
    # GEGENSTUECK zum best-effort-Test: eine ANDERE Exception als ScheduleParseError
    # (z. B. ein CronTrigger-Feld-Syntaxfehler aus add_job, hier ValueError) wird
    # NICHT als "kaputtes Schedule" stillgelegt -- der gezielte ``except
    # ScheduleParseError`` faengt sie nicht, sie propagiert sichtbar. Das ist der
    # eigentliche Beweis der eigenstaendigen Exception (M.6 Schritt 1): nur der
    # ERWARTETE Parse-Fehler ist best-effort, jeder andere Fehler bleibt sichtbar.
    repo = _FakeRepo()
    jobs = _FakeJobScheduler(raise_other=ValueError("ungueltiges Cron-Feld"))
    uc = ManageSchedules(repo, jobs, _callback)

    with pytest.raises(ValueError):
        uc.add("X", "10.0.0.0/24", "p", "cron:99 99 * * *")

    # Die DB-Zeile wurde dennoch angelegt (add ruft repo.add VOR register) -- aber
    # der unerwartete Fehler propagiert, statt still geschluckt zu werden.
    assert len(repo.list()) == 1


def test_add_also_propagates_runtime_error() -> None:
    # Auch ein voellig unerwarteter Fehler (RuntimeError) propagiert -- der Fang ist
    # NUR auf ScheduleParseError, nicht auf Exception/ValueError verbreitert.
    repo = _FakeRepo()
    jobs = _FakeJobScheduler(raise_other=RuntimeError("scheduler kaputt"))
    uc = ManageSchedules(repo, jobs, _callback)

    with pytest.raises(RuntimeError):
        uc.add("X", "10.0.0.0/24", "p", "interval:1h")


# ── ManageSchedules.delete ──────────────────────────────────────────────────


def test_delete_orchestrates_repo_and_job() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler()
    uc = ManageSchedules(repo, jobs, _callback)
    sid = uc.add("A", "10.0.0.0/24", "p", "interval:1h")

    uc.delete(sid)

    assert repo.list() == []  # Zeile weg
    assert jobs.unregistered == [sid]  # Job entfernt


# ── Pass-Through-Use-Cases ──────────────────────────────────────────────────


def test_get_schedules_passes_through() -> None:
    repo = _FakeRepo()
    repo.add("A", "10.0.0.0/24", "p", "interval:1h")
    uc = GetSchedules(repo)
    rows = uc()
    assert len(rows) == 1
    assert rows[0]["name"] == "A"


def test_update_schedule_schreibt_zeile() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler()
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:1h")
    uc = UpdateSchedule(repo, jobs, _callback)
    uc(sid, enabled=False, name="B")
    row = repo.list()[0]
    assert row["enabled"] == 0
    assert row["name"] == "B"


# ── UpdateSchedule: Job-Nachzug (E1b) ───────────────────────────────────────


def test_update_enabled_false_entfernt_den_job() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler()
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:1h")
    uc = UpdateSchedule(repo, jobs, _callback)

    uc(sid, enabled=False, name=None)

    assert jobs.unregistered == [sid]  # Job mit der richtigen id entfernt
    assert jobs.registered == []


def test_update_enabled_true_registriert_aus_aktualisierter_zeile() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler()
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:1h")
    uc = UpdateSchedule(repo, jobs, _callback)

    uc(sid, enabled=True, name=None)

    assert jobs.registered == [sid]  # Job aus der Zeile (id/cidr/profile/schedule)
    assert jobs.unregistered == []


def test_update_nur_name_laesst_job_unangetastet() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler()
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:1h")
    uc = UpdateSchedule(repo, jobs, _callback)

    uc(sid, enabled=None, name="Neuer Name")

    assert jobs.registered == []  # weder register ...
    assert jobs.unregistered == []  # ... noch unregister
    assert repo.list()[0]["name"] == "Neuer Name"


def test_update_enabled_true_parse_error_gezielt_gefangen() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler(raise_parse_error=True)
    sid = repo.add("A", "10.0.0.0/24", "p", "kaputt")
    uc = UpdateSchedule(repo, jobs, _callback)

    # Kein Wurf: ScheduleParseError wird gezielt gefangen (Warn-geloggt), die
    # Zeile bleibt aktualisiert.
    uc(sid, enabled=True, name=None)

    assert jobs.registered == []
    assert repo.list()[0]["enabled"] == 1


def test_update_geloeschte_zeile_ist_warn_noop() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler()
    uc = UpdateSchedule(repo, jobs, _callback)

    # id existiert nicht (geloescht) -> Warn-Log statt Wurf, kein register.
    uc(999, enabled=True, name=None)

    assert jobs.registered == []


# ── Ausfuehrungszeiten (Finding 3) ──────────────────────────────────────────


class _FakeClock:
    """Erfuellt ``Clock`` strukturell -- fester, timezone-aware UTC-Zeitpunkt."""

    FIXED = datetime(2026, 7, 18, 13, 23, 45, tzinfo=UTC)

    def now(self) -> datetime:
        return self.FIXED


class _KaputtesRepo(_FakeRepo):
    """Repo, dessen ``set_run_times`` wirft -- fuer den best-effort-Nachweis."""

    def set_run_times(
        self,
        schedule_id: int,
        last_run: str | None,
        next_run: str | None,
    ) -> None:
        raise sqlite3.OperationalError("database is locked")


def test_add_zieht_next_run_aus_der_engine_nach() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler()
    uc = ManageSchedules(repo, jobs, _callback)

    sid = uc.add("A", "10.0.0.0/24", "p", "interval:2m")

    row = repo.list()[0]
    assert row["next_run"] == "2026-06-03T02:00:00+00:00"  # aus der Job-Engine
    assert row["last_run"] is None  # frisches Schedule ist nie gelaufen
    assert repo.run_time_calls == [(sid, None, "2026-06-03T02:00:00+00:00")]


def test_add_ohne_job_laesst_next_run_leer() -> None:
    # Kaputter Schedule-String -> kein Job -> keine Feuerzeit (kein erfundener Wert).
    repo = _FakeRepo()
    jobs = _FakeJobScheduler(raise_parse_error=True)
    uc = ManageSchedules(repo, jobs, _callback)

    uc.add("Broken", "10.0.0.0/24", "p", "kaputt")

    assert repo.list()[0]["next_run"] is None
    assert repo.run_time_calls == []  # gar kein Schreibversuch


def test_update_enabled_false_leert_next_run_und_haelt_last_run() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler()
    manage = ManageSchedules(repo, jobs, _callback)
    sid = manage.add("A", "10.0.0.0/24", "p", "interval:2m")
    # Ein Lauf hat stattgefunden.
    RecordScheduleRun(repo, jobs, _FakeClock())(sid)
    assert repo.list()[0]["last_run"] == _FakeClock.FIXED.isoformat()

    UpdateSchedule(repo, jobs, _callback)(sid, enabled=False, name=None)

    row = repo.list()[0]
    assert row["next_run"] is None  # kein Job mehr -> keine naechste Feuerzeit
    assert row["last_run"] == _FakeClock.FIXED.isoformat()  # bleibt erhalten


def test_update_enabled_true_setzt_next_run_wieder() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler()
    manage = ManageSchedules(repo, jobs, _callback)
    sid = manage.add("A", "10.0.0.0/24", "p", "interval:2m")
    RecordScheduleRun(repo, jobs, _FakeClock())(sid)
    uc = UpdateSchedule(repo, jobs, _callback)
    uc(sid, enabled=False, name=None)
    assert repo.list()[0]["next_run"] is None

    uc(sid, enabled=True, name=None)

    row = repo.list()[0]
    assert row["next_run"] == "2026-06-03T02:00:00+00:00"  # wieder gefuellt
    assert row["last_run"] == _FakeClock.FIXED.isoformat()  # unveraendert


def test_update_nur_name_laesst_zeiten_unberuehrt() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler()
    sid = ManageSchedules(repo, jobs, _callback).add("A", "10.0.0.0/24", "p", "interval:2m")
    repo.run_time_calls.clear()

    UpdateSchedule(repo, jobs, _callback)(sid, enabled=None, name="Neu")

    assert repo.run_time_calls == []  # kein Schreibversuch bei enabled=None


def test_update_enabled_true_parse_error_laesst_next_run_leer() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler(raise_parse_error=True)
    sid = repo.add("A", "10.0.0.0/24", "p", "kaputt")

    UpdateSchedule(repo, jobs, _callback)(sid, enabled=True, name=None)

    assert repo.list()[0]["next_run"] is None  # kein Job -> ehrlich leer


def test_delete_schreibt_keine_zeiten() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler()
    uc = ManageSchedules(repo, jobs, _callback)
    sid = uc.add("A", "10.0.0.0/24", "p", "interval:2m")
    repo.run_time_calls.clear()

    uc.delete(sid)

    assert repo.run_time_calls == []  # delete beruehrt die Zeiten nicht


def test_record_schedule_run_setzt_last_run_und_zieht_next_run_nach() -> None:
    repo = _FakeRepo()
    jobs = _FakeJobScheduler()
    sid = ManageSchedules(repo, jobs, _callback).add("A", "10.0.0.0/24", "p", "interval:2m")
    repo.run_time_calls.clear()

    RecordScheduleRun(repo, jobs, _FakeClock())(sid)

    row = repo.list()[0]
    # last_run aus der injizierten Clock, im created_at-Format (ISO 8601, UTC, +00:00).
    assert row["last_run"] == "2026-07-18T13:23:45+00:00"
    assert row["last_run"].endswith("+00:00")
    # next_run frisch aus der Engine nachgezogen.
    assert row["next_run"] == "2026-06-03T02:00:00+00:00"
    assert repo.run_time_calls == [(sid, "2026-07-18T13:23:45+00:00", "2026-06-03T02:00:00+00:00")]


def test_record_schedule_run_ohne_job_setzt_last_run_und_leeres_next_run() -> None:
    # Zeile ohne registrierten Job: der Lauf HAT stattgefunden (last_run gefuellt),
    # aber es gibt keine naechste Feuerzeit -> leer statt erfunden.
    repo = _FakeRepo()
    jobs = _FakeJobScheduler()
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:2m")

    RecordScheduleRun(repo, jobs, _FakeClock())(sid)

    row = repo.list()[0]
    assert row["last_run"] == "2026-07-18T13:23:45+00:00"
    assert row["next_run"] is None


def test_record_schedule_run_wirft_nie_bei_persistenz_fehler() -> None:
    # Punkt E: ein Fehler beim Schreiben der Zeiten darf den Scan-Lauf NIEMALS
    # verhindern -- Warn-Log statt Wurf.
    repo = _KaputtesRepo()
    jobs = _FakeJobScheduler()
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:2m")

    RecordScheduleRun(repo, jobs, _FakeClock())(sid)  # kein Wurf

    # Die Zeile ist unveraendert (nichts erfunden, nichts halb geschrieben).
    assert repo.list()[0]["last_run"] is None


def test_add_wirft_nie_bei_persistenz_fehler_der_zeiten() -> None:
    # Gleiche best-effort-Linie im Anlege-Pfad: die Zeile entsteht, der Job wird
    # registriert, nur die Zeit-Buchung scheitert sichtbar (Log) statt zu reissen.
    repo = _KaputtesRepo()
    jobs = _FakeJobScheduler()

    sid = ManageSchedules(repo, jobs, _callback).add("A", "10.0.0.0/24", "p", "interval:2m")

    assert sid == 1
    assert jobs.registered == [sid]
