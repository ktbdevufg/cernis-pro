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
"""

from typing import Any

import pytest

from application.monitoring import GetSchedules, ManageSchedules, UpdateSchedule
from domain.monitoring import ScheduleParseError
from ports.monitoring import ScanTriggerCallback


async def _callback(cidr: str, profile_id: str, schedule_id: int) -> None:
    return None


class _FakeRepo:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self._next_id = 1

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
    ) -> None:
        self.registered: list[int] = []
        self.unregistered: list[int] = []
        self._raise = raise_parse_error
        self._raise_other = raise_other

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
