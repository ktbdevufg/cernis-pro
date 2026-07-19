"""Tests fuer ``SqliteScheduleRepository`` (M.6) -- CRUD-Round-trip + Schema.

Getestet: (1) Port-Konformitaet, (2) add->list-Round-trip mit den neun Spalten +
enabled-Default 1, (3) update (enabled/name, None=unveraendert), (4) delete
(idempotent), (5) list-Reihenfolge (ORDER BY id). Gegen eine temp-DB (tmp_path).
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from infrastructure.monitoring.schedule_repository import SqliteScheduleRepository
from ports.monitoring import ScheduleRepository

_NINE_COLUMNS = {
    "id",
    "name",
    "cidr",
    "profile_id",
    "schedule",
    "enabled",
    "last_run",
    "next_run",
    "created_at",
}


class FakeClock:
    """Erfuellt das ``Clock``-Protocol strukturell; liefert einen festen Zeitpunkt.

    Timezone-aware UTC -- wie ``SystemClock``, damit ``.isoformat()`` einen Offset
    (``+00:00``) traegt und der Test deterministisch gegen den Erwartungswert prueft.
    """

    FIXED = datetime(2026, 7, 18, 13, 23, 45, 123456, tzinfo=UTC)

    def now(self) -> datetime:
        return self.FIXED


@pytest.fixture
def repo(tmp_path: Path) -> SqliteScheduleRepository:
    return SqliteScheduleRepository(tmp_path / "cernis.db", FakeClock())


def test_conforms_to_schedule_repository_protocol(repo: SqliteScheduleRepository) -> None:
    _: ScheduleRepository = repo


def test_add_then_list_roundtrip_nine_columns(repo: SqliteScheduleRepository) -> None:
    sid = repo.add("Nightly", "192.168.1.0/24", "standard", "cron:0 2 * * *")
    assert isinstance(sid, int)
    rows = repo.list()
    assert len(rows) == 1
    row = rows[0]
    assert set(row.keys()) == _NINE_COLUMNS
    assert row["id"] == sid
    assert row["name"] == "Nightly"
    assert row["cidr"] == "192.168.1.0/24"
    assert row["profile_id"] == "standard"
    assert row["schedule"] == "cron:0 2 * * *"
    assert row["enabled"] == 1  # DEFAULT 1
    assert row["last_run"] is None
    assert row["next_run"] is None


def test_add_sets_created_at_from_clock_with_tz_offset(repo: SqliteScheduleRepository) -> None:
    """``created_at`` kommt aus der Clock: nicht leer, mit Zonen-Offset, exakter Wert.

    Belegt die A10-Etappe-2: der Zeitstempel wird explizit ueber den Clock-Port gesetzt
    (timezone-aware UTC, ISO-8601 mit +00:00) statt ueber den Schema-Default
    ``datetime('now')`` (UTC ohne Zonen-Kennzeichnung).
    """
    repo.add("Nightly", "192.168.1.0/24", "standard", "cron:0 2 * * *")

    created_at = repo.list()[0]["created_at"]
    assert created_at.endswith("+00:00")  # traegt eine Zeitzonen-Kennzeichnung
    assert created_at == FakeClock.FIXED.isoformat()  # exakt der Clock-Wert


def test_add_stores_schedule_string_unparsed(repo: SqliteScheduleRepository) -> None:
    # add parst den Schedule-String NICHT -- auch ein kaputter landet in der Zeile.
    sid = repo.add("Broken", "10.0.0.0/24", "p", "kaputt-kein-format")
    row = repo.list()[0]
    assert row["id"] == sid
    assert row["schedule"] == "kaputt-kein-format"


def test_update_enabled_and_name(repo: SqliteScheduleRepository) -> None:
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:1h")
    repo.update(sid, enabled=False, name="B")
    row = repo.list()[0]
    assert row["enabled"] == 0
    assert row["name"] == "B"


def test_update_none_args_are_noops(repo: SqliteScheduleRepository) -> None:
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:1h")
    repo.update(sid, enabled=None, name=None)
    row = repo.list()[0]
    assert row["enabled"] == 1
    assert row["name"] == "A"


def test_delete_removes_row(repo: SqliteScheduleRepository) -> None:
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:1h")
    assert len(repo.list()) == 1
    repo.delete(sid)
    assert repo.list() == []


def test_delete_unknown_id_is_idempotent(repo: SqliteScheduleRepository) -> None:
    repo.delete(9999)  # kein Fehler, keine Zeile betroffen
    assert repo.list() == []


def test_list_orders_by_id(repo: SqliteScheduleRepository) -> None:
    s1 = repo.add("A", "10.0.0.0/24", "p", "interval:1h")
    s2 = repo.add("B", "10.0.0.0/24", "p", "interval:2h")
    rows = repo.list()
    assert [r["id"] for r in rows] == sorted([s1, s2])


def test_list_empty_returns_empty(repo: SqliteScheduleRepository) -> None:
    assert repo.list() == []
