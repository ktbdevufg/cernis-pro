"""Tests fuer ``SqliteScheduleRepository`` (M.6) -- CRUD-Round-trip + Schema.

Getestet: (1) Port-Konformitaet, (2) add->list-Round-trip mit den elf Spalten +
enabled-Default 1, (3) update (enabled/name, None=unveraendert), (4) delete
(idempotent), (5) list-Reihenfolge (ORDER BY id), (6) set_run_times (Finding 3):
beide Zeiten schreiben, ``None`` = wirklich leer (nicht "unveraendert"), uebrige
Spalten unberuehrt, unbekannte id idempotent, (7) set_run_result (S88-P4): Ausgang
+ Wortlaut schreiben, Erfolg raeumt den alten Wortlaut weg, (8) der additive
Schema-Guard (S88-P4): die zwei neuen Spalten entstehen auf einer BESTEHENDEN
Datenbank ohne sie -- gegen eine echte SQLite-Datei im Zustand vor der Aenderung.
Gegen eine temp-DB (tmp_path).
"""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from infrastructure.monitoring.schedule_repository import SqliteScheduleRepository
from ports.monitoring import ScheduleRepository

# Die neun Altcode-Spalten plus die zwei additiven Ergebnis-Spalten (S88-P4).
_ALLE_SPALTEN = {
    "id",
    "name",
    "cidr",
    "profile_id",
    "schedule",
    "enabled",
    "last_run",
    "next_run",
    "created_at",
    "last_result",
    "last_error",
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


def test_add_then_list_roundtrip_alle_spalten(repo: SqliteScheduleRepository) -> None:
    sid = repo.add("Nightly", "192.168.1.0/24", "standard", "cron:0 2 * * *")
    assert isinstance(sid, int)
    rows = repo.list()
    assert len(rows) == 1
    row = rows[0]
    assert set(row.keys()) == _ALLE_SPALTEN
    assert row["id"] == sid
    assert row["name"] == "Nightly"
    assert row["cidr"] == "192.168.1.0/24"
    assert row["profile_id"] == "standard"
    assert row["schedule"] == "cron:0 2 * * *"
    assert row["enabled"] == 1  # DEFAULT 1
    assert row["last_run"] is None
    assert row["next_run"] is None
    # S88-P4: ein frisch angelegtes Schedule ist noch nie gelaufen -- es hat keinen
    # Ausgang, und das steht ehrlich als NULL da (kein erfundenes 'ok').
    assert row["last_result"] is None
    assert row["last_error"] is None


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


def test_set_run_times_schreibt_beide_zeiten(repo: SqliteScheduleRepository) -> None:
    """Finding 3: der erste und einzige Schreibpfad der beiden toten Spalten."""
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:2m")
    assert repo.list()[0]["last_run"] is None  # Ausgangszustand: leer
    assert repo.list()[0]["next_run"] is None

    repo.set_run_times(sid, "2026-07-18T13:23:45+00:00", "2026-07-18T13:25:45+00:00")

    row = repo.list()[0]
    assert row["last_run"] == "2026-07-18T13:23:45+00:00"
    assert row["next_run"] == "2026-07-18T13:25:45+00:00"


def test_set_run_times_none_setzt_leer_statt_unveraendert(
    repo: SqliteScheduleRepository,
) -> None:
    """``None`` heisst EXPLIZIT leer -- nicht "unveraendert lassen" wie bei ``update``."""
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:2m")
    repo.set_run_times(sid, "2026-07-18T13:23:45+00:00", "2026-07-18T13:25:45+00:00")

    # next_run auf leer (Fall "Schedule deaktiviert"), last_run bleibt bestehen.
    repo.set_run_times(sid, "2026-07-18T13:23:45+00:00", None)

    row = repo.list()[0]
    assert row["last_run"] == "2026-07-18T13:23:45+00:00"
    assert row["next_run"] is None  # wirklich NULL, kein Altwert


def test_set_run_times_laesst_uebrige_spalten_unberuehrt(
    repo: SqliteScheduleRepository,
) -> None:
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:2m")
    vorher = repo.list()[0]

    repo.set_run_times(sid, "2026-07-18T13:23:45+00:00", "2026-07-18T13:25:45+00:00")

    nachher = repo.list()[0]
    for spalte in ("id", "name", "cidr", "profile_id", "schedule", "enabled", "created_at"):
        assert nachher[spalte] == vorher[spalte]


def test_set_run_times_unknown_id_is_idempotent(repo: SqliteScheduleRepository) -> None:
    # UPDATE auf eine nicht-existente id trifft 0 Zeilen -- kein Fehler (Muster delete).
    repo.set_run_times(9999, "2026-07-18T13:23:45+00:00", None)
    assert repo.list() == []


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


# ── S88-P4: der Ausgang des letzten Laufs ────────────────────────────────────
# Vor S88-P4 trug die Tabelle KEIN state, last_error oder last_result, und ``last_run``
# wird VOR dem Scan und AUSSERHALB dessen try gebucht -- ein gescheiterter Lauf war von
# einem geglueckten nicht zu unterscheiden. Die beiden additiven Spalten schliessen
# genau diese Luecke.


def test_set_run_result_haelt_fehlschlag_mit_wortlaut_fest(
    repo: SqliteScheduleRepository,
) -> None:
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:2m")

    repo.set_run_result(sid, "failed", "nmap nicht gefunden")

    row = repo.list()[0]
    assert row["last_result"] == "failed"
    assert row["last_error"] == "nmap nicht gefunden"


def test_geglueckter_und_gescheiterter_lauf_sind_unterscheidbar(
    repo: SqliteScheduleRepository,
) -> None:
    """4.5: beide Ausgaenge stehen in der Tabelle und sind auseinanderzuhalten.

    Das ist der Kern des Befunds: ``last_run`` allein sagt nur, DASS ausgeloest wurde.
    """
    geglueckt = repo.add("A", "10.0.0.0/24", "p", "interval:2m")
    gescheitert = repo.add("B", "10.0.0.0/24", "p", "interval:2m")

    repo.set_run_result(geglueckt, "ok", None)
    repo.set_run_result(gescheitert, "failed", "Netz nicht erreichbar")

    zeilen = {r["id"]: r for r in repo.list()}
    assert zeilen[geglueckt]["last_result"] == "ok"
    assert zeilen[geglueckt]["last_error"] is None
    assert zeilen[gescheitert]["last_result"] == "failed"
    assert zeilen[gescheitert]["last_error"] == "Netz nicht erreichbar"


def test_erfolg_raeumt_den_wortlaut_des_vorigen_fehlschlags_weg(
    repo: SqliteScheduleRepository,
) -> None:
    """Ein alter Fehlertext neben einem frischen Erfolg waere schlimmer als gar keiner."""
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:2m")
    repo.set_run_result(sid, "failed", "Netz nicht erreichbar")

    repo.set_run_result(sid, "ok", None)

    row = repo.list()[0]
    assert row["last_result"] == "ok"
    assert row["last_error"] is None


def test_set_run_result_laesst_last_run_und_uebrige_spalten_unberuehrt(
    repo: SqliteScheduleRepository,
) -> None:
    """3.2: der Ausgang kommt NEBEN ``last_run``, nicht an seine Stelle."""
    sid = repo.add("A", "10.0.0.0/24", "p", "interval:2m")
    repo.set_run_times(sid, "2026-07-18T13:23:45+00:00", "2026-07-18T13:25:45+00:00")
    vorher = repo.list()[0]

    repo.set_run_result(sid, "failed", "kaputt")

    nachher = repo.list()[0]
    for spalte in ("id", "name", "cidr", "profile_id", "schedule", "enabled", "created_at"):
        assert nachher[spalte] == vorher[spalte]
    assert nachher["last_run"] == "2026-07-18T13:23:45+00:00"
    assert nachher["next_run"] == "2026-07-18T13:25:45+00:00"


def test_set_run_result_unknown_id_is_idempotent(repo: SqliteScheduleRepository) -> None:
    repo.set_run_result(9999, "ok", None)
    assert repo.list() == []


def test_neue_spalten_entstehen_auf_einer_bestehenden_datenbank(tmp_path: Path) -> None:
    """4.6: gegen eine ECHTE SQLite-Datei im Zustand VOR der Aenderung.

    Die Alt-Tabelle wird hier mit den NEUN Altcode-Spalten von Hand angelegt (genau so,
    wie ``_init_schedule_db`` sie hinterliess) und mit einer Zeile befuellt. Erst danach
    baut das Repository darauf auf: ein ``CREATE TABLE IF NOT EXISTS`` ist auf eine
    bestehende Tabelle ein No-Op -- ohne den additiven ALTER-Guard entstuenden die
    beiden Spalten hier NIE. Die Bestandszeile behaelt ihre Werte und bekommt in den
    neuen Spalten ehrlich NULL (kein erfundenes 'ok').
    """
    db_pfad = tmp_path / "bestand.db"
    conn = sqlite3.connect(db_pfad)
    try:
        conn.execute(
            """
            CREATE TABLE scan_schedules (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT,
                cidr        TEXT,
                profile_id  TEXT,
                schedule    TEXT,
                enabled     INTEGER DEFAULT 1,
                last_run    TEXT,
                next_run    TEXT,
                created_at  TEXT DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            "INSERT INTO scan_schedules (name, cidr, profile_id, schedule, last_run) "
            "VALUES ('Alt', '10.0.0.0/24', 'p', 'interval:1h', '2026-01-01T00:00:00+00:00')"
        )
        conn.commit()
        spalten_vorher = {r[1] for r in conn.execute("PRAGMA table_info(scan_schedules)")}
    finally:
        conn.close()
    assert "last_result" not in spalten_vorher  # Ausgangszustand: die Spalten fehlen
    assert "last_error" not in spalten_vorher

    repo = SqliteScheduleRepository(db_pfad, FakeClock())

    row = repo.list()[0]
    assert set(row.keys()) == _ALLE_SPALTEN
    assert row["name"] == "Alt"  # Bestandsdaten unberuehrt
    assert row["last_run"] == "2026-01-01T00:00:00+00:00"
    assert row["last_result"] is None  # kein erfundener Ausgang fuer einen Alt-Lauf
    assert row["last_error"] is None

    # Und die nachgeruesteten Spalten sind auch beschreibbar (nicht nur vorhanden).
    repo.set_run_result(int(row["id"]), "failed", "nach der Nachruestung")
    assert repo.list()[0]["last_result"] == "failed"


def test_zweiter_bau_auf_derselben_datei_ist_idempotent(tmp_path: Path) -> None:
    """Der ALTER-Guard laeuft bei JEDEM Start -- ein zweiter Bau darf nicht scheitern."""
    db_pfad = tmp_path / "zweimal.db"
    erstes = SqliteScheduleRepository(db_pfad, FakeClock())
    sid = erstes.add("A", "10.0.0.0/24", "p", "interval:1h")
    erstes.set_run_result(sid, "ok", None)

    zweites = SqliteScheduleRepository(db_pfad, FakeClock())

    assert zweites.list()[0]["last_result"] == "ok"
