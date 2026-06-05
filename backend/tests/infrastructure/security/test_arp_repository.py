"""Tests fuer ``SqliteArpGuardRepository`` (SEC.4) -- round-trip des v2-Adapters.

Reine Struktur-Migration, AS-IS -- KEINE Heilung. (Der frueher hier gefuehrte
Schema-Vertrag gegen das echte ``modules.arp_guard._init_arp_db`` ist mit dem
Loeschen des Altcode-moduls in ADR-0004 P.4 entfallen -- es gibt keine Altcode-
Tabelle mehr, gegen die verglichen werden koennte.)
"""

from pathlib import Path

import pytest

from domain.security import ArpAlert, ArpEntry
from infrastructure.security.arp_repository import SqliteArpGuardRepository
from ports.security import ArpGuardRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteArpGuardRepository:
    return SqliteArpGuardRepository(tmp_path / "cernis.db")


def test_conforms_to_repository_protocol(repo: SqliteArpGuardRepository) -> None:
    _: ArpGuardRepository = repo


# ── round-trip: ArpEntry/ArpAlert rein -> SQLite -> raus ──────


def test_baseline_roundtrip(repo: SqliteArpGuardRepository) -> None:
    repo.save_baseline_entry(ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp"))
    repo.save_baseline_entry(ArpEntry("192.168.1.11", "BB:BB:BB:22:22:22", "BetaInc"))
    loaded = {e.ip: e for e in repo.load_baseline()}
    assert loaded["192.168.1.10"] == ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp")
    assert loaded["192.168.1.11"].vendor == "BetaInc"


def test_save_baseline_preserves_first_seen(repo: SqliteArpGuardRepository) -> None:
    # Altcode-Semantik: first_seen bleibt beim erneuten Speichern erhalten.
    import sqlite3 as _sq

    repo.save_baseline_entry(ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp"))
    conn = _sq.connect(repo._db_path)
    first1 = conn.execute(
        "SELECT first_seen FROM arp_baseline WHERE ip=?", ("192.168.1.10",)
    ).fetchone()[0]
    conn.close()

    repo.save_baseline_entry(ArpEntry("192.168.1.10", "CC:CC:CC:33:33:33", "GammaLtd"))
    conn = _sq.connect(repo._db_path)
    row = conn.execute(
        "SELECT first_seen, last_seen, mac FROM arp_baseline WHERE ip=?", ("192.168.1.10",)
    ).fetchone()
    conn.close()
    assert row[0] == first1  # first_seen erhalten
    assert row[1] >= first1  # last_seen aktualisiert
    assert row[2] == "CC:CC:CC:33:33:33"  # mac aktualisiert (INSERT OR REPLACE)


def test_load_baseline_records_returns_time(repo: SqliteArpGuardRepository) -> None:
    # AUFLAGE A (Zeit-Wiederherstellung): load_baseline_records liefert ArpBaselineRecord
    # MIT first_seen/last_seen (der Lese-Pfad fuers Frontend). load_baseline (zeitfrei)
    # bleibt fuer RunArpScan.
    repo.save_baseline_entry(ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp"))
    records = repo.load_baseline_records()
    assert len(records) == 1
    r = records[0]
    assert (r.ip, r.mac, r.vendor) == ("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp")
    # ZEIT durchgereicht: first_seen/last_seen float > 0 (vom Adapter beim save gesetzt).
    assert isinstance(r.first_seen, float) and r.first_seen > 0
    assert isinstance(r.last_seen, float) and r.last_seen > 0


def test_load_baseline_stays_timefree_for_scan(repo: SqliteArpGuardRepository) -> None:
    # Additiv-Beweis: load_baseline gibt WEITER zeitfreie ArpEntry (RunArpScan-Pfad
    # unveraendert) -- KEIN first_seen/last_seen am ArpEntry.
    repo.save_baseline_entry(ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp"))
    entries = repo.load_baseline()
    assert entries == [ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp")]
    assert not hasattr(entries[0], "first_seen")


def test_alert_roundtrip_returns_record_with_time(repo: SqliteArpGuardRepository) -> None:
    # AUFLAGE A (Zeit-Wiederherstellung): recent_alerts liefert ArpAlertRecord MIT ts +
    # datetime (vorher gab es nur ArpAlert ohne Zeit -> die Wire-Luecke). Beweist, dass
    # die Zeit jetzt durch den Lese-Pfad kommt (nicht 0/leer).
    alert = ArpAlert(
        alert_type="mac_changed",
        ip="192.168.1.10",
        old_mac="AA:AA:AA:11:11:11",
        new_mac="BB:BB:BB:22:22:22",
        old_vendor="AcmeCorp",
        new_vendor="BetaInc",
        severity="high",
        message="IP 192.168.1.10: MAC changed ...",
    )
    repo.save_alert(alert)
    loaded = repo.recent_alerts(50)
    assert len(loaded) == 1
    rec = loaded[0]
    # alle Domaenenfelder treu.
    assert rec.alert_type == "mac_changed"
    assert rec.ip == "192.168.1.10"
    assert rec.old_mac == "AA:AA:AA:11:11:11"
    assert rec.new_mac == "BB:BB:BB:22:22:22"
    assert rec.old_vendor == "AcmeCorp"
    assert rec.new_vendor == "BetaInc"
    assert rec.severity == "high"
    assert rec.message == "IP 192.168.1.10: MAC changed ..."
    # ZEIT durchgereicht (der Kern der Heilung): ts float > 0, datetime ISO-Text.
    assert isinstance(rec.ts, float) and rec.ts > 0
    assert isinstance(rec.datetime, str) and len(rec.datetime) == len("2026-01-01 00:00:00")
    # KEIN id-Feld am Record (bewusste Streichung).
    assert not hasattr(rec, "id")


def test_recent_alerts_orders_ts_desc(repo: SqliteArpGuardRepository) -> None:
    for i in range(3):
        repo.save_alert(ArpAlert("ip_conflict", f"10.0.0.{i}", "", "M", "", "V", "high", f"m{i}"))
    loaded = repo.recent_alerts(50)
    assert [a.ip for a in loaded] == ["10.0.0.2", "10.0.0.1", "10.0.0.0"]  # neueste zuerst


def test_clear_alerts_leaves_baseline(repo: SqliteArpGuardRepository) -> None:
    repo.save_baseline_entry(ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp"))
    repo.save_alert(ArpAlert("ip_conflict", "x", "", "M", "", "V", "high", "m"))
    repo.clear_alerts()
    assert repo.recent_alerts(50) == []
    assert len(repo.load_baseline()) == 1  # baseline unberuehrt (SEC.1-Vertrag 7)


def test_clear_baseline_leaves_alerts(repo: SqliteArpGuardRepository) -> None:
    repo.save_baseline_entry(ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp"))
    repo.save_alert(ArpAlert("ip_conflict", "x", "", "M", "", "V", "high", "m"))
    repo.clear_baseline()
    assert repo.load_baseline() == []
    assert len(repo.recent_alerts(50)) == 1  # alerts unberuehrt
