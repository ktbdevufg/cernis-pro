"""Tests fuer ``SqliteAcknowledgementRepository`` (ADR 0031) -- gegen tmp_path-DB.

Belegt den ``record`` (ack) -> ``acknowledged_ports``-Round-trip, das Zuruecknehmen per
unack (juengster Eintrag gewinnt), die Append-only-Natur (mehrfaches ack/unack), die
PORT-GENAUE Granularitaet pro (mac, port) und die Isolation verschiedener MACs/Ports.
Muster der uebrigen infrastructure-Repo-Tests (``tmp_path``-DB, wie
``test_analysis_host_history_db.py``).
"""

from pathlib import Path

import pytest

from infrastructure.analysis_acknowledgements_db import SqliteAcknowledgementRepository

MAC = "aa:bb:cc:dd:ee:ff"
OTHER = "11:22:33:44:55:66"


@pytest.fixture
def repo(tmp_path: Path) -> SqliteAcknowledgementRepository:
    return SqliteAcknowledgementRepository(tmp_path / "cernis.db")


# ── Round-trip ────────────────────────────────────────────────────────────────


def test_ack_dann_acknowledged_ports_enthaelt_port(
    repo: SqliteAcknowledgementRepository,
) -> None:
    repo.record(MAC, 3306, "notable", "ack")
    assert repo.acknowledged_ports(MAC) == {3306}


def test_keine_eintraege_keine_acknowledged_ports(
    repo: SqliteAcknowledgementRepository,
) -> None:
    assert repo.acknowledged_ports(MAC) == set()


# ── unack hebt auf (juengster Eintrag gewinnt) ────────────────────────────────


def test_unack_nach_ack_nimmt_port_wieder_raus(
    repo: SqliteAcknowledgementRepository,
) -> None:
    repo.record(MAC, 3306, "notable", "ack")
    repo.record(MAC, 3306, "notable", "unack")
    assert repo.acknowledged_ports(MAC) == set()


def test_mehrfaches_ack_unack_juengster_gewinnt(
    repo: SqliteAcknowledgementRepository,
) -> None:
    # ack -> unack -> ack: der JUENGSTE Eintrag (ack) entscheidet -> quittiert.
    repo.record(MAC, 4444, "critical", "ack")
    repo.record(MAC, 4444, "critical", "unack")
    repo.record(MAC, 4444, "critical", "ack")
    assert repo.acknowledged_ports(MAC) == {4444}


# ── Append-only: nichts wird geloescht ────────────────────────────────────────


def test_append_only_history_bleibt_vollstaendig(
    repo: SqliteAcknowledgementRepository,
) -> None:
    # Drei Aktionen -> drei Zeilen (kein Update/Delete). Direkt gegen die Tabelle gezaehlt.
    repo.record(MAC, 22, "notable", "ack")
    repo.record(MAC, 22, "notable", "unack")
    repo.record(MAC, 22, "notable", "ack")
    with repo._connect() as conn:
        count = conn.execute(
            "SELECT count(*) AS c FROM analysis_acknowledgements WHERE mac = ? AND port = ?",
            (MAC, 22),
        ).fetchone()["c"]
    assert count == 3


# ── PORT-GENAUE Granularitaet pro (mac, port) ─────────────────────────────────


def test_verschiedene_ports_isoliert(repo: SqliteAcknowledgementRepository) -> None:
    # 3306 quittiert, 6379 NICHT -> nur 3306 ist acknowledged (Karl-Garantie).
    repo.record(MAC, 3306, "notable", "ack")
    assert repo.acknowledged_ports(MAC) == {3306}
    assert 6379 not in repo.acknowledged_ports(MAC)


def test_unack_eines_ports_laesst_anderen_quittiert(
    repo: SqliteAcknowledgementRepository,
) -> None:
    repo.record(MAC, 3306, "notable", "ack")
    repo.record(MAC, 6379, "notable", "ack")
    repo.record(MAC, 3306, "notable", "unack")  # nur 3306 zurueck
    assert repo.acknowledged_ports(MAC) == {6379}


# ── Isolation verschiedener MACs ──────────────────────────────────────────────


def test_verschiedene_macs_isoliert(repo: SqliteAcknowledgementRepository) -> None:
    repo.record(MAC, 3306, "notable", "ack")
    repo.record(OTHER, 4444, "critical", "ack")
    assert repo.acknowledged_ports(MAC) == {3306}
    assert repo.acknowledged_ports(OTHER) == {4444}


# ── leere MAC ─────────────────────────────────────────────────────────────────


def test_leere_mac_liefert_leere_menge(repo: SqliteAcknowledgementRepository) -> None:
    assert repo.acknowledged_ports("") == set()
