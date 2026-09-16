"""Tests fuer ``SqliteDnsWatchAcknowledgementRepository`` (Block 2, 2d) -- tmp_path-DB.

Belegt den ``record`` (ack) -> ``acknowledged_keys``-Round-trip, das Zuruecknehmen per
unack (juengster Eintrag gewinnt), die Append-only-Natur (mehrfaches ack/unack), die
BEFUNDGENAUE Granularitaet pro (remote_ip, category) und die Isolation verschiedener
Befunde. Muster der uebrigen infrastructure-Repo-Tests (``tmp_path``-DB, wie
``test_analysis_acknowledgements_db.py``).

Schluessel-Form ist ``f"{remote_ip}:{category}"`` -- der ``AcknowledgedProvider``-Vertrag
aus 2d-1.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from infrastructure.dns_watch_acknowledgements_db import (
    SqliteDnsWatchAcknowledgementRepository,
)

IP = "1.2.3.4"
OTHER = "9.9.9.9"
CAT_OPEN = "offen"
CAT_DOH = "moegliche_doh"


class FakeClock:
    """Erfuellt das ``Clock``-Protocol strukturell; liefert einen festen Zeitpunkt.

    Timezone-aware UTC -- wie ``SystemClock``, damit ``.isoformat()`` einen Offset
    (``+00:00``) traegt und der Test deterministisch gegen den Erwartungswert prueft.
    """

    FIXED = datetime(2026, 7, 18, 13, 23, 45, 123456, tzinfo=UTC)

    def now(self) -> datetime:
        return self.FIXED


@pytest.fixture
def repo(tmp_path: Path) -> SqliteDnsWatchAcknowledgementRepository:
    return SqliteDnsWatchAcknowledgementRepository(tmp_path / "cernis.db", FakeClock())


# ── Round-trip ────────────────────────────────────────────────────────────────


def test_ack_dann_acknowledged_keys_enthaelt_schluessel(
    repo: SqliteDnsWatchAcknowledgementRepository,
) -> None:
    repo.record(IP, CAT_OPEN, "ack")
    assert repo.acknowledged_keys() == {f"{IP}:{CAT_OPEN}"}


def test_record_setzt_created_at_aus_clock_mit_tz_offset(
    repo: SqliteDnsWatchAcknowledgementRepository,
) -> None:
    """``created_at`` kommt aus der Clock: nicht leer, mit Zonen-Offset, exakter Wert.

    Belegt die A10-Etappe-2: der Zeitstempel wird explizit ueber den Clock-Port gesetzt
    (timezone-aware UTC, ISO-8601 mit +00:00) statt ueber den Schema-Default
    ``datetime('now')`` (UTC ohne Zonen-Kennzeichnung). Das Repository hat keinen Lesepfad
    fuer ``created_at`` -- der Test liest die Spalte direkt aus der Tabelle.
    """
    repo.record(IP, CAT_OPEN, "ack")
    with repo._connect() as conn:
        created_at = conn.execute(
            "SELECT created_at FROM dns_watch_acknowledgements WHERE remote_ip = ?", (IP,)
        ).fetchone()["created_at"]

    assert created_at.endswith("+00:00")  # traegt eine Zeitzonen-Kennzeichnung
    assert created_at == FakeClock.FIXED.isoformat()  # exakt der Clock-Wert


def test_keine_eintraege_keine_acknowledged_keys(
    repo: SqliteDnsWatchAcknowledgementRepository,
) -> None:
    assert repo.acknowledged_keys() == set()


# ── unack hebt auf (juengster Eintrag gewinnt) ────────────────────────────────


def test_unack_nach_ack_nimmt_schluessel_wieder_raus(
    repo: SqliteDnsWatchAcknowledgementRepository,
) -> None:
    repo.record(IP, CAT_OPEN, "ack")
    repo.record(IP, CAT_OPEN, "unack")
    assert repo.acknowledged_keys() == set()


def test_mehrfaches_ack_unack_juengster_gewinnt(
    repo: SqliteDnsWatchAcknowledgementRepository,
) -> None:
    # ack -> unack -> ack: der JUENGSTE Eintrag (ack) entscheidet -> quittiert.
    repo.record(IP, CAT_DOH, "ack")
    repo.record(IP, CAT_DOH, "unack")
    repo.record(IP, CAT_DOH, "ack")
    assert repo.acknowledged_keys() == {f"{IP}:{CAT_DOH}"}


# ── Append-only: nichts wird geloescht ────────────────────────────────────────


def test_append_only_history_bleibt_vollstaendig(
    repo: SqliteDnsWatchAcknowledgementRepository,
) -> None:
    # Drei Aktionen -> drei Zeilen (kein Update/Delete). Direkt gegen die Tabelle gezaehlt.
    repo.record(IP, CAT_OPEN, "ack")
    repo.record(IP, CAT_OPEN, "unack")
    repo.record(IP, CAT_OPEN, "ack")
    with repo._connect() as conn:
        count = conn.execute(
            "SELECT count(*) AS c FROM dns_watch_acknowledgements "
            "WHERE remote_ip = ? AND category = ?",
            (IP, CAT_OPEN),
        ).fetchone()["c"]
    assert count == 3


# ── BEFUNDGENAUE Granularitaet pro (remote_ip, category) ──────────────────────


def test_verschiedene_kategorien_selber_ip_isoliert(
    repo: SqliteDnsWatchAcknowledgementRepository,
) -> None:
    # (IP, "offen") quittiert, (IP, "moegliche_doh") NICHT -> nur der eine Schluessel.
    repo.record(IP, CAT_OPEN, "ack")
    assert repo.acknowledged_keys() == {f"{IP}:{CAT_OPEN}"}
    assert f"{IP}:{CAT_DOH}" not in repo.acknowledged_keys()


def test_unack_einer_kategorie_laesst_andere_quittiert(
    repo: SqliteDnsWatchAcknowledgementRepository,
) -> None:
    repo.record(IP, CAT_OPEN, "ack")
    repo.record(IP, CAT_DOH, "ack")
    repo.record(IP, CAT_OPEN, "unack")  # nur "offen" zurueck
    assert repo.acknowledged_keys() == {f"{IP}:{CAT_DOH}"}


# ── Isolation verschiedener IPs ───────────────────────────────────────────────


def test_verschiedene_ips_isoliert(
    repo: SqliteDnsWatchAcknowledgementRepository,
) -> None:
    repo.record(IP, CAT_OPEN, "ack")
    repo.record(OTHER, CAT_DOH, "ack")
    assert repo.acknowledged_keys() == {f"{IP}:{CAT_OPEN}", f"{OTHER}:{CAT_DOH}"}


# ── clear_all leert ───────────────────────────────────────────────────────────


def test_clear_all_leert_das_log(
    repo: SqliteDnsWatchAcknowledgementRepository,
) -> None:
    repo.record(IP, CAT_OPEN, "ack")
    repo.record(OTHER, CAT_DOH, "ack")
    repo.clear_all()
    assert repo.acknowledged_keys() == set()


# ── leere Eingaben ────────────────────────────────────────────────────────────


def test_leere_eingaben_werden_geloggt_und_abgeleitet(
    repo: SqliteDnsWatchAcknowledgementRepository,
) -> None:
    # Leere IP/category sind keine kaputten Werte -- sie werden regulaer geloggt und
    # ergeben den (degenerierten) Schluessel ":" .
    repo.record("", "", "ack")
    assert repo.acknowledged_keys() == {":"}
