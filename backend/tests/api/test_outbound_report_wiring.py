"""Tests des ECHTEN Aussenkontakte-Berichts-Lesepfads (Composition Root, app.py).

Der Weg von den REPOSITORIES bis zum fertigen Berichtsergebnis -- mit echten
SQLite-Adaptern gegen eine temporaere DB (``CERNIS_DATA_DIR`` -> ``tmp_path``),
NICHT mit Fakes. Genau diese Ebene fehlte bisher: ``test_outbound_report.py``
prueft nur die reine Zaehlfunktion mit vorgefertigten Zeilen, und
``test_report_api.py`` haengt einen Fake-Runner ein. Dadurch konnte der Fehler
"Detail-Aufzeichnungen liefern einen leeren Bericht" durch alle Gates laufen,
obwohl beide Nachbar-Testebenen gruen waren.

Kern der Behauptungen -- der Zeitmodus bestimmt nur die QUELLE, nicht das Ergebnis:

* ``DETAIL``: die rohen Messpunkte aus ``outbound_log_detail`` werden je
  ``remote_ip`` verdichtet -- ``total_count`` SUMME, ``peak_count`` MAXIMUM eines
  einzelnen Messpunkts, ``first_seen``/``last_seen`` min/max der ``ts``.
* ``AGGREGATE``: unveraendert aus ``outbound_log_aggregate``.
* Alle-Fall: gemischte Bestaende aus BEIDEN Modi laufen korrekt zusammen.
* Ohne Daten: ehrlich leeres Ergebnis (alle Zaehler 0), KEINE erfundenen Werte.

``CERNIS_DATA_DIR`` wirkt hier zuverlaessig, weil der Composition Root
``get_db_path()`` als FUNKTION aufruft (nicht die beim Import gebundene
``DB_PATH``-Konstante) -- der Umweg ueber ``monkeypatch.setattr`` am Modul-
Namespace (Muster ``test_monitoring_storage``) ist dafuer nicht noetig.
"""

import asyncio
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI

from api.report import provide_outbound_report
from app import create_app
from domain.outbound_log import (
    AggregatedContact,
    DetailDepth,
    OutboundRecording,
    RecordingMode,
    RecordingState,
)
from infrastructure.config import AppConfig
from infrastructure.outbound_log_aggregate import SqliteOutboundAggregateRepository
from infrastructure.outbound_log_detail import SqliteOutboundDetailRepository
from infrastructure.outbound_log_recordings import SqliteOutboundRecordingRepository

# Fester Bezugs-ts (keine Wanduhr im Test). Die obere Fenstergrenze der DETAIL-Abfrage
# bildet der Composition Root aus ``time.time()`` -- die Messpunkte liegen darum
# bewusst in der VERGANGENHEIT, damit sie sicher ins Fenster [0.0, now) fallen.
_TS = 1_700_000_000.0


@pytest.fixture
def db_pfad(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Lenkt die DB-Aufloesung auf eine temporaere DB um (nie die echte cernis.db)."""
    monkeypatch.setenv("CERNIS_DATA_DIR", str(tmp_path))
    return tmp_path / "cernis.db"


def _recording(rec_id: str, mode: RecordingMode, label: str = "") -> OutboundRecording:
    """Eine gueltige Aufzeichnungs-Definition im gewuenschten Modus."""
    return OutboundRecording(
        id=rec_id,
        label=label or rec_id,
        purpose="test",
        mode=mode,
        depth=DetailDepth.ANONYMOUS,
        state=RecordingState.FINISHED,
        interval_s=60,
        created_at=_TS,
    )


def _save_detail(
    repo: SqliteOutboundDetailRepository,
    rec_id: str,
    ts: float,
    remote_ip: str,
    connection_count: int,
) -> None:
    """Ein DETAIL-Messpunkt (ein Tick) mit fester Anreicherung."""
    repo.save(
        rec_id,
        ts,
        remote_ip,
        443,
        "host.example",
        "DE",
        "Example Operator",
        "AS64500",
        "firefox",
        None,
        connection_count,
    )


def _aggregat(remote_ip: str, total: int, peak: int) -> AggregatedContact:
    """Ein fertiges Aggregat mit derselben Anreicherung wie ``_save_detail``."""
    return AggregatedContact(
        remote_ip=remote_ip,
        first_seen=_TS,
        last_seen=_TS + 60.0,
        total_count=total,
        peak_count=peak,
        remote_port=443,
        hostname="host.example",
        country="DE",
        operator="Example Operator",
        asn="AS64500",
        app_name="firefox",
    )


@pytest.fixture
def report_runner(db_pfad: Path) -> Iterator[Any]:
    """Der ECHTE, in app.py verdrahtete Berichts-Runner (kein Fake).

    Wird ueber ``dependency_overrides`` aus der frisch gebauten App geholt: das ist
    exakt das Objekt, das der Endpunkt ``GET /api/report/outbound`` aufruft.
    """
    app: FastAPI = create_app(AppConfig())
    yield app.dependency_overrides[provide_outbound_report]()


def _zeile(report: Any, remote_ip: str) -> Any:
    """Die Kontaktzeile zu einer IP (oder ``None``, wenn sie fehlt)."""
    return next((r for r in report.contact_rows if r.remote_ip == remote_ip), None)


# ── DETAIL: die rohen Messpunkte werden verdichtet ───────────────────────────


def test_detail_recording_liefert_verdichtete_zahlen(db_pfad: Path, report_runner: Any) -> None:
    """DETAIL ueber mehrere Ticks -> total_count SUMME, peak_count MAXIMUM.

    Der Kern des Fixes: vor ihm las der Bericht nur ``outbound_log_aggregate`` und
    lieferte fuer JEDE Detail-Aufzeichnung Nullen, obwohl die Daten vorlagen.
    """
    SqliteOutboundRecordingRepository(db_pfad).save(
        _recording("rec-detail", RecordingMode.DETAIL, label="Testlauf")
    )
    detail = SqliteOutboundDetailRepository(db_pfad)
    # Drei Ticks derselben IP: 2 + 7 + 3 = 12 Verbindungen, Spitze eines Ticks = 7.
    _save_detail(detail, "rec-detail", _TS, "203.0.113.10", 2)
    _save_detail(detail, "rec-detail", _TS + 60.0, "203.0.113.10", 7)
    _save_detail(detail, "rec-detail", _TS + 120.0, "203.0.113.10", 3)
    # Eine zweite IP, damit contacts_total nicht zufaellig stimmt.
    _save_detail(detail, "rec-detail", _TS + 60.0, "198.51.100.5", 4)

    report = asyncio.run(report_runner("rec-detail"))

    assert report.recording_label == "Testlauf"
    assert report.recording_scope == "single"
    assert report.contacts_total == 2
    assert report.connection_total == 16  # 12 + 4

    zeile = _zeile(report, "203.0.113.10")
    assert zeile is not None
    assert zeile.total_count == 12  # SUMME der Ticks
    assert zeile.peak_count == 7  # MAXIMUM eines einzelnen Ticks
    assert zeile.first_seen_ts == _TS  # frueheste ts
    assert zeile.last_seen_ts == _TS + 120.0  # spaeteste ts
    # Anreicherung wird durchgereicht, nicht verworfen.
    assert zeile.hostname == "host.example"
    assert zeile.country == "DE"


def test_detail_recording_ohne_daten_ist_ehrlich_leer(db_pfad: Path, report_runner: Any) -> None:
    """DETAIL-Aufzeichnung ohne Messpunkte -> alle Zaehler 0, KEINE erfundenen Werte.

    Wichtig fuer S3: leer ist ein DATUM. Es wird insbesondere NICHT ersatzweise die
    Aggregate-Tabelle gelesen (kein stiller Fallback auf eine fremde Quelle).
    """
    SqliteOutboundRecordingRepository(db_pfad).save(_recording("rec-leer", RecordingMode.DETAIL))
    # Ein Aggregat unter DERSELBEN id -- es darf NICHT einspringen.
    SqliteOutboundAggregateRepository(db_pfad).upsert(
        "rec-leer", _aggregat("203.0.113.99", total=999, peak=999)
    )

    report = asyncio.run(report_runner("rec-leer"))

    assert report.contacts_total == 0
    assert report.connection_total == 0
    assert report.contact_rows == []
    assert report.recording_label == "rec-leer"


# ── AGGREGATE: unveraendertes Verhalten ──────────────────────────────────────


def test_aggregate_recording_bleibt_unveraendert(db_pfad: Path, report_runner: Any) -> None:
    """AGGREGATE liest weiterhin die Aggregat-Tabelle -- der Fix aendert daran nichts."""
    SqliteOutboundRecordingRepository(db_pfad).save(
        _recording("rec-agg", RecordingMode.AGGREGATE, label="Sammlung")
    )
    SqliteOutboundAggregateRepository(db_pfad).upsert(
        "rec-agg", _aggregat("203.0.113.20", total=25, peak=9)
    )

    report = asyncio.run(report_runner("rec-agg"))

    assert report.recording_label == "Sammlung"
    assert report.contacts_total == 1
    assert report.connection_total == 25

    zeile = _zeile(report, "203.0.113.20")
    assert zeile is not None
    assert zeile.total_count == 25
    assert zeile.peak_count == 9


def test_aggregate_recording_liest_keine_detailzeilen(db_pfad: Path, report_runner: Any) -> None:
    """Gegenprobe: bei AGGREGATE bleiben DETAIL-Zeilen derselben id unberuecksichtigt.

    Die Quellwahl ist in BEIDE Richtungen strikt -- kein Vermischen der Tabellen.
    """
    SqliteOutboundRecordingRepository(db_pfad).save(
        _recording("rec-agg-only", RecordingMode.AGGREGATE)
    )
    SqliteOutboundAggregateRepository(db_pfad).upsert(
        "rec-agg-only", _aggregat("203.0.113.30", total=5, peak=5)
    )
    _save_detail(SqliteOutboundDetailRepository(db_pfad), "rec-agg-only", _TS, "198.51.100.77", 42)

    report = asyncio.run(report_runner("rec-agg-only"))

    assert report.contacts_total == 1
    assert report.connection_total == 5
    assert _zeile(report, "198.51.100.77") is None  # DETAIL-Zeile bleibt aussen vor


# ── Alle-Fall: gemischte Modi laufen korrekt zusammen ────────────────────────


def test_alle_faelle_mischen_beide_modi(db_pfad: Path, report_runner: Any) -> None:
    """Ohne recording_id: je Aufzeichnung die passende Quelle, dann zusammenfuehren.

    Zusaetzlich der Merge ueber Aufzeichnungsgrenzen hinweg: dieselbe IP taucht in
    BEIDEN Laeufen auf und muss zu EINER Zeile mit summiertem total_count und
    maximalem peak_count verschmelzen.
    """
    recordings = SqliteOutboundRecordingRepository(db_pfad)
    recordings.save(_recording("rec-d", RecordingMode.DETAIL))
    recordings.save(_recording("rec-a", RecordingMode.AGGREGATE))

    detail = SqliteOutboundDetailRepository(db_pfad)
    # DETAIL-Lauf: gemeinsame IP (3 + 6 = 9, Spitze 6) + eine eigene IP.
    _save_detail(detail, "rec-d", _TS, "203.0.113.40", 3)
    _save_detail(detail, "rec-d", _TS + 60.0, "203.0.113.40", 6)
    _save_detail(detail, "rec-d", _TS, "198.51.100.1", 1)
    # AGGREGATE-Lauf: dieselbe gemeinsame IP (total 10, peak 8) + eine eigene IP.
    aggregate = SqliteOutboundAggregateRepository(db_pfad)
    aggregate.upsert("rec-a", _aggregat("203.0.113.40", total=10, peak=8))
    aggregate.upsert("rec-a", _aggregat("198.51.100.2", total=2, peak=2))

    report = asyncio.run(report_runner(None))

    assert report.recording_scope == "all"
    assert report.recording_label == ""
    # Drei verschiedene IPs: die gemeinsame + je eine aus jedem Lauf.
    assert report.contacts_total == 3
    assert report.connection_total == 22  # 9 + 1 + 10 + 2

    gemeinsam = _zeile(report, "203.0.113.40")
    assert gemeinsam is not None
    assert gemeinsam.total_count == 19  # 9 (DETAIL) + 10 (AGGREGATE)
    assert gemeinsam.peak_count == 8  # max(6, 8)


def test_alle_faelle_ohne_aufzeichnungen_ist_leer(db_pfad: Path, report_runner: Any) -> None:
    """Gar keine Aufzeichnungen -> ehrlich leeres Ergebnis, kein Fehler."""
    report = asyncio.run(report_runner(None))

    assert report.contacts_total == 0
    assert report.connection_total == 0
    assert report.contact_rows == []


def test_unbekannte_recording_id_ist_leer(db_pfad: Path, report_runner: Any) -> None:
    """Unbekannte id -> leeres Ergebnis, Label faellt ehrlich auf die id zurueck."""
    report = asyncio.run(report_runner("gibt-es-nicht"))

    assert report.recording_label == "gibt-es-nicht"
    assert report.contacts_total == 0
    assert report.contact_rows == []
