"""Tests des Aussenkontakte-Snapshot-Workers (E3b) gegen Fake-Repos + Fake-Provider.

Reine application-Schicht: KEIN echtes sqlite, KEIN Lifespan-Loop -- jeweils EIN
``asyncio.run(recorder.tick())`` (Muster ``test_cve_use_cases``) mit festem
``now_provider`` und einem async Fake-Snapshot-Provider, der eine vorgegebene
``ContactDelta``-Liste liefert. Belegt:

* keine aktive Aufzeichnung -> Snapshot wird NICHT geholt, aber Retention laeuft (mit
  erwartetem Cutoff ``now - retention_max_age_s``).
* DETAIL aktiv -> ``detail.save`` je Delta mit korrekten Feldern + ``pid=None``; KEIN
  ``aggregate.upsert``.
* AGGREGATE aktiv -> Merge-Pfad: erster Tick legt an, zweiter Tick summiert
  (``total_count``) + ``peak_count = max``; ``aggregate.upsert`` je Delta; KEIN
  ``detail.save``.
* DETAIL mit abgelaufenem Fenster -> gilt als NICHT aktiv -> kein ``detail.save`` (nur
  Retention).
* ``_current_interval``: ``interval_provider``-Vorrang; sonst ``rec.interval_s``; sonst 60.
* ``tick`` ist best-effort: ein werfender Provider fuehrt NICHT zu einer Exception aus
  ``tick`` (geloggt, geschluckt).
"""

import asyncio

from application.outbound_log import ContactSnapshotProvider, RunOutboundRecorder
from domain.outbound_log import (
    AggregatedContact,
    ContactDelta,
    DetailDepth,
    OutboundDetailRow,
    OutboundRecording,
    RecordingMode,
    RecordingState,
)


class _FakeRecordingRepo:
    """``OutboundRecordingRepository``-Fake: nur ``list_all`` wird vom Worker gerufen."""

    def __init__(self, recordings: list[OutboundRecording] | None = None) -> None:
        self._store = list(recordings or [])

    def save(self, recording: OutboundRecording) -> None:
        raise AssertionError("save darf vom Recorder nicht gerufen werden")

    def get(self, recording_id: str) -> OutboundRecording | None:
        raise AssertionError("get darf vom Recorder nicht gerufen werden")

    def list_all(self) -> list[OutboundRecording]:
        return list(self._store)

    def delete(self, recording_id: str) -> None:
        raise AssertionError("delete darf vom Recorder nicht gerufen werden")

    def clear_all(self) -> None:
        raise AssertionError("clear_all darf vom Recorder nicht gerufen werden")


class _FakeDetailRepo:
    """``OutboundDetailRepository``-Fake: zeichnet ``save``-Aufrufe + Retention-Cutoffs auf."""

    def __init__(self) -> None:
        # Jede save-Naht als Tupel aller Felder in Reihenfolge der Port-Signatur.
        self.saved: list[tuple[object, ...]] = []
        self.deleted_older_than: list[float] = []

    def save(
        self,
        recording_id: str,
        ts: float,
        remote_ip: str,
        remote_port: int | None,
        hostname: str | None,
        country: str | None,
        operator: str | None,
        asn: str | None,
        app_name: str | None,
        pid: int | None,
        connection_count: int,
    ) -> None:
        self.saved.append(
            (
                recording_id,
                ts,
                remote_ip,
                remote_port,
                hostname,
                country,
                operator,
                asn,
                app_name,
                pid,
                connection_count,
            )
        )

    def range(self, recording_id: str, since: float, until: float) -> list[OutboundDetailRow]:
        raise AssertionError("range darf vom Recorder nicht gerufen werden")

    def delete_older_than(self, cutoff_ts: float) -> int:
        self.deleted_older_than.append(cutoff_ts)
        return 0

    def count(self) -> int:
        raise AssertionError("count darf vom Recorder nicht gerufen werden")

    def clear_all(self) -> None:
        raise AssertionError("clear_all darf vom Recorder nicht gerufen werden")


class _FakeAggregateRepo:
    """``OutboundAggregateRepository``-Fake: in-memory ueber ``(recording_id, remote_ip)``."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], AggregatedContact] = {}
        self.upserts: list[tuple[str, AggregatedContact]] = []

    def upsert(self, recording_id: str, contact: AggregatedContact) -> None:
        self._store[(recording_id, contact.remote_ip)] = contact
        self.upserts.append((recording_id, contact))

    def get(self, recording_id: str, remote_ip: str) -> AggregatedContact | None:
        return self._store.get((recording_id, remote_ip))

    def list_for(self, recording_id: str) -> list[AggregatedContact]:
        raise AssertionError("list_for darf vom Recorder nicht gerufen werden")

    def delete_for(self, recording_id: str) -> None:
        raise AssertionError("delete_for darf vom Recorder nicht gerufen werden")

    def count(self) -> int:
        raise AssertionError("count darf vom Recorder nicht gerufen werden")

    def clear_all(self) -> None:
        raise AssertionError("clear_all darf vom Recorder nicht gerufen werden")


def _make_snapshot_provider(
    deltas: list[ContactDelta],
) -> tuple[ContactSnapshotProvider, dict[str, int]]:
    """Baut einen async Fake-Snapshot-Provider, der ``deltas`` liefert + Aufrufe zaehlt."""
    calls = {"n": 0}

    async def _provider() -> list[ContactDelta]:
        calls["n"] += 1
        return deltas

    return _provider, calls


def _recording(
    *,
    state: RecordingState = RecordingState.ACTIVE,
    mode: RecordingMode = RecordingMode.AGGREGATE,
    interval_s: int = 60,
    effective_start: float | None = 1000.0,
    max_duration_s: int | None = None,
) -> OutboundRecording:
    """Baut eine ``OutboundRecording`` in beliebigem Zustand (Test-Helfer)."""
    return OutboundRecording(
        id="r1",
        label="L",
        purpose="P",
        mode=mode,
        depth=DetailDepth.ANONYMOUS,
        state=state,
        interval_s=interval_s,
        created_at=1000.0,
        effective_start=effective_start,
        max_duration_s=max_duration_s,
    )


def _delta(remote_ip: str = "9.9.9.9", connection_count: int = 3) -> ContactDelta:
    """Baut ein angereichertes ``ContactDelta`` (Test-Helfer)."""
    return ContactDelta(
        remote_ip=remote_ip,
        remote_port=443,
        hostname="example.test",
        country="US",
        operator="Example LLC",
        asn="64500",
        app_name="firefox",
        connection_count=connection_count,
    )


_NOW = 5000.0
_RETENTION = 86400


def test_keine_aktive_aufzeichnung_holt_keinen_snapshot_aber_retention() -> None:
    """Keine aktive Aufzeichnung -> Snapshot NICHT geholt, Retention mit korrektem Cutoff."""
    recordings = _FakeRecordingRepo([_recording(state=RecordingState.PAUSED)])
    detail = _FakeDetailRepo()
    aggregate = _FakeAggregateRepo()
    provider, calls = _make_snapshot_provider([_delta()])
    recorder = RunOutboundRecorder(
        recordings,
        detail,
        aggregate,
        provider,
        retention_max_age_s=_RETENTION,
        now_provider=lambda: _NOW,
    )

    asyncio.run(recorder.tick())

    assert calls["n"] == 0  # Snapshot NICHT geholt
    assert detail.saved == []
    assert aggregate.upserts == []
    assert detail.deleted_older_than == [_NOW - _RETENTION]  # Retention dennoch


def test_detail_aktiv_schreibt_je_delta_mit_pid_none_kein_aggregate() -> None:
    """DETAIL aktiv -> detail.save je Delta mit korrekten Feldern + pid=None; kein upsert."""
    rec = _recording(mode=RecordingMode.DETAIL, effective_start=1000.0, max_duration_s=_RETENTION)
    recordings = _FakeRecordingRepo([rec])
    detail = _FakeDetailRepo()
    aggregate = _FakeAggregateRepo()
    deltas = [_delta("1.1.1.1", 2), _delta("2.2.2.2", 5)]
    provider, calls = _make_snapshot_provider(deltas)
    recorder = RunOutboundRecorder(
        recordings,
        detail,
        aggregate,
        provider,
        retention_max_age_s=_RETENTION,
        now_provider=lambda: _NOW,
    )

    asyncio.run(recorder.tick())

    assert calls["n"] == 1
    assert aggregate.upserts == []  # KEIN Aggregat im DETAIL-Modus
    assert detail.saved == [
        (
            "r1",
            _NOW,
            "1.1.1.1",
            443,
            "example.test",
            "US",
            "Example LLC",
            "64500",
            "firefox",
            None,
            2,
        ),
        (
            "r1",
            _NOW,
            "2.2.2.2",
            443,
            "example.test",
            "US",
            "Example LLC",
            "64500",
            "firefox",
            None,
            5,
        ),
    ]
    # pid ist in jeder Zeile None (vorletztes Feld).
    assert all(row[9] is None for row in detail.saved)
    assert detail.deleted_older_than == [_NOW - _RETENTION]


def test_aggregate_aktiv_merge_pfad_summiert_ueber_zwei_ticks() -> None:
    """AGGREGATE aktiv -> erster Tick legt an, zweiter summiert total + peak=max; kein detail."""
    rec = _recording(mode=RecordingMode.AGGREGATE)
    recordings = _FakeRecordingRepo([rec])
    detail = _FakeDetailRepo()
    aggregate = _FakeAggregateRepo()
    # Erster Tick: count=3, zweiter Tick: count=10 (peak steigt, total summiert).
    provider1, _ = _make_snapshot_provider([_delta("9.9.9.9", 3)])
    recorder = RunOutboundRecorder(
        recordings,
        detail,
        aggregate,
        provider1,
        retention_max_age_s=_RETENTION,
        now_provider=lambda: _NOW,
    )

    asyncio.run(recorder.tick())
    first = aggregate.get("r1", "9.9.9.9")
    assert first is not None
    assert first.total_count == 3
    assert first.peak_count == 3
    assert first.first_seen == _NOW
    assert first.last_seen == _NOW

    # Zweiter Tick: neuer Provider mit count=10.
    recorder._snapshot_provider = _make_snapshot_provider([_delta("9.9.9.9", 10)])[0]
    asyncio.run(recorder.tick())
    second = aggregate.get("r1", "9.9.9.9")
    assert second is not None
    assert second.total_count == 13  # 3 + 10 summiert
    assert second.peak_count == 10  # max(3, 10)
    assert second.first_seen == _NOW  # bleibt

    assert detail.saved == []  # KEIN Detail im AGGREGATE-Modus
    assert len(aggregate.upserts) == 2  # je Tick ein upsert


def test_detail_mit_abgelaufenem_fenster_gilt_nicht_aktiv() -> None:
    """DETAIL mit abgelaufenem 24h-Fenster -> nicht aktiv -> kein save, nur Retention."""
    # effective_start so, dass now ausserhalb [start, start+max_duration_s) liegt.
    rec = _recording(
        mode=RecordingMode.DETAIL,
        effective_start=1000.0,
        max_duration_s=100,  # Fenster endet bei 1100, now=5000 ist drueber.
    )
    recordings = _FakeRecordingRepo([rec])
    detail = _FakeDetailRepo()
    aggregate = _FakeAggregateRepo()
    provider, calls = _make_snapshot_provider([_delta()])
    recorder = RunOutboundRecorder(
        recordings,
        detail,
        aggregate,
        provider,
        retention_max_age_s=_RETENTION,
        now_provider=lambda: _NOW,
    )

    asyncio.run(recorder.tick())

    assert calls["n"] == 0  # gilt als nicht aktiv -> kein Snapshot
    assert detail.saved == []
    assert aggregate.upserts == []
    assert detail.deleted_older_than == [_NOW - _RETENTION]  # nur Retention


def test_current_interval_provider_hat_vorrang() -> None:
    """interval_provider gesetzt -> dessen Wert (vor rec.interval_s)."""
    recorder = RunOutboundRecorder(
        _FakeRecordingRepo(),
        _FakeDetailRepo(),
        _FakeAggregateRepo(),
        _make_snapshot_provider([])[0],
        interval_provider=lambda: 7,
    )
    rec = _recording(interval_s=300)
    assert recorder._current_interval(rec) == 7  # Provider schlaegt rec.interval_s
    assert recorder._current_interval(None) == 7  # auch ohne rec


def test_current_interval_ohne_provider_nutzt_rec_dann_default() -> None:
    """Ohne interval_provider -> rec.interval_s; ohne rec -> Default 60."""
    recorder = RunOutboundRecorder(
        _FakeRecordingRepo(),
        _FakeDetailRepo(),
        _FakeAggregateRepo(),
        _make_snapshot_provider([])[0],
    )
    assert recorder._current_interval(_recording(interval_s=300)) == 300
    assert recorder._current_interval(None) == 60  # Default


def test_tick_ist_best_effort_provider_wirft_keine_exception() -> None:
    """Ein werfender Provider fuehrt NICHT zu einer Exception aus tick (geschluckt)."""
    rec = _recording(mode=RecordingMode.AGGREGATE)
    recordings = _FakeRecordingRepo([rec])
    detail = _FakeDetailRepo()
    aggregate = _FakeAggregateRepo()

    async def _exploding_provider() -> list[ContactDelta]:
        raise RuntimeError("snapshot kaputt")

    recorder = RunOutboundRecorder(
        recordings,
        detail,
        aggregate,
        _exploding_provider,
        retention_max_age_s=_RETENTION,
        now_provider=lambda: _NOW,
    )

    # Darf NICHT werfen.
    asyncio.run(recorder.tick())

    assert aggregate.upserts == []
    assert detail.saved == []
    # Retention liegt im selben try-Block NACH dem werfenden Snapshot -- sie wird durch
    # den Provider-Fehler uebersprungen (best-effort: Fehler geschluckt, kein Crash).
    assert detail.deleted_older_than == []
