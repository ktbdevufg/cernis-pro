"""Tests der Aussenkontakte-Lifecycle-Use-Cases (E3a) gegen Fake-Repos.

Reine application-Schicht: KEIN echtes sqlite. Ein aufzeichnender Fake-
``OutboundRecordingRepository`` (in-memory dict ueber ``id``) belegt die Naht jedes
Lifecycle-Use-Cases:

* ``CreateOutboundRecording`` -> Zustand CREATED + ``created_at`` + ``save`` (reine
  Anlage, kein Konflikt); DETAIL-Default-Deckel; AGGREGATE erzwingt ``max_duration_s``
  None; Domaenen-``ValueError`` propagiert (ungueltiges Intervall, DETAIL-Deckel).
* ``StartOutboundRecording`` -> CREATED->ACTIVE + ``effective_start`` + ``save``;
  host-weiter Konflikt -> ``RecordingConflict`` (mit ``running_id``); kein Konflikt mit
  sich selbst; unbekannt -> ``RecordingNotFound``; falscher Ausgangszustand ->
  ``InvalidRecordingTransition`` durchgereicht.
* ``Pause``/``Resume``/``Stop`` -> Uebergang + ``save``; ``Resume`` prueft VOR dem
  resume die Host-Konfliktregel; falscher Ausgangszustand ->
  ``InvalidRecordingTransition``.
* ``Delete`` -> Definition + Aggregat (delete_for) entfernt, idempotent.
"""

import pytest

from application.outbound_log import (
    CreateOutboundRecording,
    DeleteOutboundRecording,
    PauseOutboundRecording,
    RecordingConflict,
    RecordingNotFound,
    ResumeOutboundRecording,
    StartOutboundRecording,
    StopOutboundRecording,
)
from domain.outbound_log import (
    MAX_DETAIL_DURATION_S,
    AggregatedContact,
    DetailDepth,
    OutboundDetailRow,
    OutboundRecording,
    RecordingMode,
    RecordingState,
)


class _FakeRecordingRepo:
    """Aufzeichnender ``OutboundRecordingRepository``-Fake (in-memory ueber ``id``)."""

    def __init__(self, recordings: list[OutboundRecording] | None = None) -> None:
        self._store: dict[str, OutboundRecording] = {r.id: r for r in (recordings or [])}
        self.saved: list[OutboundRecording] = []
        self.deleted: list[str] = []

    def save(self, recording: OutboundRecording) -> None:
        self._store[recording.id] = recording
        self.saved.append(recording)

    def get(self, recording_id: str) -> OutboundRecording | None:
        return self._store.get(recording_id)

    def list_all(self) -> list[OutboundRecording]:
        return list(self._store.values())

    def delete(self, recording_id: str) -> None:
        self.deleted.append(recording_id)
        self._store.pop(recording_id, None)

    def clear_all(self) -> None:
        """Leert den internen Speicher (No-op-Naht fuer den Fake)."""
        self._store.clear()


class _FakeDetailRepo:
    """``OutboundDetailRepository``-Fake -- belegt nur die vom Delete gehaltene Naht."""

    def __init__(self) -> None:
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
        raise AssertionError("save darf vom Lifecycle nicht gerufen werden")

    def range(self, recording_id: str, since: float, until: float) -> list[OutboundDetailRow]:
        raise AssertionError("range darf vom Lifecycle nicht gerufen werden")

    def delete_older_than(self, cutoff_ts: float) -> int:
        self.deleted_older_than.append(cutoff_ts)
        return 0

    def count(self) -> int:
        raise AssertionError("count darf vom Lifecycle nicht gerufen werden")

    def clear_all(self) -> None:
        """No-op fuer den Fake."""


class _FakeAggregateRepo:
    """``OutboundAggregateRepository``-Fake -- zeichnet ``delete_for`` auf."""

    def __init__(self) -> None:
        self.deleted_for: list[str] = []

    def upsert(self, recording_id: str, contact: AggregatedContact) -> None:
        raise AssertionError("upsert darf vom Lifecycle nicht gerufen werden")

    def get(self, recording_id: str, remote_ip: str) -> AggregatedContact | None:
        raise AssertionError("get darf vom Lifecycle nicht gerufen werden")

    def list_for(self, recording_id: str) -> list[AggregatedContact]:
        raise AssertionError("list_for darf vom Lifecycle nicht gerufen werden")

    def delete_for(self, recording_id: str) -> None:
        self.deleted_for.append(recording_id)

    def count(self) -> int:
        raise AssertionError("count darf vom Lifecycle nicht gerufen werden")

    def clear_all(self) -> None:
        """No-op fuer den Fake."""


def _recording(
    recording_id: str = "r1",
    *,
    state: RecordingState = RecordingState.CREATED,
    mode: RecordingMode = RecordingMode.AGGREGATE,
) -> OutboundRecording:
    """Baut eine ``OutboundRecording`` in beliebigem Zustand (Test-Helfer)."""
    return OutboundRecording(
        id=recording_id,
        label="L",
        purpose="P",
        mode=mode,
        depth=DetailDepth.ANONYMOUS,
        state=state,
        interval_s=60,
        created_at=1000.0,
        effective_start=None if state is RecordingState.CREATED else 1000.0,
        max_duration_s=None,
    )


# ── CreateOutboundRecording ─────────────────────────────────────────────────


def test_create_legt_im_zustand_created_an_und_speichert() -> None:
    repo = _FakeRecordingRepo()
    rec = CreateOutboundRecording(repo)(
        recording_id="abc",
        label="Aussenkontakte",
        purpose="Beobachtung",
        mode="aggregate",
        depth="anonymous",
        interval_s=60,
        now=1234.0,
    )
    assert rec.state is RecordingState.CREATED
    assert rec.id == "abc"
    assert rec.created_at == 1234.0
    assert rec.effective_start is None
    assert repo.saved == [rec]


def test_create_detail_ohne_max_duration_setzt_24h_deckel() -> None:
    repo = _FakeRecordingRepo()
    rec = CreateOutboundRecording(repo)(
        recording_id="d1",
        label="L",
        purpose="P",
        mode="detail",
        depth="app_resolved",
        interval_s=30,
        now=1.0,
    )
    assert rec.mode is RecordingMode.DETAIL
    assert rec.max_duration_s == MAX_DETAIL_DURATION_S


def test_create_detail_mit_max_duration_reicht_durch() -> None:
    repo = _FakeRecordingRepo()
    rec = CreateOutboundRecording(repo)(
        recording_id="d2",
        label="L",
        purpose="P",
        mode="detail",
        depth="anonymous",
        interval_s=60,
        now=1.0,
        max_duration_s=3600,
    )
    assert rec.max_duration_s == 3600


def test_create_aggregate_erzwingt_max_duration_none() -> None:
    # Auch ein faelschlich uebergebener Wert wird im AGGREGATE-Fall auf None gezwungen.
    repo = _FakeRecordingRepo()
    rec = CreateOutboundRecording(repo)(
        recording_id="a1",
        label="L",
        purpose="P",
        mode="aggregate",
        depth="anonymous",
        interval_s=60,
        now=1.0,
        max_duration_s=3600,
    )
    assert rec.max_duration_s is None


def test_create_ungueltiges_intervall_wirft_value_error_aus_domaene() -> None:
    repo = _FakeRecordingRepo()
    with pytest.raises(ValueError):
        CreateOutboundRecording(repo)(
            recording_id="x",
            label="L",
            purpose="P",
            mode="aggregate",
            depth="anonymous",
            interval_s=45,  # nicht in ALLOWED_INTERVALS
            now=1.0,
        )
    assert repo.saved == []


def test_create_detail_max_duration_ueber_deckel_wirft_value_error() -> None:
    repo = _FakeRecordingRepo()
    with pytest.raises(ValueError):
        CreateOutboundRecording(repo)(
            recording_id="x",
            label="L",
            purpose="P",
            mode="detail",
            depth="anonymous",
            interval_s=60,
            now=1.0,
            max_duration_s=MAX_DETAIL_DURATION_S + 1,
        )
    assert repo.saved == []


# ── StartOutboundRecording ──────────────────────────────────────────────────


def test_start_created_wird_active_und_gespeichert() -> None:
    repo = _FakeRecordingRepo([_recording("r1", state=RecordingState.CREATED)])
    started = StartOutboundRecording(repo)("r1", now=999.0)
    assert started.state is RecordingState.ACTIVE
    assert started.effective_start == 999.0
    assert repo.saved == [started]


def test_start_unbekannt_wirft_not_found() -> None:
    repo = _FakeRecordingRepo()
    with pytest.raises(RecordingNotFound) as exc:
        StartOutboundRecording(repo)("nope", now=1.0)
    assert exc.value.recording_id == "nope"
    assert repo.saved == []


def test_start_konflikt_wenn_andere_active_wirft_conflict() -> None:
    running = _recording("running", state=RecordingState.ACTIVE)
    candidate = _recording("candidate", state=RecordingState.CREATED)
    repo = _FakeRecordingRepo([running, candidate])
    with pytest.raises(RecordingConflict) as exc:
        StartOutboundRecording(repo)("candidate", now=1.0)
    assert exc.value.running_id == "running"
    assert repo.saved == []


def test_start_kein_konflikt_mit_sich_selbst() -> None:
    # Nur die eigene Aufzeichnung ist (noch CREATED) im Repo -- kein Konkurrent.
    repo = _FakeRecordingRepo([_recording("solo", state=RecordingState.CREATED)])
    started = StartOutboundRecording(repo)("solo", now=1.0)
    assert started.state is RecordingState.ACTIVE


def test_start_falscher_ausgangszustand_reicht_transition_durch() -> None:
    from domain.outbound_log import InvalidRecordingTransition

    repo = _FakeRecordingRepo([_recording("r1", state=RecordingState.FINISHED)])
    with pytest.raises(InvalidRecordingTransition):
        StartOutboundRecording(repo)("r1", now=1.0)


# ── Pause / Resume / Stop ───────────────────────────────────────────────────


def test_pause_active_wird_paused() -> None:
    repo = _FakeRecordingRepo([_recording("r1", state=RecordingState.ACTIVE)])
    paused = PauseOutboundRecording(repo)("r1")
    assert paused.state is RecordingState.PAUSED
    assert repo.saved == [paused]


def test_pause_unbekannt_wirft_not_found() -> None:
    with pytest.raises(RecordingNotFound):
        PauseOutboundRecording(_FakeRecordingRepo())("nope")


def test_pause_falscher_zustand_wirft_transition() -> None:
    from domain.outbound_log import InvalidRecordingTransition

    repo = _FakeRecordingRepo([_recording("r1", state=RecordingState.CREATED)])
    with pytest.raises(InvalidRecordingTransition):
        PauseOutboundRecording(repo)("r1")
    assert repo.saved == []


def test_resume_paused_wird_active() -> None:
    repo = _FakeRecordingRepo([_recording("r1", state=RecordingState.PAUSED)])
    resumed = ResumeOutboundRecording(repo)("r1")
    assert resumed.state is RecordingState.ACTIVE
    assert repo.saved == [resumed]


def test_resume_konflikt_wenn_andere_active_wirft_conflict() -> None:
    running = _recording("running", state=RecordingState.ACTIVE)
    paused = _recording("paused", state=RecordingState.PAUSED)
    repo = _FakeRecordingRepo([running, paused])
    with pytest.raises(RecordingConflict) as exc:
        ResumeOutboundRecording(repo)("paused")
    assert exc.value.running_id == "running"
    assert repo.saved == []


def test_resume_falscher_zustand_wirft_transition() -> None:
    from domain.outbound_log import InvalidRecordingTransition

    repo = _FakeRecordingRepo([_recording("r1", state=RecordingState.CREATED)])
    with pytest.raises(InvalidRecordingTransition):
        ResumeOutboundRecording(repo)("r1")


def test_stop_active_wird_finished() -> None:
    repo = _FakeRecordingRepo([_recording("r1", state=RecordingState.ACTIVE)])
    finished = StopOutboundRecording(repo)("r1")
    assert finished.state is RecordingState.FINISHED
    assert repo.saved == [finished]


def test_stop_paused_wird_finished() -> None:
    repo = _FakeRecordingRepo([_recording("r1", state=RecordingState.PAUSED)])
    finished = StopOutboundRecording(repo)("r1")
    assert finished.state is RecordingState.FINISHED


def test_stop_unbekannt_wirft_not_found() -> None:
    with pytest.raises(RecordingNotFound):
        StopOutboundRecording(_FakeRecordingRepo())("nope")


def test_stop_falscher_zustand_wirft_transition() -> None:
    from domain.outbound_log import InvalidRecordingTransition

    repo = _FakeRecordingRepo([_recording("r1", state=RecordingState.CREATED)])
    with pytest.raises(InvalidRecordingTransition):
        StopOutboundRecording(repo)("r1")


# ── DeleteOutboundRecording ─────────────────────────────────────────────────


def test_delete_entfernt_definition_und_aggregat() -> None:
    rec_repo = _FakeRecordingRepo([_recording("r1")])
    detail_repo = _FakeDetailRepo()
    agg_repo = _FakeAggregateRepo()
    DeleteOutboundRecording(rec_repo, detail_repo, agg_repo)("r1")
    assert rec_repo.deleted == ["r1"]
    assert agg_repo.deleted_for == ["r1"]
    # Detail wird BEWUSST nicht gezielt geloescht (zeit-basierte Retention).
    assert detail_repo.deleted_older_than == []


def test_delete_unbekannt_ist_idempotent() -> None:
    rec_repo = _FakeRecordingRepo()
    detail_repo = _FakeDetailRepo()
    agg_repo = _FakeAggregateRepo()
    DeleteOutboundRecording(rec_repo, detail_repo, agg_repo)("nope")  # kein Fehler
    assert rec_repo.deleted == ["nope"]
    assert agg_repo.deleted_for == ["nope"]
