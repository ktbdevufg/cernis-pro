"""Tests der Aussenkontakte-Lese-Use-Cases (E3a) gegen Fake-Repos.

Reine application-Schicht, KEIN sqlite. Belegt die Pass-Through-Naht der Lese- und
Retention-Use-Cases:

* ``ListOutboundRecordings`` -> ``list_all`` durchgereicht (auch leer).
* ``GetOutboundRecording`` -> Definition; unbekannt -> ``RecordingNotFound``.
* ``GetOutboundAggregate`` -> ``list_for`` durchgereicht (leer -> []).
* ``GetOutboundDetailRange`` -> ``range`` durchgereicht (Fenster-Grenzen weitergegeben).
* ``EnforceOutboundDetailRetention`` -> ``delete_older_than`` durchgereicht (Cutoff vom
  Aufrufer, Rueckgabe geloeschte Zeilen).
"""

import pytest

from application.outbound_log import (
    EnforceOutboundDetailRetention,
    GetOutboundAggregate,
    GetOutboundDetailRange,
    GetOutboundRecording,
    ListOutboundRecordings,
    RecordingNotFound,
)
from domain.outbound_log import (
    AggregatedContact,
    DetailDepth,
    OutboundDetailRow,
    OutboundRecording,
    RecordingMode,
    RecordingState,
)


class _FakeRecordingRepo:
    """Minimaler ``OutboundRecordingRepository``-Fake fuer die Lesepfade."""

    def __init__(self, recordings: list[OutboundRecording] | None = None) -> None:
        self._store: dict[str, OutboundRecording] = {r.id: r for r in (recordings or [])}

    def save(self, recording: OutboundRecording) -> None:
        raise AssertionError("save darf von den Lesepfaden nicht gerufen werden")

    def get(self, recording_id: str) -> OutboundRecording | None:
        return self._store.get(recording_id)

    def list_all(self) -> list[OutboundRecording]:
        return list(self._store.values())

    def delete(self, recording_id: str) -> None:
        raise AssertionError("delete darf von den Lesepfaden nicht gerufen werden")

    def clear_all(self) -> None:
        """No-op fuer den Fake."""


class _FakeAggregateRepo:
    """``OutboundAggregateRepository``-Fake -- ``list_for`` liefert einen festen Stand."""

    def __init__(self, contacts: dict[str, list[AggregatedContact]] | None = None) -> None:
        self._contacts = contacts or {}
        self.list_for_calls: list[str] = []

    def upsert(self, recording_id: str, contact: AggregatedContact) -> None:
        raise AssertionError("upsert darf vom Lesepfad nicht gerufen werden")

    def get(self, recording_id: str, remote_ip: str) -> AggregatedContact | None:
        raise AssertionError("get darf vom Lesepfad nicht gerufen werden")

    def list_for(self, recording_id: str) -> list[AggregatedContact]:
        self.list_for_calls.append(recording_id)
        return self._contacts.get(recording_id, [])

    def delete_for(self, recording_id: str) -> None:
        raise AssertionError("delete_for darf vom Lesepfad nicht gerufen werden")

    def count(self) -> int:
        raise AssertionError("count darf vom Lesepfad nicht gerufen werden")

    def clear_all(self) -> None:
        """No-op fuer den Fake."""


class _FakeDetailRepo:
    """``OutboundDetailRepository``-Fake -- zeichnet range/delete_older_than auf."""

    def __init__(
        self,
        rows: list[OutboundDetailRow] | None = None,
        deleted: int = 0,
    ) -> None:
        self._rows = rows or []
        self._deleted = deleted
        self.range_calls: list[tuple[str, float, float]] = []
        self.cutoffs: list[float] = []

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
        raise AssertionError("save darf vom Lesepfad nicht gerufen werden")

    def range(self, recording_id: str, since: float, until: float) -> list[OutboundDetailRow]:
        self.range_calls.append((recording_id, since, until))
        return self._rows

    def delete_older_than(self, cutoff_ts: float) -> int:
        self.cutoffs.append(cutoff_ts)
        return self._deleted

    def count(self) -> int:
        raise AssertionError("count darf vom Lesepfad nicht gerufen werden")

    def clear_all(self) -> None:
        """No-op fuer den Fake."""


def _recording(recording_id: str) -> OutboundRecording:
    """Baut eine ``OutboundRecording`` (Test-Helfer)."""
    return OutboundRecording(
        id=recording_id,
        label="L",
        purpose="P",
        mode=RecordingMode.AGGREGATE,
        depth=DetailDepth.ANONYMOUS,
        state=RecordingState.CREATED,
        interval_s=60,
        created_at=1000.0,
    )


def _contact(remote_ip: str = "1.2.3.4") -> AggregatedContact:
    """Baut einen ``AggregatedContact`` (Test-Helfer)."""
    return AggregatedContact(
        remote_ip=remote_ip,
        first_seen=1.0,
        last_seen=2.0,
        total_count=5,
        peak_count=3,
        remote_port=443,
        hostname=None,
        country=None,
        operator=None,
        asn=None,
        app_name=None,
    )


def _row(ts: float = 1.0) -> OutboundDetailRow:
    """Baut eine ``OutboundDetailRow`` (Test-Helfer)."""
    return OutboundDetailRow(
        ts=ts,
        remote_ip="1.2.3.4",
        remote_port=443,
        hostname=None,
        country=None,
        operator=None,
        asn=None,
        app_name=None,
        pid=None,
        connection_count=1,
    )


# ── ListOutboundRecordings ──────────────────────────────────────────────────


def test_list_gibt_alle_zurueck() -> None:
    repo = _FakeRecordingRepo([_recording("a"), _recording("b")])
    assert {r.id for r in ListOutboundRecordings(repo)()} == {"a", "b"}


def test_list_leer_ist_leere_liste() -> None:
    assert ListOutboundRecordings(_FakeRecordingRepo())() == []


# ── GetOutboundRecording ────────────────────────────────────────────────────


def test_get_gibt_definition_zurueck() -> None:
    repo = _FakeRecordingRepo([_recording("r1")])
    assert GetOutboundRecording(repo)("r1").id == "r1"


def test_get_unbekannt_wirft_not_found() -> None:
    with pytest.raises(RecordingNotFound) as exc:
        GetOutboundRecording(_FakeRecordingRepo())("nope")
    assert exc.value.recording_id == "nope"


# ── GetOutboundAggregate ────────────────────────────────────────────────────


def test_get_aggregate_reicht_durch() -> None:
    repo = _FakeAggregateRepo({"r1": [_contact("9.9.9.9")]})
    result = GetOutboundAggregate(repo)("r1")
    assert [c.remote_ip for c in result] == ["9.9.9.9"]
    assert repo.list_for_calls == ["r1"]


def test_get_aggregate_leer_ist_leere_liste() -> None:
    assert GetOutboundAggregate(_FakeAggregateRepo())("r1") == []


# ── GetOutboundDetailRange ──────────────────────────────────────────────────


def test_get_detail_range_reicht_fenster_durch() -> None:
    repo = _FakeDetailRepo(rows=[_row(5.0)])
    result = GetOutboundDetailRange(repo)("r1", since=1.0, until=10.0)
    assert [r.ts for r in result] == [5.0]
    assert repo.range_calls == [("r1", 1.0, 10.0)]


def test_get_detail_range_leer_ist_leere_liste() -> None:
    repo = _FakeDetailRepo()
    assert GetOutboundDetailRange(repo)("r1", since=0.0, until=1.0) == []


# ── EnforceOutboundDetailRetention ──────────────────────────────────────────


def test_enforce_retention_reicht_cutoff_durch_und_gibt_zeilenzahl() -> None:
    repo = _FakeDetailRepo(deleted=7)
    deleted = EnforceOutboundDetailRetention(repo)(cutoff_ts=123.0)
    assert deleted == 7
    assert repo.cutoffs == [123.0]
