"""Tests fuer ``EnforceLoggingRetention`` (B-I) -- gegen Fake-Repos.

Reine application-Schicht: KEIN echtes sqlite. Getestet wird die Naht des Use-Cases:

* korrekte Cutoff-Weitergabe: der RTT-Cutoff geht ans RTT-Repo, der Event-Cutoff ans
  Event-Repo -- NICHT vertauscht.
* das Ergebnis (``LoggingRetentionResult``) buendelt die Rueckgaben beider
  ``delete_older_than``-Aufrufe korrekt.
* KEINE Uhr im Use-Case: die Cutoffs kommen rein als Parameter (kein time.time()).
"""

from application.monitoring import EnforceLoggingRetention, LoggingRetentionResult


class _FakeRttRepo:
    """Zeichnet den uebergebenen Cutoff auf und meldet eine feste Loeschzahl."""

    def __init__(self, deleted: int) -> None:
        self._deleted = deleted
        self.cutoff_calls: list[float] = []

    def save(self, task_id: str, rtt_ms: float, loss_pct: float, alive: bool, ts: float) -> None:
        raise AssertionError("save darf im Retention-Use-Case nicht gerufen werden")

    def range(self, task_id: str, since: float, until: float) -> list:  # type: ignore[type-arg]
        raise AssertionError("range darf im Retention-Use-Case nicht gerufen werden")

    def all_for(self, task_id: str) -> list:  # type: ignore[type-arg]
        raise AssertionError("all_for darf im Retention-Use-Case nicht gerufen werden")

    def delete_older_than(self, cutoff_ts: float) -> int:
        self.cutoff_calls.append(cutoff_ts)
        return self._deleted

    def count(self) -> int:
        raise AssertionError("count darf im Retention-Use-Case nicht gerufen werden")


class _FakeEventRepo:
    def __init__(self, deleted: int) -> None:
        self._deleted = deleted
        self.cutoff_calls: list[float] = []

    def save(self, task_id: str, event_type: str, rtt_ms: float, ts: float) -> None:
        raise AssertionError("save darf im Retention-Use-Case nicht gerufen werden")

    def range(self, task_id: str, since: float, until: float) -> list:  # type: ignore[type-arg]
        raise AssertionError("range darf im Retention-Use-Case nicht gerufen werden")

    def delete_older_than(self, cutoff_ts: float) -> int:
        self.cutoff_calls.append(cutoff_ts)
        return self._deleted


def test_run_passes_each_cutoff_to_its_repo() -> None:
    rtt = _FakeRttRepo(deleted=3)
    events = _FakeEventRepo(deleted=7)
    EnforceLoggingRetention(rtt, events).run(rtt_cutoff_ts=1000.0, event_cutoff_ts=500.0)
    # Jeder Cutoff geht an SEIN Repo -- nicht vertauscht.
    assert rtt.cutoff_calls == [1000.0]
    assert events.cutoff_calls == [500.0]


def test_run_result_bundles_deleted_counts() -> None:
    rtt = _FakeRttRepo(deleted=3)
    events = _FakeEventRepo(deleted=7)
    result = EnforceLoggingRetention(rtt, events).run(rtt_cutoff_ts=1000.0, event_cutoff_ts=500.0)
    assert result == LoggingRetentionResult(rtt_deleted=3, event_deleted=7)


def test_run_nothing_deleted_yields_zeros() -> None:
    rtt = _FakeRttRepo(deleted=0)
    events = _FakeEventRepo(deleted=0)
    result = EnforceLoggingRetention(rtt, events).run(rtt_cutoff_ts=1.0, event_cutoff_ts=1.0)
    assert result == LoggingRetentionResult(rtt_deleted=0, event_deleted=0)
