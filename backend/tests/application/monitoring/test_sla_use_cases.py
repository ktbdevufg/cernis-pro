"""Tests fuer ``GetSlaStats`` / ``GetAllSlaStats`` (M.7) -- gegen einen Fake-Repo.

Reine application-Schicht: KEIN echtes sqlite, KEIN Mock der Domaene -- der Fake-Repo
liefert (alive, rtt_ms, ts)-Zeilen, die echte ``compute_sla_stats`` (M.2) rechnet.
Getestet wird die Naht des Use-Cases:

* GetSlaStats reicht die rows in compute_sla_stats UND injiziert ``target_id`` (die
  Domaene setzt es bewusst nicht -- Vertrag /api/sla/{id}).
* Leere Samples -> die Domaenen-Null-Stats (``uptime_pct=None``), ebenfalls mit
  ``target_id``.
* days -> since: der Use-Case rechnet now - days*86400 und reicht ``since`` an den
  Repo; der Fake zeichnet das seit-since auf (Beweis der Umrechnung).
* GetAllSlaStats: je target_id eine Statistik, leere target_ids -> [].
"""

import time
from typing import Any

from application.monitoring import GetAllSlaStats, GetSlaStats
from domain.monitoring import SlaSample


class _FakeSlaRepo:
    """Liefert vorgegebene Zeilen je target_id; zeichnet den ``since``-Wert auf."""

    def __init__(self, samples: dict[str, list[SlaSample]] | None = None) -> None:
        self._samples = samples or {}
        self.since_calls: dict[str, float] = {}

    def samples_for(self, target_id: str, since: float) -> list[SlaSample]:
        self.since_calls[target_id] = since
        return [s for s in self._samples.get(target_id, []) if s[2] > since]

    def target_ids(self) -> list[str]:
        return list(self._samples.keys())


def _now() -> float:
    return time.time()


def test_get_sla_stats_injects_target_id() -> None:
    # Zwei Samples knapp in der Vergangenheit (sicher im 30-Tage-Fenster).
    now = _now()
    repo = _FakeSlaRepo({"wlan": [(1, 4.0, now - 10), (1, 6.0, now - 5)]})
    result = GetSlaStats(repo)("wlan", days=30)

    assert result["target_id"] == "wlan"  # injiziert (Domaene setzt es nicht)
    assert result["samples"] == 2
    assert result["uptime_pct"] == 100.0  # beide alive
    assert result["avg_rtt_ms"] == 5.0  # (4+6)/2
    assert result["days"] == 30


def test_get_sla_stats_empty_yields_null_stats_with_target_id() -> None:
    repo = _FakeSlaRepo({})  # keine Samples fuer "wlan"
    result = GetSlaStats(repo)("wlan", days=7)

    assert result["target_id"] == "wlan"  # auch im Leerfall injiziert
    assert result["samples"] == 0
    assert result["uptime_pct"] is None  # Domaenen-Null-Stat: None, NICHT 0
    assert result["avg_rtt_ms"] == 0
    assert result["chart"] == []
    assert result["days"] == 7


def test_get_sla_stats_computes_since_from_days() -> None:
    now = _now()
    repo = _FakeSlaRepo({"wlan": [(1, 3.0, now - 100)]})
    GetSlaStats(repo)("wlan", days=1)
    # since ~ now - 1*86400. Toleranz fuer die time.time()-Differenz im Use-Case.
    expected = now - 86400
    assert abs(repo.since_calls["wlan"] - expected) < 5.0


def test_get_sla_stats_default_days_is_30() -> None:
    now = _now()
    repo = _FakeSlaRepo({"wlan": [(1, 3.0, now - 10)]})
    result = GetSlaStats(repo)("wlan")
    assert result["days"] == 30
    assert abs(repo.since_calls["wlan"] - (now - 30 * 86400)) < 5.0


def test_get_all_sla_stats_one_per_target() -> None:
    now = _now()
    repo = _FakeSlaRepo(
        {
            "wlan": [(1, 4.0, now - 10)],
            "lan": [(0, -1.0, now - 10)],  # down
        }
    )
    results = GetAllSlaStats(repo)(days=30)
    by_target: dict[str, Any] = {r["target_id"]: r for r in results}
    assert set(by_target) == {"wlan", "lan"}
    assert by_target["wlan"]["uptime_pct"] == 100.0
    assert by_target["lan"]["uptime_pct"] == 0.0  # down -> 0%


def test_get_all_sla_stats_empty_returns_empty_list() -> None:
    repo = _FakeSlaRepo({})
    assert GetAllSlaStats(repo)(days=30) == []
