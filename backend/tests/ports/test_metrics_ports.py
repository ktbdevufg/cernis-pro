"""Strukturtest des MetricsReader-Ports (M.8 Schritt 1): ein Fake erfuellt das Protocol.

Reine ``typing.Protocol``-Vertraege haben kein Verhalten -- der Verhaltenstest kommt
mit dem Adapter (M.8 Schritt 2). Hier NUR die strukturelle Konformitaet:

* **statisch (mypy):** ``_assert_metrics_reader`` nimmt den Port-TYP und bekommt die
  Fake-Instanz uebergeben. Erfuellt der Fake das Protocol nicht, schlaegt ``uv run
  mypy`` fehl -- das ist die eigentliche Pruefung.
* **dynamisch (pytest):** ein Smoke ruft ``snapshot()`` und prueft den Rueckgabetyp.

KEIN ``@runtime_checkable`` am Port -> bewusst KEIN ``isinstance``-Check.
"""

from domain.metrics import MetricsSnapshot, RttPoint, SlaPoint
from ports.metrics import MetricsReader


class _FakeMetricsReader:
    """Minimaler Fake, der den ``MetricsReader``-Vertrag strukturell erfuellt."""

    def snapshot(self) -> MetricsSnapshot:
        return MetricsSnapshot(
            device_total=1,
            rtt_points=(RttPoint("wlan", 5.0, True),),
            sla_points=(SlaPoint("wlan", 99.0, 4.0),),
            scans_7d=3,
            scan_hosts_max=10,
        )


def _assert_metrics_reader(_reader: MetricsReader) -> None:
    """Statischer Konformitaets-Anker (von mypy geprueft)."""


def test_fake_satisfies_metrics_reader_protocol() -> None:
    fake = _FakeMetricsReader()
    _assert_metrics_reader(fake)
    snap = fake.snapshot()
    assert isinstance(snap, MetricsSnapshot)
    assert snap.device_total == 1
    assert snap.rtt_points[0].alive is True
