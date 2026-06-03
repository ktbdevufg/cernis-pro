"""Charakterisierung der monitoring-Domaenenmodelle (frozen dataclasses + StrEnum).

Haelt fest: ``MonitorEventType`` serialisiert StrEnum-typisch als Altcode-String;
die Datentraeger sind frozen und tragen die 1:1-Altcode-Felder (inkl. PingSample-
Sentinel ``-1.0``); ``MonitorEvent`` hat KEINE ``.to_dict()``-Methode mehr.
"""

import dataclasses

import pytest

from domain.monitoring import (
    MonitorEvent,
    MonitorEventType,
    MonitorTarget,
    PingSample,
)


def test_event_type_serializes_as_altcode_string() -> None:
    # StrEnum: der Member IST sein str-Wert -- serialisierungskompatibel zum Altcode.
    # Ueber str()/.value geprueft (nicht Member == "literal" direkt: mypy sieht das
    # statisch als non-overlapping, obwohl es zur Laufzeit StrEnum-True ist).
    assert str(MonitorEventType.UP) == "up"
    assert str(MonitorEventType.DOWN) == "down"
    assert str(MonitorEventType.DEGRADED) == "degraded"
    assert MonitorEventType.UP.value == "up"
    assert f"{MonitorEventType.UP}" == "up"
    assert MonitorEventType("up") is MonitorEventType.UP  # Round-trip vom str
    assert list(MonitorEventType) == [
        MonitorEventType.UP,
        MonitorEventType.DOWN,
        MonitorEventType.DEGRADED,
    ]


def test_monitor_target_fields_and_default() -> None:
    t = MonitorTarget(id="wlan", label="WLAN", host="192.168.1.1", interface="")
    assert (t.id, t.label, t.host, t.interface) == ("wlan", "WLAN", "192.168.1.1", "")
    assert t.enabled is True  # Default


def test_ping_sample_one_to_one_with_altcode_defaults() -> None:
    # Sentinel -1.0 + loss/timestamp-Defaults treu zum Altcode-PingResult.
    s = PingSample(target_id="wlan", host="192.168.1.1", alive=True)
    assert s.rtt_ms == -1.0
    assert s.loss_pct == 0.0
    assert s.timestamp == 0.0


def test_monitor_event_is_pure_data_carrier() -> None:
    evt = MonitorEvent(
        target_id="wlan",
        label="WLAN",
        event=MonitorEventType.DOWN,
        rtt_ms=-1.0,
        timestamp=1_700_000_000.0,
    )
    assert evt.event is MonitorEventType.DOWN
    # KEINE .to_dict()-Methode (View-Verhalten gehoert an den Rand, nicht in domain).
    assert not hasattr(evt, "to_dict")


def test_models_are_frozen() -> None:
    target = MonitorTarget(id="x", label="X", host="h", interface="")
    sample = PingSample(target_id="x", host="h", alive=True)
    event = MonitorEvent(target_id="x", label="X", event=MonitorEventType.UP, rtt_ms=1.0)
    for obj, attr, val in (
        (target, "id", "y"),
        (sample, "alive", False),
        (event, "rtt_ms", 2.0),
    ):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(obj, attr, val)
