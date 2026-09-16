"""Unit-Tests des ScanEvent-Vokabulars inkl. exhaustivem Pattern-Match.

``_describe`` deckt alle Union-Mitglieder ab; der ``case _: assert_never(event)``
laesst mypy die Vollstaendigkeit pruefen -- fehlt ein Event-Typ, schlaegt der
mypy-Gate fehl.
"""

from typing import assert_never

from domain.scanning import (
    EnrichedHost,
    HostEnriched,
    HostFound,
    Info,
    PhaseChanged,
    PortInterception,
    Progress,
    ScanCompleted,
    ScanError,
    ScanEvent,
    ScanStarted,
)


def _describe(event: ScanEvent) -> str:
    match event:
        case ScanStarted():
            return "started"
        case PhaseChanged():
            return "phase"
        case HostFound():
            return "host_found"
        case HostEnriched():
            return "host_enriched"
        case Progress():
            return "progress"
        case Info():
            return "info"
        case ScanCompleted():
            return "completed"
        case ScanError():
            return "error"
        case _:
            assert_never(event)


def test_scan_event_pattern_match_is_exhaustive() -> None:
    events: list[ScanEvent] = [
        ScanStarted(cidr="192.168.1.0/24", total_hosts=2),
        PhaseChanged(phase="discovery", status="running", total=2),
        HostFound(
            ip="192.168.1.2",
            mac="AA:BB:CC:DD:EE:01",
            vendor="TestVendor",
            rtt_ms=1.0,
            is_unknown=True,
            source="ping",
        ),
        HostEnriched(host=EnrichedHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01")),
        Progress(phase="enrich", completed=1, total=1, pct=100),
        Info(message="FritzBox merged"),
        ScanCompleted(total_found=1),
        ScanError(message="boom"),
    ]
    assert [_describe(e) for e in events] == [
        "started",
        "phase",
        "host_found",
        "host_enriched",
        "progress",
        "info",
        "completed",
        "error",
    ]


def test_events_carry_their_payload() -> None:
    assert ScanStarted(cidr="c", total_hosts=5).total_hosts == 5
    assert PhaseChanged(phase="discovery", status="done", alive_count=3).alive_count == 3
    assert HostEnriched(host=EnrichedHost(ip="1.2.3.4", mac="AA")).host.ip == "1.2.3.4"
    assert PhaseChanged(phase="enrich", status="running", total=7).total == 7


def test_scan_completed_carries_the_interception_result() -> None:
    """``ScanCompleted`` traegt das Gegenproben-Ergebnis mit (Befund 53, S86-A11).

    Additiv: ohne Angabe steht der Default "nicht geprueft, leere Portliste" --
    bestehende Erzeuger bleiben gueltig.
    """
    assert ScanCompleted(total_found=1).interception == PortInterception()
    mit_befund = ScanCompleted(
        total_found=2,
        interception=PortInterception(checked=True, intercepted_ports=(25, 143)),
    )
    assert mit_befund.total_found == 2
    assert mit_befund.interception.intercepted_ports == (25, 143)
