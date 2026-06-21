"""Tests fuer den ``/ws/scan``-Handler (S.6, Composition Root ``ws_scan.py``).

Der Handler wird mit einer Fake-``RunNetworkScan``-Factory auf eine FRISCHE
FastAPI-App gehaengt (``add_api_websocket_route``) -- KEINE app.py-Lifespan, kein
echtes Netz. Geprueft wird die Event->Frame-Uebersetzung (am S.1-Contract) und der
Fehlerpfad (NmapScanError/FritzAuthError -> error-Frame statt Abbruch).

``ws_scan.py`` liegt im Composition Root (darf domain/infrastructure importieren);
der Test darf das ebenfalls -- er ist kein Ring-Modul.
"""

from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import ws_scan
from application.devices.errors import DeviceNotFoundError
from domain.devices import ScannedHost, TrustState
from domain.scanning import (
    EnrichedHost,
    HostEnriched,
    HostFound,
    PhaseChanged,
    PortInfo,
    Progress,
    ScanCompleted,
    ScanEvent,
    ScanStarted,
)
from infrastructure.scanning.fritz_hosts import FritzAuthError
from infrastructure.scanning.port_scanner import NmapScanError
from ws_scan import make_ws_scan


class _FakeRunNetworkScan:
    """Yieldet eine vorgegebene Event-Liste (oder wirft am Ende eine Exception)."""

    def __init__(self, events: list[ScanEvent], raise_at_end: Exception | None = None) -> None:
        self._events = events
        self._raise_at_end = raise_at_end

    async def run(self, config: Any) -> AsyncIterator[ScanEvent]:
        for event in self._events:
            yield event
        if self._raise_at_end is not None:
            raise self._raise_at_end


class _FakeRecordScannedHost:
    """Faengt die Projektions-Aufrufe (devices-Verbuchung, S.7d).

    Sammelt die uebergebenen ``ScannedHost``-Objekte; optional wirft er, um den
    best-effort-Fehlerpfad zu pruefen.
    """

    def __init__(self, raise_exc: Exception | None = None) -> None:
        self.recorded: list[ScannedHost] = []
        self._raise_exc = raise_exc

    def __call__(self, scanned: ScannedHost) -> None:
        if self._raise_exc is not None:
            raise self._raise_exc
        self.recorded.append(scanned)


class _FakeRecordSeen:
    """Faengt die Host-Historie-Schreibnaht (C.2, analysis_known_hosts).

    Sammelt die uebergebenen MACs; optional wirft er, um den best-effort-Fehlerpfad
    zu pruefen. Das echte Pendant ist ``SqliteHostHistoryRepository.record_seen``.
    """

    def __init__(self, raise_exc: Exception | None = None) -> None:
        self.seen: list[str] = []
        self._raise_exc = raise_exc

    def __call__(self, mac: str) -> None:
        if self._raise_exc is not None:
            raise self._raise_exc
        self.seen.append(mac)


class _FakeStoredDevice:
    """Minimal-Stand-in fuer ein gespeichertes ``Device`` (kuratierte Felder + last_ip).

    ``last_ip`` ist die VORZUSTANDS-IP aus der devices-DB (ADR 0020); Default ``None``
    (frisch angelegt / keine IP). Aus ihr leitet der Loop ``is_changed`` ab.
    ``open_ports`` ist der VORZUSTANDS-Portstand aus der devices-DB (ADR 0026); Default
    leeres Tupel (kein Vorzustand). Aus ihm leitet der Loop ``new_ports`` ab.
    ``trust_state`` ist die wertende Einordnung aus der devices-DB; Default ``NEUTRAL``
    (noch keine Wertung). Der Loop projiziert daraus ``.value`` ins host_detail-Frame.
    """

    def __init__(
        self,
        label: str,
        tags: tuple[str, ...],
        notes: str,
        last_ip: str | None = None,
        open_ports: tuple[int, ...] = (),
        trust_state: TrustState = TrustState.NEUTRAL,
    ) -> None:
        self.label = label
        self.tags = tags
        self.notes = notes
        self.last_ip = last_ip
        self.open_ports = open_ports
        self.trust_state = trust_state


class _FakeDeviceWithHistory:
    """Stand-in fuer das ``GetDevice``-Ergebnis: kuratierte Felder auf ``.device``."""

    def __init__(self, device: _FakeStoredDevice) -> None:
        self.device = device


class _FakeGetDevice:
    """Faengt die GetDevice-Lese-Naht (Baseline-Anreicherung, ADR 0019).

    Ist ``stored`` gesetzt, liefert der Aufruf ein ``DeviceWithHistory``-Stand-in mit
    den kuratierten Feldern. Sonst -> ``DeviceNotFoundError`` (Host noch nie als device
    gespeichert). ``raise_exc`` erzwingt einen echten Fehler (best-effort-Pfad).
    """

    def __init__(
        self,
        stored: _FakeStoredDevice | None = None,
        raise_exc: Exception | None = None,
    ) -> None:
        self._stored = stored
        self._raise_exc = raise_exc
        self.asked: list[str] = []

    def __call__(self, mac: str) -> _FakeDeviceWithHistory:
        self.asked.append(mac)
        if self._raise_exc is not None:
            raise self._raise_exc
        if self._stored is None:
            raise DeviceNotFoundError(mac)
        return _FakeDeviceWithHistory(self._stored)


class _FakeIsKnown:
    """Faengt die is_known-Lese-Naht (Baseline-Anreicherung, ADR 0019).

    Liefert den VORZUSTAND der Historie: ``known`` enthaelt die MACs, die VOR diesem
    Scan schon bekannt waren. ``asked`` protokolliert die Abfragen (Timing-Pruefung).
    ``raise_exc`` erzwingt einen Fehler (best-effort -> True). Leere MAC -> True.
    """

    def __init__(
        self,
        known: set[str] | None = None,
        raise_exc: Exception | None = None,
    ) -> None:
        self._known = known or set()
        self._raise_exc = raise_exc
        self.asked: list[str] = []

    def __call__(self, mac: str) -> bool:
        self.asked.append(mac)
        if self._raise_exc is not None:
            raise self._raise_exc
        if not mac:
            return True
        return mac in self._known


class _FakeSeverity:
    """Faengt die kombinierte Achse-B-Bewertung (ADR 0029 + 0030 + 0031).

    Liefert in EINEM Aufruf die drei Achse-B-Werte als Tripel
    ``(analysis_severity, flagged_ports, acknowledged_ports)``. ``result`` ist die feste
    Severity (``None``/``"notable"``/``"critical"``); ``flagged`` die feste flagged_ports-Form
    (Default leere Form); ``acked`` die feste quittierten-Ports-Liste (Default []).
    ``raise_exc`` erzwingt einen Fehler (best-effort -> Defaults). ``calls`` protokolliert die
    (ip, is_known)-Aufrufe. Das echte Pendant ist die ``_build_axis_b``-Closure aus app.py.
    """

    def __init__(
        self,
        result: str | None = None,
        flagged: dict[str, list[int]] | None = None,
        acked: list[int] | None = None,
        raise_exc: Exception | None = None,
    ) -> None:
        self._result = result
        self._flagged = flagged if flagged is not None else {"critical": [], "notable": []}
        self._acked = acked if acked is not None else []
        self._raise_exc = raise_exc
        self.calls: list[tuple[str, bool]] = []

    def __call__(
        self, host: EnrichedHost, is_known: bool
    ) -> tuple[str | None, dict[str, list[int]], list[int]]:
        self.calls.append((host.ip, is_known))
        if self._raise_exc is not None:
            raise self._raise_exc
        return self._result, self._flagged, self._acked


def _client(
    events: list[ScanEvent],
    raise_at_end: Exception | None = None,
    recorder: _FakeRecordScannedHost | None = None,
    seen_recorder: _FakeRecordSeen | None = None,
    get_device: _FakeGetDevice | None = None,
    is_known: _FakeIsKnown | None = None,
    severity: _FakeSeverity | None = None,
) -> TestClient:
    record = recorder or _FakeRecordScannedHost()
    record_seen = seen_recorder or _FakeRecordSeen()
    device_reader = get_device or _FakeGetDevice()
    known_reader = is_known or _FakeIsKnown()
    severity_reader = severity or _FakeSeverity()
    app = FastAPI()
    app.add_api_websocket_route(
        "/ws/scan",
        make_ws_scan(
            lambda: _FakeRunNetworkScan(events, raise_at_end),
            lambda: record,
            lambda: record_seen,
            lambda: device_reader,
            lambda: known_reader,
            lambda: severity_reader,
        ),
    )
    return TestClient(app)


# ── Volle 9-Frame-Sequenz (S.1-Contract) ───────────────────────────────────


def test_full_frame_sequence_matches_s1_contract() -> None:
    host = EnrichedHost(
        ip="192.168.1.2",
        mac="AA:BB:CC:DD:EE:01",
        vendor="TestVendor",
        rtt_ms=1.0,
        is_unknown=True,
        category="unknown",
    )
    events: list[ScanEvent] = [
        ScanStarted(cidr="192.168.1.0/30", total_hosts=2),
        PhaseChanged(phase="discovery", status="running", total=2),
        HostFound(
            ip="192.168.1.2",
            mac="AA:BB:CC:DD:EE:01",
            vendor="TestVendor",
            rtt_ms=1.0,
            is_unknown=True,
            source="ping",
        ),
        Progress(phase="discovery", completed=1, total=1, pct=100),
        PhaseChanged(phase="discovery", status="done", alive_count=1),
        PhaseChanged(phase="enrich", status="running", total=1),
        HostEnriched(host=host),
        Progress(phase="enrich", completed=1, total=1, pct=100),
        ScanCompleted(total_found=1),
    ]
    with _client(events).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/30"})
        frames = [ws.receive_json() for _ in range(9)]

    assert [f["type"] for f in frames] == [
        "scan_started",
        "phase",
        "host_found",
        "progress",
        "phase",
        "phase",
        "host_detail",
        "progress",
        "scan_complete",
    ]
    assert frames[0] == {"type": "scan_started", "cidr": "192.168.1.0/30", "total_hosts": 2}
    assert frames[1] == {"type": "phase", "phase": "discovery", "status": "running", "total": 2}
    # host_found MIT source-Feld (S.7f, 1A: einheitlich in jedem Frame).
    assert frames[2] == {
        "type": "host_found",
        "ip": "192.168.1.2",
        "rtt_ms": 1.0,
        "mac": "AA:BB:CC:DD:EE:01",
        "vendor": "TestVendor",
        "is_unknown": True,
        "source": "ping",
    }
    assert frames[4] == {
        "type": "phase",
        "phase": "discovery",
        "status": "done",
        "alive_count": 1,
    }
    assert frames[8] == {"type": "scan_complete", "total_found": 1}


def test_host_detail_frame_has_29_keys_incl_axis_b() -> None:
    host = EnrichedHost(
        ip="10.0.0.5",
        mac="AA:BB:CC:DD:EE:02",
        ports=(PortInfo(port=22, state="open", service="ssh"),),
        category="server",
        source="arp",  # nicht-Default -> beweist source-Durchstich bis host_detail
        additional_ips=("10.0.0.6", "10.0.0.7"),  # MAC-Gruppierung -> Durchstich
    )
    with _client([HostEnriched(host=host)]).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "10.0.0.0/30"})
        frame = ws.receive_json()

    assert frame["type"] == "host_detail"
    # 29 Keys: die 20 S.1-Contract-Keys + source (S.7f) + additional_ips (MAC-Gruppierung)
    # + is_known (Baseline-Anreicherung, ADR 0019) + is_changed (DHCP-Wechsel, ADR 0020)
    # + new_ports (Port-History Achse A, ADR 0026)
    # + analysis_severity (Auffaelligkeits-Bewertung Achse B, ADR 0029)
    # + flagged_ports (getroffene Ports je Stufe, Achse B, ADR 0030)
    # + acknowledged_ports (quittierte Ports, Achse B, ADR 0031)
    # + trust_state (wertende Einordnung aus der devices-DB).
    assert set(frame.keys()) == {
        "type",
        "ip",
        "mac",
        "vendor",
        "rtt_ms",
        "hostname",
        "smb_name",
        "smb_domain",
        "os_guess",
        "os_accuracy",
        "scan_method",
        "ports",
        "mdns_services",
        "ssdp_services",
        "is_ndi",
        "is_unknown",
        "category",
        "label",
        "tags",
        "notes",
        "source",
        "additional_ips",
        "is_known",
        "is_changed",
        "new_ports",
        "analysis_severity",
        "flagged_ports",
        "acknowledged_ports",
        "trust_state",
    }
    assert frame["ports"] == [{"port": 22, "state": "open", "service": "ssh"}]
    assert frame["category"] == "server"
    assert frame["additional_ips"] == ["10.0.0.6", "10.0.0.7"]
    assert frame["source"] == "arp"  # Quelle haengt am persistenten Host (S.7f)
    # Ohne kuratiertes device (kein _FakeGetDevice mit stored) bleibt der Default:
    # trust_state "neutral" -- IMMER vorhanden, wie is_known.
    assert frame["trust_state"] == "neutral"


# ── analysis_severity (Auffaelligkeits-Bewertung, Achse B, ADR 0029) ──────────


def test_analysis_severity_default_none_without_finding() -> None:
    """Ohne Auffaelligkeit (Severity-Callable liefert None) -> Frame analysis_severity=None."""
    host = EnrichedHost(ip="192.168.1.40", mac="AA:BB:CC:DD:EE:40", category="server")
    with _client([HostEnriched(host=host)]).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["analysis_severity"] is None
    # flagged_ports default-leer mitgeliefert (Achse B, ADR 0030).
    assert frame["flagged_ports"] == {"critical": [], "notable": []}


def test_analysis_severity_notable_for_suspicious_port() -> None:
    """Auffaelliger Port -> Severity-Callable liefert "notable" -> Frame traegt es."""
    host = EnrichedHost(ip="192.168.1.41", mac="AA:BB:CC:DD:EE:41", category="server")
    severity = _FakeSeverity(result="notable")
    with _client([HostEnriched(host=host)], severity=severity).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["analysis_severity"] == "notable"


def test_analysis_severity_critical_for_critical_port() -> None:
    """Kritischer Port -> Severity-Callable liefert "critical" -> Frame traegt es."""
    host = EnrichedHost(ip="192.168.1.42", mac="AA:BB:CC:DD:EE:42", category="server")
    severity = _FakeSeverity(result="critical")
    with _client([HostEnriched(host=host)], severity=severity).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["analysis_severity"] == "critical"


def test_analysis_severity_independent_from_new_ports() -> None:
    """Achse B (analysis_severity) ist GETRENNT von Achse A (new_ports).

    Ein brandneuer Host OHNE Kuratierung hat keinen Port-Vorzustand -> new_ports bleibt
    [] (Achse A). analysis_severity wird trotzdem gesetzt (Achse B braucht keine
    Kuratierung) -- beide Felder sind unabhaengig.
    """
    host = EnrichedHost(
        ip="192.168.1.43",
        mac="AA:BB:CC:DD:EE:43",
        ports=(PortInfo(port=4444, state="open", service=""),),
        category="server",
    )
    # Kein gespeichertes Device -> kein Vorzustand -> new_ports bleibt [].
    severity = _FakeSeverity(result="critical")
    with _client([HostEnriched(host=host)], severity=severity).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["new_ports"] == []  # Achse A: kein Vorzustand
    assert frame["analysis_severity"] == "critical"  # Achse B: unabhaengig gesetzt


def test_analysis_severity_uses_baseline_known() -> None:
    """Die is_known-Eingabe der Bewertung ist der VOR record_seen gelesene baseline_known.

    Leere Historie -> baseline_known=False; das Severity-Callable wird mit (ip, False)
    aufgerufen (genau wie new_host_seen den Vorzustand braucht).
    """
    host = EnrichedHost(ip="192.168.1.44", mac="AA:BB:CC:DD:EE:44", category="server")
    is_known = _FakeIsKnown(known=set())  # leere Historie -> unbekannt
    severity = _FakeSeverity(result=None)
    client = _client([HostEnriched(host=host)], is_known=is_known, severity=severity)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        ws.receive_json()

    assert severity.calls == [("192.168.1.44", False)]


def test_analysis_severity_failure_is_best_effort_scan_continues() -> None:
    """Wirft das Severity-Callable -> analysis_severity=None, Scan laeuft weiter."""
    host = EnrichedHost(ip="192.168.1.45", mac="AA:BB:CC:DD:EE:45", category="server")
    severity = _FakeSeverity(raise_exc=RuntimeError("engine kaputt"))
    with _client([HostEnriched(host=host)], severity=severity).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    # best-effort: kein Abbruch, BEIDE Achse-B-Felder fallen auf ihren Default zurueck
    # (analysis_severity None, flagged_ports leer) -- mit Log.
    assert frame["type"] == "host_detail"
    assert frame["analysis_severity"] is None
    assert frame["flagged_ports"] == {"critical": [], "notable": []}
    # acknowledged_ports faellt ebenfalls auf den Default [] zurueck (ADR 0031).
    assert frame["acknowledged_ports"] == []


# ── flagged_ports (getroffene Ports je Stufe, Achse B, ADR 0030) ──────────────


def test_flagged_ports_notable_for_suspicious_open_port() -> None:
    """Auffaelliger offener Port -> flagged_ports["notable"] traegt ihn, critical leer."""
    host = EnrichedHost(
        ip="192.168.1.50",
        mac="AA:BB:CC:DD:EE:50",
        ports=(PortInfo(port=3389, state="open", service=""),),
        category="server",
    )
    severity = _FakeSeverity(result="notable", flagged={"critical": [], "notable": [3389]})
    with _client([HostEnriched(host=host)], severity=severity).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["flagged_ports"] == {"critical": [], "notable": [3389]}


def test_flagged_ports_critical_for_backdoor_open_port() -> None:
    """Backdoor-Port -> flagged_ports["critical"] traegt ihn."""
    host = EnrichedHost(
        ip="192.168.1.51",
        mac="AA:BB:CC:DD:EE:51",
        ports=(PortInfo(port=4444, state="open", service=""),),
        category="server",
    )
    severity = _FakeSeverity(result="critical", flagged={"critical": [4444], "notable": []})
    with _client([HostEnriched(host=host)], severity=severity).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["flagged_ports"] == {"critical": [4444], "notable": []}


def test_flagged_ports_separate_from_new_ports() -> None:
    """flagged_ports (Achse B) ist GETRENNT von new_ports (Achse A).

    Ein brandneuer Host OHNE Kuratierung -> new_ports bleibt [] (kein Vorzustand),
    flagged_ports traegt trotzdem den getroffenen Port (Achse B braucht keine Kuratierung).
    """
    host = EnrichedHost(
        ip="192.168.1.52",
        mac="AA:BB:CC:DD:EE:52",
        ports=(PortInfo(port=4444, state="open", service=""),),
        category="server",
    )
    severity = _FakeSeverity(result="critical", flagged={"critical": [4444], "notable": []})
    with _client([HostEnriched(host=host)], severity=severity).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["new_ports"] == []  # Achse A: kein Vorzustand
    assert frame["flagged_ports"] == {"critical": [4444], "notable": []}  # Achse B: unabhaengig


# ── acknowledged_ports (quittierte Ports, Achse B, ADR 0031) ──────────────────


def test_acknowledged_ports_default_empty_without_acks() -> None:
    """Ohne Quittierungen (Callable liefert []) -> Frame acknowledged_ports=[]."""
    host = EnrichedHost(ip="192.168.1.60", mac="AA:BB:CC:DD:EE:60", category="server")
    with _client([HostEnriched(host=host)]).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["acknowledged_ports"] == []


def test_acknowledged_ports_carried_into_frame() -> None:
    """Quittierte Ports (Callable liefert Liste) -> Frame traegt sie sortiert."""
    host = EnrichedHost(
        ip="192.168.1.61",
        mac="AA:BB:CC:DD:EE:61",
        ports=(PortInfo(port=3306, state="open", service=""),),
        category="server",
    )
    # 3306 quittiert -> aus der Bewertung raus (flagged leer), aber im acknowledged_ports-Feld.
    severity = _FakeSeverity(result=None, flagged={"critical": [], "notable": []}, acked=[3306])
    with _client([HostEnriched(host=host)], severity=severity).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["acknowledged_ports"] == [3306]
    assert frame["flagged_ports"] == {"critical": [], "notable": []}  # quittiert -> nicht geflaggt


def test_acknowledged_port_stays_in_ports_field() -> None:
    """Quittierter Port bleibt im ``ports``-Feld offen gefuehrt (nur Bewertung reduziert)."""
    host = EnrichedHost(
        ip="192.168.1.62",
        mac="AA:BB:CC:DD:EE:62",
        ports=(PortInfo(port=3306, state="open", service="mysql"),),
        category="server",
    )
    severity = _FakeSeverity(result=None, acked=[3306])
    with _client([HostEnriched(host=host)], severity=severity).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    # ports-Feld traegt 3306 WEITER (offen), acknowledged_ports markiert es als quittiert.
    assert frame["ports"] == [{"port": 3306, "state": "open", "service": "mysql"}]
    assert frame["acknowledged_ports"] == [3306]


# ── Invalid-CIDR -> error-Frame (ScanConfig.__post_init__ wirft ValueError) ──


def test_invalid_cidr_yields_error_frame() -> None:
    with _client([]).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "nonsense"})
        frame = ws.receive_json()
    assert frame["type"] == "error"
    assert "Invalid CIDR" in frame["message"]


# ── Adapter-Exceptions -> error-Frame statt Abbruch (S.6-Merkposten 2) ──────


def test_nmap_scan_error_yields_error_frame() -> None:
    # Erst ein paar Frames, dann wirft der Generator NmapScanError.
    events: list[ScanEvent] = [
        ScanStarted(cidr="10.0.0.0/30", total_hosts=2),
        PhaseChanged(phase="discovery", status="running", total=2),
    ]
    client = _client(events, raise_at_end=NmapScanError("10.0.0.5", "nmap_timeout"))
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "10.0.0.0/30"})
        frames = [ws.receive_json() for _ in range(3)]  # 2 + error

    assert frames[0]["type"] == "scan_started"
    assert frames[2]["type"] == "error"
    assert "nmap_timeout" in frames[2]["message"]


def test_fritz_auth_error_yields_error_frame() -> None:
    client = _client([], raise_at_end=FritzAuthError("fritz.box"))
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "10.0.0.0/30"})
        frame = ws.receive_json()
    assert frame["type"] == "error"
    assert "fritz.box" in frame["message"]


# ── devices-Projektion (S.7d) ──────────────────────────────────────────────────


def test_host_enriched_records_projected_scanned_host() -> None:
    """HostEnriched -> RecordScannedHost mit korrekt projiziertem ScannedHost."""
    host = EnrichedHost(
        ip="192.168.1.5",
        mac="AA:BB:CC:DD:EE:10",
        vendor="Acme",
        hostname="nas.local",
        os_guess="Linux",
        ports=(
            PortInfo(port=22, state="open", service="ssh"),
            PortInfo(port=445, state="open", service="smb"),
        ),
        category="server",  # darf NICHT projiziert werden
    )
    recorder = _FakeRecordScannedHost()
    with _client([HostEnriched(host=host)], recorder=recorder).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        ws.receive_json()  # host_detail-Frame

    assert len(recorder.recorded) == 1
    scanned = recorder.recorded[0]
    assert scanned.mac == "AA:BB:CC:DD:EE:10"
    assert scanned.ip == "192.168.1.5"
    assert scanned.vendor == "Acme"
    assert scanned.hostname == "nas.local"
    assert scanned.os_guess == "Linux"
    # ports -> open_ports (int-Tupel), nicht die PortInfo-Objekte.
    assert scanned.open_ports == (22, 445)
    # category ist kein ScannedHost-Feld -- nicht projiziert (kein Attribut).
    assert not hasattr(scanned, "category")


def test_host_without_mac_is_not_recorded_but_frame_sent() -> None:
    """Host ohne MAC: KEIN RecordScannedHost (skip), Frame trotzdem gesendet."""
    host = EnrichedHost(ip="192.168.1.9", mac="", category="unknown")
    recorder = _FakeRecordScannedHost()
    with _client([HostEnriched(host=host)], recorder=recorder).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["type"] == "host_detail"  # Frame kommt trotzdem
    assert recorder.recorded == []  # aber NICHT verbucht (MAC-keyed, skip)


def test_record_failure_is_best_effort_scan_continues(monkeypatch: pytest.MonkeyPatch) -> None:
    """RecordScannedHost wirft -> Scan laeuft weiter, Frame kommt, Fehler GELOGGT."""
    logged: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(ws_scan.logger, "warning", lambda event, **kw: logged.append((event, kw)))

    host = EnrichedHost(ip="10.0.0.5", mac="AA:BB:CC:DD:EE:11", category="server")
    recorder = _FakeRecordScannedHost(raise_exc=RuntimeError("database is locked"))
    events: list[ScanEvent] = [HostEnriched(host=host), ScanCompleted(total_found=1)]
    with _client(events, recorder=recorder).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "10.0.0.0/24"})
        frames = [ws.receive_json() for _ in range(2)]

    # Trotz DB-Fehler: host_detail + scan_complete kommen durch (Scan nicht abgebrochen).
    assert [f["type"] for f in frames] == ["host_detail", "scan_complete"]
    # Und der Fehler ist GELOGGT (Pflicht: stiller Fang waere S3).
    assert len(logged) == 1
    assert logged[0][0] == "record_scanned_host_failed"
    assert logged[0][1]["mac"] == "AA:BB:CC:DD:EE:11"


# ── analysis-Host-Historie-Schreibnaht (C.2) ───────────────────────────────────


def test_host_enriched_records_seen_mac_in_history() -> None:
    """HostEnriched -> record_seen mit der Host-MAC (Baseline fuer new_host_seen)."""
    host = EnrichedHost(ip="192.168.1.7", mac="AA:BB:CC:DD:EE:20", category="server")
    seen = _FakeRecordSeen()
    with _client([HostEnriched(host=host)], seen_recorder=seen).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        ws.receive_json()  # host_detail-Frame

    assert seen.seen == ["AA:BB:CC:DD:EE:20"]


def test_host_without_mac_is_not_recorded_in_history() -> None:
    """Host ohne MAC: KEIN record_seen (skip), Frame trotzdem gesendet."""
    host = EnrichedHost(ip="192.168.1.8", mac="", category="unknown")
    seen = _FakeRecordSeen()
    with _client([HostEnriched(host=host)], seen_recorder=seen).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["type"] == "host_detail"  # Frame kommt trotzdem
    assert seen.seen == []  # aber NICHT in der Historie (MAC-keyed, skip)


def test_record_seen_failure_is_best_effort_scan_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """record_seen wirft -> Scan laeuft weiter, Frames kommen, Fehler GELOGGT."""
    logged: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(ws_scan.logger, "warning", lambda event, **kw: logged.append((event, kw)))

    host = EnrichedHost(ip="10.0.0.7", mac="AA:BB:CC:DD:EE:21", category="server")
    seen = _FakeRecordSeen(raise_exc=RuntimeError("database is locked"))
    events: list[ScanEvent] = [HostEnriched(host=host), ScanCompleted(total_found=1)]
    with _client(events, seen_recorder=seen).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "10.0.0.0/24"})
        frames = [ws.receive_json() for _ in range(2)]

    # Trotz DB-Fehler: host_detail + scan_complete kommen durch (Scan nicht abgebrochen).
    assert [f["type"] for f in frames] == ["host_detail", "scan_complete"]
    # Und der Fehler ist GELOGGT (Pflicht: stiller Fang waere S3).
    assert len(logged) == 1
    assert logged[0][0] == "record_seen_host_failed"
    assert logged[0][1]["mac"] == "AA:BB:CC:DD:EE:21"


# ── Baseline-Anreicherung des host_detail-Frames (ADR 0019) ────────────────────


def test_host_detail_is_known_default_true_for_known_host() -> None:
    """Host, dessen MAC im Vorzustand der Historie steht -> Frame is_known=true."""
    host = EnrichedHost(ip="192.168.1.30", mac="AA:BB:CC:DD:EE:30", category="server")
    is_known = _FakeIsKnown(known={"AA:BB:CC:DD:EE:30"})
    with _client([HostEnriched(host=host)], is_known=is_known).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["type"] == "host_detail"
    assert frame["is_known"] is True


def test_host_detail_is_known_false_for_host_not_in_history() -> None:
    """Host, dessen MAC NICHT in der Historie ist -> Frame is_known=false (neu)."""
    host = EnrichedHost(ip="192.168.1.31", mac="AA:BB:CC:DD:EE:31", category="server")
    is_known = _FakeIsKnown(known=set())  # leere Historie -> unbekannt
    with _client([HostEnriched(host=host)], is_known=is_known).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["is_known"] is False


def test_host_detail_is_known_read_before_record_seen() -> None:
    """Timing: is_known wird VOR record_seen gelesen.

    Ein Host, der im selben Scan ERSTMALS gesehen wird (leere Historie), ist im Frame
    is_known=false -- obwohl record_seen ihn im selben Durchlauf eintraegt. Der Fake-
    is_known liefert den Vorzustand (leer), der Fake-record_seen sammelt parallel.
    """
    host = EnrichedHost(ip="192.168.1.32", mac="AA:BB:CC:DD:EE:32", category="server")
    is_known = _FakeIsKnown(known=set())
    seen = _FakeRecordSeen()
    client = _client([HostEnriched(host=host)], seen_recorder=seen, is_known=is_known)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    # Vorzustand war leer -> neu, obwohl record_seen die MAC eingetragen hat.
    assert frame["is_known"] is False
    assert is_known.asked == ["AA:BB:CC:DD:EE:32"]
    assert seen.seen == ["AA:BB:CC:DD:EE:32"]


def test_host_detail_enriched_with_stored_curated_fields() -> None:
    """Gespeichertes device -> Frame traegt label/tags/notes/trust_state, nicht Defaults."""
    # Der Scan traegt label/tags/notes LEER; die devices-DB ist die Wahrheit.
    host = EnrichedHost(ip="192.168.1.33", mac="AA:BB:CC:DD:EE:33", category="server")
    stored = _FakeStoredDevice(
        label="NAS",
        tags=("infra", "storage"),
        notes="im Keller",
        trust_state=TrustState.WATCH,
    )
    get_device = _FakeGetDevice(stored=stored)
    client = _client([HostEnriched(host=host)], get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["label"] == "NAS"
    assert frame["tags"] == ["infra", "storage"]
    assert frame["notes"] == "im Keller"
    # trust_state aus der devices-DB ueberschreibt den "neutral"-Default -> haftet
    # auch nach einem echten Re-Scan (das eigentliche Fix-Ziel von Etappe 2).
    assert frame["trust_state"] == "watch"
    assert get_device.asked == ["AA:BB:CC:DD:EE:33"]


def test_host_detail_keeps_scan_defaults_when_device_not_found() -> None:
    """Kein gespeichertes device (DeviceNotFoundError) -> Frame behaelt Scan-Defaults."""
    host = EnrichedHost(
        ip="192.168.1.34",
        mac="AA:BB:CC:DD:EE:34",
        label="vom-scan",
        tags=("scan-tag",),
        notes="scan-notiz",
    )
    get_device = _FakeGetDevice(stored=None)  # -> DeviceNotFoundError
    client = _client([HostEnriched(host=host)], get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    # Keine Kuratierung -> die (hier nicht-leeren) Scan-Werte bleiben unveraendert.
    assert frame["label"] == "vom-scan"
    assert frame["tags"] == ["scan-tag"]
    assert frame["notes"] == "scan-notiz"


def test_is_known_failure_is_best_effort_defaults_true(monkeypatch: pytest.MonkeyPatch) -> None:
    """is_known wirft -> Frame is_known=true (im Zweifel bekannt), Scan laeuft weiter."""
    logged: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(ws_scan.logger, "warning", lambda event, **kw: logged.append((event, kw)))

    host = EnrichedHost(ip="10.0.0.40", mac="AA:BB:CC:DD:EE:40", category="server")
    is_known = _FakeIsKnown(raise_exc=RuntimeError("database is locked"))
    events: list[ScanEvent] = [HostEnriched(host=host), ScanCompleted(total_found=1)]
    client = _client(events, is_known=is_known)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "10.0.0.0/24"})
        frames = [ws.receive_json() for _ in range(2)]

    assert [f["type"] for f in frames] == ["host_detail", "scan_complete"]
    assert frames[0]["is_known"] is True  # im Zweifel bekannt
    assert any(e == "host_is_known_failed" for e, _ in logged)


def test_get_device_real_error_is_best_effort_no_curation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_device wirft (echter Fehler, kein DeviceNotFound) -> keine Kuratierung, Scan laeuft."""
    logged: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(ws_scan.logger, "warning", lambda event, **kw: logged.append((event, kw)))

    host = EnrichedHost(
        ip="10.0.0.41",
        mac="AA:BB:CC:DD:EE:41",
        label="vom-scan",
        notes="scan-notiz",
    )
    get_device = _FakeGetDevice(raise_exc=RuntimeError("database is locked"))
    events: list[ScanEvent] = [HostEnriched(host=host), ScanCompleted(total_found=1)]
    client = _client(events, get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "10.0.0.0/24"})
        frames = [ws.receive_json() for _ in range(2)]

    assert [f["type"] for f in frames] == ["host_detail", "scan_complete"]
    # Keine Kuratierung -> Scan-Defaults bleiben, Scan nicht abgebrochen.
    assert frames[0]["label"] == "vom-scan"
    assert frames[0]["notes"] == "scan-notiz"
    assert any(e == "host_get_device_failed" for e, _ in logged)


def test_host_without_mac_is_known_true_and_no_curation() -> None:
    """Host ohne MAC: is_known=true (nie neu), keine Kuratierung, Frame gesendet."""
    host = EnrichedHost(ip="192.168.1.42", mac="", category="unknown")
    get_device = _FakeGetDevice(stored=_FakeStoredDevice("X", ("t",), "n"))
    is_known = _FakeIsKnown(known=set())
    client = _client([HostEnriched(host=host)], get_device=get_device, is_known=is_known)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["type"] == "host_detail"
    assert frame["is_known"] is True  # MAC-los -> nie neu
    # get_device wird fuer leere MAC gar nicht erst gefragt (Kuratierung uebersprungen).
    assert get_device.asked == []
    assert frame["label"] == ""  # Scan-Default, keine Kuratierung


# ── is_changed: DHCP-IP-Wechsel als Baseline-Signal (ADR 0020) ─────────────────


def test_host_detail_is_changed_true_for_known_host_with_different_ip() -> None:
    """Bekanntes Geraet, gespeicherte last_ip weicht von der Scan-IP ab -> is_changed=true."""
    host = EnrichedHost(ip="192.168.1.50", mac="AA:BB:CC:DD:EE:50", category="server")
    # Vorzustand der devices-DB: dasselbe Geraet wurde zuletzt unter .49 gesehen.
    stored = _FakeStoredDevice(label="NAS", tags=("infra",), notes="", last_ip="192.168.1.49")
    get_device = _FakeGetDevice(stored=stored)
    client = _client([HostEnriched(host=host)], get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["type"] == "host_detail"
    assert frame["is_changed"] is True
    # Kuratierung bleibt unberuehrt vom is_changed-Pfad.
    assert frame["label"] == "NAS"


def test_host_detail_is_changed_false_for_same_ip() -> None:
    """Bekanntes Geraet, gespeicherte last_ip == Scan-IP -> is_changed=false (kein Wechsel)."""
    host = EnrichedHost(ip="192.168.1.51", mac="AA:BB:CC:DD:EE:51", category="server")
    stored = _FakeStoredDevice(label="", tags=(), notes="", last_ip="192.168.1.51")
    get_device = _FakeGetDevice(stored=stored)
    client = _client([HostEnriched(host=host)], get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["is_changed"] is False


def test_host_detail_is_changed_false_for_new_device_without_last_ip() -> None:
    """Frisch angelegtes Geraet (last_ip None) -> nie is_changed (disjunkt zu 'neu')."""
    host = EnrichedHost(ip="192.168.1.52", mac="AA:BB:CC:DD:EE:52", category="server")
    stored = _FakeStoredDevice(label="", tags=(), notes="", last_ip=None)
    get_device = _FakeGetDevice(stored=stored)
    client = _client([HostEnriched(host=host)], get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["is_changed"] is False


def test_host_detail_is_changed_false_when_device_not_found() -> None:
    """Kein gespeichertes Geraet (DeviceNotFoundError) -> is_changed=false (kein Vorzustand)."""
    host = EnrichedHost(ip="192.168.1.53", mac="AA:BB:CC:DD:EE:53", category="server")
    get_device = _FakeGetDevice(stored=None)  # -> DeviceNotFoundError
    client = _client([HostEnriched(host=host)], get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["is_changed"] is False


def test_host_detail_is_changed_read_from_prestate_before_devices_upsert() -> None:
    """Timing (ADR 0020): last_ip wird VOR dem devices-Upsert gelesen.

    Wuerde die Kuratierung NACH _record_host laufen, traege last_ip schon die neue
    Scan-IP -> is_changed waere faelschlich False. Der Fake-GetDevice liefert den
    Vorzustand (.60), die Scan-IP ist .61 -> is_changed muss True sein, und get_device
    muss genau einmal (vor dem Upsert) gefragt worden sein.
    """
    host = EnrichedHost(ip="192.168.1.61", mac="AA:BB:CC:DD:EE:60", category="server")
    stored = _FakeStoredDevice(label="", tags=(), notes="", last_ip="192.168.1.60")
    get_device = _FakeGetDevice(stored=stored)
    recorder = _FakeRecordScannedHost()
    client = _client([HostEnriched(host=host)], recorder=recorder, get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["is_changed"] is True
    assert get_device.asked == ["AA:BB:CC:DD:EE:60"]
    # Der devices-Upsert lief trotzdem (mit der neuen IP) -- der Vorzustand wurde davor gelesen.
    assert recorder.recorded[0].ip == "192.168.1.61"


# ── new_ports: neuer Port seit letztem Scan (Achse A, Port-History, ADR 0026) ──


def test_host_detail_new_ports_lists_only_added_port() -> None:
    """Bekannter Host, Vorzustand {22}, Scan {22, 3389} -> new_ports == [3389]."""
    host = EnrichedHost(
        ip="192.168.1.70",
        mac="AA:BB:CC:DD:EE:70",
        ports=(
            PortInfo(port=22, state="open", service="ssh"),
            PortInfo(port=3389, state="open", service="ms-wbt-server"),
        ),
        category="server",
    )
    stored = _FakeStoredDevice(label="", tags=(), notes="", open_ports=(22,))
    get_device = _FakeGetDevice(stored=stored)
    client = _client([HostEnriched(host=host)], get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["type"] == "host_detail"
    assert frame["new_ports"] == [3389]


def test_host_detail_new_ports_ignores_removed_port() -> None:
    """Bekannter Host, Vorzustand {22, 3389}, Scan {22} -> new_ports == [] (Zugaenge zaehlen)."""
    host = EnrichedHost(
        ip="192.168.1.71",
        mac="AA:BB:CC:DD:EE:71",
        ports=(PortInfo(port=22, state="open", service="ssh"),),
        category="server",
    )
    stored = _FakeStoredDevice(label="", tags=(), notes="", open_ports=(22, 3389))
    get_device = _FakeGetDevice(stored=stored)
    client = _client([HostEnriched(host=host)], get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    # Ein WEGGEFALLENER Port ist KEIN "neuer Port" -- nur Zugaenge.
    assert frame["new_ports"] == []


def test_host_detail_new_ports_empty_when_unchanged() -> None:
    """Bekannter Host, Vorzustand {22}, Scan {22} -> new_ports == [] (unveraendert)."""
    host = EnrichedHost(
        ip="192.168.1.72",
        mac="AA:BB:CC:DD:EE:72",
        ports=(PortInfo(port=22, state="open", service="ssh"),),
        category="server",
    )
    stored = _FakeStoredDevice(label="", tags=(), notes="", open_ports=(22,))
    get_device = _FakeGetDevice(stored=stored)
    client = _client([HostEnriched(host=host)], get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["new_ports"] == []


def test_host_detail_new_ports_empty_for_new_device() -> None:
    """Neues Geraet (DeviceNotFoundError), Scan {22, 3389} -> new_ports == [].

    Kein devices-Vorzustand -> kein Signal, disjunkt zu is_changed: ein neues Geraet
    hat per Definition keine "neuen Ports seit letztem Scan" (es war nie da).
    """
    host = EnrichedHost(
        ip="192.168.1.73",
        mac="AA:BB:CC:DD:EE:73",
        ports=(
            PortInfo(port=22, state="open", service="ssh"),
            PortInfo(port=3389, state="open", service="ms-wbt-server"),
        ),
        category="server",
    )
    get_device = _FakeGetDevice(stored=None)  # -> DeviceNotFoundError
    client = _client([HostEnriched(host=host)], get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["new_ports"] == []


def test_host_detail_new_ports_sorted_ascending() -> None:
    """Mehrere neue Ports, Vorzustand {22}, Scan {22, 80, 443} -> [80, 443] (sortiert)."""
    host = EnrichedHost(
        ip="192.168.1.74",
        mac="AA:BB:CC:DD:EE:74",
        ports=(
            # bewusst unsortierte Reihenfolge -> beweist die aufsteigende Sortierung.
            PortInfo(port=443, state="open", service="https"),
            PortInfo(port=22, state="open", service="ssh"),
            PortInfo(port=80, state="open", service="http"),
        ),
        category="server",
    )
    stored = _FakeStoredDevice(label="", tags=(), notes="", open_ports=(22,))
    get_device = _FakeGetDevice(stored=stored)
    client = _client([HostEnriched(host=host)], get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["new_ports"] == [80, 443]


def test_host_detail_new_ports_read_from_prestate_before_devices_upsert() -> None:
    """Timing/Symmetrie zu is_changed (ADR 0026): open_ports wird VOR dem Upsert gelesen.

    Wuerde die Kuratierung NACH _record_host laufen, traege open_ports schon den neuen
    Scan-Portstand {22, 3389} -> new_ports waere faelschlich []. Der Fake-GetDevice
    liefert den Vorzustand {22}, der Scan bringt {22, 3389} -> new_ports muss [3389]
    sein, get_device genau einmal gefragt, der Upsert lief trotzdem mit dem neuen Stand.
    """
    host = EnrichedHost(
        ip="192.168.1.75",
        mac="AA:BB:CC:DD:EE:75",
        ports=(
            PortInfo(port=22, state="open", service="ssh"),
            PortInfo(port=3389, state="open", service="ms-wbt-server"),
        ),
        category="server",
    )
    stored = _FakeStoredDevice(label="", tags=(), notes="", open_ports=(22,))
    get_device = _FakeGetDevice(stored=stored)
    recorder = _FakeRecordScannedHost()
    client = _client([HostEnriched(host=host)], recorder=recorder, get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["new_ports"] == [3389]
    assert get_device.asked == ["AA:BB:CC:DD:EE:75"]
    # Der devices-Upsert lief trotzdem (mit dem neuen Portstand) -- Vorzustand davor gelesen.
    assert recorder.recorded[0].open_ports == (22, 3389)
