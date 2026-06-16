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
from domain.devices import ScannedHost
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
    """

    def __init__(
        self,
        label: str,
        tags: tuple[str, ...],
        notes: str,
        last_ip: str | None = None,
    ) -> None:
        self.label = label
        self.tags = tags
        self.notes = notes
        self.last_ip = last_ip


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


def _client(
    events: list[ScanEvent],
    raise_at_end: Exception | None = None,
    recorder: _FakeRecordScannedHost | None = None,
    seen_recorder: _FakeRecordSeen | None = None,
    get_device: _FakeGetDevice | None = None,
    is_known: _FakeIsKnown | None = None,
) -> TestClient:
    record = recorder or _FakeRecordScannedHost()
    record_seen = seen_recorder or _FakeRecordSeen()
    device_reader = get_device or _FakeGetDevice()
    known_reader = is_known or _FakeIsKnown()
    app = FastAPI()
    app.add_api_websocket_route(
        "/ws/scan",
        make_ws_scan(
            lambda: _FakeRunNetworkScan(events, raise_at_end),
            lambda: record,
            lambda: record_seen,
            lambda: device_reader,
            lambda: known_reader,
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


def test_host_detail_frame_has_24_keys_incl_source_additional_ips_is_known_is_changed() -> None:
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
    # 24 Keys: die 20 S.1-Contract-Keys + source (S.7f) + additional_ips (MAC-Gruppierung)
    # + is_known (Baseline-Anreicherung, ADR 0019) + is_changed (DHCP-Wechsel, ADR 0020).
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
    }
    assert frame["ports"] == [{"port": 22, "state": "open", "service": "ssh"}]
    assert frame["category"] == "server"
    assert frame["additional_ips"] == ["10.0.0.6", "10.0.0.7"]
    assert frame["source"] == "arp"  # Quelle haengt am persistenten Host (S.7f)


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
    """Gespeichertes device -> Frame traegt dessen label/tags/notes, nicht Scan-Defaults."""
    # Der Scan traegt label/tags/notes LEER; die devices-DB ist die Wahrheit.
    host = EnrichedHost(ip="192.168.1.33", mac="AA:BB:CC:DD:EE:33", category="server")
    stored = _FakeStoredDevice(label="NAS", tags=("infra", "storage"), notes="im Keller")
    get_device = _FakeGetDevice(stored=stored)
    client = _client([HostEnriched(host=host)], get_device=get_device)
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/24"})
        frame = ws.receive_json()

    assert frame["label"] == "NAS"
    assert frame["tags"] == ["infra", "storage"]
    assert frame["notes"] == "im Keller"
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
