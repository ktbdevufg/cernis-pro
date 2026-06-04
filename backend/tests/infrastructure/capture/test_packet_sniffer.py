"""Tests fuer ``ScapyPacketSniffer`` -- scapy vollstaendig gemockt (KEIN Raw-Socket).

Getestet: (1) Port-Konformitaet, (2) ``_parse_packet`` gegen ein gemocktes
scapy-Paket inkl. Protokoll-Ableitung, (3) die Thread->Loop-Naht (``prn`` aus einem
FREMD-Thread schiebt ueber ``call_soon_threadsafe`` in die Queue, der Generator
yieldet im Loop die richtige Reihenfolge, Stop-Sentinel beendet sauber), (4) die
Thread-Alive-Probe (toter Thread -> ``CaptureError``), (5) ``check_permission``
(``AF_PACKET``-Socket gemockt: ``PermissionError`` -> cap_net_raw-Text, ``OSError``
-> ``None``), (6) ``is_available`` HAS_SCAPY True/False.

Mock-Strategie: die scapy-Layer-KLASSEN (``_scapy.Ether`` etc.) sind als Marker-
Objekte gemockt; ein ``_FakePacket`` kennt genau die Marker seiner Layer und
liefert pro Layer ein Feld-Objekt. ``AsyncSniffer`` ist ein Fake, der ``prn`` aus
einem echten Fremd-Thread feuert -- so wird der thread-sichere Transport real
geprueft (nicht nur im Loop-Thread).

Async-Smokes laufen ueber ``asyncio.run`` (kein ``pytest-asyncio``, wie M.3/S.3).
Gemockt wird am IMPORT-ORT im Adapter-Modul (``infrastructure.capture._scapy``).
"""

import asyncio
import threading
from typing import Any

import pytest

from domain.capture import PacketSummary
from infrastructure.capture import _scapy
from infrastructure.capture.errors import CaptureError
from infrastructure.capture.packet_sniffer import ScapyPacketSniffer
from ports.capture import PacketSnifferPort

# ── Marker-Layer + Fake-Paket ────────────────────────────────────────────────


class _Layer:
    """Marker fuer eine scapy-Layer-Klasse (Identitaet zaehlt, nicht der Inhalt)."""

    def __init__(self, name: str) -> None:
        self.name = name


_ETHER = _Layer("Ether")
_IP = _Layer("IP")
_IPV6 = _Layer("IPv6")
_TCP = _Layer("TCP")
_UDP = _Layer("UDP")
_ICMP = _Layer("ICMP")
_DNS = _Layer("DNS")


class _FakePacket:
    """Minimaler scapy-Paket-Stand-in: kennt seine Layer-Marker + deren Felder."""

    def __init__(self, layers: dict[Any, Any], length: int = 64) -> None:
        self._layers = layers
        self._length = length

    def haslayer(self, layer: Any) -> bool:
        return layer in self._layers

    def __getitem__(self, layer: Any) -> Any:
        return self._layers[layer]

    def __len__(self) -> int:
        return self._length


class _Fields:
    """Frei befuellbares Feld-Objekt fuer einen Layer (``.src``, ``.sport`` ...)."""

    def __init__(self, **kw: Any) -> None:
        self.__dict__.update(kw)


@pytest.fixture
def patch_layers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Setzt die scapy-Layer-Klassen im Adapter-Modul auf die Marker."""
    monkeypatch.setattr(_scapy, "HAS_SCAPY", True)
    monkeypatch.setattr(_scapy, "Ether", _ETHER)
    monkeypatch.setattr(_scapy, "IP", _IP)
    monkeypatch.setattr(_scapy, "IPv6", _IPV6)
    monkeypatch.setattr(_scapy, "TCP", _TCP)
    monkeypatch.setattr(_scapy, "UDP", _UDP)
    monkeypatch.setattr(_scapy, "ICMP", _ICMP)
    monkeypatch.setattr(_scapy, "DNS", _DNS)


# ── Port-Konformitaet ────────────────────────────────────────────────────────


def test_conforms_to_packet_sniffer_protocol() -> None:
    _: PacketSnifferPort = ScapyPacketSniffer()


# ── _parse_packet ────────────────────────────────────────────────────────────


def test_parse_https_over_tcp(patch_layers: None) -> None:
    pkt = _FakePacket(
        {
            _ETHER: _Fields(src="aa:bb", dst="cc:dd"),
            _IP: _Fields(src="10.0.0.1", dst="10.0.0.2"),
            _TCP: _Fields(sport=51000, dport=443, flags=0x02),  # SYN
        },
        length=74,
    )
    ps = ScapyPacketSniffer()._parse_packet(pkt)
    assert isinstance(ps, PacketSummary)
    assert ps.src_mac == "aa:bb"
    assert ps.dst_mac == "cc:dd"
    assert ps.src_ip == "10.0.0.1"
    assert ps.dst_ip == "10.0.0.2"
    assert ps.protocol == "HTTPS"  # 443 verfeinert TCP -> HTTPS
    assert ps.src_port == 51000
    assert ps.dst_port == 443
    assert ps.info == "SYN"
    assert ps.length == 74
    assert ps.is_ipv6 is False


def test_parse_dns_over_udp(patch_layers: None) -> None:
    pkt = _FakePacket(
        {
            _ETHER: _Fields(src="aa:bb", dst="cc:dd"),
            _IP: _Fields(src="10.0.0.1", dst="10.0.0.3"),
            _UDP: _Fields(sport=5000, dport=53),
            _DNS: _Fields(qd=_Fields(qname=b"example.com.")),
        }
    )
    ps = ScapyPacketSniffer()._parse_packet(pkt)
    assert ps is not None
    assert ps.protocol == "DNS"
    assert ps.info == "example.com."


def test_parse_ipv6_takes_precedence(patch_layers: None) -> None:
    pkt = _FakePacket(
        {
            _ETHER: _Fields(src="aa:bb", dst="cc:dd"),
            _IPV6: _Fields(src="fe80::1", dst="fe80::2"),
            _IP: _Fields(src="10.0.0.1", dst="10.0.0.2"),  # darf NICHT gewinnen
        }
    )
    ps = ScapyPacketSniffer()._parse_packet(pkt)
    assert ps is not None
    assert ps.is_ipv6 is True
    assert ps.protocol == "IPv6"
    assert ps.src_ip == "fe80::1"


def test_parse_l2_only(patch_layers: None) -> None:
    pkt = _FakePacket({_ETHER: _Fields(src="aa:bb", dst="cc:dd")})
    ps = ScapyPacketSniffer()._parse_packet(pkt)
    assert ps is not None
    assert ps.protocol == "L2"


# ── Thread->Loop-Naht ────────────────────────────────────────────────────────


class _FakeThread:
    def __init__(self) -> None:
        self._alive = True
        # Hook: wird beim ersten is_alive()-Aufruf (= Alive-Probe im Adapter)
        # gerufen, sodass der Worker das Feuern erst DANACH freigibt (deterministisch
        # nach der Probe, kein Timing-Race).
        self.on_first_probe: Any = None
        self._probed = False

    def is_alive(self) -> bool:
        if not self._probed:
            self._probed = True
            if self.on_first_probe:
                self.on_first_probe()
        return self._alive


class _FakeAsyncSniffer:
    """Realistischer ``AsyncSniffer``-Stand-in fuer die Thread->Loop-Naht.

    Der Worker-Thread lebt waehrend des "Sniffs" (``is_alive() True``, sodass die
    Alive-Probe ihn lebend sieht -- wie ein echter Capture). Er wartet auf ein
    ``_go``-Event und feuert dann ``prn`` aus DIESEM echten Fremd-Thread -- so wird
    der thread-sichere ``call_soon_threadsafe``-Transport real geprueft. Danach
    Selbst-Ende (``count`` erreicht): ``_alive=False`` + ``finished_callback``.
    Ohne gefuetterte Pakete bleibt der Thread am Leben, bis ``stop`` kommt (Dauer-
    Capture-Fall).
    """

    last_instance: "Any" = None

    def __init__(self, prn: Any, store: int, count: int, **kw: Any) -> None:
        self._prn = prn
        self._packets: list[Any] = []
        self._self_end = True
        self._ack: threading.Event | None = None
        self.thread = _FakeThread()
        self.finished_callback: Any = None
        self._worker: threading.Thread | None = None
        self._go = threading.Event()
        self._stop = threading.Event()
        _FakeAsyncSniffer.last_instance = self

    def feed(
        self, packets: list[Any], self_end: bool = True, ack: "threading.Event | None" = None
    ) -> None:
        self._packets = packets
        self._self_end = self_end
        # ack != None -> Ping-Pong: nach JEDEM gefeuerten Paket auf die Konsum-
        # Bestaetigung des Loops warten. Erzwingt, dass der Getter VOR jedem Feuern
        # parkt -> jeder Transport ist ein echtes Thread->wartender-Getter-Wakeup
        # (genau der Fall, den nur call_soon_threadsafe korrekt bedient).
        self._ack = ack

    def release(self) -> None:
        """Gibt das Feuern der Pakete frei (aus dem Test, NACH der Alive-Probe)."""
        self._go.set()

    def start(self) -> None:
        # Das Feuern wird erst NACH der Alive-Probe freigegeben (deterministisch):
        # der Adapter ruft thread.is_alive() einmal -> setzt _go. Bis dahin sieht die
        # Probe den lebenden Worker (realistischer Sniff).
        self.thread.on_first_probe = self._go.set

        def _run() -> None:
            self._go.wait(timeout=5.0)
            for p in self._packets:
                if self._ack is not None:
                    self._ack.clear()
                self._prn(p)
                if self._ack is not None:
                    # Warten, bis der Loop dieses Paket konsumiert hat -> beim
                    # NAECHSTEN Feuern parkt der Getter garantiert wieder.
                    self._ack.wait(timeout=5.0)
            if self._self_end:
                self.thread._alive = False
                if self.finished_callback:
                    self.finished_callback()
            else:
                # Dauer-Capture: am Leben bleiben, bis stop() kommt.
                self._stop.wait(timeout=5.0)

        self._worker = threading.Thread(target=_run)
        self._worker.start()

    def stop(self, join: bool = False) -> None:
        self.thread._alive = False
        self._go.set()
        self._stop.set()
        # Stop-Pfad: das Sentinel kommt ueber finished_callback (wie bei scapy).
        if self.finished_callback:
            self.finished_callback()
        if join and self._worker:
            self._worker.join()


def _make_packet(dst_port: int) -> _FakePacket:
    return _FakePacket(
        {
            _ETHER: _Fields(src="aa:bb", dst="cc:dd"),
            _IP: _Fields(src="10.0.0.1", dst="10.0.0.2"),
            _TCP: _Fields(sport=1000, dport=dst_port, flags=0x10),  # ACK
        }
    )


def test_stream_transports_packets_thread_to_loop_in_order(
    patch_layers: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # prn feuert aus einem Fremd-Thread; der Generator (im Loop) muss die Pakete
    # in der richtigen Reihenfolge yielden -- nur der thread-sichere Transport
    # ueber call_soon_threadsafe macht das korrekt.
    captured: list[int] = []

    def _fake_ctor(**kw: Any) -> _FakeAsyncSniffer:
        snf = _FakeAsyncSniffer(**kw)
        snf.feed([_make_packet(80), _make_packet(443), _make_packet(22)], self_end=True)
        return snf

    monkeypatch.setattr(_scapy, "AsyncSniffer", _fake_ctor)
    # Alive-Probe-Sleep neutralisieren (Test soll nicht 0.8 s warten).
    monkeypatch.setattr(
        "infrastructure.capture.packet_sniffer._ALIVE_PROBE_SECS", 0.0, raising=True
    )

    async def _run() -> None:
        sniffer = ScapyPacketSniffer()
        # Das Feuern gibt der Fake selbst frei, sobald der Adapter die Alive-Probe
        # macht (thread.is_alive) -- also nach dem Start, im richtigen Moment.
        async for ps in sniffer.stream(interface=None, bpf_filter="", max_packets=3):
            captured.append(ps.dst_port)

    asyncio.run(_run())
    # Reihenfolge erhalten + alle drei durchgereicht; Strom durch finished-Sentinel
    # sauber beendet (kein Haengen).
    assert captured == [80, 443, 22]


def test_stream_thread_safe_transport_to_waiting_getter(
    patch_layers: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # SCHARFE Thread-Naht-Probe (Mutation a): Ping-Pong-Feuern erzwingt, dass der
    # Generator-Getter VOR jedem Paket an queue.get() parkt. Dann ist jeder Transport
    # ein Thread->wartender-Getter-Wakeup -- nur call_soon_threadsafe weckt den Getter
    # korrekt im Loop-Thread. Bei direktem put_nowait aus dem Fremd-Thread bleibt das
    # Wakeup im falschen Thread haengen -> der Generator wartet ewig -> wait_for-Timeout.
    captured: list[int] = []
    ack = threading.Event()

    def _fake_ctor(**kw: Any) -> _FakeAsyncSniffer:
        snf = _FakeAsyncSniffer(**kw)
        snf.feed([_make_packet(80), _make_packet(443), _make_packet(22)], self_end=True, ack=ack)
        return snf

    monkeypatch.setattr(_scapy, "AsyncSniffer", _fake_ctor)
    monkeypatch.setattr(
        "infrastructure.capture.packet_sniffer._ALIVE_PROBE_SECS", 0.0, raising=True
    )

    async def _run() -> None:
        sniffer = ScapyPacketSniffer()

        async def _consume() -> None:
            async for ps in sniffer.stream(interface=None, bpf_filter="", max_packets=3):
                captured.append(ps.dst_port)
                ack.set()  # Konsum bestaetigen -> Worker feuert das naechste Paket

        # Haengt die Naht (Mutation a), schlaegt wait_for mit TimeoutError zu.
        await asyncio.wait_for(_consume(), timeout=5.0)

    asyncio.run(_run())
    assert captured == [80, 443, 22]


def test_stop_sentinel_ends_stream(patch_layers: None, monkeypatch: pytest.MonkeyPatch) -> None:
    # Dauer-Capture (kein Selbst-Ende, keine Pakete); stop() schiebt das Sentinel,
    # der Generator muss sauber enden (kein Deadlock).
    def _fake_ctor(**kw: Any) -> _FakeAsyncSniffer:
        snf = _FakeAsyncSniffer(**kw)
        snf.feed([], self_end=False)
        return snf

    monkeypatch.setattr(_scapy, "AsyncSniffer", _fake_ctor)
    monkeypatch.setattr(
        "infrastructure.capture.packet_sniffer._ALIVE_PROBE_SECS", 0.0, raising=True
    )

    async def _run() -> None:
        sniffer = ScapyPacketSniffer()
        agen = sniffer.stream(interface=None, bpf_filter="", max_packets=10)

        async def _stop_soon() -> None:
            await asyncio.sleep(0.02)
            # stop() laeuft synchron (join) -> in den Executor, damit der Loop frei
            # bleibt, das call_soon_threadsafe-Sentinel zu verarbeiten.
            await asyncio.get_running_loop().run_in_executor(None, sniffer.stop)

        task = asyncio.create_task(_stop_soon())
        result = [ps async for ps in agen]
        await task
        assert result == []

    asyncio.run(_run())


def test_dead_sniffer_thread_raises_capture_error(
    patch_layers: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Thread stirbt sofort (Permission-Fehler) -> CaptureError, KEINE leere Iteration.
    class _DeadSniffer(_FakeAsyncSniffer):
        def start(self) -> None:
            self.thread._alive = False  # sofort tot

    def _fake_ctor(**kw: Any) -> _DeadSniffer:
        return _DeadSniffer(**kw)

    monkeypatch.setattr(_scapy, "AsyncSniffer", _fake_ctor)
    monkeypatch.setattr(
        "infrastructure.capture.packet_sniffer._ALIVE_PROBE_SECS", 0.0, raising=True
    )

    async def _run() -> None:
        sniffer = ScapyPacketSniffer()
        with pytest.raises(CaptureError):
            async for _ in sniffer.stream(interface=None, bpf_filter="", max_packets=3):
                pass

    asyncio.run(_run())


def test_stream_without_scapy_raises_capture_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_scapy, "HAS_SCAPY", False)

    async def _run() -> None:
        sniffer = ScapyPacketSniffer()
        with pytest.raises(CaptureError):
            async for _ in sniffer.stream(interface=None, bpf_filter="", max_packets=3):
                pass

    asyncio.run(_run())


# ── check_permission ─────────────────────────────────────────────────────────


def test_check_permission_permission_error_yields_capnetraw_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise_perm(*a: Any, **k: Any) -> Any:
        raise PermissionError("nope")

    monkeypatch.setattr("infrastructure.capture.packet_sniffer.socket.socket", _raise_perm)
    msg = ScapyPacketSniffer().check_permission()
    assert msg is not None
    assert "CAP_NET_RAW" in msg
    assert "setcap cap_net_raw+eip" in msg


def test_check_permission_oserror_is_inconclusive_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise_os(*a: Any, **k: Any) -> Any:
        raise OSError("AF_PACKET unsupported")

    monkeypatch.setattr("infrastructure.capture.packet_sniffer.socket.socket", _raise_os)
    # OSError ist KEIN Rechte-Fehler -> None (inconclusive, scapy darf es versuchen).
    assert ScapyPacketSniffer().check_permission() is None


def test_check_permission_ok_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeSock:
        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "infrastructure.capture.packet_sniffer.socket.socket", lambda *a, **k: _FakeSock()
    )
    assert ScapyPacketSniffer().check_permission() is None


# ── is_available ─────────────────────────────────────────────────────────────


def test_is_available_reflects_has_scapy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_scapy, "HAS_SCAPY", True)
    assert ScapyPacketSniffer().is_available() is True
    monkeypatch.setattr(_scapy, "HAS_SCAPY", False)
    assert ScapyPacketSniffer().is_available() is False
