"""Tests fuer ``ScapyPacketSniffer`` -- Fake-Helfer-Client statt echtem Subprozess/scapy.

ETAPPE 3b (Privilege-Separation): Der Adapter faehrt scapy nicht mehr selbst, sondern
spricht den Helfer ueber den ``PcapHelperClient`` an. Wir injizieren einen Fake-Client
(kontrolliert STARTED/ERROR, speist PACKET-dicts aus einem ECHTEN Fremd-Thread ein) und
pruefen:

* Port-Konformitaet;
* die Thread->Loop-Naht: der Fake-Client fuellt die PACKET-dicts aus einem Fremd-Thread,
  der Bruecken-Pump zieht sie und schiebt ueber ``call_soon_threadsafe`` in die
  ``asyncio.Queue``, der Generator yieldet ``PacketSummary`` in RICHTIGER Reihenfolge;
* das Strom-Ende: Helfer-``STOPPED`` (Client-Sentinel) beendet den Generator sauber;
* Start-Fehler (Helfer-ERROR/Spawn) -> ``CaptureError`` (keine stille Leer-Iteration);
* ``export_pcap`` wird an den Client durchgereicht (Helfer-seitiger Export);
* ``check_permission`` ist optimistisch ``None`` (B-Semantik, kein Backend-Raw-Probe);
* ``is_available`` spiegelt den Helfer-Einstieg (dev: ``sniffd.py`` existiert -> True).

Async-Smokes laufen ueber ``asyncio.run`` (kein ``pytest-asyncio``, wie M.3/S.3).
KEIN echter scapy/Raw-Socket/Subprozess in diesem Modul.
"""

import asyncio
import queue
import socket
import threading
from typing import Any

import pytest

from domain.capture import PacketSummary
from infrastructure.capture.errors import CaptureError
from infrastructure.capture.packet_sniffer import ScapyPacketSniffer
from infrastructure.sniffd_client.pcap_client import _STREAM_END
from ports.capture import PacketSnifferPort

# ── Fake-PcapClient ──────────────────────────────────────────────────────────


class _FakePcapClient:
    """In-Memory-``PcapClient``: kontrolliert START-Antwort + speist PACKET-dicts ein.

    ``start_error`` ``None`` -> ``start()`` meldet Erfolg und ``is_running()`` wird
    True. Ein Text -> ``start()`` gibt ihn zurueck (der Adapter macht eine CaptureError
    daraus). ``feed_from_thread`` schiebt eine Liste PACKET-dicts aus einem ECHTEN
    Fremd-Thread in die interne Queue und beendet mit dem Strom-Ende-Sentinel -- so
    wird der thread-sichere Transport (Reader-Thread -> Pump -> Loop) real geprueft.
    """

    def __init__(self, *, start_error: str | None = None, export_ok: bool = True) -> None:
        self._start_error = start_error
        self._export_ok = export_ok
        self._running = False
        self._queue: queue.Queue[Any] = queue.Queue()
        self.start_calls: list[tuple[str | None, str, int]] = []
        self.exported_to: str | None = None
        self.stop_calls = 0
        self._feeder: threading.Thread | None = None

    def start(self, interface: str | None, bpf_filter: str, max_packets: int) -> str | None:
        self.start_calls.append((interface, bpf_filter, max_packets))
        if self._start_error is not None:
            return self._start_error
        self._running = True
        return None

    def next_packet(self, timeout: float | None = None) -> Any:
        return self._queue.get(timeout=timeout)

    def export_pcap(self, path: str) -> bool:
        if self._export_ok:
            self.exported_to = path
            return True
        return False

    def stop(self) -> None:
        self.stop_calls += 1
        self._running = False
        # Wie der echte Client: stop schiebt das Strom-Ende-Sentinel nach.
        self._queue.put(_STREAM_END)

    def is_running(self) -> bool:
        return self._running

    def feed_from_thread(self, packets: list[dict[str, Any]], *, end: bool = True) -> None:
        """Speist PACKET-dicts aus einem echten Fremd-Thread ein (+ optional Sentinel)."""

        def _run() -> None:
            for p in packets:
                self._queue.put(p)
            if end:
                self._running = False
                self._queue.put(_STREAM_END)

        self._feeder = threading.Thread(target=_run)
        self._feeder.start()


def _pkt(dst_port: int, protocol: str = "HTTPS") -> dict[str, Any]:
    """Ein rohes Helfer-PACKET-dict (Felder wie ``sniff_core.parse_packet``)."""
    return {
        "timestamp": 1.0,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": protocol,
        "src_port": 1000,
        "dst_port": dst_port,
        "length": 64,
    }


# ── Port-Konformitaet ────────────────────────────────────────────────────────


def test_conforms_to_packet_sniffer_protocol() -> None:
    _: PacketSnifferPort = ScapyPacketSniffer()


# ── Thread->Loop-Naht ────────────────────────────────────────────────────────


def test_stream_transports_packets_thread_to_loop_in_order() -> None:
    # Der Fake-Client feuert PACKET-dicts aus einem Fremd-Thread; der Generator (im
    # Loop) muss die Pakete in der richtigen Reihenfolge als PacketSummary yielden --
    # nur der thread-sichere Transport ueber call_soon_threadsafe macht das korrekt.
    fake = _FakePcapClient()
    captured: list[int] = []

    async def _run() -> None:
        sniffer = ScapyPacketSniffer(client_factory=lambda: fake)
        agen = sniffer.stream(interface=None, bpf_filter="", max_packets=3)
        # Erst nach dem Start (Client.start lief) die Pakete aus dem Fremd-Thread
        # einspeisen -- so wartet der Generator-Getter bereits.
        fake.feed_from_thread([_pkt(80), _pkt(443), _pkt(22)], end=True)
        async for ps in agen:
            assert isinstance(ps, PacketSummary)
            captured.append(ps.dst_port)

    asyncio.run(_run())
    assert captured == [80, 443, 22]


def test_stream_stopped_sentinel_ends_stream() -> None:
    # Dauer-Capture (keine Pakete); stop() schiebt das Strom-Ende-Sentinel, der
    # Generator muss sauber enden (kein Deadlock).
    fake = _FakePcapClient()

    async def _run() -> None:
        sniffer = ScapyPacketSniffer(client_factory=lambda: fake)
        agen = sniffer.stream(interface=None, bpf_filter="", max_packets=10)

        async def _stop_soon() -> None:
            await asyncio.sleep(0.02)
            await asyncio.get_running_loop().run_in_executor(None, sniffer.stop)

        task = asyncio.create_task(_stop_soon())
        result = [ps async for ps in agen]
        await task
        assert result == []

    asyncio.run(_run())
    assert fake.stop_calls >= 1


def test_stream_start_error_raises_capture_error() -> None:
    # Helfer-ERROR/Spawn-Fehler -> CaptureError, KEINE leere Iteration.
    fake = _FakePcapClient(start_error="Permission denied -- requires CAP_NET_RAW.")

    async def _run() -> None:
        sniffer = ScapyPacketSniffer(client_factory=lambda: fake)
        with pytest.raises(CaptureError, match="CAP_NET_RAW"):
            async for _ in sniffer.stream(interface=None, bpf_filter="", max_packets=3):
                pass

    asyncio.run(_run())


def test_stream_forwards_start_arguments() -> None:
    fake = _FakePcapClient()

    async def _run() -> None:
        sniffer = ScapyPacketSniffer(client_factory=lambda: fake)
        agen = sniffer.stream(interface="ens33", bpf_filter="tcp port 443", max_packets=5)
        fake.feed_from_thread([], end=True)
        async for _ in agen:
            pass

    asyncio.run(_run())
    assert fake.start_calls == [("ens33", "tcp port 443", 5)]


def test_summary_from_dict_skips_malformed() -> None:
    # Ein kaputtes PACKET-dict (unbekanntes Feld) wird still verworfen -> None.
    assert ScapyPacketSniffer._summary_from_dict({"nope": 1}) is None
    ok = ScapyPacketSniffer._summary_from_dict(_pkt(443))
    assert ok is not None
    assert ok.dst_port == 443
    assert ok.protocol == "HTTPS"


# ── export_pcap / stop ───────────────────────────────────────────────────────


def test_export_pcap_delegates_to_client_while_connected() -> None:
    # export_pcap reicht an den (verbundenen) Client durch -- VOR stop (RunCapture-
    # Reihenfolge). Kein laufender Client -> False.
    fake = _FakePcapClient(export_ok=True)

    async def _run() -> None:
        sniffer = ScapyPacketSniffer(client_factory=lambda: fake)
        # Vor dem Start: kein Client -> False.
        assert sniffer.export_pcap("/tmp/x.pcap") is False
        collected: list[int] = []

        async def _consume() -> None:
            async for ps in sniffer.stream(interface=None, bpf_filter="", max_packets=10):
                collected.append(ps.dst_port)
                # Erstes Paket konsumiert -> Client noch verbunden -> exportieren,
                # dann stop() (schiebt das Sentinel -> der Generator endet).
                assert sniffer.export_pcap("/tmp/cernis.pcap") is True
                assert fake.exported_to == "/tmp/cernis.pcap"
                await asyncio.get_running_loop().run_in_executor(None, sniffer.stop)

        # end=False: nach dem einen Paket kommt nichts -- stop() beendet den Strom.
        fake.feed_from_thread([_pkt(443)], end=False)
        await _consume()
        assert collected == [443]

    asyncio.run(_run())
    assert fake.stop_calls >= 1


def test_stop_idempotent_without_stream() -> None:
    ScapyPacketSniffer().stop()  # kein Crash ohne laufenden Strom


def test_is_running_false_without_stream() -> None:
    assert ScapyPacketSniffer().is_running() is False


# ── check_permission / is_available (B-Semantik) ──────────────────────────────


def test_check_permission_is_optimistic_none() -> None:
    # ETAPPE-3b-(B)-Semantik: keine Backend-Raw-Socket-Probe mehr (das Backend hat
    # kein CAP_NET_RAW). Optimistisch None; der echte Fehler kommt beim stream-Start
    # ueber die ERROR-Naht des Helfers.
    assert ScapyPacketSniffer().check_permission() is None


def test_is_available_reflects_helper_entry_in_dev() -> None:
    # dev-Umgebung mit tragender Plattform (Linux/macOS, AF_UNIX vorhanden):
    # backend/sniffd.py existiert -> is_available() True. Auf Windows (kein AF_UNIX)
    # meldet die Verfuegbarkeitspruefung ehrlich False, obwohl die Helfer-Binary
    # existiert (W1: Npcap/AF_UNIX-Naht noch nicht tragbar) -- deshalb plattform-abhaengig.
    expected = hasattr(socket, "AF_UNIX")
    assert ScapyPacketSniffer().is_available() is expected
