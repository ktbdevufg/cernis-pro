"""Tests fuer die Helfer-Clients -- NUR Pfade ohne echten Subprozess.

Ein echter Spawn braucht den Helfer + CAP_NET_RAW + scapy/Raw-Socket -- das wird hier
bewusst NICHT gefahren. Geprueft werden die deterministischen Naht-Punkte:

* Spawn-Fehler (Kommando zeigt auf nicht-existierendes Programm) -> ehrlicher
  Fehlertext (pcap) bzw. ``[]`` (LLDP, S3-frei); kein Crash;
* die Reader-Hook-Protokoll-Muster (``_handle_message``): PACKET -> Queue,
  STOPPED -> Strom-Ende-Sentinel, EXPORTED -> Export-Event;
* ``next_packet`` Reihenfolge + Sentinel; ``is_running`` ohne Lauf False; ``stop``
  idempotent.
"""

import socket
import sys
import time
from typing import Any

import pytest

from infrastructure.sniffd.protocol import MessageType
from infrastructure.sniffd_client import base
from infrastructure.sniffd_client.dns_client import DnsHelperClient
from infrastructure.sniffd_client.lldp_client import LldpHelperClient
from infrastructure.sniffd_client.pcap_client import _STREAM_END, PcapHelperClient
from infrastructure.sniffd_client.sni_client import SniHelperClient

# ── Spawn-Fehlerpfade (ohne echten Subprozess) ────────────────────────────────


def _point_spawn_at_nonexistent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        base,
        "_spawn_command",
        lambda socket_path: ["/nonexistent/cernis-sniffd-does-not-exist", socket_path],
    )


def test_pcap_start_returns_honest_error_when_spawn_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _point_spawn_at_nonexistent(monkeypatch)
    client = PcapHelperClient()
    error = client.start(interface=None, bpf_filter="", max_packets=10)
    assert error is not None
    assert "nicht gestartet" in error
    assert client.is_running() is False
    client.stop()  # idempotent, kein Crash


def test_sni_start_returns_honest_error_when_spawn_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _point_spawn_at_nonexistent(monkeypatch)
    client = SniHelperClient()
    error = client.start(None)
    assert error is not None
    assert "nicht gestartet" in error
    assert client.is_running() is False


def test_dns_start_returns_honest_error_when_spawn_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _point_spawn_at_nonexistent(monkeypatch)
    client = DnsHelperClient()
    error = client.start(None)
    assert error is not None
    assert "nicht gestartet" in error
    assert client.is_running() is False


def test_lldp_capture_returns_empty_when_spawn_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # S3-Heilung: Spawn-Fehler -> [] (keine Nachbarn statt Crash).
    _point_spawn_at_nonexistent(monkeypatch)
    result = LldpHelperClient().capture(interface=None, duration=0.1)
    assert result == []


def test_pcap_export_without_client_returns_false() -> None:
    # Kein verbundener Client -> export_pcap ist False (kein Senden moeglich).
    assert PcapHelperClient().export_pcap("/tmp/x.pcap") is False


def test_pcap_is_running_false_without_run() -> None:
    assert PcapHelperClient().is_running() is False


# ── Reader-Hook-Protokoll-Muster (PcapHelperClient._handle_message) ───────────


def _packet_msg(dst_port: int) -> dict[str, Any]:
    return {
        "type": MessageType.PACKET,
        "timestamp": 1.0,
        "protocol": "TCP",
        "dst_port": dst_port,
        "length": 64,
    }


def test_pcap_handle_packet_enqueues_in_order() -> None:
    client = PcapHelperClient()
    client._handle_message(_packet_msg(80))
    client._handle_message(_packet_msg(443))
    # type ist entfernt; Reihenfolge erhalten.
    first = client.next_packet(timeout=1.0)
    second = client.next_packet(timeout=1.0)
    assert "type" not in first
    assert first["dst_port"] == 80
    assert second["dst_port"] == 443


def test_pcap_handle_stopped_enqueues_stream_end() -> None:
    client = PcapHelperClient()
    client._handle_message({"type": MessageType.STOPPED})
    assert client.next_packet(timeout=1.0) is _STREAM_END


def test_pcap_handle_exported_sets_result_and_event() -> None:
    client = PcapHelperClient()
    # Vor der Quittung ist das Event nicht gesetzt.
    assert client._export_done.is_set() is False
    client._handle_message({"type": MessageType.EXPORTED, "ok": True})
    assert client._export_done.is_set() is True
    assert client._export_result is True
    # Auch ok=False wird korrekt uebernommen.
    client._export_done.clear()
    client._handle_message({"type": MessageType.EXPORTED, "ok": False})
    assert client._export_result is False


def test_pcap_stop_enqueues_stream_end_without_run() -> None:
    # stop() ohne laufenden Helfer ist idempotent und reicht das Sentinel nach, damit
    # ein wartender next_packet aufwacht.
    client = PcapHelperClient()
    client.stop()
    assert client.next_packet(timeout=1.0) is _STREAM_END


# ── SNI-Reader-Hook (HIT-Sammlung) ────────────────────────────────────────────


def test_sni_handle_hit_collects_into_poll_hits() -> None:
    client = SniHelperClient()
    client._handle_message(
        {
            "type": MessageType.HIT,
            "hostname": "example.com",
            "remote_ip": "93.184.216.34",
            "remote_port": 443,
            "monotonic_ts": 1.0,
        }
    )
    # Nicht-HIT-Nachrichten ignoriert der Lese-Pfad.
    client._handle_message({"type": MessageType.STOPPED})
    hits = client.poll_hits()
    assert len(hits) == 1
    assert "type" not in hits[0]
    assert hits[0]["hostname"] == "example.com"
    # poll_hits leert -- zweiter Aufruf ist leer.
    assert client.poll_hits() == []


# ── DNS-Reader-Hook (DNS_QUERY-Sammlung) ──────────────────────────────────────


def test_dns_handle_query_collects_into_poll_queries() -> None:
    client = DnsHelperClient()
    client._handle_message(
        {
            "type": MessageType.DNS_QUERY,
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "l4": "udp",
            "monotonic_ts": 1.0,
            "qname": "example.com",
        }
    )
    # Nicht-DNS_QUERY-Nachrichten ignoriert der Lese-Pfad.
    client._handle_message({"type": MessageType.STOPPED})
    queries = client.poll_queries()
    assert len(queries) == 1
    assert "type" not in queries[0]
    assert queries[0]["src_ip"] == "192.168.1.10"
    assert queries[0]["qname"] == "example.com"
    # poll_queries leert -- zweiter Aufruf ist leer.
    assert client.poll_queries() == []


# ── Gespraechiger Helfer blockiert nicht (Pipe-Puffer-Regression) ─────────────
#
# Regression zu Etappe 2d: der Helfer wurde ohne stdout/stderr-Umlenkung gespawnt
# und erbte damit die fds des Backends. Mit einer Pipe OHNE Leser laeuft der
# 64-KiB-Puffer voll und der Helfer blockiert im ``write`` -- moeglicherweise BEVOR
# er die Socket-Datei anlegt: er lebt, bindet aber nie (gemessenes Bild im Bundle:
# Prozess laeuft, Socket-Verzeichnis leer). Der Drain-Thread muss das verhindern.
#
# Bewusst OHNE echten sniffd/scapy/CAP_NET_RAW: ein nackter Python-Prozess, der
# deutlich mehr als einen Pipe-Puffer auf stderr schreibt und ERST DANACH bindet.

# Deutlich ueber dem 64-KiB-Pipe-Puffer -- ohne Drain blockiert das sicher.
_NOISE_BYTES = 512 * 1024

_NOISY_HELPER = r"""
import socket, sys

# Erst laut sein: mehr als ein Pipe-Puffer, auf stdout UND stderr verteilt.
line = "x" * 200
for i in range({noise} // (len(line) + 1) // 2):
    print(f"stderr-noise {{i}} {line}", file=sys.stderr)
    print(f"stdout-noise {{i}} {line}", file=sys.stdout)
sys.stderr.flush()
sys.stdout.flush()

# Und ERST DANACH binden -- genau die Reihenfolge, die den Bug sichtbar macht.
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sys.argv[1])
srv.listen(1)
conn, _ = srv.accept()
# Verbindung offen halten, bis das Gegenueber schliesst/terminiert.
try:
    while conn.recv(4096):
        pass
except OSError:
    pass
""".replace("{noise}", str(_NOISE_BYTES))


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="AF_UNIX noetig (nicht Windows)")
def test_spawn_survives_helper_with_huge_startup_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ein Helfer mit >64 KiB Startausgabe bindet trotzdem -- kein Pipe-Deadlock."""
    monkeypatch.setattr(
        base,
        "_spawn_command",
        lambda socket_path: [sys.executable, "-c", _NOISY_HELPER, socket_path],
    )

    helper = base._BaseSubprocessHelper()
    try:
        error = helper._spawn_connect_send({"type": "PING"}, "Test")
        # Ohne Drain-Thread haengt der Fake im vollen Puffer, die Socket-Datei
        # entsteht nie und _wait_for_socket laeuft in den Timeout.
        assert error is None, f"Spawn scheiterte: {error}"
        assert helper._sock is not None
    finally:
        helper._cleanup()


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="AF_UNIX noetig (nicht Windows)")
def test_helper_output_reaches_backend_log(monkeypatch: pytest.MonkeyPatch) -> None:
    """Die Helfer-Ausgabe wird nicht verworfen, sondern landet im Backend-Log."""
    seen: list[dict[str, Any]] = []

    class _CapturingLogger:
        def info(self, event: str, **kw: Any) -> None:
            seen.append({"event": event, **kw})

        def debug(self, event: str, **kw: Any) -> None:
            pass

        def warning(self, event: str, **kw: Any) -> None:
            pass

    monkeypatch.setattr(base, "_logger", _CapturingLogger())
    monkeypatch.setattr(
        base,
        "_spawn_command",
        lambda socket_path: [sys.executable, "-c", _NOISY_HELPER, socket_path],
    )

    helper = base._BaseSubprocessHelper()
    try:
        assert helper._spawn_connect_send({"type": "PING"}, "Test") is None
        # Der Drain laeuft nebenlaeufig -- kurz pollen statt fix schlafen.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and len(seen) < 2:
            time.sleep(0.02)
    finally:
        helper._cleanup()

    lines = [e for e in seen if e["event"] == "sniffd_helper_output"]
    assert lines, "Keine Helfer-Ausgabe im Log -- Diagnosequelle ginge verloren"
    assert all(e["helper"] == "Test" for e in lines)
    # BEIDE Stroeme muessen ankommen (stderr ist auf stdout umgelenkt).
    joined = " ".join(e["line"] for e in lines)
    assert "stderr-noise" in joined
    assert "stdout-noise" in joined
