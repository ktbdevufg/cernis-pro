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
