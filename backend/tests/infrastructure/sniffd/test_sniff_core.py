"""Tests der pcap-/LLDP-/Export-Kerne (Etappe 3a) -- OHNE echten Raw-Socket/scapy.

Der harte Kern dieser Tests laeuft scapy-frei: ``parse_packet`` muss bei kaputtem
Input (Objekt ohne ``haslayer``, Objekt das wirft) ROBUST ``None`` liefern statt zu
crashen -- das ist der vom Vertrag vorgesehene "uninteressantes/kaputtes Paket"-Fall.
``run_lldp_sniff`` darf ohne ``scapy.contrib`` (CI-Fall) NICHT crashen, sondern ``[]``
liefern. ``export_pcap`` ohne Pakete ist deterministisch ``False``.

Die macOS-Rechteprobe (``/dev/bpf*``) wird plattformfrei per ``monkeypatch`` auf
``os.open``/``sys.platform`` geprueft -- ohne echte Geraeteknoten, damit sie auch auf
Linux-CI laeuft.

Ein optionaler scapy-Pfad (echtes synthetisches Paket -> Summary-dict) laeuft NUR,
wenn scapy lokal verfuegbar ist (``skipif``) -- in CI ohne scapy wird er uebersprungen,
nicht erzwungen.
"""

import errno
import os
import socket
import sys
import threading
from typing import Any

import pytest

from infrastructure.sniffd import _scapy, sniff_core
from infrastructure.sniffd.sniff_core import (
    export_pcap,
    parse_packet,
    run_lldp_sniff,
    start_dns_sniff,
)

# ── parse_packet-Robustheit (scapy-frei) ──────────────────────────────────────


class _NoHaslayer:
    """Ein Objekt ohne ``haslayer`` -- ``parse_packet`` muss daran sauber scheitern."""


class _RaisingPacket:
    """Ein ``haslayer``, das wirft -- der Parse-Fehler muss zu ``None`` werden."""

    def haslayer(self, _layer: Any) -> bool:
        raise RuntimeError("kaputtes Paket")


def test_parse_packet_object_without_haslayer_returns_none() -> None:
    """Ein Objekt ohne ``haslayer`` -> ``None`` (AttributeError gefangen, kein Crash)."""
    assert parse_packet(_NoHaslayer()) is None


def test_parse_packet_raising_packet_returns_none() -> None:
    """``haslayer`` wirft -> ``None`` (Parse-Fehler verworfen, kein Crash)."""
    assert parse_packet(_RaisingPacket()) is None


def test_parse_packet_none_returns_none() -> None:
    """``None`` als Paket -> ``None`` (kein Crash beim Attribut-Zugriff)."""
    assert parse_packet(None) is None


# ── run_lldp_sniff ohne scapy.contrib (CI-Fall) ───────────────────────────────


def test_run_lldp_sniff_without_contrib_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fehlt ``scapy.contrib`` (HAS_SCAPY_CONTRIB False) -> ``[]`` + Warn, kein Crash.

    S3-Heilung wie im Original: ohne contrib kann nicht geparst werden, das Aussen-
    verhalten ist eine leere Liste (kein Sniff-Versuch). Wir simulieren den CI-Fall
    per ``monkeypatch`` auf das geteilte ``_scapy``-Flag -- so braucht der Test weder
    Rechte noch einen echten Sniff.
    """
    monkeypatch.setattr(_scapy, "HAS_SCAPY_CONTRIB", False)
    assert run_lldp_sniff(interface=None, duration=0.1) == []


# ── export_pcap (best-effort) ─────────────────────────────────────────────────


def test_export_pcap_empty_returns_false(tmp_path: Any) -> None:
    """Leere Rohpaket-Liste -> ``False`` (nichts zu schreiben), deterministisch."""
    assert export_pcap([], str(tmp_path / "out.pcap")) is False


# ── optionaler scapy-Pfad (nur wenn scapy lokal da ist) ───────────────────────


@pytest.mark.skipif(not _scapy.HAS_SCAPY, reason="scapy nicht verfuegbar (CI-Fall)")
def test_parse_packet_real_tcp_https_summary() -> None:
    """Ein echtes synthetisches TCP:443-Paket -> Summary-dict mit HTTPS-Protokoll.

    Nur mit lokal verfuegbarem scapy (KEIN Netz/Raw-Socket noetig -- das Paket wird
    rein im Speicher gebaut). Prueft die portierte Parse-Logik end-to-end: Ether-MACs,
    IPv4, TCP-Ports und die 443->HTTPS-Verfeinerung; fehlende Felder fehlen (nicht None).
    """
    pkt = (
        _scapy.Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        / _scapy.IP(src="10.0.0.1", dst="10.0.0.2")
        / _scapy.TCP(sport=51000, dport=443, flags="S")
    )
    summary = parse_packet(pkt)
    assert summary is not None
    assert summary["src_mac"] == "aa:bb:cc:dd:ee:ff"
    assert summary["dst_mac"] == "11:22:33:44:55:66"
    assert summary["src_ip"] == "10.0.0.1"
    assert summary["dst_ip"] == "10.0.0.2"
    assert summary["protocol"] == "HTTPS"
    assert summary["src_port"] == 51000
    assert summary["dst_port"] == 443
    assert "SYN" in summary["info"]
    assert summary["length"] > 0
    assert "timestamp" in summary
    # Fehlende Felder werden weggelassen, nicht None-gefuellt.
    assert "is_ipv6" not in summary


# ── DNS-Sniff-Klassifikation (start_dns_sniff, nur mit lokal verfuegbarem scapy) ─


class _FakeSniffer:
    """Ersetzt ``AsyncSniffer``: faengt den prn ab, haelt einen lebenden Thread.

    ``start_dns_sniff`` erwartet nach ``start()`` einen lebenden ``.thread`` (Alive-
    Probe). Ein realer Daemon-Thread, der auf ein Event wartet, erfuellt das ohne
    echten Raw-Socket -- so wird NUR die reine Klassifikations-Logik im prn getestet.
    """

    def __init__(self, **kwargs: Any) -> None:
        self.prn = kwargs["prn"]
        self.promisc = kwargs["promisc"]
        self.filter = kwargs["filter"]
        self._alive = threading.Event()
        self.thread = threading.Thread(target=self._alive.wait, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self, join: bool = False) -> None:
        self._alive.set()
        if join:
            self.thread.join(timeout=1.0)


@pytest.mark.skipif(not _scapy.HAS_SCAPY, reason="scapy nicht verfuegbar (CI-Fall)")
def test_start_dns_sniff_classifies_requests_and_ignores_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nur ANFRAGEN (dport==53) ergeben ein ``on_query``; Antworten/Nicht-53 nicht.

    Ein synthetisches UDP/53-Paket (Anfrage) -> genau ein ``on_query`` mit
    ``src_ip``/``dst_ip``/``l4="udp"`` (+ ``qname``, weil scapy DNS parst). Ein Paket
    mit ``sport==53`` (Antwort) und ein Nicht-53-Paket loesen KEINEN Aufruf aus.
    Die Rohpakete werden rein im Speicher gebaut (kein Netz/Raw-Socket); der
    ``AsyncSniffer`` ist durch ``_FakeSniffer`` ersetzt, sodass NUR die
    Klassifikations-Logik im prn geprueft wird.
    """
    # DNSQR ist kein ``_scapy``-Re-Export (nur DNS); lokal unter dem skipif holen.
    from scapy.all import DNSQR

    captured: dict[str, Any] = {}

    def _capture(**kwargs: Any) -> _FakeSniffer:
        sniffer = _FakeSniffer(**kwargs)
        captured["sniffer"] = sniffer
        return sniffer

    monkeypatch.setattr(_scapy, "AsyncSniffer", _capture)

    queries: list[dict[str, Any]] = []
    stop_event = threading.Event()
    # Alive-Probe nicht abwarten: das Event ist gesetzt, die Probe kehrt sofort zurueck.
    stop_event.set()
    sniffer = start_dns_sniff(queries.append, "lo", stop_event)
    try:
        prn = captured["sniffer"].prn
        # promisc=True IST der Unterschied zu SNI/pcap (ADR 0042).
        assert captured["sniffer"].promisc is True

        request = (
            _scapy.IP(src="192.168.1.10", dst="8.8.8.8")
            / _scapy.UDP(sport=54321, dport=53)
            / _scapy.DNS(qd=DNSQR(qname="example.com"))
        )
        response = (
            _scapy.IP(src="8.8.8.8", dst="192.168.1.10")
            / _scapy.UDP(sport=53, dport=54321)
            / _scapy.DNS(qr=1, qd=DNSQR(qname="example.com"))
        )
        non_dns = _scapy.IP(src="192.168.1.10", dst="10.0.0.2") / _scapy.TCP(sport=51000, dport=443)

        prn(request)
        prn(response)
        prn(non_dns)
    finally:
        sniffer.stop(join=True)

    assert len(queries) == 1
    query = queries[0]
    assert query["src_ip"] == "192.168.1.10"
    assert query["dst_ip"] == "8.8.8.8"
    assert query["l4"] == "udp"
    assert query["qname"] == "example.com"
    assert "monotonic_ts" in query


# ── macOS-Rechteprobe ueber /dev/bpf* (plattformfrei per monkeypatch) ──────────


def _fake_open(results: dict[str, Any]) -> Any:
    """Baut ein ``os.open``-Double: pro Knotenpfad Exception-Instanz oder fd-Zahl."""

    def _open(path: str, flags: int) -> int:
        outcome = results[path]
        if isinstance(outcome, OSError):
            raise outcome
        return int(outcome)

    return _open


def test_bpf_probe_returns_none_when_a_node_opens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein belegter Knoten (EBUSY), der naechste oeffnet -> Recht vorhanden -> ``None``."""
    closed: list[int] = []
    monkeypatch.setattr(
        os,
        "open",
        _fake_open(
            {
                "/dev/bpf0": OSError(errno.EBUSY, "busy"),
                "/dev/bpf1": 7,
            }
        ),
    )
    monkeypatch.setattr(os, "close", closed.append)

    assert sniff_core._check_bpf_permission("SNI capture") is None
    assert closed == [7]  # der geoeffnete fd wird sofort wieder geschlossen


def test_bpf_probe_all_permission_denied_returns_error_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scheitert JEDER Knoten mit ``PermissionError`` -> Fehlertext mit ``CAP_NET_RAW``.

    Der Text nennt den ``zweck`` und weist ehrlich auf die BPF-Geraete hin statt auf
    ``setcap`` (das es auf macOS nicht gibt) -- der stabile Substring bleibt erhalten.
    """
    monkeypatch.setattr(
        os,
        "open",
        _fake_open(
            dict.fromkeys(sniff_core._BPF_PROBE_NODES, PermissionError(errno.EACCES, "denied"))
        ),
    )

    result = sniff_core._check_bpf_permission("DNS capture")

    assert result is not None
    assert "CAP_NET_RAW" in result
    assert "DNS capture" in result
    assert "/dev/bpf" in result
    assert "setcap" not in result


def test_bpf_probe_missing_nodes_is_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    """Kein Knoten existiert (ENOENT) -> ``None`` (inconclusive), scapy darf es versuchen."""
    monkeypatch.setattr(
        os,
        "open",
        _fake_open(dict.fromkeys(sniff_core._BPF_PROBE_NODES, OSError(errno.ENOENT, "missing"))),
    )

    assert sniff_core._check_bpf_permission("Packet capture") is None


def test_check_raw_permission_on_darwin_uses_bpf_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auf ``darwin`` geht die Probe ueber BPF -- KEIN Raw-Socket wird mehr angelegt."""
    monkeypatch.setattr(sys, "platform", "darwin")

    def _no_socket(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("darwin darf keinen Raw-Socket mehr proben")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(
        os,
        "open",
        _fake_open(
            dict.fromkeys(sniff_core._BPF_PROBE_NODES, PermissionError(errno.EPERM, "denied"))
        ),
    )

    result = sniff_core.check_raw_permission("SNI capture")

    assert result is not None
    assert "CAP_NET_RAW" in result


def test_check_raw_permission_unknown_platform_is_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fremde Plattform -> ``None`` (inconclusive), unveraendert zum Bestand."""
    monkeypatch.setattr(sys, "platform", "win32")

    assert sniff_core.check_raw_permission("Packet capture") is None
