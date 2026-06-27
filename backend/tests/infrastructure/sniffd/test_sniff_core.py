"""Tests der pcap-/LLDP-/Export-Kerne (Etappe 3a) -- OHNE echten Raw-Socket/scapy.

Der harte Kern dieser Tests laeuft scapy-frei: ``parse_packet`` muss bei kaputtem
Input (Objekt ohne ``haslayer``, Objekt das wirft) ROBUST ``None`` liefern statt zu
crashen -- das ist der vom Vertrag vorgesehene "uninteressantes/kaputtes Paket"-Fall.
``run_lldp_sniff`` darf ohne ``scapy.contrib`` (CI-Fall) NICHT crashen, sondern ``[]``
liefern. ``export_pcap`` ohne Pakete ist deterministisch ``False``.

Ein optionaler scapy-Pfad (echtes synthetisches Paket -> Summary-dict) laeuft NUR,
wenn scapy lokal verfuegbar ist (``skipif``) -- in CI ohne scapy wird er uebersprungen,
nicht erzwungen.
"""

from typing import Any

import pytest

from infrastructure.sniffd import _scapy
from infrastructure.sniffd.sniff_core import export_pcap, parse_packet, run_lldp_sniff

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
