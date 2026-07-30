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
import time
from typing import Any

import pytest

from infrastructure.sniffd import _scapy, sniff_core
from infrastructure.sniffd.sniff_core import (
    decode_tlv_text,
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


# ── decode_tlv_text: die Bytes->Text-Naht der Nachbar-dicts (scapy-frei) ──────


def test_decode_tlv_text_bytes_become_real_text() -> None:
    """Rohe ``bytes`` vom Draht werden zu ECHTEM Text -- nicht zur bytes-Schreibweise.

    Der gemeldete Mangel: ``str(b'Fritzchen')`` ergibt ``"b'Fritzchen'"`` und dieser
    Text erreichte unveraendert die Oberflaeche.
    """
    assert decode_tlv_text(b"Fritzchen", "system_name") == "Fritzchen"
    assert decode_tlv_text(b"AVM FRITZ!Box 5590 Fiber 272.08.02", "system_desc") == (
        "AVM FRITZ!Box 5590 Fiber 272.08.02"
    )
    assert decode_tlv_text(b"LAN:1", "port_desc") == "LAN:1"
    # Die alte, kaputte Form darf NICHT mehr entstehen.
    assert "b'" not in decode_tlv_text(b"Fritzchen", "system_name")


def test_decode_tlv_text_accepts_str_unchanged() -> None:
    """scapy liefert ``chassis_id`` je nach Subtype schon als ``str`` -- unveraendert durch.

    Ein blindes ``.decode()`` waere an diesem Fall gescheitert (AttributeError).
    """
    assert decode_tlv_text("11:22:33:44:55:66", "chassis_id") == "11:22:33:44:55:66"


def test_decode_tlv_text_utf8_umlauts() -> None:
    """IEEE 802.1AB schreibt UTF-8 vor -- Mehrbyte-Zeichen kommen korrekt an."""
    assert decode_tlv_text("Büro-Süd".encode(), "system_name") == "Büro-Süd"


def test_decode_tlv_text_undecodable_neither_crashes_nor_lies() -> None:
    """DER UNANGENEHME FALL: nicht dekodierbare Bytes -- kein Absturz, keine stille Luege.

    Ein fremdes Geraet darf beliebige Bytes senden. Erwartet wird: kein Crash, kein
    leerer Wert (das waere die stille Luege "das Geraet hat keinen Namen"), sondern
    ein als teilweise unlesbar ERKENNBARER Text (U+FFFD) -- und der lesbare Anteil
    bleibt erhalten.
    """
    result = decode_tlv_text(b"Switch\xff\xfeName", "system_name")
    assert isinstance(result, str)
    assert result != ""  # keine stille Luege
    assert "�" in result  # der Vorfall bleibt am Wert sichtbar
    assert result.startswith("Switch")  # der lesbare Anteil geht nicht verloren
    assert result.endswith("Name")


def test_decode_tlv_text_undecodable_is_logged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nicht dekodierbare Bytes werden PROTOKOLLIERT (kein stilles Schlucken)."""
    seen: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(
        sniff_core._logger,
        "warning",
        lambda event, **kw: seen.append((event, kw)),
    )
    decode_tlv_text(b"\xff\xfe", "system_desc")
    assert [e for e, _ in seen] == ["lldp_tlv_undecodable"]
    assert seen[0][1]["field"] == "system_desc"


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


@pytest.mark.skipif(
    not (_scapy.HAS_SCAPY and _scapy.HAS_SCAPY_CONTRIB),
    reason="scapy.contrib nicht verfuegbar (CI-Fall)",
)
def test_parse_lldp_neighbor_real_frame_yields_text_and_timestamp() -> None:
    """Ein ECHTES, vom Draht dissektiertes LLDP-Frame -> lesbarer Text + ``last_seen``.

    Beide gemeldeten Maengel an einem realen Wert (Form der gemessenen FRITZ!Box):
    die Text-TLVs kommen als echter Text heraus (nicht als ``"b'Fritzchen'"``), und
    ``last_seen`` traegt einen Zeitstempel der Wanduhr statt ``0.0``.

    Das Frame wird gebaut, zu Bytes serialisiert und WIEDER dissektiert -- nur so
    liefert scapy dieselben Feldtypen wie ein echt gesniffter Frame.
    """
    from scapy.contrib.lldp import LLDPDUEndOfLLDPDU, LLDPDUTimeToLive

    frame = (
        _scapy.Ether(src="11:22:33:44:55:66", dst="01:80:c2:00:00:0e", type=0x88CC)
        / _scapy.LLDPDUChassisID(subtype=4, id=b"\x11\x22\x33\x44\x55\x66")
        / _scapy.LLDPDUPortID(subtype=5, id=b"LAN:1")
        / LLDPDUTimeToLive(ttl=120)
        / _scapy.LLDPDUSystemName(system_name=b"Fritzchen")
        / _scapy.LLDPDUSystemDescription(description=b"AVM FRITZ!Box 5590 Fiber 272.08.02")
        / _scapy.LLDPDUPortDescription(description=b"LAN:1")
        / LLDPDUEndOfLLDPDU()
    )
    before = time.time()
    neighbor = sniff_core._parse_lldp_neighbor(_scapy.Ether(bytes(frame)))
    after = time.time()

    assert neighbor is not None
    # Mangel 1: echter Text, keine bytes-Schreibweise.
    assert neighbor["system_name"] == "Fritzchen"
    assert neighbor["system_desc"] == "AVM FRITZ!Box 5590 Fiber 272.08.02"
    assert neighbor["port_desc"] == "LAN:1"
    assert neighbor["port_id"] == "LAN:1"
    assert neighbor["chassis_id"] == "11:22:33:44:55:66"
    assert not any(str(v).startswith("b'") for v in neighbor.values())
    # Mangel 2: gesetzter Zeitpunkt auf der Wanduhr-Zeitachse.
    assert before <= neighbor["last_seen"] <= after


@pytest.mark.skipif(
    not (_scapy.HAS_SCAPY and _scapy.HAS_SCAPY_CONTRIB),
    reason="scapy.contrib nicht verfuegbar (CI-Fall)",
)
def test_parse_lldp_neighbor_undecodable_name_does_not_crash() -> None:
    """DER UNANGENEHME FALL am echten Frame: kaputte Bytes im System-Namen.

    Ein fremdes Geraet sendet einen nicht UTF-8-dekodierbaren System-Namen. Erwartet:
    kein Absturz, kein leerer Name (stille Luege), sondern ein erkennbar teilweise
    unlesbarer Text -- und der Rest des Nachbarn bleibt intakt.
    """
    from scapy.contrib.lldp import LLDPDUEndOfLLDPDU, LLDPDUTimeToLive

    frame = (
        _scapy.Ether(src="11:22:33:44:55:66", dst="01:80:c2:00:00:0e", type=0x88CC)
        / _scapy.LLDPDUChassisID(subtype=4, id=b"\x11\x22\x33\x44\x55\x66")
        / _scapy.LLDPDUPortID(subtype=5, id=b"LAN:1")
        / LLDPDUTimeToLive(ttl=120)
        / _scapy.LLDPDUSystemName(system_name=b"Switch\xff\xfeName")
        / LLDPDUEndOfLLDPDU()
    )
    neighbor = sniff_core._parse_lldp_neighbor(_scapy.Ether(bytes(frame)))

    assert neighbor is not None  # kein Absturz
    name = neighbor["system_name"]
    assert isinstance(name, str)
    assert name != ""  # keine stille Luege
    assert "�" in name  # der Vorfall bleibt sichtbar
    assert neighbor["source_mac"] == "11:22:33:44:55:66"  # Rest intakt
    assert neighbor["last_seen"] > 0.0


# ── CDP am ECHTEN 802.3-Rahmen durch die volle Kette (Befund 26) ──────────────
#
# Warum echte Rahmen und nicht handgeschriebene Woerterbuecher: die beiden hier
# geheilten Defekte sassen BEIDE in der scapy-Naht und sind fuer einen Nachbau
# unsichtbar.
#
# 1. CDP liegt als IEEE-802.3-Rahmen mit LAENGENFELD auf dem Draht (gemessen
#    0x0021), nicht als Ethernet II. scapy dissektiert das als ``Dot3``; ein
#    ``haslayer(Ether)`` ist dort schlicht falsch (gemessen: 0). Die alte Weiche in
#    ``_dispatch_neighbor`` verwarf deshalb jeden echten CDP-Rahmen, BEVOR die
#    Feldauswertung gerufen wurde.
# 2. ``CDPMsgPortID`` fuehrt ``type``, ``len``, ``iface`` -- ein ``val`` existiert
#    dort NICHT (``AttributeError: val``), im Unterschied zu den drei anderen
#    gelesenen CDP-Klassen.
#
# Die Rahmen werden gebaut, zu Bytes serialisiert und ueber ``_scapy.Ether(bytes)``
# WIEDER dissektiert -- genau der Weg eines gesnifften Pakets (und der Beweis, dass
# scapy dabei selbst zu ``Dot3`` umschaltet). Kein Netz, kein Raw-Socket.


def _cdp_frame(src: str, msgs: list[Any]) -> Any:
    """Ein echter CDP-Rahmen: ``Dot3`` + LLC/SNAP + CDPv2-Kopf, wie auf dem Draht."""
    frame = (
        _scapy.Dot3(src=src, dst="01:00:0c:cc:cc:cc")
        / _scapy.LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / _scapy.SNAP(OUI=0x0C, code=0x2000)
        / _scapy.CDPv2_HDR(msg=msgs)
    )
    # Serialisieren + neu dissektieren: derselbe Weg wie ein gesniffter Rahmen.
    return _scapy.Ether(bytes(frame))


def _lldp_frame(src: str, system_name: bytes = b"Fritzchen") -> Any:
    """Ein echter LLDP-Rahmen (Ethernet II, EtherType ``0x88cc``), neu dissektiert."""
    from scapy.contrib.lldp import LLDPDUEndOfLLDPDU, LLDPDUTimeToLive

    frame = (
        _scapy.Ether(src=src, dst="01:80:c2:00:00:0e", type=0x88CC)
        / _scapy.LLDPDUChassisID(subtype=4, id=b"\x11\x22\x33\x44\x55\x66")
        / _scapy.LLDPDUPortID(subtype=5, id=b"LAN:1")
        / LLDPDUTimeToLive(ttl=120)
        / _scapy.LLDPDUSystemName(system_name=system_name)
        / _scapy.LLDPDUSystemDescription(description=b"AVM FRITZ!Box 5590 Fiber 272.08.02")
        / _scapy.LLDPDUPortDescription(description=b"LAN:1")
        / LLDPDUEndOfLLDPDU()
    )
    return _scapy.Ether(bytes(frame))


@pytest.mark.skipif(
    not (_scapy.HAS_SCAPY and _scapy.HAS_SCAPY_CONTRIB),
    reason="scapy.contrib nicht verfuegbar (CI-Fall)",
)
def test_cdp_802_3_frame_yields_all_four_fields() -> None:
    """Ein VOLLSTAENDIGER CDP-Rahmen -> Nachbar mit allen vier Textfeldern.

    Der Kern-Nachweis von Befund 26: der Rahmen laeuft durch die ECHTE Kette
    (``_dispatch_neighbor`` -> ``_parse_cdp_neighbor``) und kommt als vollstaendiger
    Nachbar heraus. Ohne die Rahmenform-Weiche gibt ``_dispatch_neighbor`` hier
    ``None`` zurueck; ohne den Feldnamen fehlt ``port_id``.
    """
    pkt = _cdp_frame(
        "11:22:33:44:55:66",
        [
            _scapy.CDPMsgDeviceID(val=b"SwitchA"),
            _scapy.CDPMsgPortID(iface=b"GigabitEthernet0/1"),
            _scapy.CDPMsgSoftwareVersion(val=b"Cisco IOS 15.2"),
            _scapy.CDPMsgPlatform(val=b"cisco WS-C2960"),
        ],
    )
    # Die Vorbedingung selbst pruefen: scapy liefert 802.3, NICHT Ethernet II.
    assert not pkt.haslayer(_scapy.Ether)
    assert pkt.haslayer(_scapy.Dot3)

    before = time.time()
    neighbor = sniff_core._dispatch_neighbor(pkt)
    after = time.time()

    assert neighbor is not None  # der alte Ether-Zweig lieferte hier None
    assert neighbor["protocol"] == "CDP"
    assert neighbor["system_name"] == "SwitchA"
    assert neighbor["chassis_id"] == "SwitchA"
    assert neighbor["port_id"] == "GigabitEthernet0/1"  # Feld ``iface``, nicht ``val``
    assert neighbor["system_desc"] == "Cisco IOS 15.2"
    assert neighbor["capabilities"] == ["cisco WS-C2960"]
    # Echter Text, keine bytes-Schreibweise -- gleiche Regel wie im LLDP-Pfad.
    assert not any(str(v).startswith("b'") for v in neighbor.values())
    assert before <= neighbor["last_seen"] <= after


@pytest.mark.skipif(
    not (_scapy.HAS_SCAPY and _scapy.HAS_SCAPY_CONTRIB),
    reason="scapy.contrib nicht verfuegbar (CI-Fall)",
)
def test_cdp_frame_without_port_id_keeps_the_neighbor() -> None:
    """Fehlt die Anschlusskennung, bleibt der Nachbar -- nur DIESES Feld fehlt.

    Ein einzelnes fehlendes Feld darf nie den ganzen Eintrag kosten: das Geraet
    steht im Netz, die Topologie muss es kennen. Der Schluessel wird weggelassen
    (nicht ``None``-gefuellt) -- konsistent zum LLDP-Pfad bei fehlenden TLVs.
    """
    pkt = _cdp_frame(
        "aa:bb:cc:dd:ee:01",
        [
            _scapy.CDPMsgDeviceID(val=b"SwitchB"),
            _scapy.CDPMsgSoftwareVersion(val=b"Cisco IOS 15.2"),
            _scapy.CDPMsgPlatform(val=b"cisco WS-C2960"),
        ],
    )
    neighbor = sniff_core._dispatch_neighbor(pkt)

    assert neighbor is not None
    assert neighbor["system_name"] == "SwitchB"  # Nachbar erhalten
    assert neighbor["system_desc"] == "Cisco IOS 15.2"
    assert neighbor["capabilities"] == ["cisco WS-C2960"]
    assert "port_id" not in neighbor  # nur dieses Feld fehlt


@pytest.mark.skipif(
    not (_scapy.HAS_SCAPY and _scapy.HAS_SCAPY_CONTRIB),
    reason="scapy.contrib nicht verfuegbar (CI-Fall)",
)
def test_cdp_unreadable_single_field_keeps_neighbor_and_names_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ein VORHANDENES, aber unlesbares Feld kostet nur SICH SELBST, nie den Nachbarn.

    Der Auffangblock sitzt pro Feld, nicht um den ganzen Nachbarn -- genau der
    Unterschied, an dem der alte Code scheiterte: dort riss der Zugriff auf das
    nicht existierende ``CDPMsgPortID.val`` (``AttributeError``) den KOMPLETTEN
    Nachbarn mit, obwohl Geraetekennung, Softwarefassung und Plattform einwandfrei
    lesbar waren.

    Simuliert wird ein unlesbares Feld hier ueber ein ``decode_tlv_text``, das fuer
    ``port_id`` wirft -- das deckt die Bruchstelle unabhaengig davon ab, welches
    scapy-Attribut sich in einer kuenftigen Version umbenennt.
    """
    events: list[tuple[str, dict[str, Any]]] = []

    def _capture(event: str, **kwargs: Any) -> None:
        events.append((event, kwargs))

    real_decode = sniff_core.decode_tlv_text

    def _decode_but_break_port_id(value: Any, field: str) -> str:
        if field == "port_id":
            raise AttributeError("val")
        return real_decode(value, field)

    monkeypatch.setattr(sniff_core, "decode_tlv_text", _decode_but_break_port_id)
    monkeypatch.setattr(sniff_core._logger, "warning", _capture)

    pkt = _cdp_frame(
        "aa:bb:cc:dd:ee:03",
        [
            _scapy.CDPMsgDeviceID(val=b"SwitchC"),
            _scapy.CDPMsgPortID(iface=b"GigabitEthernet0/1"),
            _scapy.CDPMsgSoftwareVersion(val=b"Cisco IOS 15.2"),
            _scapy.CDPMsgPlatform(val=b"cisco WS-C2960"),
        ],
    )
    neighbor = sniff_core._dispatch_neighbor(pkt)

    assert neighbor is not None  # der Nachbar bleibt -- das ist der Kern
    assert neighbor["system_name"] == "SwitchC"  # die lesbaren Felder bleiben lesbar
    assert neighbor["system_desc"] == "Cisco IOS 15.2"
    assert neighbor["capabilities"] == ["cisco WS-C2960"]
    assert neighbor["source_mac"] == "aa:bb:cc:dd:ee:03"
    assert "port_id" not in neighbor  # nur das betroffene Feld bleibt leer
    # Nicht still: protokolliert unter ``cdp_parse_failed`` UND mit Feldnamen.
    assert any(
        event == "cdp_parse_failed" and kwargs.get("field") == "port_id" for event, kwargs in events
    )


@pytest.mark.skipif(
    not (_scapy.HAS_SCAPY and _scapy.HAS_SCAPY_CONTRIB),
    reason="scapy.contrib nicht verfuegbar (CI-Fall)",
)
def test_lldp_frame_still_dispatches_unchanged() -> None:
    """Der LLDP-Pfad bleibt bitgleich: derselbe Rahmen -> dasselbe Ergebnis.

    LLDP nutzt EtherType ``0x88cc`` (> 1500), bleibt also Ethernet II und ist von
    der CDP-Heilung nicht betroffen. Geprueft wird das, was die Umstellung haette
    brechen koennen: die Weiche greift weiterhin, und das Ergebnis aus
    ``_dispatch_neighbor`` ist identisch zu dem aus ``_parse_lldp_neighbor``.
    """
    pkt = _lldp_frame("11:22:33:44:55:66")

    dispatched = sniff_core._dispatch_neighbor(pkt)
    direct = sniff_core._parse_lldp_neighbor(pkt)

    assert dispatched is not None
    assert direct is not None
    assert dispatched["protocol"] == "LLDP"
    assert dispatched["system_name"] == "Fritzchen"
    assert dispatched["system_desc"] == "AVM FRITZ!Box 5590 Fiber 272.08.02"
    assert dispatched["port_id"] == "LAN:1"
    assert dispatched["port_desc"] == "LAN:1"
    assert dispatched["chassis_id"] == "11:22:33:44:55:66"
    # Identisch bis auf den Zeitstempel (zwei Aufrufe, zwei Wanduhr-Werte).
    assert {k: v for k, v in dispatched.items() if k != "last_seen"} == {
        k: v for k, v in direct.items() if k != "last_seen"
    }


@pytest.mark.skipif(
    not (_scapy.HAS_SCAPY and _scapy.HAS_SCAPY_CONTRIB),
    reason="scapy.contrib nicht verfuegbar (CI-Fall)",
)
def test_source_mac_read_from_both_frame_forms() -> None:
    """Die Absenderadresse kommt aus BEIDEN Rahmenformen -- 802.3 wie Ethernet II.

    Das ist der Grund, warum die Rahmenform an genau EINER Stelle bestimmt wird:
    ``Dot3`` und ``Ether`` tragen ``src`` unter demselben Namen, also bleibt der
    Rest des Moduls formunabhaengig. Das Feld ist zugleich der Dedup-Schluessel der
    Nachbarliste -- eine leere oder erfundene Adresse verschmilzt Geraete.
    """
    cdp = sniff_core._dispatch_neighbor(
        _cdp_frame("aa:bb:cc:dd:ee:01", [_scapy.CDPMsgDeviceID(val=b"SwitchB")])
    )
    lldp = sniff_core._dispatch_neighbor(_lldp_frame("11:22:33:44:55:66"))

    assert cdp is not None
    assert lldp is not None
    assert cdp["source_mac"] == "aa:bb:cc:dd:ee:01"  # aus Dot3
    assert lldp["source_mac"] == "11:22:33:44:55:66"  # aus Ether


@pytest.mark.skipif(
    not (_scapy.HAS_SCAPY and _scapy.HAS_SCAPY_CONTRIB),
    reason="scapy.contrib nicht verfuegbar (CI-Fall)",
)
def test_cdp_undecodable_field_keeps_neighbor_and_logs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kaputte Bytes im CDP-Text -> Ersatzzeichen + Protokoll, NICHT Verwerfen.

    Ein fremdes Geraet darf beliebige Bytes senden. Erwartet ist dieselbe Regel wie
    im LLDP-Pfad (derselbe Helfer ``decode_tlv_text``, kein Zwilling): der Wert
    bleibt als teilweise unlesbar ERKENNBAR (U+FFFD), der Vorfall wird mit
    Feldnamen protokolliert, und der Nachbar bleibt vollstaendig erhalten.
    """
    events: list[tuple[str, dict[str, Any]]] = []

    def _capture(event: str, **kwargs: Any) -> None:
        events.append((event, kwargs))

    monkeypatch.setattr(sniff_core._logger, "warning", _capture)

    pkt = _cdp_frame(
        "aa:bb:cc:dd:ee:02",
        [
            _scapy.CDPMsgDeviceID(val=b"Switch\xff\xfeName"),
            _scapy.CDPMsgPortID(iface=b"GigabitEthernet0/1"),
        ],
    )
    neighbor = sniff_core._dispatch_neighbor(pkt)

    assert neighbor is not None  # kein Verwerfen des Nachbarn
    name = neighbor["system_name"]
    assert name != ""  # keine stille Luege
    assert "�" in name  # der Vorfall bleibt sichtbar
    assert neighbor["port_id"] == "GigabitEthernet0/1"  # Rest intakt
    assert neighbor["source_mac"] == "aa:bb:cc:dd:ee:02"
    # Nicht still: der Vorfall wird mit Feldnamen protokolliert.
    assert any(
        event == "lldp_tlv_undecodable" and kwargs.get("field") == "system_name"
        for event, kwargs in events
    )


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


def test_bpf_probe_opens_read_write(monkeypatch: pytest.MonkeyPatch) -> None:
    """Die Probe oeffnet mit ``O_RDWR`` -- genau das, was scapy danach braucht.

    Etappe 2f: mit ``O_RDONLY`` gelang die Probe auf ``crw-r-----``-Geraeten und
    meldete faelschlich "Recht vorhanden", waehrend der echte Sniff an
    "Permission denied: could not open /dev/bpf0" scheiterte (scapy oeffnet BPF
    schreibend, um die Filter per ioctl zu setzen). Der Modus wird darum
    festgenagelt: sonst faellt genau diese Diskrepanz wieder durch.
    """
    gesehen: list[int] = []

    def _open(path: str, flags: int) -> int:
        gesehen.append(flags)
        return 7

    monkeypatch.setattr(os, "open", _open)
    monkeypatch.setattr(os, "close", lambda _fd: None)

    assert sniff_core._check_bpf_permission("SNI capture") is None
    assert gesehen, "Die Probe hat keinen BPF-Knoten geoeffnet"
    assert all(f & os.O_RDWR == os.O_RDWR for f in gesehen)


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
