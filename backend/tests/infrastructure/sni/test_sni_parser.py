"""Tests des manuellen ClientHello-Parsers (das Herzstueck der sni-Infrastruktur).

Reine Byte-Pruefung OHNE Netz/scapy: ein synthetisch zusammengebauter, echter
TLS-ClientHello mit SNI -> korrekter Hostname; jede Stoerung (abgeschnitten, kein
Handshake, ServerHello, kein SNI) -> ``None`` (kein Crash). Die Bytes folgen exakt
RFC 8446/6066 (Aufbau wie im Spike-Selbsttest).
"""

import struct

from infrastructure.sni.sni_sniffer import parse_sni


def _build_client_hello(host: bytes, *, extensions: bytes | None = None) -> bytes:
    """Baut einen echten TLS-ClientHello. Default: eine SNI-Extension fuer ``host``.
    ``extensions`` ueberschreibt den gesamten Extensions-Block (auch leer = ``b""``)."""
    if extensions is None:
        extensions = (
            b"\x00\x00"  # ext_type = server_name
            + struct.pack(">H", 2 + 1 + 2 + len(host))  # ext_len
            + struct.pack(">H", 1 + 2 + len(host))  # server_name_list len
            + b"\x00"  # name_type = host_name
            + struct.pack(">H", len(host))  # name_len
            + host
        )
    body = (
        b"\x03\x03"  # client_version TLS1.2
        + b"\x00" * 32  # random
        + b"\x00"  # session_id len = 0
        + struct.pack(">H", 2)
        + b"\x00\x2f"  # cipher_suites: len 2 + 1 suite
        + b"\x01\x00"  # compression: len 1 + null
        + struct.pack(">H", len(extensions))
        + extensions  # extensions
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body  # type + 3B len
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    return record


def test_parse_sni_real_client_hello() -> None:
    record = _build_client_hello(b"example.com")
    assert parse_sni(record) == "example.com"


def test_parse_sni_truncated_record_returns_none() -> None:
    # Abgeschnittener ClientHello (nur die ersten 20 Bytes des vollen Records).
    record = _build_client_hello(b"example.com")
    assert parse_sni(record[:20]) is None


def test_parse_sni_app_data_returns_none() -> None:
    # 0x17 = Application Data, kein Handshake-Record.
    assert parse_sni(b"\x17\x03\x03\x00\x10" + b"\x00" * 16) is None


def test_parse_sni_server_hello_returns_none() -> None:
    # TLS-Handshake (0x16), aber Handshake-Typ 0x02 = ServerHello (nicht ClientHello).
    record = _build_client_hello(b"example.com")
    server_hello = b"\x16\x03\x03" + record[3:5] + b"\x02" + record[6:]
    assert parse_sni(server_hello) is None


def test_parse_sni_no_sni_extension_returns_none() -> None:
    # Gueltiger ClientHello, aber mit einer NICHT-SNI-Extension (Typ 0x0017 ext_master).
    other_ext = b"\x00\x17" + struct.pack(">H", 0)  # ext_type 0x0017, ext_len 0
    record = _build_client_hello(b"", extensions=other_ext)
    assert parse_sni(record) is None


def test_parse_sni_empty_extensions_returns_none() -> None:
    record = _build_client_hello(b"", extensions=b"")  # leerer Extensions-Block
    assert parse_sni(record) is None


def test_parse_sni_empty_payload_returns_none() -> None:
    assert parse_sni(b"") is None
