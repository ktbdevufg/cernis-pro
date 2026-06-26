"""Tests fuer das IPC-Protokoll (``protocol``) und den reinen Parser (``parse_sni``).

Reine stdlib-Tests: ``socket.socketpair`` fuer den Roundtrip, kein scapy, keine
echten Raw-Sockets. Der ClientHello fuer ``parse_sni`` wird von Hand als ``bytes``
gebaut.
"""

import socket
import struct
from typing import Any

import pytest

from infrastructure.sniffd.protocol import (
    MessageType,
    ProtocolError,
    recv_message,
    send_message,
)
from infrastructure.sniffd.sniff_core import parse_sni

# ── Framing-Roundtrip ─────────────────────────────────────────────────────────


def test_roundtrip_single_message() -> None:
    """Eine Nachricht geht 1:1 durch (send -> recv liefert dasselbe dict)."""
    a, b = socket.socketpair()
    try:
        payload = {"type": MessageType.PING, "extra": 42}
        send_message(a, payload)
        received = recv_message(b)
        assert received == {"type": "PING", "extra": 42}
    finally:
        a.close()
        b.close()


def test_roundtrip_multiple_messages_in_order() -> None:
    """Mehrere Nachrichten hintereinander kommen in Reihenfolge + vollstaendig an."""
    a, b = socket.socketpair()
    try:
        messages: list[dict[str, Any]] = [
            {"type": MessageType.STARTED},
            {"type": MessageType.HIT, "hostname": "example.com", "remote_port": 443},
            {"type": MessageType.HIT, "hostname": "cernis.test", "remote_port": 443},
            {"type": MessageType.STOPPED},
        ]
        for msg in messages:
            send_message(a, msg)
        for msg in messages:
            received = recv_message(b)
            assert received is not None
            # StrEnum-Werte serialisieren als reine Strings.
            assert received["type"] == str(msg["type"])
            assert received == {**msg, "type": str(msg["type"])}
    finally:
        a.close()
        b.close()


def test_recv_message_returns_none_on_clean_close() -> None:
    """Schliesst die Gegenseite sauber (EOF am Frame-Anfang), liefert recv None."""
    a, b = socket.socketpair()
    try:
        a.close()  # Gegenseite zu, ohne etwas zu senden
        assert recv_message(b) is None
    finally:
        b.close()


def test_recv_message_raises_on_truncated_body() -> None:
    """Laenge groesser als gesendete Body-Bytes -> EOF mitten im Body -> ProtocolError.

    Definiertes Verhalten: ein abgeschnittener Frame (vollstaendiger 4B-Laengen-
    praefix, aber zu wenig Body) ist ein KAPUTTER Frame, kein sauberes Ende -- der
    Parser wirft ``ProtocolError``.
    """
    a, b = socket.socketpair()
    try:
        # Praefix behauptet 100 Body-Bytes, wir senden nur 3 und schliessen dann.
        a.sendall(struct.pack(">I", 100) + b"abc")
        a.close()
        with pytest.raises(ProtocolError):
            recv_message(b)
    finally:
        b.close()


def test_recv_message_raises_on_non_object_body() -> None:
    """Ein gueltig gerahmter, aber nicht-Objekt-JSON-Body (Liste) wirft ProtocolError."""
    a, b = socket.socketpair()
    try:
        body = b"[1, 2, 3]"  # gueltiges JSON, aber kein Objekt
        a.sendall(struct.pack(">I", len(body)) + body)
        with pytest.raises(ProtocolError):
            recv_message(b)
    finally:
        a.close()
        b.close()


# ── parse_sni ─────────────────────────────────────────────────────────────────


def _build_client_hello(hostname: str) -> bytes:
    """Baut einen minimalen, gueltigen TLS-ClientHello-Record mit SNI von Hand.

    Layout exakt wie ``parse_sni`` es liest (big-endian):

      Record:    0x16 | version 2B | record_len 2B | handshake...
      Handshake: 0x01 | hs_len 3B | client_version 2B | random 32B
                 | session_id len 1B (+ data) | cipher_suites len 2B (+ data)
                 | compression len 1B (+ data) | extensions len 2B (+ data)
      Ext SNI:   0x0000 | ext_len 2B | server_name_list len 2B
                 | name_type 0x00 | name_len 2B | hostname
    """
    host = hostname.encode("ascii")

    # SNI-Extension-Body (server_name_list).
    name_entry = b"\x00" + struct.pack(">H", len(host)) + host  # name_type + len + host
    server_name_list = struct.pack(">H", len(name_entry)) + name_entry
    sni_ext = (
        struct.pack(">H", 0x0000) + struct.pack(">H", len(server_name_list)) + server_name_list
    )

    extensions = sni_ext
    ext_block = struct.pack(">H", len(extensions)) + extensions

    body = (
        b"\x03\x03"  # client_version
        + b"\x00" * 32  # random
        + b"\x00"  # session_id len 0
        + struct.pack(">H", 0)  # cipher_suites len 0
        + b"\x00"  # compression_methods len 0
        + ext_block
    )

    # Handshake-Header: type 0x01 + 3B Laenge des Body.
    hs_len = struct.pack(">I", len(body))[1:]  # 3 Byte big-endian
    handshake = b"\x01" + hs_len + body

    # Record-Header: type 0x16 + version + 2B Laenge des Handshake.
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    return record


def test_parse_sni_extracts_hostname() -> None:
    """Ein handgebauter ClientHello mit SNI 'example.com' wird korrekt geparst."""
    payload = _build_client_hello("example.com")
    assert parse_sni(payload) == "example.com"


def test_parse_sni_empty_bytes_returns_none() -> None:
    """Leere Bytes sind kein Record -> None."""
    assert parse_sni(b"") is None


def test_parse_sni_non_clienthello_returns_none() -> None:
    """Record 0x16, aber Handshake-Typ != ClientHello (z. B. ServerHello 0x02) -> None."""
    # 0x16 Record, dann genug Fuell-Bytes, aber payload[5] != 0x01.
    junk = b"\x16\x03\x01\x00\x10\x02" + b"\x00" * 16
    assert parse_sni(junk) is None


def test_parse_sni_garbage_returns_none() -> None:
    """Reiner Muell (kein 0x16-Record) -> None."""
    assert parse_sni(b"\xde\xad\xbe\xef\x00\x01") is None
