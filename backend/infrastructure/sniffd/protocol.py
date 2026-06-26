"""IPC-Protokoll des Sniff-Helfers -- reine stdlib (``socket``/``json``/``struct``).

Bewusst OHNE scapy/psutil/domain-Import: das Protokoll ist die schmale Naht
zwischen unprivilegiertem Backend und privilegiertem Helfer und muss isoliert
(ohne schwere Abhaengigkeiten) testbar bleiben.

Framing (laengen-praefixiert, ein Frame = eine Nachricht):

    [4 Byte big-endian unsigned length (struct ">I")][UTF-8-JSON-Body]

Jede Nachricht ist ein JSON-Objekt mit einem Schluessel ``"type"`` (einer der
Werte aus ``MessageType``). Befehle laufen vom Backend an den Helfer (START /
START_PCAP / START_LLDP / EXPORT_PCAP / STOP / PING), Antworten und Events vom
Helfer zurueck (HIT / PACKET / NEIGHBORS / EXPORTED / STARTED / STOPPED / PONG /
ERROR).
"""

import json
import socket
import struct
from enum import StrEnum
from typing import Any

# Laengen-Praefix: 4 Byte big-endian unsigned (max ~4 GiB Body, weit jenseits
# jeder realen Nachricht -- ein einzelner SNI-Hit ist wenige hundert Byte).
_LEN_PREFIX = struct.Struct(">I")
_LEN_PREFIX_SIZE = _LEN_PREFIX.size  # == 4


class ProtocolError(Exception):
    """Ein kaputter/inkonsistenter IPC-Frame (z. B. EOF mitten im Body)."""


class MessageType(StrEnum):
    """Die ``"type"``-Werte der IPC-Nachrichten.

    Befehle (Backend -> Helfer): ``START`` (= SNI), ``START_PCAP``,
    ``START_LLDP``, ``EXPORT_PCAP``, ``STOP``, ``PING``.
    Antworten/Events (Helfer -> Backend): ``HIT``, ``PACKET``, ``NEIGHBORS``,
    ``EXPORTED``, ``STARTED``, ``STOPPED``, ``PONG``, ``ERROR``.
    """

    # Befehle vom Backend an den Helfer.
    START = "START"  # SNI-Dauerstrom (unveraendert).
    START_PCAP = "START_PCAP"  # pcap-Dauerstrom (PACKET-Events bis max_packets/STOP).
    START_LLDP = "START_LLDP"  # einmaliger, zeitbegrenzter LLDP/CDP-Sniff (-> NEIGHBORS).
    EXPORT_PCAP = "EXPORT_PCAP"  # gesammelte Rohpakete als .pcap schreiben (-> EXPORTED).
    STOP = "STOP"  # beendet SNI- ODER pcap-Strom.
    PING = "PING"

    # Antworten/Events vom Helfer an das Backend.
    HIT = "HIT"  # ein roher SNI-Hit.
    PACKET = "PACKET"  # ein pcap-Summary-dict.
    NEIGHBORS = "NEIGHBORS"  # die LLDP/CDP-Nachbarliste (am Ende des Sniffs).
    EXPORTED = "EXPORTED"  # Ergebnis eines pcap-Exports ({"ok": bool}).
    STARTED = "STARTED"
    STOPPED = "STOPPED"
    PONG = "PONG"
    ERROR = "ERROR"


def send_message(sock: socket.socket, payload: dict[str, Any]) -> None:
    """Serialisiert ``payload`` als JSON und sendet es laengen-praefixiert.

    ``json.dumps`` -> UTF-8-encode -> 4-Byte-Laengenpraefix + Body, alles in einem
    ``sock.sendall`` (ein Frame geht atomar genug raus; ``sendall`` deckt
    Teil-Sends ab).
    """
    body = json.dumps(payload).encode("utf-8")
    frame = _LEN_PREFIX.pack(len(body)) + body
    sock.sendall(frame)


def _recv_exactly(sock: socket.socket, n: int) -> bytes | None:
    """Liest GENAU ``n`` Bytes per Schleife ueber ``sock.recv``.

    Gibt ``None`` bei vorzeitigem EOF (Gegenseite schliesst, bevor ``n`` Bytes
    da sind) -- so unterscheidet der Aufrufer ein sauberes Verbindungsende von
    einem vollstaendigen Frame.
    """
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None  # vorzeitiges EOF
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_message(sock: socket.socket) -> dict[str, Any] | None:
    """Liest einen vollstaendigen Frame und gibt die dekodierte Nachricht zurueck.

    Liest erst die 4 Byte Laenge, dann genau so viele Body-Bytes (per Schleife
    bis vollstaendig). Sauberes Verbindungsende/EOF am Frame-Anfang -> ``None``.
    Ein abgeschnittener Frame (EOF mitten im Laengenpraefix oder mitten im Body)
    oder ein nicht dekodierbarer Body wirft ``ProtocolError`` -- ein halber
    Frame ist ein kaputter Frame, kein sauberes Ende.
    """
    header = _recv_exactly(sock, _LEN_PREFIX_SIZE)
    if header is None:
        # EOF GENAU am Frame-Anfang -> sauberes Verbindungsende.
        return None
    (length,) = _LEN_PREFIX.unpack(header)
    body = _recv_exactly(sock, length)
    if body is None:
        # EOF mitten im Body -> abgeschnittener (kaputter) Frame.
        raise ProtocolError(f"unvollstaendiger Frame: {length} Body-Bytes erwartet, EOF erreicht")
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"kaputter Frame-Body: {exc}") from exc
    if not isinstance(decoded, dict):
        raise ProtocolError(f"Frame-Body ist kein JSON-Objekt: {type(decoded).__name__}")
    return decoded
