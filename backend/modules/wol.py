"""Wake-on-LAN (WoL) magic packet sender."""
import socket
import re
import struct


def _build_magic_packet(mac: str) -> bytes:
    """Build WoL magic packet: 6x 0xFF + 16x MAC."""
    clean = re.sub(r"[:\-\.]", "", mac).upper()
    if len(clean) != 12:
        raise ValueError(f"Invalid MAC address: {mac}")
    mac_bytes = bytes.fromhex(clean)
    return b"\xff" * 6 + mac_bytes * 16


def send_wol(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> bool:
    """Send a WoL magic packet. Returns True on success."""
    try:
        packet = _build_magic_packet(mac)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(packet, (broadcast, port))
        return True
    except Exception as e:
        print(f"WoL failed for {mac}: {e}")
        return False
