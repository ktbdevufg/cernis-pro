"""Smoke-Test des Helfer-Servers: nur Protokoll-/Lifecycle-Pfad, KEIN echter Sniff.

``serve()`` laeuft in einem Thread auf einem temp-Socket (``tmp_path``). Der Test
verbindet sich per AF_UNIX, prueft PING -> PONG und dass die Verbindungsende den
Server-Thread sauber beendet. KEIN scapy-Import, keine echten Raw-Sockets -- ein
START-Versuch darf an fehlenden Rechten NICHT scheitern (STARTED ODER ERROR ist
beides gueltig).
"""

import socket
import threading
import time
from pathlib import Path

from infrastructure.sniffd.protocol import MessageType, recv_message, send_message
from infrastructure.sniffd.server import serve


def _wait_for_socket(path: Path, timeout: float = 5.0) -> None:
    """Pollt, bis die Socket-Datei existiert (statt eines festen sleep)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"Socket {path} ist nicht innerhalb {timeout}s aufgetaucht")


def _connect(path: Path, timeout: float = 5.0) -> socket.socket:
    """Verbindet sich auf den AF_UNIX-Socket (mit kurzer Retry-Schleife)."""
    deadline = time.monotonic() + timeout
    while True:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(path))
            return sock
        except (FileNotFoundError, ConnectionRefusedError):
            sock.close()
            if time.monotonic() > deadline:
                raise
            time.sleep(0.01)


def test_ping_pong_and_clean_shutdown(tmp_path: Path) -> None:
    """PING -> PONG; danach Verbindungsende -> Server-Thread endet sauber."""
    socket_path = tmp_path / "cernis-sniffd.sock"
    server_thread = threading.Thread(target=serve, args=(str(socket_path),), daemon=True)
    server_thread.start()

    _wait_for_socket(socket_path)
    conn = _connect(socket_path)
    try:
        send_message(conn, {"type": MessageType.PING})
        reply = recv_message(conn)
        assert reply is not None
        assert reply["type"] == str(MessageType.PONG)
    finally:
        conn.close()  # Verbindungsende -> Server soll sauber zurueckkehren

    server_thread.join(timeout=5)
    assert not server_thread.is_alive(), "Server-Thread nach Verbindungsende nicht beendet"
    # Socket-Datei ist nach sauberem Shutdown wieder entfernt.
    assert not socket_path.exists()


def test_start_returns_started_or_error(tmp_path: Path) -> None:
    """START liefert STARTED (falls Rechte) ODER ERROR (ohne Rechte) -- beides gueltig.

    Der Test darf an fehlenden Raw-Socket-Rechten NICHT scheitern. Anschliessend
    schliesst er die Verbindung und erwartet einen sauberen Server-Shutdown.
    """
    socket_path = tmp_path / "cernis-sniffd.sock"
    server_thread = threading.Thread(target=serve, args=(str(socket_path),), daemon=True)
    server_thread.start()

    _wait_for_socket(socket_path)
    conn = _connect(socket_path)
    try:
        send_message(conn, {"type": MessageType.START})
        reply = recv_message(conn)
        assert reply is not None
        assert reply["type"] in (str(MessageType.STARTED), str(MessageType.ERROR))
    finally:
        conn.close()

    server_thread.join(timeout=5)
    assert not server_thread.is_alive()
