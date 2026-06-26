"""Der Helfer-Server: AF_UNIX-Stream-Socket, spricht ``protocol``, fuehrt ``sniff_core``.

On-demand-Helfer: ein Backend, eine Sniff-Session. ``serve`` bindet einen
AF_UNIX-Stream-Socket, akzeptiert GENAU eine Verbindung, bedient sie ueber die
Kommando-Schleife und beendet sich nach Verbindungsende sauber (Socket-Datei
entfernen).

Kommandos (Backend -> Helfer): ``PING`` -> ``PONG``; ``START`` (optional
``"interface"``) -> ``check_raw_permission``; bei Fehlt-Recht ``ERROR`` + KEIN
Sniff, sonst ``start_raw_sniff`` in eigenem Thread + ``STARTED`` + je Hit eine
``HIT``-Nachricht; ``STOP`` -> ``stop_event`` setzen, Sniff joinen, ``STOPPED``.

Thread-Sicherheit: Hit-Thread (scapy-prn ruft ``on_hit``) und Kommando-Schleife
schreiben denselben Socket -- ``send_message`` laeuft daher unter einem
``threading.Lock``.

Signal-Handling: ``SIGTERM``/``SIGINT`` -> ``stop_event`` setzen + Socket
aufraeumen + ``sys.exit``.
"""

import os
import signal
import socket
import threading
from types import FrameType
from typing import Any

import structlog

from infrastructure.sniffd.protocol import (
    MessageType,
    ProtocolError,
    recv_message,
    send_message,
)
from infrastructure.sniffd.sniff_core import check_raw_permission, start_raw_sniff

_logger = structlog.get_logger(__name__)


class _Session:
    """Haelt den Zustand EINER Verbindung: Socket, Send-Lock, Sniff-Handle/-Thread.

    Eine Instanz lebt fuer die Dauer genau einer akzeptierten Verbindung. Der
    Send-Lock serialisiert ``send_message`` zwischen Hit-Thread und Kommando-
    Schleife (beide schreiben denselben Socket).
    """

    def __init__(self, conn: socket.socket) -> None:
        self._conn = conn
        self._send_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._sniffer: Any = None

    def _send(self, payload: dict[str, Any]) -> None:
        """Thread-sicheres Senden (Lock um ``send_message``)."""
        with self._send_lock:
            send_message(self._conn, payload)

    def _on_hit(self, hit: dict[str, Any]) -> None:
        """Sniff-Callback: rohen Hit als ``HIT``-Nachricht senden (Hit-Thread)."""
        self._send({"type": MessageType.HIT, **hit})

    def _handle_start(self, message: dict[str, Any]) -> None:
        """``START``: Recht pruefen, dann ``start_raw_sniff`` aufspinnen + ``STARTED``.

        Fehlt das Recht (``check_raw_permission`` liefert einen Text), geht eine
        ``ERROR``-Nachricht zurueck und es wird KEIN Sniff gestartet (S3-frei:
        kein stiller Fallback). Ein bereits laufender Sniff wird nicht doppelt
        gestartet.
        """
        if self._sniffer is not None:
            self._send({"type": MessageType.STARTED})
            return

        permission_error = check_raw_permission()
        if permission_error is not None:
            self._send({"type": MessageType.ERROR, "error": permission_error})
            return

        interface = message.get("interface")
        self._stop_event.clear()
        try:
            self._sniffer = start_raw_sniff(self._on_hit, interface, self._stop_event)
        except RuntimeError as exc:
            self._sniffer = None
            self._send({"type": MessageType.ERROR, "error": str(exc)})
            return

        self._send({"type": MessageType.STARTED})

    def _handle_stop(self) -> None:
        """``STOP``: ``stop_event`` setzen, Sniff joinen, ``STOPPED`` senden."""
        self._stop_event.set()
        sniffer = self._sniffer
        self._sniffer = None
        if sniffer is not None:
            try:
                sniffer.stop(join=True)
            except Exception as exc:
                _logger.warning("sniffd_stop_failed", error=str(exc))
        self._send({"type": MessageType.STOPPED})

    def _teardown(self) -> None:
        """Beendet einen evtl. laufenden Sniff (Verbindungsende/Signal)."""
        self._stop_event.set()
        sniffer = self._sniffer
        self._sniffer = None
        if sniffer is not None:
            try:
                sniffer.stop(join=True)
            except Exception as exc:
                _logger.warning("sniffd_teardown_failed", error=str(exc))

    def run(self) -> None:
        """Kommando-Schleife ueber ``recv_message`` bis Verbindungsende/EOF.

        ``PING`` -> ``PONG``, ``START`` -> ``_handle_start``, ``STOP`` ->
        ``_handle_stop``. ``recv_message`` ``None`` (sauberes Verbindungsende) ->
        aufraeumen + return. Ein ``ProtocolError`` (kaputter Frame) wird geloggt
        und beendet die Verbindung -- ein halber Frame ist nicht reparierbar.
        """
        try:
            while True:
                try:
                    message = recv_message(self._conn)
                except ProtocolError as exc:
                    _logger.warning("sniffd_protocol_error", error=str(exc))
                    return
                if message is None:
                    return  # sauberes Verbindungsende
                msg_type = message.get("type")
                if msg_type == MessageType.PING:
                    self._send({"type": MessageType.PONG})
                elif msg_type == MessageType.START:
                    self._handle_start(message)
                elif msg_type == MessageType.STOP:
                    self._handle_stop()
                else:
                    self._send(
                        {"type": MessageType.ERROR, "error": f"unbekannter Befehl: {msg_type!r}"}
                    )
        finally:
            self._teardown()


def _unlink_quietly(socket_path: str) -> None:
    """Entfernt die Socket-Datei, falls vorhanden -- ohne Krach bei Abwesenheit."""
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        _logger.warning("sniffd_unlink_failed", path=socket_path, error=str(exc))


def serve(socket_path: str) -> None:
    """Bindet einen AF_UNIX-Stream-Socket, bedient EINE Verbindung, raeumt auf.

    Vorab-``unlink`` der evtl. existierenden Socket-Datei, ``bind`` + ``listen(1)``,
    ``accept`` GENAU einer Verbindung. Nach Verbindungsende wird der Listen-Socket
    geschlossen und die Socket-Datei entfernt.

    Signal-Handling (``SIGTERM``/``SIGINT``): Socket-Datei aufraeumen + ``sys.exit``
    -- ein per Signal getoeteter Helfer hinterlaesst keinen verwaisten Socket.
    """

    def _on_signal(signum: int, _frame: FrameType | None) -> None:
        _logger.info("sniffd_signal", signal=signum)
        _unlink_quietly(socket_path)
        raise SystemExit(0)

    # Signal-Handler nur registrierbar, wenn ``serve`` im Haupt-Thread laeuft
    # (Python erlaubt ``signal.signal`` nur dort). Im realen Helfer-Prozess
    # (``sniffd.py``) ist das der Fall; ein Thread-Start (z. B. Smoke-Test)
    # ueberspringt die Registrierung still -- dort uebernimmt das
    # Verbindungsende/der Test-Teardown das Aufraeumen.
    try:
        signal.signal(signal.SIGTERM, _on_signal)
        signal.signal(signal.SIGINT, _on_signal)
    except ValueError:
        _logger.debug("sniffd_signal_skip_non_main_thread")

    _unlink_quietly(socket_path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(socket_path)
        listener.listen(1)
        _logger.info("sniffd_listening", path=socket_path)
        conn, _addr = listener.accept()
        _logger.info("sniffd_connected")
        try:
            _Session(conn).run()
        finally:
            conn.close()
    finally:
        listener.close()
        _unlink_quietly(socket_path)
        _logger.info("sniffd_shutdown", path=socket_path)
