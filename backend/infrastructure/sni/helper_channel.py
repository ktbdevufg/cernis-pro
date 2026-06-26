"""``SubprocessSniffHelper`` -- die echte ``SniffHelperChannel`` ueber AF_UNIX-IPC.

Spawnt den privilegierten Helfer ``cernis-sniffd`` on-demand, verbindet ueber einen
AF_UNIX-Stream-Socket und spricht das ``infrastructure.sniffd.protocol``-Framing. Der
rohe Sniff lebt im Helfer (der EINZIGE Prozess mit ``CAP_NET_RAW``); ueber diese Naht
kommen nur die rohen Hit-dicts zurueck. Die teure Zuordnung (psutil/match_snapshot)
bleibt im Adapter (``ScapySniSniffer``), NICHT hier.

SICHERHEIT (Socket-Pfad): pro Instanz ein eigenes ``tempfile.mkdtemp``-Verzeichnis
(0700, NICHT world-writable wie ``/tmp/cernis-sniffd.sock``); der Socket liegt darin.
Beim ``stop`` wird das Verzeichnis wieder entfernt.

SPAWN (frozen vs. dev, Muster ``serve.py._is_frozen`` / ``app.py``):
* frozen (PyInstaller): die Helfer-Binary ``cernis-sniffd`` liegt neben
  ``sys.executable`` -> ``[<exe-dir>/cernis-sniffd, socket_path]``.
* dev: der aktuelle Python startet ``<repo>/backend/sniffd.py`` ->
  ``[sys.executable, <repo>/backend/sniffd.py, socket_path]``.

ROBUST (S3-frei): scheitert Spawn/Connect, liefert ``start`` einen EHRLICHEN
Fehlertext (kein Crash, keine stille Leer-Erfassung). Alle scapy-/Rechte-Fehler
kommen als ERROR-Text vom Helfer und werden 1:1 durchgereicht.
"""

import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

import structlog

from infrastructure.sniffd.protocol import (
    MessageType,
    ProtocolError,
    recv_message,
    send_message,
)

_logger = structlog.get_logger(__name__)

# Helfer-Binary-/Entry-Name (frozen: neben sys.executable; dev: backend/sniffd.py).
_HELPER_BINARY_NAME = "cernis-sniffd"

# Wie lange auf das Auftauchen der Socket-Datei nach dem Spawn gewartet wird (Poll-
# Loop). Der Helfer bindet + listen()t direkt beim Start -- 3 s sind grosszuegig.
_SOCKET_WAIT_SECS = 3.0
_SOCKET_POLL_INTERVAL_SECS = 0.02

# Antwort-Timeout fuer die START-Quittung (STARTED/ERROR). Der Helfer fuehrt eine
# Alive-Probe (~0.8 s) aus, bevor er antwortet -- 5 s decken das mit Reserve ab.
_START_REPLY_TIMEOUT_SECS = 5.0

# Teardown-Timeouts: dem Subprozess nach terminate kurz Zeit geben, dann kill().
_TERMINATE_TIMEOUT_SECS = 2.0


def _is_frozen() -> bool:
    """``True`` im PyInstaller-Bundle (Muster ``serve.py._is_frozen``)."""
    return getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS")


def _spawn_command(socket_path: str) -> list[str]:
    """Baut das Spawn-Kommando frozen vs. dev (Muster ``serve.py``/``app.py``).

    frozen: ``cernis-sniffd`` neben ``sys.executable``.
    dev: der aktuelle Python startet ``<repo>/backend/sniffd.py``.
    """
    if _is_frozen():
        helper = Path(sys.executable).parent / _HELPER_BINARY_NAME
        return [str(helper), socket_path]
    # dev: <repo>/backend/sniffd.py -- parents[2] von infrastructure/sni/helper_channel.py
    entry = Path(__file__).resolve().parents[2] / "sniffd.py"
    return [sys.executable, str(entry), socket_path]


def helper_entry_exists() -> bool:
    """``True``, wenn der Helfer-Einstieg (frozen-Binary bzw. dev-``sniffd.py``) existiert.

    Reiner Pfad-Check fuer den optimistischen Verfuegbarkeits-Check des Adapters
    (``is_available``). Sagt NICHTS ueber Rechte/scapy aus -- das prueft erst der
    echte Start ueber die ERROR-Naht des Helfers.
    """
    cmd = _spawn_command("")
    if _is_frozen():
        return Path(cmd[0]).exists()
    return Path(cmd[1]).exists()  # dev: sniffd.py-Pfad


class SubprocessSniffHelper:
    """``SniffHelperChannel`` ueber einen on-demand gespawnten Helfer-Subprozess.

    Eine Instanz haelt hoechstens einen laufenden Helfer. Der Reader-Thread liest die
    HIT-Nachrichten in eine thread-sichere ``deque`` (Lock); ``poll_hits`` leert sie.
    Kommando-Senden (START/STOP) und der Reader laufen NIE gleichzeitig schreibend --
    nur der Adapter ruft start/stop, der Reader liest. Der Send-Pfad ist mit dem
    Teardown ueber ``_lock`` serialisiert.
    """

    def __init__(self) -> None:
        self._proc: subprocess.Popen[bytes] | None = None
        self._sock: socket.socket | None = None
        self._socket_dir: str | None = None
        self._reader: threading.Thread | None = None
        self._reader_stop = threading.Event()
        self._lock = threading.Lock()
        self._hits: deque[dict[str, Any]] = deque()

    # -- Lifecycle ------------------------------------------------------------

    def start(self, interface: str | None) -> str | None:
        """Spawnt Helfer, connectet, schickt START. ``None`` bei Erfolg, sonst Fehlertext.

        Reihenfolge: Socket-Dir (0700) -> Popen -> auf Socket-Datei warten -> connecten
        -> START senden -> auf STARTED/ERROR warten -> Reader-Thread starten. Jeder
        Fehlschritt raeumt das Halb-Gestartete wieder ab (``_cleanup``) und gibt einen
        ehrlichen Fehlertext zurueck -- KEIN Crash, KEINE stille Leer-Erfassung.
        """
        if self.is_running():
            return None  # bereits aktiv -- kein Doppelstart

        # Frischer Zustand fuer diesen Lauf.
        self._reader_stop = threading.Event()
        self._hits = deque()

        try:
            self._socket_dir = tempfile.mkdtemp(prefix="cernis-sniffd-")
        except OSError as exc:
            return f"SNI-Helfer: Socket-Verzeichnis nicht anlegbar: {exc}"
        socket_path = str(Path(self._socket_dir) / "sniffd.sock")

        try:
            self._proc = subprocess.Popen(_spawn_command(socket_path))
        except OSError as exc:
            self._cleanup()
            return f"SNI-Helfer konnte nicht gestartet werden: {exc}"

        if not self._wait_for_socket(socket_path):
            err = self._proc_exit_hint()
            self._cleanup()
            return f"SNI-Helfer-Socket nicht erreichbar (Timeout){err}"

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(socket_path)
        except OSError as exc:
            self._cleanup()
            return f"SNI-Helfer-Verbindung fehlgeschlagen: {exc}"
        self._sock = sock

        start_msg: dict[str, Any] = {"type": MessageType.START}
        if interface is not None:
            start_msg["interface"] = interface
        try:
            send_message(sock, start_msg)
            reply = self._await_start_reply(sock)
        except (OSError, ProtocolError) as exc:
            self._cleanup()
            return f"SNI-Helfer-START fehlgeschlagen: {exc}"

        if reply is None:
            self._cleanup()
            return "SNI-Helfer beendete die Verbindung vor der START-Antwort"
        reply_type = reply.get("type")
        if reply_type == MessageType.ERROR:
            error = str(reply.get("error", "unbekannter Helfer-Fehler"))
            self._cleanup()
            return error
        if reply_type != MessageType.STARTED:
            self._cleanup()
            return f"SNI-Helfer antwortete unerwartet: {reply_type!r}"

        # Ab hier laeuft der Sniff im Helfer -- Reader-Thread fuer die HIT-Nachrichten.
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        return None

    def poll_hits(self) -> list[dict[str, Any]]:
        """Leert die interne Hit-deque und gibt die rohen Hit-dicts zurueck (thread-sicher)."""
        with self._lock:
            hits = list(self._hits)
            self._hits.clear()
        return hits

    def stop(self) -> None:
        """Stoppt Sniff + Helfer (idempotent): STOP best-effort, dann ``_cleanup``."""
        sock = self._sock
        if sock is not None:
            with self._lock:
                try:
                    send_message(sock, {"type": MessageType.STOP})
                except OSError as exc:
                    _logger.debug("sni_helper_stop_send_failed", error=str(exc))
        self._cleanup()

    def is_running(self) -> bool:
        """``True``, solange Subprozess UND Reader-Thread leben."""
        proc = self._proc
        reader = self._reader
        proc_alive = proc is not None and proc.poll() is None
        reader_alive = reader is not None and reader.is_alive()
        return proc_alive and reader_alive

    # -- Reader-Thread --------------------------------------------------------

    def _read_loop(self) -> None:
        """Liest Helfer-Nachrichten bis Verbindungsende; HIT-dicts in die deque.

        Nur HIT-Nachrichten landen in der deque (die rohen Felder ohne ``type``).
        STOPPED/PONG/ERROR werden geloggt/ignoriert -- der Lese-Pfad zieht die Hits,
        die Quittungen interessieren ihn nicht. ``recv_message`` ``None`` (sauberes
        Ende) oder ein ``ProtocolError``/``OSError`` beendet den Reader.
        """
        sock = self._sock
        if sock is None:
            return
        while not self._reader_stop.is_set():
            try:
                message = recv_message(sock)
            except (OSError, ProtocolError) as exc:
                if not self._reader_stop.is_set():
                    _logger.debug("sni_helper_read_ended", error=str(exc))
                return
            if message is None:
                return  # sauberes Verbindungsende
            if message.get("type") == MessageType.HIT:
                hit = {k: v for k, v in message.items() if k != "type"}
                with self._lock:
                    self._hits.append(hit)

    # -- Helfer-Spawn-/Connect-Hilfen ----------------------------------------

    def _wait_for_socket(self, socket_path: str) -> bool:
        """Pollt bis ``_SOCKET_WAIT_SECS``, ob die Socket-Datei existiert + Proc lebt.

        Bricht frueh ab, wenn der Subprozess vorzeitig stirbt (dann kommt der Socket
        nie) -- so wird der ehrliche Exit-Hinweis schneller sichtbar.
        """
        path = Path(socket_path)
        waited = 0.0
        while waited < _SOCKET_WAIT_SECS:
            if path.exists():
                return True
            proc = self._proc
            if proc is not None and proc.poll() is not None:
                return False  # Helfer vorzeitig gestorben -- Socket kommt nicht mehr
            time.sleep(_SOCKET_POLL_INTERVAL_SECS)
            waited += _SOCKET_POLL_INTERVAL_SECS
        return path.exists()

    def _await_start_reply(self, sock: socket.socket) -> dict[str, Any] | None:
        """Wartet (mit Timeout) auf die erste Nachricht (STARTED/ERROR) nach START.

        Setzt fuer die Quittung ein Socket-Timeout; danach blocking zuruecksetzen, weil
        der Reader-Thread denselben Socket per ``recv`` blockierend liest.
        """
        sock.settimeout(_START_REPLY_TIMEOUT_SECS)
        try:
            return recv_message(sock)
        finally:
            sock.settimeout(None)

    def _proc_exit_hint(self) -> str:
        """Liefert ``" (Exit-Code N)"``, wenn der Helfer schon beendet ist, sonst ``""``."""
        proc = self._proc
        if proc is not None and proc.poll() is not None:
            return f" (Helfer-Exit-Code {proc.returncode})"
        return ""

    def _cleanup(self) -> None:
        """Raeumt Reader, Socket, Subprozess und Socket-Verzeichnis ab (idempotent)."""
        self._reader_stop.set()

        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError as exc:
                _logger.debug("sni_helper_sock_close_failed", error=str(exc))

        reader = self._reader
        self._reader = None
        if reader is not None and reader.is_alive():
            reader.join(timeout=2)

        proc = self._proc
        self._proc = None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=_TERMINATE_TIMEOUT_SECS)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=_TERMINATE_TIMEOUT_SECS)
                except subprocess.TimeoutExpired:
                    _logger.warning("sni_helper_kill_timeout")

        socket_dir = self._socket_dir
        self._socket_dir = None
        if socket_dir is not None:
            shutil.rmtree(socket_dir, ignore_errors=True)
