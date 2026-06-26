"""Gemeinsamer Spawn-/Connect-/Teardown-Kern der Helfer-Clients (Backend-Seite).

ETAPPE 3b: Bis Etappe 2 lag die Spawn-/IPC-Naht SNI-spezifisch in
``infrastructure/sni/helper_channel.py`` (``SubprocessSniffHelper``). Mit pcap und
LLDP (Etappe 3b) braucht der Backend-Adapter denselben Spawn-/Connect-/Teardown-
Mechanismus, aber andere Befehle (``START_PCAP``/``START_LLDP``/``EXPORT_PCAP``) und
andere Events (``PACKET``/``NEIGHBORS``/``EXPORTED``). Darum ist der gemeinsame Kern
hierher gezogen -- EINE Stelle fuer Spawn (frozen/dev), ``mkdtemp``-Socket (0700),
``_wait_for_socket``, Connect, Reader-Thread-Grundgeruest und ``_cleanup``.

Auf ``_BaseSubprocessHelper`` bauen drei schmale Clients (eigene Module):
``SniHelperClient``, ``PcapHelperClient``, ``LldpHelperClient``. Jeder schickt seinen
START-Befehl und wertet die Helfer-Events nach seinem eigenen Muster aus.

NAMENSGRENZE: ``infrastructure.sniffd_client`` ist die BACKEND-Seite (der Client, der
den Helfer spawnt + anspricht). ``infrastructure.sniffd`` ist die HELFER-Prozess-Seite
(Server + Sniff-Kern). Nicht verwechseln.

SICHERHEIT (Socket-Pfad): pro Instanz ein eigenes ``tempfile.mkdtemp``-Verzeichnis
(0700, NICHT world-writable wie ``/tmp/cernis-sniffd.sock``); der Socket liegt darin.
Beim Teardown wird das Verzeichnis wieder entfernt.

SPAWN (frozen vs. dev, Muster ``serve.py._is_frozen`` / ``app.py``):
* frozen (PyInstaller): die Helfer-Binary ``cernis-sniffd`` liegt neben
  ``sys.executable`` -> ``[<exe-dir>/cernis-sniffd, socket_path]``.
* dev: der aktuelle Python startet ``<repo>/backend/sniffd.py`` ->
  ``[sys.executable, <repo>/backend/sniffd.py, socket_path]``.

ROBUST (S3-frei): scheitert Spawn/Connect, liefert der Verbindungsaufbau einen
EHRLICHEN Fehlertext (kein Crash, keine stille Leer-Erfassung). Alle scapy-/Rechte-
Fehler kommen als ERROR-Text vom Helfer und werden 1:1 durchgereicht.
"""

import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import structlog

from infrastructure.sniffd.protocol import (
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
    # dev: <repo>/backend/sniffd.py -- parents[2] von
    # infrastructure/sniffd_client/base.py
    entry = Path(__file__).resolve().parents[2] / "sniffd.py"
    return [sys.executable, str(entry), socket_path]


def helper_entry_exists() -> bool:
    """``True``, wenn der Helfer-Einstieg (frozen-Binary bzw. dev-``sniffd.py``) existiert.

    Reiner Pfad-Check fuer den optimistischen Verfuegbarkeits-Check der Adapter
    (``is_available``). Sagt NICHTS ueber Rechte/scapy aus -- das prueft erst der
    echte Start ueber die ERROR-Naht des Helfers.
    """
    cmd = _spawn_command("")
    if _is_frozen():
        return Path(cmd[0]).exists()
    return Path(cmd[1]).exists()  # dev: sniffd.py-Pfad


class _BaseSubprocessHelper:
    """Spawn-/Connect-/Teardown-Kern eines on-demand gestarteten Helfer-Subprozesses.

    Eine Instanz haelt hoechstens einen laufenden Helfer. Die abgeleiteten Clients
    schicken ihren START-Befehl ueber ``_spawn_connect_send`` (spawnt + connectet +
    sendet, gibt den Socket oder einen ehrlichen Fehlertext zurueck) und werten die
    Helfer-Events nach ihrem eigenen Muster aus (Reader-Thread bei pcap/SNI,
    blockierendes Einmal-Warten bei LLDP).

    Der ``_send``-Pfad ist mit dem Teardown ueber ``_lock`` serialisiert (Kommando-
    Senden und Reader laufen nie gleichzeitig schreibend -- nur der Adapter sendet,
    der Reader liest).
    """

    def __init__(self) -> None:
        self._proc: subprocess.Popen[bytes] | None = None
        self._sock: socket.socket | None = None
        self._socket_dir: str | None = None
        self._reader: threading.Thread | None = None
        self._reader_stop = threading.Event()
        self._lock = threading.Lock()

    # -- Spawn/Connect/Send (gemeinsamer Kern) --------------------------------

    def _spawn_connect_send(self, command: dict[str, Any], label: str) -> str | None:
        """Spawnt Helfer, connectet, schickt ``command``. ``None`` bei Erfolg, sonst Text.

        Reihenfolge: Socket-Dir (0700) -> Popen -> auf Socket-Datei warten ->
        connecten -> ``command`` senden. Jeder Fehlschritt raeumt das Halb-Gestartete
        wieder ab (``_cleanup``) und gibt einen ehrlichen Fehlertext zurueck -- KEIN
        Crash, KEINE stille Leer-Erfassung. ``label`` (z. B. "SNI"/"pcap"/"LLDP")
        geht in die Fehlertexte ein. Bei Erfolg liegt der verbundene Socket in
        ``self._sock`` und die Quittung holt der aufrufende Client selbst.
        """
        # Frischer Reader-Stop-Zustand fuer diesen Lauf.
        self._reader_stop = threading.Event()

        try:
            self._socket_dir = tempfile.mkdtemp(prefix="cernis-sniffd-")
        except OSError as exc:
            return f"{label}-Helfer: Socket-Verzeichnis nicht anlegbar: {exc}"
        socket_path = str(Path(self._socket_dir) / "sniffd.sock")

        try:
            self._proc = subprocess.Popen(_spawn_command(socket_path))
        except OSError as exc:
            self._cleanup()
            return f"{label}-Helfer konnte nicht gestartet werden: {exc}"

        if not self._wait_for_socket(socket_path):
            err = self._proc_exit_hint()
            self._cleanup()
            return f"{label}-Helfer-Socket nicht erreichbar (Timeout){err}"

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(socket_path)
        except OSError as exc:
            self._cleanup()
            return f"{label}-Helfer-Verbindung fehlgeschlagen: {exc}"
        self._sock = sock

        try:
            send_message(sock, command)
        except OSError as exc:
            self._cleanup()
            return f"{label}-Helfer-Befehl fehlgeschlagen: {exc}"
        return None

    def _send(self, payload: dict[str, Any]) -> None:
        """Thread-sicheres Senden eines Befehls an den Helfer (best-effort).

        Unter ``_lock`` (serialisiert mit dem Teardown). Ein OSError (z. B. der
        Helfer ist schon weg) wird geloggt, nicht geworfen -- der Aufrufer ist im
        Stop-/Best-Effort-Pfad.
        """
        sock = self._sock
        if sock is None:
            return
        with self._lock:
            try:
                send_message(sock, payload)
            except OSError as exc:
                _logger.debug("sniffd_client_send_failed", error=str(exc))

    # -- Reader-Thread-Grundgeruest -------------------------------------------

    def _start_reader(self) -> None:
        """Startet den Reader-Thread; jede Nachricht geht an ``_handle_message``."""
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        """Liest Helfer-Nachrichten bis Verbindungsende; reicht sie an ``_handle_message``.

        ``recv_message`` ``None`` (sauberes Ende) oder ein ``ProtocolError``/``OSError``
        beendet den Reader. Die Auswertung (welche Events interessieren) macht die
        Subklasse in ``_handle_message``.
        """
        sock = self._sock
        if sock is None:
            return
        while not self._reader_stop.is_set():
            try:
                message = recv_message(sock)
            except (OSError, ProtocolError) as exc:
                if not self._reader_stop.is_set():
                    _logger.debug("sniffd_client_read_ended", error=str(exc))
                return
            if message is None:
                return  # sauberes Verbindungsende
            self._handle_message(message)

    def _handle_message(self, message: dict[str, Any]) -> None:
        """Verarbeitet EINE Helfer-Nachricht (von der Subklasse ueberschrieben)."""
        raise NotImplementedError

    # -- Helfer-Spawn-/Connect-Hilfen -----------------------------------------

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

    def _recv_reply_with_timeout(
        self, timeout: float = _START_REPLY_TIMEOUT_SECS
    ) -> dict[str, Any] | None:
        """Wartet (mit Timeout) auf die naechste Helfer-Nachricht auf ``self._sock``.

        Setzt fuer die eine Quittung ein Socket-Timeout; danach blocking zuruecksetzen
        (der Reader-Thread liest denselben Socket spaeter blockierend). ``None`` bei
        sauberem Verbindungsende vor der Antwort.
        """
        sock = self._sock
        if sock is None:
            return None
        sock.settimeout(timeout)
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

    def is_running(self) -> bool:
        """``True``, solange Subprozess UND Reader-Thread leben.

        Clients ohne Reader-Thread (LLDP: blockierendes Einmal-Warten) ueberschreiben
        dies -- fuer pcap/SNI ist "Subprozess + Reader lebt" der korrekte Lauf-Status.
        """
        proc = self._proc
        reader = self._reader
        proc_alive = proc is not None and proc.poll() is None
        reader_alive = reader is not None and reader.is_alive()
        return proc_alive and reader_alive

    def _cleanup(self) -> None:
        """Raeumt Reader, Socket, Subprozess und Socket-Verzeichnis ab (idempotent)."""
        self._reader_stop.set()

        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError as exc:
                _logger.debug("sniffd_client_sock_close_failed", error=str(exc))

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
                    _logger.warning("sniffd_client_kill_timeout")

        socket_dir = self._socket_dir
        self._socket_dir = None
        if socket_dir is not None:
            shutil.rmtree(socket_dir, ignore_errors=True)
