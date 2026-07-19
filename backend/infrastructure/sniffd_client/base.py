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

HELFER-AUSGABE (stdout/stderr): der Helfer bekommt eine PIPE und ein eigener
Drain-Thread (``_drain_output``) holt sie ZEILENWEISE ab und schreibt jede Zeile ins
Backend-Log (``sniffd_helper_output``). Das ist bewusst so und nicht verhandelbar:

* NICHT geerbte fds (der frueherer Zustand). Dann landete die Helfer-Ausgabe
  ungefiltert dort, wo das Backend gerade seine eigenen fds hatte -- im Bundle die
  Tauri-Logdatei, im Dev-Betrieb das Terminal. Die ``sniffd_``-Zeilen waren also nie
  echte Backend-Log-Zeilen, sondern der Helfer, der in ein fremdes fd schreibt. Ob
  sie ankommen, haengt damit an der Verpackung statt am Code.
* NICHT ``DEVNULL``. Die Helfer-Ausgabe ist die EINZIGE Diagnosequelle bei
  Sniff-Problemen (scapy-/Rechte-Fehler tauchen dort zuerst auf) -- Wegwerfen ist
  keine Option.
* NICHT eine Pipe ohne Leser. Genau DAS waere der Deadlock: laeuft der Pipe-Puffer
  (64 KiB) voll, blockiert der Helfer im ``write`` -- und zwar potenziell BEVOR er
  ``bind``/``listen`` erreicht. Er lebt dann, legt aber nie die Socket-Datei an.
  Der Drain-Thread haelt die Pipe darum dauerhaft leer.

Der Drain-Thread laeuft ab dem Popen (also VOR ``_wait_for_socket``), damit schon die
Startausgabe abfliesst; er endet mit EOF der Pipe und wird im ``_cleanup`` gejoint.
"""

import contextlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import IO, Any

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
# Loop).
#
# ETAPPE 2e -- 3.0 war zu knapp und die Ursache des Bundle-Fehlers: GEMESSEN braucht
# der gebundelte Helfer im macOS-Bundle 7 s vom Start bis zur angelegten Socket-Datei
# (mit und ohne Terminal identisch). Das ist kein Haenger, sondern die Startzeit des
# PyInstaller-ONEFILE-Binaries: Archiv ins temporaere Verzeichnis entpacken + der
# scapy-Import. Ein ``sample`` des Prozesses zeigt durchgehend normalen Fortschritt in
# ``PyImport_ImportModuleLevelObject``. Das Backend gab also nach 3 s auf, WAEHREND der
# Helfer noch startete -- daher Timeout, leeres Socket-Verzeichnis und (weil der Helfer
# vor seiner ersten Log-Zeile abgeraeumt wurde) keine Helfer-Ausgabe.
#
# 30 s = gemessene 7 s plus grosszuegige Reserve fuer langsamere Maschinen und
# Kaltstarts (ungecachtes Entpacken, kalter Dateicache, ausgelastete CPU).
#
# Das ist eine OBERGRENZE, KEINE Wartedauer: die Poll-Schleife kehrt beim ersten
# ``path.exists()`` sofort zurueck (alle 0.02 s geprueft), und ein vorzeitig
# gestorbener Helfer bricht sie ebenso sofort ab. Voll ausgeschoepft werden die 30 s
# nur von einem LEBENDEN Helfer, der wirklich noch startet -- im Dev-Betrieb bleibt
# der Erfolgsfall damit unveraendert schnell.
_SOCKET_WAIT_SECS = 30.0
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


def sniffd_platform_supported() -> tuple[bool, str]:
    """``(ok, marker)`` -- traegt die Sniff-Naht auf DIESER Plattform grundsaetzlich?

    ``ok=True, marker=""`` wenn tragbar (Linux/macOS: AF_UNIX vorhanden). Sonst
    ``ok=False`` mit stabilem Marker-String fuer den API-Layer.

    Windows-Zweig (``sys.platform == "win32"``): Die Sniff-Familie
    (SNI/pcap/LLDP) braucht Npcap FUER die Rohpaket-Erfassung UND die AF_UNIX-IPC-
    Naht zum Helfer. Beides ist auf Windows in W1 noch nicht tragbar:
    * Npcap fehlt -> ``"NPCAP_MISSING"`` (ohne Treiber kein Sniffing).
    * Npcap da, aber kein AF_UNIX -> ``"WINDOWS_IPC_UNSUPPORTED"``. Auch mit Npcap
      bleibt die Naht in W1 unnutzbar, weil die AF_UNIX-Helfer-IPC noch NICHT auf
      Windows Named Pipes portiert ist (das ist Aufgabe W2). Darum sind BEIDE
      Windows-Faelle ``ok=False``.
    """
    # Plattform-Weiche ueber ``sys.platform == "win32"``: DIESEN Guard wertet mypy
    # STATISCH aus (anders als ``hasattr(socket, "AF_UNIX")``). Nur so aktiviert mypy
    # die Windows-``winreg``-Stubs im Windows-Zweig und behandelt ihn auf Linux/macOS
    # als unerreichbar -- die frueheren ``winreg``-``attr-defined``-Fehler auf dem
    # Linux-Runner entfallen dadurch. Laufzeit-Semantik bleibt identisch: ``win32``
    # deckt sich mit dem alten ``not hasattr(socket, "AF_UNIX")``-Zweig.
    if sys.platform == "win32":
        # Windows: Npcap ueber drei Stufen pruefen (erste positive genuegt).
        # winreg/ctypes.util lokal importieren, damit Linux/macOS sie nie laden.
        import ctypes.util
        import winreg

        npcap = False
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap"):
                npcap = True
        except OSError:
            pass  # Registry-Schluessel fehlt -- naechste Stufe pruefen.

        if not npcap:
            driver = os.path.join(
                os.environ.get("WINDIR", "C:\\Windows"),
                "System32",
                "Npcap",
                "npcap.sys",
            )
            if os.path.exists(driver):
                npcap = True

        if not npcap and ctypes.util.find_library("wpcap") is not None:
            npcap = True

        if not npcap:
            return (False, "NPCAP_MISSING")
        return (False, "WINDOWS_IPC_UNSUPPORTED")

    # Linux/macOS: AF_UNIX vorhanden -> Naht grundsaetzlich tragbar.
    return (True, "")


def sniffd_unavailable_reason() -> str:
    """Marker aus ``sniffd_platform_supported()`` bei nicht getragener Plattform, sonst ``""``.

    Der API-Layer haengt diesen Marker spaeter an ``permission_error`` an (in diesem
    Auftrag NICHT verdrahtet). Auf Linux/macOS immer ``""``.
    """
    ok, marker = sniffd_platform_supported()
    return "" if ok else marker


def helper_entry_exists() -> bool:
    """``True``, wenn der Helfer-Einstieg (frozen-Binary bzw. dev-``sniffd.py``) existiert.

    Reiner Pfad-Check fuer den optimistischen Verfuegbarkeits-Check der Adapter
    (``is_available``). Sagt NICHTS ueber Rechte/scapy aus -- das prueft erst der
    echte Start ueber die ERROR-Naht des Helfers.

    ZUERST ``sniffd_platform_supported()``: traegt die Plattform grundsaetzlich nicht
    (Windows in W1), ist der Helfer trotz existierender Binary NICHT nutzbar -> ``False``
    (ehrlich statt faelschlich "verfuegbar"). Der Datei-Existenz-Check laeuft nur, wenn
    die Plattform traegt (Linux/macOS: Verhalten unveraendert, ``ok=True``).
    """
    ok, _ = sniffd_platform_supported()
    if not ok:
        return False
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
        self._drain: threading.Thread | None = None

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
            # stderr in DIESELBE Pipe wie stdout (der Helfer nutzt beide: structlog
            # schreibt per Default auf stdout, Tracebacks/scapy-Warnungen auf stderr).
            # EIN Strom = EIN Drain-Thread; keine zweite Pipe, die volllaufen kann.
            self._proc = subprocess.Popen(
                _spawn_command(socket_path),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except OSError as exc:
            self._cleanup()
            return f"{label}-Helfer konnte nicht gestartet werden: {exc}"

        # SOFORT nach dem Popen -- der Drain muss stehen, bevor auf die Socket-Datei
        # gewartet wird, sonst blockiert ein gespraechiger Helfer im vollen Pipe-Puffer,
        # noch bevor er bindet.
        self._start_drain(label)

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

    # -- Drain-Thread fuer die Helfer-Ausgabe ---------------------------------

    def _start_drain(self, label: str) -> None:
        """Startet den Drain-Thread, der stdout+stderr des Helfers ins Log holt."""
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        self._drain = threading.Thread(
            target=self._drain_output,
            args=(proc.stdout, label),
            daemon=True,
        )
        self._drain.start()

    def _drain_output(self, stream: IO[bytes], label: str) -> None:
        """Liest die Helfer-Ausgabe zeilenweise bis EOF und loggt jede Zeile.

        Zeilenweise (Iteration ueber den Stream) statt ``communicate()``: die Ausgabe
        soll LAUFEND im Backend-Log erscheinen, nicht erst wenn der Helfer endet --
        bei einem Dauer-Sniff endet er lange nicht. Der Puffer bleibt dadurch
        dauerhaft leer, der Helfer kann im ``write`` nie blockieren.

        Endet mit EOF (Helfer beendet oder Pipe geschlossen). Ein ``OSError`` beim
        Lesen (z. B. Pipe im Teardown geschlossen) beendet den Thread still -- der
        Drain ist reiner Diagnosepfad und darf den Teardown nie stoeren.
        """
        try:
            for raw in stream:
                line = raw.decode("utf-8", errors="replace").rstrip()
                if line:
                    _logger.info("sniffd_helper_output", helper=label, line=line)
        except (OSError, ValueError) as exc:
            # ValueError: Stream wurde waehrend des Lesens geschlossen (Teardown).
            _logger.debug("sniffd_client_drain_ended", helper=label, error=str(exc))
        finally:
            with contextlib.suppress(OSError):
                stream.close()

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

        # ERST NACH dem Prozess-Ende joinen: das Ende des Helfers schliesst die
        # Schreibseite der Pipe, der Drain laeuft daraufhin auf EOF und endet von
        # selbst. Umgekehrt (joinen vor terminate) haenge man am blockierenden
        # Lesen eines noch laufenden Helfers.
        #
        # PyInstaller (frozen) zeigt ZWEI Prozesse: Bootloader + eigentliches Kind.
        # ``proc`` ist der Bootloader; er reicht Signale an sein Kind weiter und
        # wartet auf dessen Ende, darum raeumt terminate/kill beide ab. Das Kind
        # haelt aber DASSELBE Pipe-Schreibende -- EOF kommt daher erst, wenn auch
        # das Kind weg ist. Der Timeout-Join schuetzt gegen ein Kind, das trotz
        # Signal haengt: der Drain ist ein Daemon-Thread und blockiert dann
        # weder Teardown noch Prozess-Ende, statt hier unbegrenzt zu warten.
        drain = self._drain
        self._drain = None
        if drain is not None and drain.is_alive():
            drain.join(timeout=_TERMINATE_TIMEOUT_SECS)
            if drain.is_alive():
                _logger.debug("sniffd_client_drain_join_timeout")

        socket_dir = self._socket_dir
        self._socket_dir = None
        if socket_dir is not None:
            shutil.rmtree(socket_dir, ignore_errors=True)
