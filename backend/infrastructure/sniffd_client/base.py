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
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import IO, Any

import structlog

from infrastructure.sniffd.protocol import (
    MessageType,
    ProtocolError,
    recv_message,
    send_message,
)
from infrastructure.sniffd.transport import (
    address_for_dir,
    address_ready,
    connect,
    create_address_dir,
    remove_address_dir,
)

_logger = structlog.get_logger(__name__)

# Helfer-Binary-/Entry-Name (frozen: neben sys.executable; dev: backend/sniffd.py).
#
# EINE Stelle, plattformuebliche Endung: Windows legt die Binary als
# ``cernis-sniffd.exe`` ab (``build.ps1``), Linux/macOS ohne Endung
# (``build.sh``/``build-linux.sh``). Der Name wurde frueher OHNE Endung gebildet --
# im eingefrorenen Windows-Bau zeigte das Spawn-Kommando damit GEMESSEN auf einen
# Pfad, den es nicht gibt (``...\dist\cernis-sniffd``), waehrend die echte
# ``cernis-sniffd.exe`` DANEBEN lag. Die Endung haengt hier an genau EINEM Ort,
# damit sie nicht wieder auseinanderlaufen kann.
#
# ``sys.platform``-Guard statt ``os.name``: mypy wertet GENAU DIESEN statisch aus
# (Projektlinie, wie in ``transport.py``/``sniffd_platform_supported``).
if sys.platform == "win32":
    _HELPER_BINARY_NAME = "cernis-sniffd.exe"
else:
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

# Frist des FREUNDLICHEN Beendens, bevor hart abgeraeumt wird.
#
# Der freundliche Weg ist auf ALLEN Plattformen dasselbe Ereignis: das
# geschlossene Verbindungsende. Der Helfer verlaesst daraufhin seine
# Kommando-Schleife (``recv_message`` -> ``None``), raeumt seinen Sniff ab und
# endet von SELBST mit Rueckgabewert 0.
#
# GEMESSEN (Windows, Dev-Lauf): vom Schliessen des Kanals bis zum Prozess-Ende
# vergehen 0.11 s. 3 s decken das mit reichlich Reserve ab -- auch fuer den
# eingefrorenen Bau, wo der PyInstaller-Bootloader sein Kind noch abwickeln muss.
#
# Das ist eine OBERGRENZE, KEINE Wartedauer: ``wait`` kehrt beim tatsaechlichen
# Prozess-Ende sofort zurueck. Voll ausgeschoepft wird die Frist nur von einem
# Helfer, der wirklich nicht von selbst geht -- und danach greift das harte
# Beenden.
_GRACEFUL_EXIT_TIMEOUT_SECS = 3.0

# Wie lange auf die ``STOPPED``-Quittung gewartet wird, bevor der Kanal faellt
# (siehe ``_await_stop_ack``). Kurz gehalten: es geht nur darum, dem Helfer das
# Absetzen einer bereits fertigen Antwort zu ermoeglichen, nicht darum, auf einen
# langen Sniff-Abbau zu warten -- ``sniffer.stop(join=True)`` laeuft im Helfer vor
# dem Senden der Quittung. GEMESSEN liegt die Spanne im Millisekundenbereich.
_STOP_ACK_TIMEOUT_SECS = 2.0


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

    ``ok=True, marker=""`` wenn tragbar (Linux/macOS immer; Windows mit erkanntem
    Npcap). Sonst ``ok=False`` mit stabilem Marker-String fuer den API-Layer.

    ERKENNUNGSSTUFEN (Windows): VIER Stufen, geordnet von der verlaesslichsten zur
    schwaechsten Spur; die erste zutreffende genuegt. Die Reihenfolge und die Wahl
    der Orte sind GEMESSEN begruendet -- jede Stufe traegt unten den Befund, der
    sie rechtfertigt. Mehrere Stufen sind Absicht, nicht Redundanz: welche Spur
    eine fremde Maschine bzw. eine aeltere Npcap-Fassung traegt, ist nicht
    gemessen, darum bleiben alle vier stehen.

    ENTFALLEN (W17) -- die frueher fuenfte Stufe ``ctypes.util.find_library(
    "wpcap")``: sie wertete nur aus, OB der Lader irgendeine ``wpcap.dll`` im
    Suchpfad findet -- ohne Ablageort, ohne Version, ohne Hersteller. Eine
    Bibliothek ohne Herkunftsnachweis belegt kein Npcap: GEMESSEN loeste die
    Suche hier auf ``C:\\WINDOWS\\system32\\wpcap.dll`` auf, und genau diese Datei
    legt eine reine WinPcap-Installation am selben Ort ab (Npcap traegt sie im
    WinPcap-Vertraeglichkeitsmodus, GEMESSEN ``WinPcapCompatible = 1`` am
    Produktschluessel aus Stufe 2). Die Stufe konnte damit ohne funktionierendes
    Npcap anschlagen und Npcap faelschlich als vorhanden melden. Die vier
    verbleibenden Stufen pruefen dagegen jeweils einen Npcap-exklusiven Ort bzw.
    Namen; GEMESSEN greifen sie auf dieser Maschine alle vier.

    Windows-Zweig (``sys.platform == "win32"``): Die Sniff-Familie
    (SNI/pcap/LLDP) braucht Npcap FUER die Rohpaket-Erfassung. Die IPC-Naht zum
    Helfer traegt auf Windows seit W2 ueber eine benannte Pipe mit Zugriff nur
    fuer den eigenen Benutzer (siehe ``transport.py``) -- sie ist damit KEIN
    Hinderungsgrund mehr. Es bleiben genau ZWEI Faelle:
    * Npcap erkannt -> ``ok=True``, kein Marker (Funktion verfuegbar).
    * Npcap fehlt -> ``ok=False, "NPCAP_MISSING"`` (ohne Treiber kein Sniffing);
      das Frontend graut die Funktion mit dem bestehenden Npcap-Hinweis aus und
      bietet die Nachinstallation an.

    Einen dritten Fall ("Npcap da, aber Naht nicht portiert") gibt es nicht mehr;
    der frueher dafuer gefuehrte Marker ist ersatzlos entfallen.

    KEIN stiller Fallback: schlagen ALLE Erkennungsstufen fehl, gilt Npcap als
    nicht vorhanden und das wird ueber ``"NPCAP_MISSING"`` benannt -- nie als
    vorhanden angenommen.
    """
    # Plattform-Weiche ueber ``sys.platform == "win32"``: DIESEN Guard wertet mypy
    # STATISCH aus (anders als ``hasattr(socket, "AF_UNIX")``). Nur so aktiviert mypy
    # die Windows-``winreg``-Stubs im Windows-Zweig und behandelt ihn auf Linux/macOS
    # als unerreichbar -- die frueheren ``winreg``-``attr-defined``-Fehler auf dem
    # Linux-Runner entfallen dadurch. Der Guard trennt hier die PLATTFORM (welche
    # Pruefung gilt), nicht mehr die Verfuegbarkeit der IPC-Naht.
    if sys.platform == "win32":
        # Windows: Npcap ueber mehrere Stufen pruefen (erste positive genuegt).
        # winreg lokal importieren, damit Linux/macOS es nie laden.
        import winreg

        windir = os.environ.get("WINDIR", "C:\\Windows")
        npcap = False

        # STUFE 1 -- Dienst-/Treibereintrag ``SYSTEM\CurrentControlSet\Services\npcap``.
        #
        # WO: der Eintrag, den der Kerneltreiber selbst traegt. WARUM DORT: das ist
        # die VERLAESSLICHSTE Spur, darum steht sie vorn. GEMESSEN auf dieser
        # Maschine: vorhanden, ``ImagePath = \SystemRoot\system32\DRIVERS\npcap.sys``,
        # der Dienst laeuft (``sc query npcap`` -> ``KERNEL_DRIVER``/``RUNNING``). Der
        # Name ``npcap`` ist Npcap-exklusiv -- WinPcap fuehrte seinen Treiber unter
        # ``npf``, und dieser Schluessel ist hier GEMESSEN NICHT vorhanden. Der
        # Eintrag entsteht erst beim Einrichten des Treibers und faellt mit dem
        # Entfernen wieder weg; er beschreibt damit den tatsaechlich nutzbaren
        # Zustand und nicht nur zurueckgebliebene Dateien.
        #
        # Diese Sicht ist NICHT umgeleitet: ``SYSTEM`` kennt keine 32-Bit-Spiegelung,
        # ein Sichten-Flag ist hier also gegenstandslos.
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap"
            ):
                npcap = True
        except OSError:
            pass  # Kein Treibereintrag -- naechste Stufe pruefen.

        # STUFE 2 -- Produktschluessel ``SOFTWARE\Npcap`` in BEIDEN Sichten.
        #
        # WO: 64-Bit-Sicht (``KEY_WOW64_64KEY``) UND 32-Bit-Sicht
        # (``KEY_WOW64_32KEY``, physisch ``SOFTWARE\WOW6432Node\Npcap``).
        # WARUM BEIDE: GEMESSEN liegt der Schluessel dieser Fassung (Npcap 1.88)
        # AUSSCHLIESSLICH in der 32-Bit-Sicht -- das Einrichtprogramm ist ein
        # 32-Bit-Programm und wird darum umgeleitet. Die Weiche prueft aus einem
        # 64-Bit-Python und sah daher bisher (ohne Flag = 64-Bit-Sicht) ins Leere,
        # obwohl Npcap installiert ist. Die 64-Bit-Sicht bleibt trotzdem stehen: ob
        # aeltere oder kuenftige Fassungen dort ablegen, ist nicht gemessen, und
        # eine zusaetzliche Pruefung kostet nichts.
        # GEMESSENE Werte des Schluessels: ``(default) = C:\Program Files\Npcap``,
        # ``WinPcapCompatible = 1``, ``AdminOnly = 0``.
        if not npcap:
            for sicht in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Npcap",
                        0,
                        winreg.KEY_READ | sicht,
                    ):
                        npcap = True
                        break
                except OSError:
                    continue  # Schluessel in dieser Sicht nicht da -- naechste Sicht.

        # STUFE 3 -- Treiberdatei an BEIDEN bekannten Orten.
        #
        # WO: ``System32\drivers\npcap.sys`` (der tatsaechliche Ort) und
        # ``System32\Npcap\npcap.sys`` (der bisher gepruefte). WARUM BEIDE:
        # GEMESSEN liegt die Datei hier unter ``System32\drivers\npcap.sys``
        # (82592 Bytes, Version 1.88) -- genau dorthin zeigt auch der ``ImagePath``
        # aus Stufe 1. Das Verzeichnis ``System32\Npcap`` existiert zwar, enthaelt
        # aber NUR ``NpcapHelper.exe``, ``Packet.dll``, ``WlanHelper.exe`` und
        # ``wpcap.dll`` -- NICHT den Treiber. Der alte Ort bleibt dennoch stehen,
        # weil nicht gemessen ist, wie aeltere Fassungen ablegen.
        #
        # Schwaecher als Stufe 1/2: eine Datei kann nach einem unvollstaendigen
        # Entfernen zurueckbleiben, ohne dass der Treiber noch eingerichtet ist.
        if not npcap:
            for treiber in (
                os.path.join(windir, "System32", "drivers", "npcap.sys"),
                os.path.join(windir, "System32", "Npcap", "npcap.sys"),
            ):
                if os.path.exists(treiber):
                    npcap = True
                    break

        # STUFE 4 -- Npcap-EIGENE Bibliothek unter ``System32\Npcap\wpcap.dll``
        # (SCHWAECHSTE der vier Stufen, darum zuletzt).
        #
        # WO: das Npcap-eigene Unterverzeichnis. WARUM DORT: GEMESSEN liegt die
        # Bibliothek dort (Version 1.10.6); dieser Pfad gehoert AUSSCHLIESSLICH
        # Npcap. Der Ablageort ist damit der Herkunftsnachweis -- genau der, den
        # die entfallene fuenfte Stufe nicht hatte (siehe Funktionskopf).
        if not npcap and os.path.exists(os.path.join(windir, "System32", "Npcap", "wpcap.dll")):
            npcap = True

        if not npcap:
            return (False, "NPCAP_MISSING")
        return (True, "")

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
    (Windows ohne Npcap), ist der Helfer trotz existierender Binary NICHT nutzbar ->
    ``False`` (ehrlich statt faelschlich "verfuegbar"). Der Datei-Existenz-Check laeuft
    nur, wenn die Plattform traegt (Linux/macOS immer; Windows mit erkanntem Npcap).
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
        # Wurde ein ``STOP`` abgesetzt, auf dessen Quittung der Abbau kurz warten
        # soll? (siehe ``_await_stop_ack``)
        self._stop_sent = False
        # Vom Reader-Thread gesetzt, sobald die ``STOPPED``-Quittung durch ist.
        self._stopped_seen = threading.Event()

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
        # Frischer Quittungs-Zustand: aus einem frueheren Lauf darf weder ein
        # offenes ``STOP`` noch eine gesehene Quittung nachhaengen.
        self._stop_sent = False
        self._stopped_seen = threading.Event()

        try:
            self._socket_dir = create_address_dir()
        except OSError as exc:
            return f"{label}-Helfer: Socket-Verzeichnis nicht anlegbar: {exc}"
        socket_path = address_for_dir(self._socket_dir)

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
            sock = connect(socket_path)
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
                return
        # Nur ein ERFOLGREICH abgesetztes ``STOP`` begruendet das kurze Warten auf
        # die Quittung im Abbau (siehe ``_await_stop_ack``).
        if payload.get("type") == MessageType.STOP:
            self._stop_sent = True

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
        try:
            while not self._reader_stop.is_set():
                try:
                    message = recv_message(sock)
                except (OSError, ProtocolError) as exc:
                    if not self._reader_stop.is_set():
                        _logger.debug("sniffd_client_read_ended", error=str(exc))
                    return
                if message is None:
                    return  # sauberes Verbindungsende
                # Die ``STOPPED``-Quittung freigeben, auf die der Abbau kurz
                # wartet (``_await_stop_ack``) -- VOR der Weitergabe, damit ein
                # langsamer ``_handle_message`` das Warten nicht verlaengert.
                if message.get("type") == MessageType.STOPPED:
                    self._stopped_seen.set()
                self._handle_message(message)
        finally:
            # Endet der Reader aus IRGENDEINEM Grund, wartet niemand mehr auf
            # eine Quittung, die dann nicht mehr kommen kann.
            self._stopped_seen.set()

    def _handle_message(self, message: dict[str, Any]) -> None:
        """Verarbeitet EINE Helfer-Nachricht (von der Subklasse ueberschrieben)."""
        raise NotImplementedError

    # -- Helfer-Spawn-/Connect-Hilfen -----------------------------------------

    def _wait_for_socket(self, socket_path: str) -> bool:
        """Pollt bis ``_SOCKET_WAIT_SECS``, ob die Socket-Datei existiert + Proc lebt.

        Bricht frueh ab, wenn der Subprozess vorzeitig stirbt (dann kommt der Socket
        nie) -- so wird der ehrliche Exit-Hinweis schneller sichtbar.
        """
        waited = 0.0
        while waited < _SOCKET_WAIT_SECS:
            if address_ready(socket_path):
                return True
            proc = self._proc
            if proc is not None and proc.poll() is not None:
                return False  # Helfer vorzeitig gestorben -- Socket kommt nicht mehr
            time.sleep(_SOCKET_POLL_INTERVAL_SECS)
            waited += _SOCKET_POLL_INTERVAL_SECS
        return address_ready(socket_path)

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

    def _await_stop_ack(self) -> None:
        """Wartet kurz, bis der Helfer ein angefordertes ``STOP`` quittiert hat.

        WARUM DAS NOETIG IST (im echten Lauf gemessen): ``stop()`` der Clients
        sendet ``STOP`` und ruft UNMITTELBAR ``_cleanup``. Der Helfer verarbeitet
        das ``STOP``, stoppt seinen Sniff und will die Quittung ``STOPPED``
        zuruecksenden -- traf dabei aber auf einen bereits geschlossenen Kanal.
        Sein ``sendall`` scheiterte, die Ausnahme schlug bis in seine
        Hauptfunktion durch und er endete mit Rueckgabewert 1 statt 0
        (GEMESSEN: ``OSError: Pipe-Schreibvorgang hat 0 Bytes geschrieben``).
        Der Helfer starb also AM AUFRAEUMEN, obwohl der freundliche Weg gewaehlt
        war -- das Ende war nur scheinbar sauber.

        Hier wird ihm die kurze Spanne gegeben, seine Quittung noch abzusetzen.
        Danach faellt der Kanal, was ihn regulaer aus der Kommando-Schleife
        entlaesst (Rueckgabewert 0).

        Die Quittung wird NICHT erzwungen: sie ist ein Hoeflichkeitsfenster, kein
        Vertrag. Wer ohne ``STOP`` abraeumt (Fehlerpfade in ``_spawn_connect_send``)
        oder wessen Helfer schon weg ist, wartet hier nicht -- es gibt dann
        nichts zu quittieren.

        Kein stiller Fallback: bleibt die Quittung trotz laufendem Helfer aus,
        wird das benannt (``sniffd_client_stop_ack_timeout``) und der Abbau geht
        regulaer weiter -- der gestufte Prozess-Abbau faengt den Rest.
        """
        if not self._stop_sent:
            return  # kein STOP angefordert -- es gibt nichts zu quittieren
        self._stop_sent = False

        proc = self._proc
        if self._sock is None or proc is None or proc.poll() is not None:
            return  # kein Kanal bzw. Helfer schon beendet

        # Laeuft ein Reader-Thread, liest DIESER die Quittung -- dann wird auf
        # sein Ende gewartet (er endet mit dem Verbindungsende bzw. hier mit der
        # verarbeiteten Quittung). Ohne Reader wird direkt gelesen.
        reader = self._reader
        if reader is not None and reader.is_alive():
            if not self._stopped_seen.wait(timeout=_STOP_ACK_TIMEOUT_SECS):
                _logger.debug("sniffd_client_stop_ack_timeout", timeout=_STOP_ACK_TIMEOUT_SECS)
            return

        try:
            reply = self._recv_reply_with_timeout(_STOP_ACK_TIMEOUT_SECS)
        except (OSError, ProtocolError, TimeoutError) as exc:
            _logger.debug("sniffd_client_stop_ack_failed", error=str(exc))
            return
        if reply is None:
            return  # Helfer hat die Verbindung selbst beendet -- auch das ist ein Ende

    def _stop_process(self, proc: "subprocess.Popen[bytes]") -> None:
        """Beendet den Helfer GESTUFT: erst freundlich, nach Frist hart.

        STUFE 1 -- freundlich. Der Kanal ist zu diesem Zeitpunkt bereits
        geschlossen (``_cleanup`` schliesst ihn VOR diesem Aufruf). Genau das IST
        die freundliche Aufforderung: der Helfer sieht das Verbindungsende,
        verlaesst seine Kommando-Schleife, raeumt seinen Sniff ab (``_teardown``)
        und endet von selbst mit Rueckgabewert 0. Hier wird ihm dafuer bis
        ``_GRACEFUL_EXIT_TIMEOUT_SECS`` Zeit gegeben.

        WARUM NICHT ``terminate()`` ALS FREUNDLICHER WEG: auf Windows ist
        ``Popen.terminate()`` ein ``TerminateProcess`` -- ein hartes Abschiessen
        OHNE zugestelltes Signal. Der ``SIGTERM``-Handler in ``sniffd/server.py``
        laeuft dort NIE (GEMESSEN: weder ``sniffd_signal`` noch ``sniffd_shutdown``
        erscheinen im Helfer-Log, der Rueckgabewert ist 1). Frueher rief
        ``_cleanup`` ``terminate()`` SOFORT nach dem Schliessen des Kanals -- das
        harte Beenden gewann damit das Rennen gegen den freundlichen Weg
        (GEMESSEN: nur-Kanal-schliessen endet nach 0.11 s mit Rueckgabewert 0,
        Kanal-schliessen-plus-terminate nach 0.00 s mit Rueckgabewert 1). Auf
        Windows gab es dadurch faktisch NUR den harten Weg.

        STUFE 2 -- hart, erst NACH der Frist. Geht der Helfer nicht von selbst,
        greift ``terminate()`` (Linux/macOS: ``SIGTERM``, dort loest es den
        Handler wirklich aus; Windows: ``TerminateProcess``), danach als letztes
        Mittel ``kill()``. Beides mit eigener Frist, damit der Abbau nicht haengt.

        Linux/macOS bleiben zeichengleich: dieselbe Reihenfolge, dieselben Mittel.
        Neu ist allein, dass dem Selbst-Ende VOR dem harten Zugriff Zeit bleibt --
        dort endete der Helfer bisher regelmaessig schon am Verbindungsende, und
        ``terminate()`` traf einen bereits beendeten Prozess.
        """
        if proc.poll() is not None:
            return  # schon von selbst beendet -- nichts zu tun

        # Stufe 1: freundlich -- auf das Selbst-Ende am Verbindungsende warten.
        try:
            proc.wait(timeout=_GRACEFUL_EXIT_TIMEOUT_SECS)
            _logger.debug("sniffd_client_graceful_exit", returncode=proc.returncode)
            return
        except subprocess.TimeoutExpired:
            # Kein stiller Fallback: dass der freundliche Weg nicht griff, wird
            # BENANNT, bevor hart abgeraeumt wird.
            _logger.warning(
                "sniffd_client_graceful_exit_timeout",
                timeout=_GRACEFUL_EXIT_TIMEOUT_SECS,
            )

        # Stufe 2: hart -- terminate, dann als letztes Mittel kill.
        proc.terminate()
        try:
            proc.wait(timeout=_TERMINATE_TIMEOUT_SECS)
            return
        except subprocess.TimeoutExpired:
            _logger.warning("sniffd_client_terminate_timeout")

        proc.kill()
        try:
            proc.wait(timeout=_TERMINATE_TIMEOUT_SECS)
        except subprocess.TimeoutExpired:
            _logger.warning("sniffd_client_kill_timeout")

    def _cleanup(self) -> None:
        """Raeumt Reader, Socket, Subprozess und Socket-Verzeichnis ab (idempotent).

        Reihenfolge tragend: der Kanal wird ZUERST geschlossen -- das ist die
        freundliche Aufforderung ans Helfer-Ende (siehe ``_stop_process``) --,
        erst danach greift der gestufte Prozess-Abbau.
        """
        # Dem Helfer Gelegenheit geben, ein angefordertes ``STOP`` noch zu
        # quittieren, BEVOR der Kanal faellt (siehe ``_await_stop_ack``).
        self._await_stop_ack()

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
        if proc is not None:
            self._stop_process(proc)

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
            remove_address_dir(socket_dir)
