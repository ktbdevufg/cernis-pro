"""``PcapHelperClient`` -- pcap-Dauerstrom + Export ueber den Helfer-Client-Kern.

Schickt ``START_PCAP`` und zieht die ``PACKET``-Nachrichten ueber den Reader-Thread
in eine thread-sichere ``Queue`` (``next_packet`` zieht sie ab). ``STOPPED`` (Selbst-
Ende durch ``max_packets`` oder ``STOP``) schiebt ein Sentinel in die Queue -> der
Adapter-Generator endet sauber. ``EXPORT_PCAP`` schickt den Befehl und wartet (ueber
ein Event, das der Reader-Thread bei ``EXPORTED`` setzt) auf das ``ok``-Ergebnis.

WARUM EXPORTED ueber den Reader (nicht selbst ``recv``): waehrend des Stroms liest der
Reader-Thread den Socket. Ein zweites ``recv`` aus ``export_pcap`` wuerde mit ihm um
die Frames konkurrieren. Darum faengt der Reader auch das ``EXPORTED`` ab und reicht
es ueber ``_export_result`` + ``_export_done`` an den wartenden ``export_pcap``-Aufruf.

REIHENFOLGE (Race mit RunCapture.stop): ``RunCapture.stop`` ruft ERST ``export_pcap``,
DANN ``stop``. Solange der Client verbunden ist (Reader laeuft, Socket offen), bleibt
``EXPORT_PCAP`` moeglich -- der Helfer-``server.py`` schliesst die Verbindung nach
``STOPPED`` NICHT (die Kommando-Schleife laeuft weiter und haelt die gesammelten
Rohpakete in der ``_Session``). Erst ``stop`` reisst die Verbindung ab. Verifiziert
am ``server.py``-Code (``run``-Schleife endet erst bei EOF/Protokollfehler).
"""

import queue
import threading
from typing import Any

import structlog

from infrastructure.sniffd.protocol import MessageType
from infrastructure.sniffd_client.base import _BaseSubprocessHelper

_logger = structlog.get_logger(__name__)

# Sentinel: signalisiert dem Abruf das Strom-Ende (Helfer-STOPPED).
_STREAM_END = object()

# Wartezeit auf die EXPORTED-Quittung nach EXPORT_PCAP. wrpcap auf eine kleine bis
# mittlere Paketsammlung ist schnell -- 10 s sind grosszuegig.
_EXPORT_REPLY_TIMEOUT_SECS = 10.0


class PcapHelperClient(_BaseSubprocessHelper):
    """pcap-Dauerstrom-Client: START_PCAP -> PACKET-Strom, EXPORT_PCAP -> bool.

    Der Reader-Thread fuellt die ``PACKET``-dicts in ``_packets`` (thread-sichere
    ``Queue``); der Adapter zieht sie ueber ``next_packet``. ``STOPPED`` legt das
    Sentinel ab. ``EXPORTED`` setzt ``_export_result`` + ``_export_done`` fuer den
    wartenden ``export_pcap``-Aufruf.
    """

    def __init__(self) -> None:
        super().__init__()
        self._packets: queue.Queue[Any] = queue.Queue()
        self._export_done = threading.Event()
        self._export_result = False

    def start(self, interface: str | None, bpf_filter: str, max_packets: int) -> str | None:
        """Spawnt Helfer, schickt START_PCAP. ``None`` bei Erfolg, sonst Fehlertext.

        Reihenfolge wie ``SniHelperClient.start``: Spawn/Connect/Send -> auf
        STARTED/ERROR warten -> Reader-Thread starten. Fehlertext (Helfer-ERROR/
        Spawn-Fehler) -> Rueckgabe (der Adapter macht daraus eine ``CaptureError``).
        """
        if self.is_running():
            return None  # bereits aktiv -- kein Doppelstart

        self._packets = queue.Queue()
        self._export_done = threading.Event()
        self._export_result = False

        start_msg: dict[str, Any] = {
            "type": MessageType.START_PCAP,
            "bpf_filter": bpf_filter,
            "max_packets": max_packets,
        }
        if interface is not None:
            start_msg["interface"] = interface
        error = self._spawn_connect_send(start_msg, "pcap")
        if error is not None:
            return error

        reply = self._recv_reply_with_timeout()
        if reply is None:
            self._cleanup()
            return "pcap-Helfer beendete die Verbindung vor der START-Antwort"
        reply_type = reply.get("type")
        if reply_type == MessageType.ERROR:
            err = str(reply.get("error", "unbekannter Helfer-Fehler"))
            self._cleanup()
            return err
        if reply_type != MessageType.STARTED:
            self._cleanup()
            return f"pcap-Helfer antwortete unerwartet: {reply_type!r}"

        self._start_reader()
        return None

    def next_packet(self, timeout: float | None = None) -> Any:
        """Zieht das naechste ``PACKET``-dict aus der Queue (blockierend, mit Timeout).

        Gibt das Strom-Ende-Sentinel (``_STREAM_END``) zurueck, sobald der Helfer
        ``STOPPED`` geschickt hat (max_packets/STOP). ``queue.Empty`` (Timeout) wird
        durchgereicht -- der Aufrufer entscheidet, wie er auf Stille reagiert.
        """
        return self._packets.get(timeout=timeout)

    def export_pcap(self, path: str) -> bool:
        """Schickt EXPORT_PCAP{path} und gibt das ``EXPORTED{ok}`` des Helfers zurueck.

        Wartet (ueber ``_export_done``, das der Reader-Thread bei ``EXPORTED`` setzt)
        auf die Quittung. Kein laufender Client (Socket weg) -> ``False``. Bleibt der
        Helfer die Quittung schuldig (Timeout) -> ``False`` + Warn (kein Haengen).
        """
        if self._sock is None:
            return False
        self._export_done.clear()
        self._export_result = False
        self._send({"type": MessageType.EXPORT_PCAP, "path": path})
        if not self._export_done.wait(timeout=_EXPORT_REPLY_TIMEOUT_SECS):
            _logger.warning("pcap_export_no_reply", path=path)
            return False
        return self._export_result

    def stop(self) -> None:
        """Stoppt den pcap-Strom + Helfer (idempotent): STOP best-effort, dann Teardown.

        Schiebt zusaetzlich das Strom-Ende-Sentinel nach, damit ein noch wartender
        ``next_packet``-Aufruf garantiert aufwacht (auch wenn der Reader vor dem
        ``STOPPED`` schon abgeraeumt wurde).
        """
        self._send({"type": MessageType.STOP})
        self._cleanup()
        self._packets.put(_STREAM_END)

    def _handle_message(self, message: dict[str, Any]) -> None:
        """Reader-Hook: ``PACKET`` -> Queue, ``STOPPED`` -> Sentinel, ``EXPORTED`` -> Event."""
        msg_type = message.get("type")
        if msg_type == MessageType.PACKET:
            packet = {k: v for k, v in message.items() if k != "type"}
            self._packets.put(packet)
        elif msg_type == MessageType.STOPPED:
            self._packets.put(_STREAM_END)
        elif msg_type == MessageType.EXPORTED:
            self._export_result = bool(message.get("ok", False))
            self._export_done.set()
