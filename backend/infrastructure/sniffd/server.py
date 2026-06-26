"""Der Helfer-Server: AF_UNIX-Stream-Socket, spricht ``protocol``, fuehrt ``sniff_core``.

On-demand-Helfer: ein Backend, eine Sniff-Session. ``serve`` bindet einen
AF_UNIX-Stream-Socket, akzeptiert GENAU eine Verbindung, bedient sie ueber die
Kommando-Schleife und beendet sich nach Verbindungsende sauber (Socket-Datei
entfernen).

Kommandos (Backend -> Helfer): ``PING`` -> ``PONG``; ``START`` (optional
``"interface"``) -> ``check_raw_permission``; bei Fehlt-Recht ``ERROR`` + KEIN
Sniff, sonst ``start_raw_sniff`` in eigenem Thread + ``STARTED`` + je Hit eine
``HIT``-Nachricht; ``STOP`` -> ``stop_event`` setzen, Sniff joinen, ``STOPPED``.

ETAPPE 3a -- drei weitere Befehle (KEIN Backend-Adapter umgestellt, app.py
unberuehrt; der Helfer bleibt isoliert per Socket testbar):

* ``START_PCAP`` (optional ``interface``/``bpf_filter``, ``max_packets``) ->
  ``check_raw_permission``, sonst ``start_pcap_sniff`` in eigenem Thread +
  ``STARTED`` + je Paket eine ``PACKET``-Nachricht; Rohpakete werden intern fuer
  ``EXPORT_PCAP`` gesammelt. Bei Selbst-Ende (``max_packets``) folgt ``STOPPED``.
  ``STOP`` beendet auch diesen Modus.
* ``START_LLDP`` (optional ``interface``, ``duration``) -> KEIN Dauerstrom:
  ``run_lldp_sniff`` blockierend in einem Thread; danach EINE ``NEIGHBORS``-
  Nachricht mit der Liste.
* ``EXPORT_PCAP`` (``path``) -> ``export_pcap`` der gesammelten Rohpakete,
  Ergebnis als ``EXPORTED {"ok": bool}``.

Defensiv bei bereits laufendem Sniff: ein erneutes ``START``/``START_PCAP``/
``START_LLDP`` startet NICHT doppelt, sondern quittiert idempotent mit ``STARTED``
(konsistent zum bestehenden ``START``-Verhalten -- die einfachere Variante; ein
gleichzeitiger SNI- und pcap-Sniff in derselben Session ist nicht vorgesehen).

Thread-Sicherheit: Sniff-Thread (scapy-prn ruft ``on_hit``/``on_packet``) und
Kommando-Schleife schreiben denselben Socket -- ``send_message`` laeuft daher unter
einem ``threading.Lock``.

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
from infrastructure.sniffd.sniff_core import (
    check_raw_permission,
    export_pcap,
    run_lldp_sniff,
    start_pcap_sniff,
    start_raw_sniff,
)

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
        # Serialisiert die "Sniffer claimen" (lesen + nullen) gegen die STOPPED-Race:
        # ``_on_pcap_finished`` (prn-Thread, Selbst-Ende) und ``_handle_stop``
        # (Kommando-Schleife) koennen sonst BEIDE den Sniffer non-None sehen, nullen
        # und je ein STOPPED senden. ``_claim_sniffer`` macht das Lesen-und-Nullen
        # atomar -> GENAU EINER bekommt den Sniffer, also EXACTLY-ONCE STOPPED. Ein
        # eigener, schmaler Lock (nicht ``_send_lock``), damit der HIT/PACKET-Send-
        # Pfad nicht unter der Stop-Logik blockiert.
        self._sniffer_lock = threading.Lock()
        # Rohpaket-Sammelliste fuer EXPORT_PCAP -- eine aktive pcap-Session pro
        # Verbindung; START_PCAP setzt sie frisch. Der pcap-prn-Thread haengt an,
        # die Kommando-Schleife liest sie bei EXPORT_PCAP -- der Send-Lock deckt
        # das gemeinsame Senden ab; das blosse ``.append`` einer Liste ist unter
        # CPython atomar genug fuer dieses Append-only-Sammeln.
        self._raw_packets: list[Any] = []

    def _send(self, payload: dict[str, Any]) -> None:
        """Thread-sicheres Senden (Lock um ``send_message``)."""
        with self._send_lock:
            send_message(self._conn, payload)

    def _claim_sniffer(self) -> Any:
        """Liest ``_sniffer`` und nullt ihn ATOMAR; gibt das fruehere Handle zurueck.

        Der einzige Pfad, der ``_sniffer`` von non-None auf ``None`` setzt. Unter
        ``_sniffer_lock`` -- so bekommt bei gleichzeitigem Selbst-Ende (prn-Thread)
        und ``STOP`` (Kommando-Schleife) GENAU EINER ein non-``None``-Handle zurueck;
        der andere bekommt ``None``. Der Gewinner stoppt den Sniff + sendet das eine
        ``STOPPED`` (Exactly-Once), der Verlierer tut nichts.
        """
        with self._sniffer_lock:
            sniffer = self._sniffer
            self._sniffer = None
            return sniffer

    def _on_hit(self, hit: dict[str, Any]) -> None:
        """Sniff-Callback: rohen Hit als ``HIT``-Nachricht senden (Hit-Thread)."""
        self._send({"type": MessageType.HIT, **hit})

    def _on_packet(self, summary: dict[str, Any]) -> None:
        """pcap-Callback: Summary-dict als ``PACKET``-Nachricht senden (Sniff-Thread)."""
        self._send({"type": MessageType.PACKET, **summary})

    def _on_raw(self, pkt: Any) -> None:
        """pcap-Callback: Roh-Paket fuer den spaeteren ``EXPORT_PCAP`` sammeln."""
        self._raw_packets.append(pkt)

    def _on_pcap_finished(self) -> None:
        """``finished_callback`` des pcap-Sniffers: Selbst-Ende (max_packets) -> ``STOPPED``.

        scapy ruft das im Sniffer-Thread, wenn der Strom von selbst endet. Der
        Sniffer-Handle wird ATOMAR geleert (``_claim_sniffer``), dann ein ``STOPPED``
        nachgereicht. Ein gleichzeitiges ``STOP`` (Kommando-Schleife) konkurriert um
        denselben Claim -- bekommt hier (oder dort) genau EINER den Sniffer, sendet
        nur dieser das ``STOPPED`` (Exactly-Once). Der Verlierer bekommt ``None`` und
        tut nichts (kein doppeltes ``STOPPED``).
        """
        if self._claim_sniffer() is None:
            return
        self._send({"type": MessageType.STOPPED})

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

    def _handle_start_pcap(self, message: dict[str, Any]) -> None:
        """``START_PCAP``: Recht pruefen, dann ``start_pcap_sniff`` aufspinnen + ``STARTED``.

        Wie ``_handle_start``, aber pcap-Dauerstrom: jedes Paket geht als
        ``PACKET``-Nachricht raus, die Rohpakete werden fuer ``EXPORT_PCAP``
        gesammelt (``_raw_packets`` frisch gesetzt). ``max_packets``/Selbst-Ende
        loest ueber ``_on_pcap_finished`` ein ``STOPPED`` aus. Ein bereits laufender
        Sniff wird nicht doppelt gestartet (idempotentes ``STARTED``, konsistent zu
        ``START``). Fehlt das Recht -> ``ERROR`` + KEIN Sniff (S3-frei).
        """
        if self._sniffer is not None:
            self._send({"type": MessageType.STARTED})
            return

        permission_error = check_raw_permission()
        if permission_error is not None:
            self._send({"type": MessageType.ERROR, "error": permission_error})
            return

        interface = message.get("interface")
        bpf_filter = message.get("bpf_filter", "")
        max_packets = message.get("max_packets", 0)
        self._raw_packets = []
        self._stop_event.clear()
        try:
            self._sniffer = start_pcap_sniff(
                self._on_packet,
                self._on_raw,
                interface,
                bpf_filter,
                max_packets,
                self._stop_event,
                self._on_pcap_finished,
            )
        except RuntimeError as exc:
            self._sniffer = None
            self._send({"type": MessageType.ERROR, "error": str(exc)})
            return

        self._send({"type": MessageType.STARTED})

    def _handle_start_lldp(self, message: dict[str, Any]) -> None:
        """``START_LLDP``: Recht pruefen, dann zeitbegrenzten LLDP/CDP-Sniff -> ``NEIGHBORS``.

        KEIN Dauerstrom: ``run_lldp_sniff`` blockiert ``duration`` Sekunden, darf
        die Kommando-Schleife aber NICHT blockieren -- daher in einem eigenen
        Thread; nach dem Lauf geht EINE ``NEIGHBORS``-Nachricht mit der Liste raus.
        Fehlt das Recht -> ``ERROR`` + KEIN Sniff (S3-frei). Ein bereits laufender
        (pcap/SNI-)Sniff blockt auch hier idempotent (``STARTED``), um ein
        gleichzeitiges zweites Capture zu vermeiden.
        """
        if self._sniffer is not None:
            self._send({"type": MessageType.STARTED})
            return

        permission_error = check_raw_permission()
        if permission_error is not None:
            self._send({"type": MessageType.ERROR, "error": permission_error})
            return

        interface = message.get("interface")
        duration = message.get("duration", 0)

        def _run() -> None:
            try:
                neighbors = run_lldp_sniff(interface, duration)
            except Exception as exc:  # ein Sniff-Fehler darf den Helfer nicht killen
                _logger.warning("sniffd_lldp_failed", error=str(exc))
                neighbors = []
            self._send({"type": MessageType.NEIGHBORS, "neighbors": neighbors})

        threading.Thread(target=_run, daemon=True).start()

    def _handle_export_pcap(self, message: dict[str, Any]) -> None:
        """``EXPORT_PCAP``: gesammelte Rohpakete nach ``path`` schreiben -> ``EXPORTED``.

        ``export_pcap`` ist best-effort (leere Sammlung / Fehler -> ``False``); das
        Ergebnis geht als ``EXPORTED {"ok": bool}`` zurueck.
        """
        path = message.get("path", "")
        ok = export_pcap(self._raw_packets, path)
        self._send({"type": MessageType.EXPORTED, "ok": ok})

    def _handle_stop(self) -> None:
        """``STOP``: ``stop_event`` setzen, Sniff joinen, ``STOPPED`` senden (Exactly-Once).

        Claimt den Sniffer ATOMAR (``_claim_sniffer``). Bekommt dieser Pfad das
        Handle, stoppt er den Sniff und sendet das EINE ``STOPPED``. Hat sich der
        Strom GLEICHZEITIG selbst beendet (``_on_pcap_finished`` gewann den Claim und
        sandte bereits ``STOPPED``), bekommt ``_handle_stop`` ``None`` -- dann ist der
        Sniff schon beendet und das ``STOPPED`` schon raus; ein zweites wird NICHT
        gesendet (sonst die Doppelung, die der Fix gerade verhindert). ``stop_event``
        wird in jedem Fall gesetzt (idempotenter Stop-Schalter).
        """
        self._stop_event.set()
        sniffer = self._claim_sniffer()
        if sniffer is None:
            return  # Selbst-Ende war schneller -> STOPPED ist bereits raus.
        try:
            sniffer.stop(join=True)
        except Exception as exc:
            _logger.warning("sniffd_stop_failed", error=str(exc))
        self._send({"type": MessageType.STOPPED})

    def _teardown(self) -> None:
        """Beendet einen evtl. laufenden Sniff (Verbindungsende/Signal).

        Claimt den Sniffer ATOMAR (``_claim_sniffer``) -- so kollidiert das Teardown
        nicht mit einem gleichzeitigen Selbst-Ende. Sendet KEIN ``STOPPED`` (die
        Verbindung endet ohnehin), stoppt nur den Sniff.
        """
        self._stop_event.set()
        sniffer = self._claim_sniffer()
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
                elif msg_type == MessageType.START_PCAP:
                    self._handle_start_pcap(message)
                elif msg_type == MessageType.START_LLDP:
                    self._handle_start_lldp(message)
                elif msg_type == MessageType.EXPORT_PCAP:
                    self._handle_export_pcap(message)
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
