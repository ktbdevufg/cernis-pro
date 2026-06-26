"""Adapter fuer ``PacketSnifferPort`` -- pcap-Dauer-Capture ueber den Helfer-IPC.

ETAPPE 3b (Privilege-Separation): Der Adapter faehrt scapy NICHT mehr selbst. Der
rohe pcap-Sniff lebt im on-demand gestarteten Helfer ``cernis-sniffd`` (der EINZIGE
Prozess mit ``CAP_NET_RAW``); der Adapter spricht ihn ueber den ``PcapHelperClient``
an (``infrastructure/sniffd_client/``). Das scapy-Parsen zu Summary-dicts ist in den
Helfer gewandert (``sniffd.sniff_core.parse_packet``); hier wird aus dem rohen
PACKET-dict nur noch ein ``domain.PacketSummary`` gebaut.

THREAD->LOOP-NAHT (unveraendert im Muster, andere Quelle): Frueher feuerte
``AsyncSniffer.prn`` im Sniffer-Thread. Jetzt liest der ``PcapHelperClient`` die
PACKET-Nachrichten in seinem Reader-Thread in eine thread-sichere Queue; ein
Bruecken-Thread (``_pump``) zieht sie dort ab und schiebt jedes ``PacketSummary``
ueber ``loop.call_soon_threadsafe(q.put_nowait, ps)`` thread-sicher in die
``asyncio.Queue``. Der Generator ``await q.get()`` zieht es im Loop heraus und yieldet
es -- GENAU das bestehende Thread->Loop-Muster, nur ist die Quelle der Reader-Thread
statt scapy-prn. Strom-Ende (Helfer-``STOPPED`` -> Client-Sentinel) reicht der Pump
das ``_SENTINEL`` nach -> der Generator endet sauber.

START-FEHLER (Port-Vertrag, S3-frei): ``client.start`` liefert einen Fehlertext
(Helfer-ERROR: fehlendes ``CAP_NET_RAW``/scapy kaputt, oder Spawn-Fehler) ->
``CaptureError`` (wie zuvor der Permission-/Start-Fehler) -- KEINE stille Leer-
Iteration. Das beobachtbare Verhalten fuer ``RunCapture``/``StartCapture`` bleibt.

EXPORT-REIHENFOLGE (Race mit ``RunCapture.stop``): ``RunCapture.stop`` ruft ERST
``export_pcap``, DANN ``stop``. Solange der Client verbunden ist, haelt der Helfer die
Rohpakete in seiner ``_Session`` und beantwortet ``EXPORT_PCAP`` -- der ``server.py``
schliesst die Verbindung nach ``STOPPED`` NICHT (die Kommando-Schleife laeuft weiter).
Erst ``stop`` reisst die Verbindung ab. Verifiziert am ``server.py``-Code.

INJIZIERBARE SPAWN-NAHT: Der Konstruktor nimmt optional eine ``client_factory``
(``Callable[[], PcapClient]``). Default ``None`` -> baut intern einen
``PcapHelperClient``. Tests injizieren einen Fake-Client, der STARTED/ERROR
kontrolliert liefert und PACKET-dicts aus einem Fremd-Thread einspeist -- KEIN echter
Subprozess/scapy in Tests (Muster wie ``ScapySniSniffer.channel_factory``).

Plattform: NUR Linux x64 (der Helfer kapselt die plattformnahe Sniff-Technik).
"""

import asyncio
import queue
import threading
from collections.abc import AsyncIterator, Callable
from typing import Any, Protocol

import structlog

from domain.capture import PacketSummary
from infrastructure.capture.errors import CaptureError
from infrastructure.sniffd_client import PcapHelperClient, helper_entry_exists
from infrastructure.sniffd_client.pcap_client import _STREAM_END

_logger = structlog.get_logger(__name__)

# Sentinel: signalisiert dem Generator das Strom-Ende (Stop oder max_packets).
_SENTINEL = object()

# Poll-Timeout des Bruecken-Threads beim Abziehen aus der Client-Queue. Kein fester
# Block, damit der Pump auf ein gesetztes Stop-Event zeitnah reagieren kann.
_PUMP_POLL_SECS = 0.2


class PcapClient(Protocol):
    """Schmale Naht zum pcap-Helfer-Client (Spawn/Strom/Export liegen dahinter).

    Kapselt GENAU das, was der Adapter braucht: Start (Fehlertext-Naht), das Abziehen
    der PACKET-dicts (blockierend mit Timeout, Sentinel bei Strom-Ende), den
    pcap-Export und den Teardown. Die echte Implementierung ist ``PcapHelperClient``;
    Tests injizieren einen Fake.
    """

    def start(self, interface: str | None, bpf_filter: str, max_packets: int) -> str | None:
        """Startet Helfer + pcap-Sniff. ``None`` bei Erfolg, sonst der Fehlertext."""
        ...

    def next_packet(self, timeout: float | None = None) -> Any:
        """Naechstes PACKET-dict (oder Strom-Ende-Sentinel); ``queue.Empty`` bei Timeout."""
        ...

    def export_pcap(self, path: str) -> bool:
        """Schreibt die gesammelten Rohpakete als pcap nach ``path`` (Helfer-seitig)."""
        ...

    def stop(self) -> None:
        """Stoppt den Strom + Helfer (idempotent), raeumt Client-seitig ab."""
        ...

    def is_running(self) -> bool:
        """``True``, solange der Helfer-Subprozess + Reader laufen."""
        ...


class ScapyPacketSniffer:
    """Erfuellt ``PacketSnifferPort`` strukturell -- pcap-Strom ueber den Helfer-Client.

    Eine Instanz haelt hoechstens einen laufenden Capture. Der Name bleibt aus
    Naht-Treue (Port-Verdrahtung in ``app.py``), obwohl scapy jetzt im Helfer laeuft.
    Die scapy-Rohpakete fuer ``export_pcap`` liegen NICHT mehr hier, sondern im Helfer
    (``_Session._raw_packets``); ``export_pcap`` reicht den Befehl nur durch.

    ``client_factory`` ist die injizierbare Spawn-Naht: Default ``None`` -> intern ein
    ``PcapHelperClient``; Tests injizieren einen Fake-Client.
    """

    def __init__(self, client_factory: Callable[[], PcapClient] | None = None) -> None:
        self._client_factory: Callable[[], PcapClient] = (
            client_factory if client_factory is not None else PcapHelperClient
        )
        self._client: PcapClient | None = None
        self._pump: threading.Thread | None = None
        self._pump_stop = threading.Event()

    async def stream(
        self, interface: str | None, bpf_filter: str, max_packets: int
    ) -> AsyncIterator[PacketSummary]:
        """Startet den Sniff via Helfer und yieldet je erfasstem Paket ein ``PacketSummary``.

        Der ``PcapHelperClient`` liest die PACKET-dicts in seinem Reader-Thread; ein
        Bruecken-Thread schiebt sie thread-sicher in eine ``asyncio.Queue``; dieser
        Generator (im Loop) zieht heraus, baut ein ``PacketSummary`` und yieldet.
        Endet bei Helfer-``STOPPED`` (max_packets/STOP -> Sentinel) oder ``stop``.
        Ein Start-Fehler (Helfer-ERROR/Spawn) -> ``CaptureError``.
        """
        loop = asyncio.get_running_loop()
        aqueue: asyncio.Queue[Any] = asyncio.Queue()

        client = self._client_factory()
        error = client.start(interface, bpf_filter, max_packets)
        if error is not None:
            # Helfer/Spawn meldet einen ehrlichen Fehler -> CaptureError (kein stiller
            # Fallback, S3). Beobachtbar wie der fruehere Start-/Permission-Fehler.
            raise CaptureError(error)
        self._client = client
        self._pump_stop = threading.Event()

        def _pump() -> None:
            # Laeuft im Bruecken-Thread: zieht PACKET-dicts aus dem Client (der sie im
            # Reader-Thread fuellt) und schiebt je ein PacketSummary thread-sicher in
            # die asyncio.Queue. Bei JEDEM Ende (Strom-Ende-Sentinel ODER ``_pump_stop``
            # durch ``stop()``) wird GENAU EINMAL das ``_SENTINEL`` in die asyncio.Queue
            # nachgereicht -- so endet der wartende Generator-Getter immer sauber (kein
            # Deadlock, wenn ``stop()`` den Pump beendet, bevor er das Helfer-STOPPED
            # gelesen hat).
            try:
                while not self._pump_stop.is_set():
                    try:
                        item = client.next_packet(timeout=_PUMP_POLL_SECS)
                    except queue.Empty:
                        continue
                    if item is _STREAM_END:
                        return
                    ps = self._summary_from_dict(item)
                    if ps is not None:
                        loop.call_soon_threadsafe(aqueue.put_nowait, ps)
            finally:
                loop.call_soon_threadsafe(aqueue.put_nowait, _SENTINEL)

        self._pump = threading.Thread(target=_pump, daemon=True)
        self._pump.start()

        # Strom: aus der Queue ziehen, bis das Sentinel kommt (Stop/Selbst-Ende).
        try:
            while True:
                item = await aqueue.get()
                if item is _SENTINEL:
                    break
                yield item
        finally:
            # Generator-Ende (auch bei GeneratorExit/Abbruch durch den Use-Case):
            # Client + Pump sicher stoppen, damit kein Thread weiterlaeuft.
            self.stop()

    @staticmethod
    def _summary_from_dict(packet: dict[str, Any]) -> PacketSummary | None:
        """Baut aus einem rohen Helfer-PACKET-dict ein ``PacketSummary`` (defensiv).

        Die Felder des Helfer-dicts (``sniff_core.parse_packet``) entsprechen EXAKT
        den ``PacketSummary``-Feldern; fehlende Felder fuellt die dataclass mit ihren
        Defaults. Ein kaputtes dict (falscher Typ / unbekanntes Feld) ergibt ``None``
        (das Paket wird verworfen) -- ein einzelner Murks-Frame darf den Strom nicht
        killen.
        """
        try:
            return PacketSummary(**packet)
        except (TypeError, ValueError) as exc:
            _logger.warning("packet_summary_malformed", error=str(exc))
            return None

    def stop(self) -> None:
        """Stoppt einen laufenden Capture-Strom (idempotent).

        Haelt den Bruecken-Thread (Event setzen + joinen) und stoppt den Helfer-Client
        (STOP an den Helfer + Teardown). Kein laufender Strom -> No-op. ``export_pcap``
        passiert NICHT hier -- ``RunCapture.stop`` ruft ``export_pcap`` VOR ``stop``,
        solange der Client noch verbunden ist.
        """
        self._pump_stop.set()
        pump = self._pump
        self._pump = None
        client = self._client
        self._client = None
        if pump is not None and pump is not threading.current_thread():
            pump.join(timeout=2)
        if client is None:
            return
        try:
            client.stop()
        except Exception as exc:
            _logger.warning("capture_stop_failed", error=str(exc))

    def is_running(self) -> bool:
        """``True``, solange der Helfer-Client laeuft (delegiert an den Client)."""
        client = self._client
        if client is None:
            return False
        return client.is_running()

    def export_pcap(self, path: str) -> bool:
        """Schreibt die im Helfer gesammelten Rohpakete als pcap nach ``path``.

        Reicht ``EXPORT_PCAP{path}`` an den Helfer durch und gibt dessen
        ``EXPORTED{ok}`` zurueck (best-effort: leere Sammlung / Schreibfehler ->
        ``False``). MUSS aufgerufen werden, solange der Client noch verbunden ist
        (also VOR ``stop`` -- so ruft es ``RunCapture.stop``). Kein laufender Client
        -> ``False``.
        """
        client = self._client
        if client is None:
            return False
        return client.export_pcap(path)

    def check_permission(self) -> str | None:
        """Optimistischer Verfuegbarkeits-Check -- gibt ``None`` zurueck (B-Semantik).

        ETAPPE 3b / Privilege-Separation: Das Backend traegt kein ``CAP_NET_RAW`` mehr
        (das traegt allein der Helfer ``cernis-sniffd``). Eine Backend-seitige
        ``AF_PACKET``-Raw-Socket-Probe wuerde faelschlich "keine Rechte" melden,
        obwohl der Helfer sehr wohl capturen darf. Daher KEINE Backend-Probe mehr:
        optimistisch ``None`` (= "Capture moeglich"). Die ECHTE Rechtepruefung
        passiert beim ``stream``-Start ueber die ERROR-Naht des Helfers (der Helfer
        haelt das Recht) -- ein echter Rechte-Fehler kommt dann als ``CaptureError``
        aus ``stream`` heraus. Konsistent zur SNI-Naht (``ScapySniSniffer``).
        """
        return None

    def is_available(self) -> bool:
        """``True``, wenn der Helfer-Einstieg grundsaetzlich nutzbar ist (Pfad existiert).

        ETAPPE 3b: scapy lebt im Helfer und ist zur Laufzeit ohne Spawn nicht pruefbar.
        Wir pruefen daher nur, ob der Helfer-Einstieg vorhanden ist (frozen-Binary
        ``cernis-sniffd`` neben ``sys.executable`` bzw. dev-``sniffd.py``). Fehlt er,
        ist ein Capture ausgeschlossen -> ``False`` (ehrlich, kein stiller Fallback).
        Konsistent zur SNI-Naht (``ScapySniSniffer.is_available``).
        """
        return helper_entry_exists()
