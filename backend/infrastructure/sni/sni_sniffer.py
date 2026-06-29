"""Adapter fuer ``SniSnifferPort`` -- SNI-Sniff via Helfer-IPC + Prozess-Zuordnung.

ETAPPE 2 (Privilege-Separation, ADR sniffd): Der Adapter faehrt scapy NICHT mehr
selbst. Der rohe Sniff lebt im on-demand gestarteten Helfer ``cernis-sniffd`` (der
EINZIGE Prozess mit ``CAP_NET_RAW``); der Adapter spricht ihn ueber die schmale
``SniffHelperChannel``-Naht an (``channel.py`` / ``helper_channel.py``). Die TEURE
Zuordnung (psutil-Poller, ``match_snapshot``, Prozessname) BLEIBT hier im Backend --
nur der rohe Sniff ist ausgelagert.

ARCHITEKTUR (zwei Hintergrund-Threads wie zuvor, aber andere Quelle der Hits):

* **Hit-Poller** (``_hit_poll_loop``): zieht periodisch ``channel.poll_hits()`` (die
  rohen Hit-dicts vom Helfer) und fuellt sie als ``_RawHit`` in die ``_raw_hits``-
  deque um -- damit bleibt ``observed()`` voellig UNVERAENDERT (es liest dieselbe
  interne Struktur wie zuvor).
* **Socket-Poller** (``_poll_loop``): UNVERAENDERT -- periodische
  ``(ip,port)->pid``-Snapshots (psutil, billig, kein Name im Loop).

``observed()`` ordnet die rohen Hits ueber die Domaene (``match_snapshot``) den
Snapshots zu und loest den Prozessnamen NACH dem Match auf -- 1:1 wie zuvor.

INJIZIERBARE SPAWN-NAHT: Der Konstruktor nimmt optional eine ``channel_factory``
(``Callable[[], SniffHelperChannel]``). Default ``None`` -> baut intern eine
``SubprocessSniffHelper``. Tests injizieren einen Fake, der STARTED/ERROR kontrolliert
liefert und Hits einspeist -- KEIN echter Subprozess/scapy in Tests.

START-FEHLER (Port-Vertrag, S3-frei): ``channel.start`` liefert einen Fehlertext (z. B.
fehlendes ``CAP_NET_RAW`` vom Helfer, kaputter Spawn) -> der Adapter wirft ``SniError``.
KEINE stille Leer-Erfassung. Die ECHTE Rechtepruefung passiert beim ``start`` ueber
diese ERROR-Naht des Helfers (nicht mehr ueber eine Backend-Raw-Socket-Probe -- siehe
``check_permission``).

Plattform: NUR Linux x64 (der Helfer kapselt die plattformnahe Sniff-Technik).
"""

import threading
import time
from collections import deque
from collections.abc import Callable

import psutil
import structlog

from domain.sni import ObservedSni, match_snapshot
from infrastructure.sni.channel import SniffHelperChannel
from infrastructure.sni.errors import SniError, SniPermissionError
from infrastructure.sniffd_client import SniHelperClient, helper_entry_exists

_logger = structlog.get_logger(__name__)

# Poll-Intervall des Socket-Pollers (unveraendert: 0.5 s -- selten + billig).
_POLL_INTERVAL_SECS = 0.5

# Poll-Intervall des Hit-Pollers (zieht die rohen Hits vom Helfer-Channel um). Etwas
# enger als der Socket-Poller, damit ein Hit zeitnah neben einem Snapshot liegt -- die
# Zuordnung (match_snapshot) profitiert von kleinem Delta.
_HIT_POLL_INTERVAL_SECS = 0.25

# Obergrenze der gehaltenen Hits/Snapshots (unveraendert). Der passive Sniff hat KEIN
# natuerliches Ende -- der Deckel sitzt HIER im Adapter als ``deque(maxlen=...)``.
_MAX_HITS = 5000
_MAX_SNAPSHOTS = 600  # ~5 min bei 0.5 s-Intervall -- deckt jeden Hit-Zeitpunkt ab


# ── psutil-Naht (UNVERAENDERT: net_connections + defensiver Name) ─────────────


def _snapshot_sockets() -> dict[tuple[str, int], int | None]:
    """Aktuelle ``(remote_ip, remote_port) -> pid``, indexiert nach REMOTE-Endpunkt.

    Naht wie ``traffic_linux._list_connections_sync``: ``net_connections(kind="inet")``.
    BILLIG gehalten: hier NUR die PID sammeln, KEINE Namensaufloesung (die ist teuer und
    passiert erst in ``observed()`` NACH dem Match). ``pid`` kann ``None`` sein (rootless
    sieht psutil fremde Sockets ohne PID -- ehrlich uebernommen).
    """
    table: dict[tuple[str, int], int | None] = {}
    for conn in psutil.net_connections(kind="inet"):
        if not conn.raddr:
            continue
        table[(conn.raddr.ip, conn.raddr.port)] = conn.pid
    return table


def _resolve_app_name(pid: int | None) -> str | None:
    """PID -> Prozessname; defensiv -- GENAU wie ``traffic_linux._resolve_app_name``.

    Wird ERST in ``observed()`` (nach dem Match) gerufen, nie im Poller-Loop. psutil-
    Fehler (``NoSuchProcess``/``AccessDenied``) bedeuten "nicht (mehr) zuordenbar" ->
    ``None``, KEIN Crash.
    """
    if pid is None:
        return None
    try:
        return str(psutil.Process(pid).name())
    except psutil.Error:
        return None


# ── Roh-Hit (intern; UNVERAENDERT -- damit observed() unveraendert bleibt) ─────


class _RawHit:
    """Ein roher SNI-Hit (vor der Prozess-Zuordnung).

    Bewusst KEIN ``domain.ObservedSni``: der Sniff-Pfad kennt die Zuordnung noch nicht
    (die rechnet ``observed()`` ueber die Domaene). Eine schlanke interne Klasse statt
    eines dicts haelt die Felder typsicher beieinander. Etappe 2: gefuellt aus den rohen
    Helfer-Hit-dicts (statt aus dem scapy-Callback) -- die Struktur ist identisch.
    """

    __slots__ = ("hostname", "monotonic_ts", "remote_ip", "remote_port")

    def __init__(
        self, hostname: str, remote_ip: str, remote_port: int, monotonic_ts: float
    ) -> None:
        self.hostname = hostname
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.monotonic_ts = monotonic_ts


class ScapySniSniffer:
    """Erfuellt ``SniSnifferPort`` strukturell -- Helfer-Channel + psutil-Poller-Thread.

    Eine Instanz haelt hoechstens einen laufenden Sniff. Die rohen Hits (``_raw_hits``,
    aus dem Helfer ueber den Hit-Poller umgefuellt) und die periodischen Socket-
    Snapshots (``_snapshots``, psutil-Poller) liegen hier intern; ``observed()`` ordnet
    sie ueber die Domaene zu (UNVERAENDERT). Der Name ``ScapySniSniffer`` bleibt aus
    Naht-Treue (Port-Verdrahtung in ``app.py``), obwohl scapy jetzt im Helfer laeuft.

    ``channel_factory`` ist die injizierbare Spawn-Naht: Default ``None`` -> intern eine
    ``SubprocessSniffHelper``; Tests injizieren einen Fake-Channel.
    """

    def __init__(self, channel_factory: Callable[[], SniffHelperChannel] | None = None) -> None:
        self._channel_factory: Callable[[], SniffHelperChannel] = (
            channel_factory if channel_factory is not None else SniHelperClient
        )
        self._channel: SniffHelperChannel | None = None
        self._poller: threading.Thread | None = None
        self._hit_poller: threading.Thread | None = None
        self._stop_poll = threading.Event()
        # Ringpuffer (deque mit maxlen): aelteste raus, am thread-lokalen Schreib-Ort.
        self._raw_hits: deque[_RawHit] = deque(maxlen=_MAX_HITS)
        # Snapshots als (monotonic_ts, table) -- genau die Form, die die Domaene
        # (``match_snapshot``) erwartet.
        self._snapshots: deque[tuple[float, dict[tuple[str, int], int | None]]] = deque(
            maxlen=_MAX_SNAPSHOTS
        )

    # -- Poller (eigene daemon-Threads -- entkoppelt) --------------------------

    def _poll_loop(self) -> None:
        """Pollt die Socket-Tabelle periodisch (UNVERAENDERT, billig, entkoppelt).

        Legt nur leichte ``(monotonic_ts, table)``-Snapshots ab (kein Name -- der kommt
        in ``observed()``). Laeuft, bis ``_stop_poll`` gesetzt ist. Ein psutil-Fehler
        killt den Poller nicht (leerer Snapshot statt Crash).
        """
        while not self._stop_poll.is_set():
            ts = time.monotonic()
            try:
                self._snapshots.append((ts, _snapshot_sockets()))
            except Exception as exc:
                _logger.warning("sni_poll_failed", error=str(exc))
                self._snapshots.append((ts, {}))
            self._stop_poll.wait(_POLL_INTERVAL_SECS)

    def _hit_poll_loop(self) -> None:
        """Zieht periodisch die rohen Helfer-Hits und fuellt sie in ``_raw_hits`` um.

        ETAPPE-2-Ersatz fuer den alten scapy-``_on_packet``-Callback: statt eines
        Sniff-Threads im Backend zieht dieser Thread ``channel.poll_hits()`` und baut aus
        jedem rohen Hit-dict einen ``_RawHit`` -- damit ist ``observed()`` voellig
        unveraendert. Ein kaputtes/unvollstaendiges Hit-dict wird still uebersprungen
        (defensiv, kein Crash). Laeuft, bis ``_stop_poll`` gesetzt ist.
        """
        channel = self._channel
        if channel is None:
            return
        while not self._stop_poll.is_set():
            try:
                for hit in channel.poll_hits():
                    raw = self._raw_hit_from_dict(hit)
                    if raw is not None:
                        self._raw_hits.append(raw)
            except Exception as exc:
                _logger.warning("sni_hit_poll_failed", error=str(exc))
            self._stop_poll.wait(_HIT_POLL_INTERVAL_SECS)

    @staticmethod
    def _raw_hit_from_dict(hit: dict[str, object]) -> _RawHit | None:
        """Baut aus einem rohen Helfer-Hit-dict einen ``_RawHit`` (defensiv, ``None`` bei
        kaputter Form -- ein einzelner Murks-Hit darf den Poller nicht killen)."""
        try:
            # Werte kommen ueber JSON (str/int/float) als ``object`` herein -- der
            # Umweg ueber ``str`` macht die Zahl-Konvertierung typsicher (mypy-strict)
            # UND robust (ein Murks-Wert wirft ValueError -> None statt Crash).
            return _RawHit(
                hostname=str(hit["hostname"]),
                remote_ip=str(hit["remote_ip"]),
                remote_port=int(str(hit["remote_port"])),
                monotonic_ts=float(str(hit["monotonic_ts"])),
            )
        except (KeyError, TypeError, ValueError) as exc:
            _logger.warning("sni_hit_malformed", error=str(exc))
            return None

    # -- Lifecycle (Port-Vertrag) ----------------------------------------------

    def start(self, interface: str | None) -> None:
        """Startet den passiven Sniff via Helfer (idempotent gegenueber einem aktiven Lauf).

        Baut den Channel (``channel_factory``), ruft ``channel.start(interface)``. Liefert
        der Channel einen Fehlertext (z. B. fehlendes ``CAP_NET_RAW`` vom Helfer, kaputter
        Spawn) -> ``SniError`` (KEINE stille Leer-Erfassung -- die ECHTE Rechtepruefung
        passiert hier ueber die ERROR-Naht des Helfers). Bei Erfolg: frischer Puffer +
        Socket-Poller + Hit-Poller aufspinnen.
        """
        if self.is_running():
            return  # bereits aktiv -- nicht doppelt starten

        # Frischer Puffer je Lauf (ein start() ist eine frische Erfassung).
        self._raw_hits = deque(maxlen=_MAX_HITS)
        self._snapshots = deque(maxlen=_MAX_SNAPSHOTS)
        self._stop_poll = threading.Event()

        channel = self._channel_factory()
        error = channel.start(interface)
        if error is not None:
            # Helfer/Spawn meldet einen ehrlichen Fehler -> SniError (kein stiller
            # Fallback, S3). Der globale Handler in app.py macht daraus eine 503.
            self._channel = None
            if "CAP_NET_RAW" in error:
                raise SniPermissionError(error)
            raise SniError(error)
        self._channel = channel

        # Poller erst NACH erfolgreichem Channel-Start aufspinnen (keine verwaisten
        # Threads, falls der Start scheitert).
        self._poller = threading.Thread(target=self._poll_loop, daemon=True)
        self._poller.start()
        self._hit_poller = threading.Thread(target=self._hit_poll_loop, daemon=True)
        self._hit_poller.start()

    def stop(self) -> None:
        """Stoppt einen laufenden Sniff (idempotent). Erfasste Daten bleiben erhalten.

        Haelt beide Poller (Event setzen + joinen) und den Helfer-Channel (``stop``) an.
        Kein laufender Sniff -> No-op. Die ``_raw_hits``/``_snapshots`` werden NICHT
        geleert (ein letzter ``observed()``-Abruf nach dem Stop liefert noch die
        Momentaufnahme; der naechste ``start()`` setzt den Puffer frisch).
        """
        self._stop_poll.set()
        poller = self._poller
        if poller is not None:
            poller.join(timeout=2)
            self._poller = None
        hit_poller = self._hit_poller
        if hit_poller is not None:
            hit_poller.join(timeout=2)
            self._hit_poller = None
        channel = self._channel
        self._channel = None
        if channel is None:
            return
        try:
            channel.stop()
        except Exception as exc:
            _logger.warning("sni_stop_failed", error=str(exc))

    def is_running(self) -> bool:
        """``True``, solange der Helfer-Channel laeuft (delegiert an ``channel.is_running``)."""
        channel = self._channel
        if channel is None:
            return False
        return channel.is_running()

    def observed(self) -> list[ObservedSni]:
        """Momentaufnahme: jedem rohen Hit den naechsten Snapshot zuordnen + Name aufloesen.

        UNVERAENDERT gegenueber Etappe 1: Schwere Arbeit (Zuordnung + Namensaufloesung)
        lebt HIER, nicht im Hit-/Poller-Pfad. Pro Hit: ``match_snapshot`` (Domaene)
        liefert ``(pid, delta_ms)``, ``_resolve_app_name`` (psutil, NACH dem Match) den
        Prozessnamen. Eine Kopie der Snapshot-Liste, damit der parallel laufende Poller
        sie waehrend der Iteration nicht unter uns veraendert.
        """
        snapshots = list(self._snapshots)
        result: list[ObservedSni] = []
        for hit in list(self._raw_hits):
            pid, delta_ms = match_snapshot(
                hit.remote_ip, hit.remote_port, hit.monotonic_ts, snapshots
            )
            result.append(
                ObservedSni(
                    hostname=hit.hostname,
                    remote_ip=hit.remote_ip,
                    remote_port=hit.remote_port,
                    monotonic_ts=hit.monotonic_ts,
                    app_name=_resolve_app_name(pid),
                    pid=pid,
                    delta_ms=delta_ms,
                )
            )
        return result

    def check_permission(self) -> str | None:
        """Optimistischer Verfuegbarkeits-Check -- gibt ``None`` zurueck (best practice B).

        ETAPPE 2 / Privilege-Separation: Das Backend traegt kuenftig KEIN ``CAP_NET_RAW``
        mehr (das traegt allein der Helfer ``cernis-sniffd``). Eine Backend-seitige
        ``AF_PACKET``-Raw-Socket-Probe wuerde darum faelschlich "keine Rechte" melden,
        obwohl der Helfer sehr wohl sniffen darf. Daher KEINE Backend-Probe mehr:

        Dieser Check ist optimistisch und gibt ``None`` zurueck (= "Sniff moeglich"). Die
        ECHTE Rechtepruefung passiert beim ``start()`` ueber die ERROR-Naht des Helfers
        (``check_raw_permission`` LAEUFT IM HELFER, der das Recht wirklich hat) -- ein
        echter Rechte-Fehler kommt dann als ``SniError`` aus ``start()`` heraus. Damit
        bleibt die 403-/503-Naht ehrlich: sie feuert genau dann, wenn der Helfer den
        Sniff ablehnt, nicht spekulativ aus dem rechtelosen Backend.
        """
        return None

    def is_available(self) -> bool:
        """``True``, wenn der Helfer-Einstieg grundsaetzlich nutzbar ist (Pfad existiert).

        ETAPPE 2: scapy lebt im Helfer und ist zur Laufzeit ohne Spawn nicht pruefbar.
        Wir pruefen daher nur, ob der Helfer-Einstieg ueberhaupt vorhanden ist (frozen-
        Binary ``cernis-sniffd`` neben ``sys.executable`` bzw. dev-``sniffd.py``). Fehlt
        er, ist ein Sniff ausgeschlossen -> ``False`` (ehrlich, kein stiller Fallback).
        Die scapy-/Rechte-Verfuegbarkeit klaert erst der ``start()`` ueber die Helfer-
        Naht.
        """
        return helper_entry_exists()
