"""Native Windows-Routenmessung (iphlpapi via ctypes, kein tracert, kein Regex).

Zweck: die Hop-Kette zu einem Ziel messen -> ``TracerouteResult``, ohne ein einziges
externes Programm. Auf Windows gibt es kein ``traceroute``-Binary; der Linux-Adapter
``SystemTracerouteRunner`` scheitert hier folglich am ``shutil.which``-Riegel und beide
Naehte (``/api/diagnostics/traceroute`` und ``/api/diagnostics/route``) blieben tot.

WARUM NICHT ``tracert.exe``: dessen Ausgabe erscheint in der System-UI-Sprache
(deutsch "Zeitueberschreitung der Anforderung", englisch "Request timed out", andere
Sprachen anders) und ``LC_ALL`` wirkt auf Windows NICHT. Ein Parser waere auf
fremdsprachigen Systemen STILL blind -- genau die Fehlerklasse, die dieses Projekt in
``icmp_windows.py``/``interfaces_windows.py`` schon fuer ``ping.exe`` verworfen hat.
Stattdessen die native API: ``IcmpCreateFile`` / ``IcmpSendEcho`` mit gesetzter TTL /
``IcmpCloseHandle`` aus ``iphlpapi.dll``. Adresse, Status und Laufzeit kommen als Zahlen
direkt aus der ``ICMP_ECHO_REPLY``-Struktur -- kein Text, kein Regex, keine Sprache.

MESSPRINZIP (am laufenden System unprivilegiert belegt): je TTL EIN Echo. Ein
Zwischenhop antwortet mit ``Status == IP_TTL_EXPIRED_TRANSIT`` (11013) und traegt seine
eigene Adresse; das Ziel antwortet mit ``Status == IP_SUCCESS`` (0) -- dann endet die
Kette. Ein nicht antwortender Hop zeigt sich als Rueckgabewert 0 bzw.
``IP_REQ_TIMED_OUT`` und wird als ehrliche Luecke (``address``/``rtt_ms`` ``None``)
gefuehrt; die Kette laeuft danach WEITER. Kein erfundener Wert, kein weggelassener Hop.

KEINE ERHOEHTEN RECHTE noetig: ``IcmpSendEcho`` misst unprivilegiert vollstaendig. Der
Rechte-Adapter meldet das ehrlich (siehe ``WindowsTraceroutePermission``).

EIGENE STRUKTURDEFINITIONEN, BEWUSST: ``icmp_windows.py`` fuehrt ``IP_OPTION_INFORMATION``
und ``ICMP_ECHO_REPLY`` bereits -- dort aber als reine Ping-Naht, deren
``RequestOptions``-Parameter als ``c_void_p`` deklariert und stets als ``None`` uebergeben
wird; sie kann also gar keine TTL setzen. Diese arbeitende, von ``modules/discovery.py``
und ``modules/monitor.py`` genutzte Naht umzubauen brauecht deren Pfad an, darum werden
die Strukturen hier eigenstaendig gefuehrt statt geteilt.

Nur IPv4: ``IcmpSendEcho`` ist IPv4. IPv6 (``Icmp6SendEcho2``) wird hier NICHT angebunden.

PLATTFORM-WEICHE (mypy-Falle, hat die Linux-CI schon mehrfach gebrochen): ``mypy``
wertet ``sys.platform`` statisch aus -- auf Linux existiert JEDER innerhalb eines
``if sys.platform == "win32":``-Blocks definierte Name NICHT. Deshalb steht nicht nur der
ctypes-Import, sondern auch jede Referenz darauf im positiven Guard, und BEIDE Zweige
binden denselben Namen (``_run_native``). Der Nicht-Windows-Zweig wirft ehrlich --
er wird nie verdrahtet (die Weiche steht in ``app.py``), aber er luegt auch nicht.

TESTBARKEIT: die gesamte Ablauflogik sitzt im plattformunabhaengigen ``_build_hop_chain``,
das seine Messung als Callable ``(ttl) -> _Probe`` gereicht bekommt (Muster
``icmp_windows._perform_echo``). So laesst sie sich OHNE echte DLL und OHNE Netz pruefen.
"""

import asyncio
import socket
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

from domain.diagnostics import TracerouteHop, TracerouteResult

# ── Statuswerte der ICMP_ECHO_REPLY-Struktur (Win32-Header IPExport.h) ────────

# Das Ziel hat geantwortet -- die Kette endet hier.
_IP_SUCCESS = 0
# Ein Zwischenhop hat die TTL verworfen und sich dabei selbst benannt.
_IP_TTL_EXPIRED_TRANSIT = 11013
# Niemand hat innerhalb der Zeitgrenze geantwortet -- ehrliche Luecke, Kette laeuft weiter.
_IP_REQ_TIMED_OUT = 11010

# ── Messparameter (Auftrag S66-W-h1, E6) ─────────────────────────────────────

# Hoechste TTL: darueber hinaus wird nicht gemessen (Endlosschutz bei unerreichbarem Ziel).
_MAX_TTL = 30
# Zeitgrenze je Hop in Millisekunden.
_HOP_TIMEOUT_MS = 1500
# Gesamtbudget der ganzen Kette in Sekunden. Wird es erreicht, wird die bis dahin
# ermittelte Kette ehrlich zurueckgegeben -- kein erfundener Resthop, keine Ausnahme.
_TOTAL_BUDGET_SECS = 55.0


class TracerouteUnavailable(RuntimeError):
    """Die native Routenmessung konnte NICHT durchgefuehrt werden (kein leeres Ergebnis).

    Kein stiller Fallback (Finding S3, ADR 0001): scheitert die Namensaufloesung oder das
    Anlegen des ICMP-Handles, ist das ein FEHLER -- eine leere Hop-Kette waere die Luege
    "gemessen, nichts gefunden". Der api-Rand macht daraus einen ehrlichen Fehlerstatus.
    """


@dataclass(frozen=True)
class _Probe:
    """Rohergebnis EINER TTL-Messung, so wie die native Schicht sie liefert.

    ``returned`` ist der Rueckgabewert von ``IcmpSendEcho`` (Anzahl Antworten; ``0`` =
    keine Antwort). ``status``/``address``/``rtt_ms`` stammen aus der Reply-Struktur und
    sind nur bei ``returned > 0`` ueberhaupt gueltig -- ein Rueckgabewert allein belegt
    bei dieser Schnittstelle keine gueltigen Daten (E8).
    """

    returned: int
    status: int
    address: str | None
    rtt_ms: int


def _classify_probe(probe: _Probe, hop_number: int) -> tuple[TracerouteHop, bool]:
    """Bildet EINE TTL-Messung auf ``(Hop, Kette-zu-Ende)`` ab -- reine Funktion.

    Drei Faelle, ohne vierten:

    * keine Antwort (``returned == 0`` ODER ``status == IP_REQ_TIMED_OUT``) -> ehrliche
      Luecke (``address``/``rtt_ms`` ``None``), Kette laeuft WEITER (``False``);
    * ``status == IP_SUCCESS`` -> das Ziel selbst hat geantwortet, Kette ist zu Ende
      (``True``);
    * jeder andere Status (im Normalfall ``IP_TTL_EXPIRED_TRANSIT``) -> ein Zwischenhop
      mit Adresse und Laufzeit, Kette laeuft weiter.

    Ein anderer Fehlerstatus (z. B. ``IP_DEST_HOST_UNREACHABLE``) wird bewusst NICHT als
    Adresse ausgegeben, wenn keine Adresse vorliegt -- dann bleibt es eine Luecke. Die
    Kette laeuft in dem Fall weiter, statt eine unvollstaendige Sicht als Ende auszugeben.
    """
    if probe.returned <= 0 or probe.status == _IP_REQ_TIMED_OUT:
        return (TracerouteHop(hop=hop_number, address=None, rtt_ms=None), False)
    if probe.status == _IP_SUCCESS:
        return (
            TracerouteHop(hop=hop_number, address=probe.address, rtt_ms=float(probe.rtt_ms)),
            True,
        )
    if probe.address is None:
        # Antwort ohne verwertbare Adresse -> Luecke statt geratener Wert.
        return (TracerouteHop(hop=hop_number, address=None, rtt_ms=None), False)
    return (
        TracerouteHop(hop=hop_number, address=probe.address, rtt_ms=float(probe.rtt_ms)),
        False,
    )


def _build_hop_chain(
    probe_ttl: Callable[[int], _Probe],
    *,
    max_ttl: int = _MAX_TTL,
    budget_secs: float = _TOTAL_BUDGET_SECS,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[TracerouteHop, ...]:
    """Plattformunabhaengiger Kern: misst TTL 1..``max_ttl`` -> die Hop-Kette.

    Reiner Kern (ohne ctypes/DLL/Netz testbar): ``probe_ttl`` liefert je TTL das
    ``_Probe``-Rohergebnis, ``_classify_probe`` macht daraus Hop + Abbruchkriterium. Bei
    ``IP_SUCCESS`` endet die Kette SOFORT (das Ziel ist erreicht, weitere TTLs waeren
    sinnlos). Luecken beenden die Kette NICHT.

    Das Gesamtbudget wird VOR jeder weiteren Messung geprueft: ist es erschoepft, wird die
    bis dahin ermittelte Kette ehrlich zurueckgegeben -- kein erfundener Resthop, keine
    Ausnahme (E6). ``monotonic`` ist injizierbar, damit der Budget-Abbruch ohne echte
    Wartezeit pruefbar ist.
    """
    start = monotonic()
    hops: list[TracerouteHop] = []
    for ttl in range(1, max_ttl + 1):
        if ttl > 1 and monotonic() - start >= budget_secs:
            # Budget erreicht -> ehrliche Teil-Kette. Die erste Messung laeuft immer,
            # sonst kaeme bei einem bereits erschoepften Budget eine leere Kette heraus.
            break
        hop, reached = _classify_probe(probe_ttl(ttl), ttl)
        hops.append(hop)
        if reached:
            break
    return tuple(hops)


def _resolve_ipv4(host: str) -> str | None:
    """Loest ``host`` (IP-Literal ODER Hostname) in eine IPv4-Adresse auf -> Str oder ``None``.

    Reine, plattformunabhaengige Funktion (ohne ctypes testbar), gleiches Vorgehen wie
    ``icmp_windows._resolve_ipv4``: ``AF_INET`` liefert ausschliesslich IPv4, ein gueltiges
    IPv4-Literal wird unveraendert durchgereicht. Jeder Fehler -> ``None``; der Aufrufer
    macht daraus einen ehrlichen Fehler, NICHT eine leere Kette (E7).
    """
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
    except OSError:
        return None
    for info in infos:
        sockaddr = info[4]
        # sockaddr fuer AF_INET ist (ip, port) -- die IP ist bereits Dotted Quad.
        return str(sockaddr[0])
    return None


# ── Windows-spezifischer ctypes-Kern (nur unter win32) ───────────────────────

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    # Nutzlast und Reply-Puffer. IcmpSendEcho verlangt einen Puffer, der Reply-Header UND
    # (Echo-)Daten aufnimmt; 256 Byte reichen fuer diese kurze Nutzlast reichlich.
    _ECHO_PAYLOAD = b"cernis-route-probe"
    _REPLY_BUFFER_SIZE = 256

    # INVALID_HANDLE_VALUE (-1 als vorzeichenlose Zeigerbreite): ungueltiges Handle.
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class _IP_OPTION_INFORMATION(ctypes.Structure):
        """``IP_OPTION_INFORMATION`` (IPv4): TTL/Tos/Flags + optionale Optionsdaten.

        Hier in ZWEI Rollen: als ``RequestOptions``-EINGABE mit gesetztem ``Ttl`` (genau
        das, was die Routenmessung ueberhaupt erst moeglich macht) und als Teil der
        ``ICMP_ECHO_REPLY``-Struktur (Feld ``Options``), damit deren Offsets stimmen.
        """

        _fields_ = [
            ("Ttl", ctypes.c_ubyte),
            ("Tos", ctypes.c_ubyte),
            ("Flags", ctypes.c_ubyte),
            ("OptionsSize", ctypes.c_ubyte),
            ("OptionsData", ctypes.c_char_p),
        ]

    class _ICMP_ECHO_REPLY(ctypes.Structure):
        """``ICMP_ECHO_REPLY`` (IPv4): die von ``IcmpSendEcho`` gefuellte Antwortstruktur.

        Gelesen werden ``Address`` (der antwortende Hop -- bei einem Zwischenhop dessen
        eigene Adresse, NICHT die Zieladresse), ``Status`` und ``RoundTripTime`` (DWORD,
        Millisekunden). Die uebrigen Felder folgen exakt dem Win32-Header
        (Reihenfolge/Groesse), damit die Offsets stimmen.
        """

        _fields_ = [
            ("Address", wintypes.DWORD),
            ("Status", wintypes.DWORD),
            ("RoundTripTime", wintypes.DWORD),
            ("DataSize", wintypes.USHORT),
            ("Reserved", wintypes.USHORT),
            ("Data", ctypes.c_void_p),
            ("Options", _IP_OPTION_INFORMATION),
        ]

    def _configure_signatures() -> None:
        """Legt argtypes/restype der drei iphlpapi-Funktionen fest (korrektes Marshalling).

        Unterschied zur Ping-Naht in ``icmp_windows.py``: ``RequestOptions`` ist hier ein
        ZEIGER auf ``IP_OPTION_INFORMATION`` (nicht ``c_void_p``/``NULL``) -- nur so laesst
        sich die TTL je Messung setzen.
        """
        iphlpapi = ctypes.windll.iphlpapi
        iphlpapi.IcmpCreateFile.restype = wintypes.HANDLE
        iphlpapi.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        iphlpapi.IcmpCloseHandle.restype = wintypes.BOOL
        iphlpapi.IcmpSendEcho.argtypes = [
            wintypes.HANDLE,  # IcmpHandle
            wintypes.DWORD,  # DestinationAddress (IPv4, network byte order)
            ctypes.c_void_p,  # RequestData
            wintypes.WORD,  # RequestSize
            ctypes.POINTER(_IP_OPTION_INFORMATION),  # RequestOptions (TTL!)
            ctypes.c_void_p,  # ReplyBuffer
            wintypes.DWORD,  # ReplySize
            wintypes.DWORD,  # Timeout (Millisekunden)
        ]
        iphlpapi.IcmpSendEcho.restype = wintypes.DWORD

    def _ipv4_to_inaddr(ipv4: str) -> int | None:
        """Wandelt eine IPv4 (Dotted Quad) in den 32-Bit-``IPAddr`` (network byte order).

        ``IcmpSendEcho`` erwartet die Zieladresse als ``IPAddr`` -- exakt das Byte-Layout,
        das ``socket.inet_aton`` liefert. Ungueltiges Literal -> ``None``.
        """
        try:
            packed = socket.inet_aton(ipv4)
        except OSError:
            return None
        return int.from_bytes(packed, byteorder="little")

    def _inaddr_to_ipv4(addr: int) -> str | None:
        """Wandelt den 32-Bit-``IPAddr`` der Reply-Struktur zurueck in eine Dotted Quad.

        ``0`` heisst "keine Adresse geliefert" -> ``None`` (der Aufrufer macht daraus eine
        ehrliche Luecke, KEINE Adresse 0.0.0.0).
        """
        if not addr:
            return None
        try:
            return socket.inet_ntoa(int(addr).to_bytes(4, byteorder="little"))
        except (OSError, OverflowError, ValueError):
            return None

    def _run_native(target_ipv4: str, timeout_ms: int, max_ttl: int) -> tuple[TracerouteHop, ...]:
        """Oeffnet das Handle EINMAL fuer die Kette, misst ueber den reinen Kern, schliesst IMMER.

        Verdrahtet die echten ctypes-Aufrufe in ``_build_hop_chain``. Der Reply-Puffer und
        die Options-Struktur werden einmal angelegt und je Messung frisch beschrieben (die
        Optionen mit der aktuellen TTL, der Puffer genullt) -- so kann keine Alt-Antwort
        als neue durchgehen (E8).
        """
        dest = _ipv4_to_inaddr(target_ipv4)
        if dest is None:
            raise TracerouteUnavailable(f"Ungueltige Zieladresse: {target_ipv4}")
        _configure_signatures()
        iphlpapi = ctypes.windll.iphlpapi

        handle = iphlpapi.IcmpCreateFile()
        if not handle or handle == _INVALID_HANDLE_VALUE:
            raise TracerouteUnavailable(
                "Das ICMP-Handle konnte nicht angelegt werden (IcmpCreateFile)."
            )

        reply_buffer = ctypes.create_string_buffer(_REPLY_BUFFER_SIZE)
        options = _IP_OPTION_INFORMATION()
        options.Tos = 0
        options.Flags = 0
        options.OptionsSize = 0
        options.OptionsData = None

        def probe(ttl: int) -> _Probe:
            options.Ttl = ttl
            # Puffer VOR jedem Aufruf nullen (E8): sonst koennte die vorige Antwort bei
            # einem Aufruf ohne neue Daten als aktuelle gelesen werden.
            ctypes.memset(reply_buffer, 0, _REPLY_BUFFER_SIZE)
            returned = int(
                iphlpapi.IcmpSendEcho(
                    handle,
                    dest,
                    _ECHO_PAYLOAD,
                    len(_ECHO_PAYLOAD),
                    ctypes.byref(options),
                    reply_buffer,
                    _REPLY_BUFFER_SIZE,
                    timeout_ms,
                )
            )
            if returned <= 0:
                # Kein Reply -> keine gueltigen Daten im Puffer; als Luecke fuehren.
                return _Probe(returned=0, status=_IP_REQ_TIMED_OUT, address=None, rtt_ms=0)
            reply = ctypes.cast(reply_buffer, ctypes.POINTER(_ICMP_ECHO_REPLY)).contents
            return _Probe(
                returned=returned,
                status=int(reply.Status),
                address=_inaddr_to_ipv4(int(reply.Address)),
                rtt_ms=int(reply.RoundTripTime),
            )

        try:
            return _build_hop_chain(probe, max_ttl=max_ttl)
        finally:
            iphlpapi.IcmpCloseHandle(handle)

else:  # pragma: no cover -- Nicht-Windows: gleicher Name, ehrlicher Fehler statt Luege.

    def _run_native(target_ipv4: str, timeout_ms: int, max_ttl: int) -> tuple[TracerouteHop, ...]:
        """Nicht-Windows-Ersatz: bindet denselben Namen, meldet ehrlich Unverfuegbarkeit.

        Damit typcheckt der Aufrufer auf beiden Plattformen (die Verwendungsstelle bleibt
        unveraendert). Erreicht wird dieser Zweig im Betrieb nie -- die Plattformweiche
        steht im Composition Root ``app.py``. Er liefert aber KEINE leere Kette, denn das
        waere die Luege "gemessen, nichts gefunden" (E7/S3).
        """
        raise TracerouteUnavailable(
            "Die native Routenmessung ueber iphlpapi gibt es nur auf Windows."
        )


class WindowsTracerouteRunner:
    """Erfuellt das ``TracerouteRunner``-Protocol nativ ueber iphlpapi (Windows, IPv4)."""

    async def run(self, target: str, privileged: bool) -> TracerouteResult:
        """Misst den Pfad zu ``target`` nativ -> ``TracerouteResult``.

        Die ctypes-Aufrufe blockieren -- die GESAMTE Messschleife (bis zu 30 Hops zu je
        1500 ms) laeuft daher ueber ``asyncio.to_thread``, NIE direkt in der
        Ereignisschleife (E5; dieselbe Fehlerklasse, die in Paket W-g den Paketmitschnitt
        lahmgelegt hat).

        ``privileged`` wird fuer die MESSUNG ignoriert und im Ergebnis als ``False``
        gefuehrt: auf Windows gibt es zu diesem Wunsch keine Entsprechung, weil der
        unprivilegierte Normalpfad hier bereits der genaue ist -- und ``privileged``
        bedeutet laut Domaene, WIE gemessen wurde, nicht was gewuenscht war (E2).

        Scheitert die Namensaufloesung oder das ICMP-Handle -> ``TracerouteUnavailable``,
        NICHT eine leere Kette (E7, kein stiller Fallback).
        """
        ipv4 = _resolve_ipv4(target)
        if ipv4 is None:
            raise TracerouteUnavailable(f"Der Name '{target}' konnte nicht aufgeloest werden.")
        hops = await asyncio.to_thread(_run_native, ipv4, _HOP_TIMEOUT_MS, _MAX_TTL)
        return TracerouteResult(target=target, privileged=False, hops=hops)


class WindowsTraceroutePermission:
    """Erfuellt das ``TraceroutePermissionPort``-Protocol (Windows: nichts fehlt)."""

    def is_available(self) -> bool:
        """Immer ``True``: die Faehigkeit steckt in ``iphlpapi.dll``, also im Betriebssystem.

        Es gibt kein nachzuinstallierendes Binary und keinen PATH-Eintrag, der fehlen
        koennte -- eine Installationsaufforderung waere sachlich unbegruendet.
        """
        return True

    def check_permission(self) -> str | None:
        """Immer ``None``: es fehlt nichts und es ist nichts nachzureichen.

        WICHTIG zur Lesart: ``None`` heisst hier NICHT, dass es zusaetzlich einen
        privilegierten, noch genaueren Modus gaebe (so liest es der Linux-Zweig, wo ``None``
        "laeuft als Root" bedeutet). Auf Windows misst ``IcmpSendEcho`` unprivilegiert
        vollstaendig -- der vorhandene Weg IST der vollstaendige. ``None`` ist deshalb die
        ehrliche Auskunft "kein Rechte-Mangel", und das Frontend blendet den Rechtehinweis
        folgerichtig aus.
        """
        return None
