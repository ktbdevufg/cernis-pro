"""Nativer Windows-ICMP-Echo-Adapter (iphlpapi via ctypes, kein ping.exe, kein Regex).

Zweck: EIN einziger ICMP-Echo gegen einen Host -> ``(alive, rtt_ms)``. Auf Windows wird
damit ``ping.exe`` weder aufgerufen noch geparst. Grund (Projektregel, wie schon in
``interfaces_windows.py``/``system_resolvers_windows.py``): lokalisierte ``ping.exe``-Ausgabe
(deutsch ``Zeit<1ms``, englisch ``time=1ms``, andere Sprachen anders) laesst jeden Regex
STILL scheitern -- verboten. Stattdessen die native API: ``IcmpCreateFile`` /
``IcmpSendEcho`` / ``IcmpCloseHandle`` aus ``iphlpapi.dll``. Die RTT kommt als Zahl
(``RoundTripTime``, DWORD, Millisekunden) direkt aus der ``ICMP_ECHO_REPLY``-Struktur --
kein Text, kein Regex. ``alive`` ist genau dann ``True``, wenn das Feld ``Status`` den Wert
``IP_SUCCESS`` (0) traegt; ein Returncode wird NICHT ausgewertet.

Nur IPv4: ``IcmpSendEcho`` ist IPv4. IPv6 wird hier NICHT behandelt (die bestehende
``ipv6.py`` bleibt unangetastet). ``host`` darf ein Hostname sein: er wird vorab per
``socket.getaddrinfo`` in eine IPv4-Adresse aufgeloest; scheitert das, ist das Ergebnis
``(False, -1.0)``.

PLATTFORM-WEICHE (mypy-Falle, hat die Linux-CI schon zweimal gebrochen): ``mypy --strict``
wertet ``sys.platform`` statisch aus. Auf dem Linux-Runner existiert JEDER Name, der
innerhalb eines ``if sys.platform == "win32":``-Blocks definiert wurde, NICHT -- deshalb
steht nicht nur der ctypes-Import, sondern AUCH jeder Aufruf und jede Referenz auf einen
solchen Namen selbst im positiven Guard. Bewaehrtes Projektmuster: BEIDE Zweige der Weiche
binden denselben Namen (``_send_echo_native``), dann existiert er fuer mypy auf beiden
Plattformen und die Verwendungsstelle bleibt unveraendert. Auf Nicht-Windows liefert der
Ersatz-Zweig den vertraglichen Nicht-erreichbar-Zustand ``(False, -1.0)``.

TESTBARKEIT: die eigentliche Ablauflogik (Handle oeffnen -> senden -> Reply lesen ->
Handle IMMER schliessen) sitzt im plattformunabhaengigen ``_perform_echo``, das seine drei
API-Schritte als Callables gereicht bekommt. So laesst sie sich auf dem Linux-CI-Runner
OHNE echte DLL mit Mocks pruefen (Erfolg, Fehlerstatus, Handle-Schluss im Fehlerfall). Der
win32-Zweig verdrahtet dort die echten ctypes-Aufrufe; der reine Kern bleibt unberuehrt.

Die ctypes-Aufrufe blockieren; damit der Event-Loop nicht blockiert, laeuft die eigentliche
Messung ueber ``asyncio.to_thread``. Bei JEDEM Fehler (DLL nicht ladbar, Aufloesung
scheitert, Timeout, Exception) ist das Ergebnis ``(False, -1.0)`` -- das ist der
vertragliche Nicht-erreichbar-Zustand, kein verdecktes Scheitern (Finding S3).
"""

import asyncio
import socket
import sys
from collections.abc import Callable

# ``IcmpSendEcho`` meldet Erfolg ueber das Struktur-Feld ``Status == IP_SUCCESS`` (0).
_IP_SUCCESS = 0

# Vertraglicher Nicht-erreichbar-Zustand (kein verdecktes Scheitern, Finding S3).
_UNREACHABLE: tuple[bool, float] = (False, -1.0)


def _resolve_ipv4(host: str) -> str | None:
    """Loest ``host`` (IP-Literal ODER Hostname) in eine IPv4-Adresse auf -> Str oder ``None``.

    Reine, plattformunabhaengige Funktion (ohne ctypes testbar). ``socket.getaddrinfo`` mit
    ``AF_INET`` liefert ausschliesslich IPv4; ein bereits gueltiges IPv4-Literal wird dabei
    unveraendert durchgereicht. Jeder Fehler (unaufloesbar, nur IPv6, leere Antwort) ->
    ``None`` -- der Aufrufer macht daraus den Nicht-erreichbar-Zustand.
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


def _reply_to_result(status: int, round_trip_ms: int) -> tuple[bool, float]:
    """Bildet die relevanten ``ICMP_ECHO_REPLY``-Felder auf ``(alive, rtt_ms)`` ab.

    Reine Funktion (ohne ctypes testbar): ``alive`` ist genau dann ``True``, wenn
    ``Status == IP_SUCCESS`` (0). Nur dann ist ``RoundTripTime`` ein gueltiger Messwert und
    wird als ``float``-Millisekunden geliefert; sonst der Sentinel ``-1.0``.
    """
    if status != _IP_SUCCESS:
        return _UNREACHABLE
    return (True, float(round_trip_ms))


def _perform_echo(
    create_handle: Callable[[], object],
    send_echo: Callable[[object], int | None],
    read_reply: Callable[[], tuple[int, int]],
    close_handle: Callable[[object], None],
) -> tuple[bool, float]:
    """Plattformunabhaengiger ICMP-Echo-Ablauf ueber gereichte API-Schritte -> ``(alive, rtt)``.

    Reiner Kern (ohne ctypes/DLL testbar): oeffnet das Handle (``create_handle``), sendet
    EINEN Echo (``send_echo`` liefert die Antwortanzahl bzw. ``0``/``None`` = keine Antwort),
    liest bei Antwort ``Status``/``RoundTripTime`` (``read_reply``) und wertet sie via
    ``_reply_to_result`` aus. Das Handle wird IMMER in ``try/finally`` geschlossen
    (``close_handle``) -- sonst leakt bei tausenden Scan-Pings jedes Handle. Ein
    falsy Handle (``None``/``0``, u. a. ``INVALID_HANDLE_VALUE``) -> Nicht-erreichbar, OHNE
    ``close_handle`` (es wurde keines geoeffnet). Keine Antwort -> Nicht-erreichbar.
    """
    handle = create_handle()
    if not handle:
        return _UNREACHABLE
    try:
        count = send_echo(handle)
        if not count:
            # Keine Antwort (Timeout/unerreichbar) -> Nicht-erreichbar.
            return _UNREACHABLE
        status, round_trip_ms = read_reply()
        return _reply_to_result(status, round_trip_ms)
    finally:
        close_handle(handle)


# ── Windows-spezifischer ctypes-Kern (nur unter win32; ausserhalb: Nicht-erreichbar) ──

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    # Puffer fuer Echo-Nutzlast und Reply. IcmpSendEcho verlangt einen Reply-Puffer, der
    # Reply-Header UND (Echo-)Daten aufnimmt.
    _ECHO_PAYLOAD = b"cernis-icmp-probe"
    _REPLY_BUFFER_SIZE = 256

    # INVALID_HANDLE_VALUE (-1 als vorzeichenlose Zeigerbreite): ungueltiges Handle.
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class _IP_OPTION_INFORMATION(ctypes.Structure):
        """``IP_OPTION_INFORMATION`` (IPv4): TTL/Tos/Flags + optionale Optionsdaten.

        Teil von ``ICMP_ECHO_REPLY`` (Feld ``Options``); vollstaendig ausmodelliert, damit
        die Reply-Struktur die korrekte Groesse/Offsets hat.
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

        Nur ``Status`` (Erfolg = ``IP_SUCCESS`` == 0) und ``RoundTripTime`` (DWORD,
        Millisekunden) werden gelesen; die uebrigen Felder folgen exakt dem Win32-Header
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
        """Legt argtypes/restype der drei iphlpapi-Funktionen fest (korrektes Marshalling)."""
        iphlpapi = ctypes.windll.iphlpapi
        iphlpapi.IcmpCreateFile.restype = wintypes.HANDLE
        iphlpapi.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        iphlpapi.IcmpCloseHandle.restype = wintypes.BOOL
        iphlpapi.IcmpSendEcho.argtypes = [
            wintypes.HANDLE,  # IcmpHandle
            wintypes.DWORD,  # DestinationAddress (IPv4, network byte order)
            ctypes.c_void_p,  # RequestData
            wintypes.WORD,  # RequestSize
            ctypes.c_void_p,  # RequestOptions (NULL -> Defaults)
            ctypes.c_void_p,  # ReplyBuffer
            wintypes.DWORD,  # ReplySize
            wintypes.DWORD,  # Timeout (Millisekunden)
        ]
        iphlpapi.IcmpSendEcho.restype = wintypes.DWORD

    def _ipv4_to_inaddr(ipv4: str) -> int | None:
        """Wandelt eine IPv4 (Dotted Quad) in den 32-Bit-``IPAddr`` (network byte order).

        ``IcmpSendEcho`` erwartet die Zieladresse als ``IPAddr`` -- exakt das Byte-Layout,
        das ``socket.inet_aton`` liefert (network byte order). Ungueltiges Literal ->
        ``None`` (der Aufrufer macht daraus den Nicht-erreichbar-Zustand).
        """
        try:
            packed = socket.inet_aton(ipv4)
        except OSError:
            return None
        return int.from_bytes(packed, byteorder="little")

    def _send_echo_native(ipv4: str, timeout: float) -> tuple[bool, float]:
        """Synchroner nativer ICMP-Echo gegen eine IPv4-Adresse -> ``(alive, rtt_ms)``.

        Verdrahtet die echten ctypes-Aufrufe in den reinen ``_perform_echo``-Kern: ein
        einzelner ``ICMP_ECHO_REPLY`` wird in einem Puffer gehalten, ``read_reply`` liest
        daraus ``Status``/``RoundTripTime``. Das Handle wird im Kern IMMER geschlossen. JEDER
        Fehler (ungueltige Adresse, ungueltiges Handle, keine Antwort) -> ``(False, -1.0)``.
        """
        dest = _ipv4_to_inaddr(ipv4)
        if dest is None:
            return _UNREACHABLE
        _configure_signatures()
        iphlpapi = ctypes.windll.iphlpapi
        reply_buffer = ctypes.create_string_buffer(_REPLY_BUFFER_SIZE)
        timeout_ms = max(int(timeout * 1000), 1)

        def create_handle() -> object:
            handle = iphlpapi.IcmpCreateFile()
            if not handle or handle == _INVALID_HANDLE_VALUE:
                return None
            return handle

        def send_echo(handle: object) -> int | None:
            return int(
                iphlpapi.IcmpSendEcho(
                    handle,
                    dest,
                    _ECHO_PAYLOAD,
                    len(_ECHO_PAYLOAD),
                    None,
                    reply_buffer,
                    _REPLY_BUFFER_SIZE,
                    timeout_ms,
                )
            )

        def read_reply() -> tuple[int, int]:
            reply = ctypes.cast(reply_buffer, ctypes.POINTER(_ICMP_ECHO_REPLY)).contents
            return (int(reply.Status), int(reply.RoundTripTime))

        def close_handle(handle: object) -> None:
            iphlpapi.IcmpCloseHandle(handle)

        return _perform_echo(create_handle, send_echo, read_reply, close_handle)

else:  # pragma: no cover -- Nicht-Windows: gleicher Name, vertraglicher Ersatz.

    def _send_echo_native(ipv4: str, timeout: float) -> tuple[bool, float]:
        """Nicht-Windows-Ersatz: liefert immer den Nicht-erreichbar-Zustand.

        Bindet denselben Namen wie der win32-Zweig, damit ``icmp_echo`` fuer mypy auf beiden
        Plattformen typcheckt (die Verwendungsstelle bleibt unveraendert). Auf Nicht-Windows
        existiert ``iphlpapi`` nicht -- ``(False, -1.0)`` ist der korrekte Vertrag.
        """
        return _UNREACHABLE


async def icmp_echo(host: str, timeout: float) -> tuple[bool, float]:
    """EIN nativer ICMP-Echo gegen ``host`` -> ``(alive, rtt_ms)`` (Windows-only gedacht).

    Loest ``host`` (Hostname ODER IPv4-Literal) per ``getaddrinfo`` in eine IPv4-Adresse auf
    und misst dann ueber die native iphlpapi (``IcmpSendEcho``). Die blockierenden
    ctypes-Aufrufe laufen ueber ``asyncio.to_thread``, damit der Event-Loop frei bleibt.
    ``alive`` ist genau dann ``True``, wenn ``Status == IP_SUCCESS``; ``rtt_ms`` ist dann
    ``RoundTripTime`` (Millisekunden) als ``float``. Bei JEDEM Fehler (Aufloesung scheitert,
    DLL nicht ladbar, Timeout, Exception) ist das Ergebnis ``(False, -1.0)`` -- der
    vertragliche Nicht-erreichbar-Zustand, kein verdecktes Scheitern.
    """
    ipv4 = _resolve_ipv4(host)
    if ipv4 is None:
        return _UNREACHABLE
    try:
        return await asyncio.to_thread(_send_echo_native, ipv4, timeout)
    except Exception:
        return _UNREACHABLE
