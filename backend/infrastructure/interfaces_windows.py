"""Windows-Adapter fuer ``InterfaceDiscoveryPort`` (nativer API-Pfad, kein Text-Parsing).

Erfuellt den ``InterfaceDiscoveryPort`` strukturell -- exakt wie
``infrastructure/interfaces_linux.py``: Klasse ``InterfaceDiscoveryAdapter`` mit
``async def discover`` ueber einen synchronen Kern ``_discover_sync``, der per
``run_in_executor`` im Thread laeuft (Event-Loop bleibt frei). Rueckgabe sind ROHE
``domain.interfaces.NetworkInterface`` -- ``type``/``status``/``is_primary`` bleiben
auf Default, die setzt der Use-Case ``ListInterfaces``.

DATENQUELLE (bewusst KEIN ipconfig/netsh/route-Parsing): lokalisierte Windows-
Ausgaben (deutsch/franzoesisch/spanisch) lassen Textparser still scheitern -- das
ist verboten. Stattdessen die Windows-API ``GetAdaptersAddresses`` aus
``iphlpapi.dll`` per ``ctypes``. Der gesamte ctypes-/Windows-spezifische Code liegt
AUSSCHLIESSLICH im Block ``if sys.platform == "win32":`` (inkl. der ctypes-Imports):
``mypy --strict`` wertet ``sys.platform`` statisch aus, ein ``hasattr``-Guard genuegt
NICHT und wuerde die Linux-CI brechen. Auf Nicht-Windows ist das Modul importierbar
und ``_discover_sync`` liefert ``[]`` (vertraglicher Leer-Zustand, kein Fehler).

FILTER (identisch zum Linux-Adapter): Loopback raus, Interfaces ohne IPv4 UND ohne
IPv6-Link-Local raus. ``network_cidr``/``host_count`` fuellt der Adapter aus
``ipv4``/``ipv4_prefix`` (die Domaene fuehrt diese Felder). Leere Strings werden zu
``None`` (Domaene: "fehlend" ist ``None``, nicht ``""``).

Die reinen Hilfsfunktionen (MAC-Formatierung, Sockaddr-nach-String, IPv6-Einordnung,
CIDR-Berechnung) liegen AUSSERHALB des ``sys.platform``-Guards und sind ohne ctypes
mit einfachen Python-Eingaben testbar (plattformunabhaengig, wie beim Linux-Adapter
die Parse-Hilfsfunktionen).
"""

import asyncio
import ipaddress
import socket
import sys

from domain.interfaces import NetworkInterface, classify_type_from_if_type

# ── Plattformunabhaengige reine Hilfsfunktionen (ohne ctypes testbar) ──────────


def format_mac(raw: bytes, length: int) -> str:
    """Formatiert ``length`` Bytes aus ``raw`` als ``aa:bb:cc:dd:ee:ff`` (lowercase).

    Reine Funktion (Altcode-treu zum Linux-``link/ether``-Format): nur die ersten
    ``length`` Bytes zaehlen (Windows liefert ``PhysicalAddress`` als Fixpuffer mit
    ``PhysicalAddressLength``). Laenge ``0`` (z. B. Loopback/PPP ohne Hardware-Adresse)
    -> leerer String, den der Adapter zu ``None`` macht. Ungewoehnliche Laengen
    (z. B. Firewire mit 8 Bytes) werden 1:1 durchgereicht -- kein Abschneiden auf 6.
    """
    if length <= 0:
        return ""
    return ":".join(f"{byte:02x}" for byte in raw[:length])


def classify_ipv6(addr: str) -> str:
    """Ordnet eine IPv6-Adresse ein: ``"link_local"`` (beginnt ``fe80``) sonst ``"global"``.

    Reine Funktion (case-insensitive, wie der Linux-Adapter): der Aufrufer legt das
    Ergebnis in ``ipv6_link_local`` bzw. ``ipv6_global`` ab.
    """
    return "link_local" if addr.lower().startswith("fe80") else "global"


def network_cidr_and_host_count(ipv4: str, prefix: int) -> tuple[str | None, int | None]:
    """``(network_cidr, host_count)`` aus IPv4 + Praefix -- exakt wie im Linux-Adapter.

    ``ipaddress.ip_interface(f"{ipv4}/{prefix}").network`` -> ``network_cidr =
    str(network)``, ``host_count = max(num_addresses - 2, 0)``. Bei ``ValueError``
    (ungueltige Adresse/Praefix) beide ``None``. Reine Funktion.
    """
    try:
        network = ipaddress.ip_interface(f"{ipv4}/{prefix}").network
    except ValueError:
        return (None, None)
    return (str(network), max(network.num_addresses - 2, 0))


class _RawInterface:
    """Sammelt die rohen Felder eines Interfaces waehrend des API-Durchlaufs.

    Analog zum ``_RawInterface`` des Linux-Adapters, aber plattformunabhaengig: der
    ctypes-Code (im Guard) befuellt nur diese einfachen Python-Attribute, die
    Abbildung auf ``NetworkInterface`` (``_to_network_interface``) und der Filter
    bleiben ohne ctypes testbar.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.ipv4 = ""
        self.ipv4_prefix = 24
        self.ipv6_link_local = ""
        self.ipv6_global = ""
        self.mac = ""
        self.gateway = ""
        self.mtu = 1500
        self.is_up = True
        self.is_loopback = False
        # Numerischer IANA-ifType (Windows: IP_ADAPTER_ADDRESSES_LH.IfType). Quelle
        # der Typ-Klassifikation auf Windows; Default 0 -> unknown.
        self.if_type = 0


def _to_network_interface(raw: _RawInterface) -> NetworkInterface:
    """Bildet ein ``_RawInterface`` auf ein rohes ``NetworkInterface`` ab.

    Fuellt ``network_cidr``/``host_count`` aus ``ipv4``/``ipv4_prefix`` (die Domaene
    fuehrt diese Felder). ``status``/``is_primary`` bleiben auf Default -- die setzt
    der Use-Case. AUSNAHME ``type``: den setzt der Adapter hier bewusst ueber den
    numerischen ``IfType`` (``classify_type_from_if_type``), weil die namensbasierte
    Klassifikation des Use-Case (``classify_type``) auf Windows strukturell nicht
    funktioniert -- Windows-Anzeigenamen (``Ethernet0``/``WLAN``, lokalisiert, frei
    umbenennbar) treffen keinen der Linux-Praefixe. Leere Strings des Roh-Durchlaufs
    werden zu ``None`` (Domaene: "fehlend" ist ``None``, nicht ``""``).
    """
    network_cidr: str | None = None
    host_count: int | None = None
    if raw.ipv4:
        network_cidr, host_count = network_cidr_and_host_count(raw.ipv4, raw.ipv4_prefix)

    return NetworkInterface(
        name=raw.name,
        ipv4=raw.ipv4 or None,
        ipv4_prefix=raw.ipv4_prefix if raw.ipv4 else None,
        ipv6_link_local=raw.ipv6_link_local or None,
        ipv6_global=raw.ipv6_global or None,
        mac=raw.mac or None,
        gateway=raw.gateway or None,
        mtu=raw.mtu,
        is_up=raw.is_up,
        is_loopback=raw.is_loopback,
        network_cidr=network_cidr,
        host_count=host_count,
        type=classify_type_from_if_type(raw.if_type),
    )


def _filter_and_map(raws: list["_RawInterface"]) -> list[NetworkInterface]:
    """Filter (identisch zum Linux-Adapter) + Abbildung, Reihenfolge bewahrt.

    Loopback raus; Interfaces ohne IPv4 UND ohne IPv6-Link-Local raus. Reine
    Funktion ueber bereits eingelesene ``_RawInterface`` -- ohne ctypes testbar.
    """
    result: list[NetworkInterface] = []
    for raw in raws:
        if raw.is_loopback:
            continue
        if not raw.ipv4 and not raw.ipv6_link_local:
            continue
        result.append(_to_network_interface(raw))
    return result


# ── Windows-spezifischer ctypes-Kern (nur unter win32; ausserhalb: Leer-Zustand) ──

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    # Konstanten der GetAdaptersAddresses-API (iphlpapi).
    _AF_UNSPEC = 0
    _AF_INET = 2
    _AF_INET6 = 23
    _GAA_FLAG_SKIP_ANYCAST = 0x0002
    _GAA_FLAG_SKIP_MULTICAST = 0x0004
    _GAA_FLAG_SKIP_DNS_SERVER = 0x0008
    _GAA_FLAG_INCLUDE_PREFIX = 0x0010
    _GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
    _NO_ERROR = 0
    _ERROR_BUFFER_OVERFLOW = 111
    _IF_TYPE_SOFTWARE_LOOPBACK = 24
    _IF_OPER_STATUS_UP = 1
    _MAX_ADAPTER_ADDRESS_LENGTH = 8

    class _SOCKADDR_IN(ctypes.Structure):
        """``sockaddr_in`` (IPv4): Family + Port + 4-Byte-Adresse."""

        _fields_ = [
            ("sin_family", ctypes.c_ushort),
            ("sin_port", ctypes.c_ushort),
            ("sin_addr", ctypes.c_ubyte * 4),
            ("sin_zero", ctypes.c_ubyte * 8),
        ]

    class _SOCKADDR_IN6(ctypes.Structure):
        """``sockaddr_in6`` (IPv6): Family + Port + Flowinfo + 16-Byte-Adresse + Scope."""

        _fields_ = [
            ("sin6_family", ctypes.c_ushort),
            ("sin6_port", ctypes.c_ushort),
            ("sin6_flowinfo", ctypes.c_ulong),
            ("sin6_addr", ctypes.c_ubyte * 16),
            ("sin6_scope_id", ctypes.c_ulong),
        ]

    class _SOCKADDR(ctypes.Structure):
        """Generischer ``sockaddr`` (nur Family lesen, dann auf IN/IN6 casten)."""

        _fields_ = [
            ("sa_family", ctypes.c_ushort),
            ("sa_data", ctypes.c_ubyte * 26),
        ]

    class _SOCKET_ADDRESS(ctypes.Structure):
        """``SOCKET_ADDRESS``: Zeiger auf ``sockaddr`` + dessen Laenge."""

        _fields_ = [
            ("lpSockaddr", ctypes.POINTER(_SOCKADDR)),
            ("iSockaddrLength", ctypes.c_int),
        ]

    class _IP_ADAPTER_UNICAST_ADDRESS_LH(ctypes.Structure):
        """``IP_ADAPTER_UNICAST_ADDRESS_LH``: verkettete Unicast-Adressliste.

        Nur die hier genutzten Felder sind ausmodelliert: ``Length``/``Flags`` des
        vorangestellten Union-Headers, ``Next`` (Verkettung), ``Address`` (Sockaddr)
        und -- am Ende -- ``OnLinkPrefixLength`` (der echte Praefix, NICHT aus einer
        Netzmaske geraten). Die dazwischenliegenden Felder werden als Platzhalter
        mitgefuehrt, damit das Offset von ``OnLinkPrefixLength`` stimmt.
        """

    _IP_ADAPTER_UNICAST_ADDRESS_LH._fields_ = [
        ("Length", ctypes.c_ulong),
        ("Flags", wintypes.DWORD),
        ("Next", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS_LH)),
        ("Address", _SOCKET_ADDRESS),
        ("PrefixOrigin", ctypes.c_int),
        ("SuffixOrigin", ctypes.c_int),
        ("DadState", ctypes.c_int),
        ("ValidLifetime", ctypes.c_ulong),
        ("PreferredLifetime", ctypes.c_ulong),
        ("LeaseLifetime", ctypes.c_ulong),
        ("OnLinkPrefixLength", ctypes.c_ubyte),
    ]

    class _IP_ADAPTER_GATEWAY_ADDRESS_LH(ctypes.Structure):
        """``IP_ADAPTER_GATEWAY_ADDRESS_LH``: verkettete Gateway-Adressliste."""

    _IP_ADAPTER_GATEWAY_ADDRESS_LH._fields_ = [
        ("Length", ctypes.c_ulong),
        ("Flags", wintypes.DWORD),
        ("Next", ctypes.POINTER(_IP_ADAPTER_GATEWAY_ADDRESS_LH)),
        ("Address", _SOCKET_ADDRESS),
    ]

    class _IP_ADAPTER_ADDRESSES_LH(ctypes.Structure):
        """``IP_ADAPTER_ADDRESSES_LH``: ein Adapter-Eintrag der verketteten Liste.

        Nur die hier gelesenen Felder sind ausmodelliert; ``Next`` verkettet die
        Adapter. Die Reihenfolge/Groesse der Felder bis ``Mtu`` folgt exakt dem
        Win32-Header (LH-Variante), damit die Offsets stimmen.
        """

    _IP_ADAPTER_ADDRESSES_LH._fields_ = [
        ("Length", ctypes.c_ulong),
        ("IfIndex", wintypes.DWORD),
        ("Next", ctypes.POINTER(_IP_ADAPTER_ADDRESSES_LH)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS_LH)),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", ctypes.c_wchar_p),
        ("Description", ctypes.c_wchar_p),
        ("FriendlyName", ctypes.c_wchar_p),
        ("PhysicalAddress", ctypes.c_ubyte * _MAX_ADAPTER_ADDRESS_LENGTH),
        ("PhysicalAddressLength", wintypes.DWORD),
        ("Flags", wintypes.DWORD),
        ("Mtu", wintypes.DWORD),
        ("IfType", wintypes.DWORD),
        ("OperStatus", ctypes.c_int),
        ("Ipv6IfIndex", wintypes.DWORD),
        ("ZoneIndices", wintypes.DWORD * 16),
        ("FirstPrefix", ctypes.c_void_p),
        # Zwischen FirstPrefix und FirstGatewayAddress liegen im echten LH-Header
        # noch TransmitLinkSpeed/ReceiveLinkSpeed (je ULONG64) und
        # FirstWinsServerAddress (Zeiger). Ohne sie steht FirstGatewayAddress um
        # 24 Byte verschoben -> Fehl-Offset -> Zugriffsverletzung. Als Platzhalter
        # mitgefuehrt, damit das Offset stimmt.
        ("TransmitLinkSpeed", ctypes.c_ulonglong),
        ("ReceiveLinkSpeed", ctypes.c_ulonglong),
        ("FirstWinsServerAddress", ctypes.c_void_p),
        ("FirstGatewayAddress", ctypes.POINTER(_IP_ADAPTER_GATEWAY_ADDRESS_LH)),
    ]

    def _sockaddr_ipv4(sockaddr_ptr: "ctypes._Pointer[_SOCKADDR]") -> str:
        """Liest eine IPv4-Adresse (Dotted Quad) aus einem ``sockaddr``-Zeiger."""
        in4 = ctypes.cast(sockaddr_ptr, ctypes.POINTER(_SOCKADDR_IN)).contents
        return socket.inet_ntop(socket.AF_INET, bytes(in4.sin_addr))

    def _sockaddr_ipv6(sockaddr_ptr: "ctypes._Pointer[_SOCKADDR]") -> str:
        """Liest eine IPv6-Adresse aus einem ``sockaddr``-Zeiger (via ``inet_ntop``)."""
        in6 = ctypes.cast(sockaddr_ptr, ctypes.POINTER(_SOCKADDR_IN6)).contents
        return socket.inet_ntop(socket.AF_INET6, bytes(in6.sin6_addr))

    def _call_get_adapters_addresses() -> "ctypes.Array[ctypes.c_char] | None":
        """Zwei-Pass-Aufruf von ``GetAdaptersAddresses`` -> Puffer oder ``None``.

        Erster Aufruf mit NULL-Puffer liefert ``ERROR_BUFFER_OVERFLOW`` (111) und die
        benoetigte Groesse; dann Puffer allozieren und zweiter Aufruf. Rueckgabewert
        ungleich ``NO_ERROR`` (0) -> ``None`` (best effort, kein Hochlaufen -- der
        Adapter macht daraus ``[]``).
        """
        get_adapters = ctypes.windll.iphlpapi.GetAdaptersAddresses
        # GAA_FLAG_INCLUDE_GATEWAYS ist zwingend: ohne dieses Flag fuellt Windows
        # FirstGatewayAddress GRUNDSAETZLICH nicht -- die Gateway-Liste bleibt
        # immer leer und der Adapter lieferte faelschlich gateway=None.
        flags = (
            _GAA_FLAG_INCLUDE_PREFIX
            | _GAA_FLAG_INCLUDE_GATEWAYS
            | _GAA_FLAG_SKIP_ANYCAST
            | _GAA_FLAG_SKIP_MULTICAST
            | _GAA_FLAG_SKIP_DNS_SERVER
        )
        size = wintypes.ULONG(0)
        # Pass 1: Groesse ermitteln (NULL-Puffer).
        ret = get_adapters(_AF_UNSPEC, flags, None, None, ctypes.byref(size))
        if ret != _ERROR_BUFFER_OVERFLOW:
            return None
        buffer = ctypes.create_string_buffer(size.value)
        # Pass 2: befuellen.
        ret = get_adapters(
            _AF_UNSPEC,
            flags,
            None,
            ctypes.cast(buffer, ctypes.POINTER(_IP_ADAPTER_ADDRESSES_LH)),
            ctypes.byref(size),
        )
        if ret != _NO_ERROR:
            return None
        return buffer

    def _raw_from_adapter(adapter: _IP_ADAPTER_ADDRESSES_LH) -> _RawInterface:
        """Bildet EINEN API-Adapter-Eintrag auf ein ``_RawInterface`` ab.

        Es zaehlt jeweils die ERSTE gefundene Adresse der Sorte (IPv4, IPv6-LL,
        IPv6-global) sowie das erste IPv4-Gateway. ``ipv4_prefix`` kommt aus
        ``OnLinkPrefixLength`` des jeweiligen Unicast-Eintrags (nicht geraten).
        """
        raw = _RawInterface(adapter.FriendlyName or "")
        raw.mac = format_mac(bytes(adapter.PhysicalAddress), adapter.PhysicalAddressLength)
        mtu = int(adapter.Mtu)
        raw.mtu = mtu if 0 < mtu < 0xFFFFFFFF else 1500
        raw.is_up = adapter.OperStatus == _IF_OPER_STATUS_UP
        raw.if_type = int(adapter.IfType)
        raw.is_loopback = adapter.IfType == _IF_TYPE_SOFTWARE_LOOPBACK

        # Unicast-Adressliste durchlaufen: erste IPv4/IPv6-LL/IPv6-global gewinnt.
        unicast_ptr = adapter.FirstUnicastAddress
        while unicast_ptr:
            unicast = unicast_ptr.contents
            sockaddr_ptr = unicast.Address.lpSockaddr
            if sockaddr_ptr:
                family = sockaddr_ptr.contents.sa_family
                if family == _AF_INET and not raw.ipv4:
                    raw.ipv4 = _sockaddr_ipv4(sockaddr_ptr)
                    raw.ipv4_prefix = int(unicast.OnLinkPrefixLength)
                elif family == _AF_INET6:
                    addr6 = _sockaddr_ipv6(sockaddr_ptr)
                    if classify_ipv6(addr6) == "link_local":
                        if not raw.ipv6_link_local:
                            raw.ipv6_link_local = addr6
                    elif not raw.ipv6_global:
                        raw.ipv6_global = addr6
            unicast_ptr = unicast.Next

        # Gateway: erster IPv4-Eintrag der Gateway-Liste.
        gateway_ptr = adapter.FirstGatewayAddress
        while gateway_ptr:
            gateway = gateway_ptr.contents
            sockaddr_ptr = gateway.Address.lpSockaddr
            if sockaddr_ptr and sockaddr_ptr.contents.sa_family == _AF_INET:
                raw.gateway = _sockaddr_ipv4(sockaddr_ptr)
                break
            gateway_ptr = gateway.Next

        return raw

    def _collect_raw_interfaces() -> list[_RawInterface]:
        """Ruft die API und sammelt alle Adapter als ``_RawInterface`` (Reihenfolge bewahrt)."""
        buffer = _call_get_adapters_addresses()
        if buffer is None:
            return []
        raws: list[_RawInterface] = []
        adapter_ptr = ctypes.cast(buffer, ctypes.POINTER(_IP_ADAPTER_ADDRESSES_LH))
        while adapter_ptr:
            raws.append(_raw_from_adapter(adapter_ptr.contents))
            adapter_ptr = adapter_ptr.contents.Next
        return raws


class InterfaceDiscoveryAdapter:
    """Erfuellt das ``InterfaceDiscoveryPort``-Protocol (Executor-Wrapper, Windows)."""

    async def discover(self) -> list[NetworkInterface]:
        """Aktuelle Interfaces als rohe ``NetworkInterface``-Liste.

        Blockierendes API-I/O -> ``run_in_executor`` (Loop bleibt frei). Keine
        Interfaces -> ``[]`` (vertraglicher Leer-Zustand, kein Fehler).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._discover_sync)

    def _discover_sync(self) -> list[NetworkInterface]:
        """Synchroner Discovery-Kern (laeuft im Executor-Thread).

        Auf Nicht-Windows ist der ctypes-Kern nicht vorhanden -> ``[]`` (vertraglicher
        Leer-Zustand). Auf Windows: API rufen, dann Filter (Loopback raus; ohne IPv4
        UND ohne IPv6-Link-Local raus), Reihenfolge der API bewahrt.
        """
        if sys.platform != "win32":
            return []
        return _filter_and_map(_collect_raw_interfaces())
