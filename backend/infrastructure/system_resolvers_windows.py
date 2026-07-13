"""Windows-Zweig der System-DNS-Server-Ermittlung (nativer API-Pfad, kein Text-Parsing).

Zweck (ADR 0043, Etappe 2, Windows): die tatsaechlich konfigurierten DNS-Server des
Systems einsammeln -- exakt der Zweck, den ``resolvectl``/``/etc/resolv.conf`` auf Linux
erfuellen. Auf Windows existiert beides nicht, daher lieferte ``detect_system_resolvers``
dort bisher IMMER eine leere Liste und das DNS-Vertrauensmodell war funktionslos.

DATENQUELLE (bewusst KEIN ipconfig/netsh-Parsing): lokalisierte Windows-Ausgaben
(deutsch/franzoesisch/spanisch) lassen Textparser still scheitern -- das ist verboten.
Stattdessen die Windows-API ``GetAdaptersAddresses`` aus ``iphlpapi.dll`` per ``ctypes``,
Feld ``FirstDnsServerAddress`` je Adapter. Die Struktur-/Aufrufmuster sind wortgetreu aus
``infrastructure/interfaces_windows.py`` uebernommen und um die DNS-Server-Adressliste
(``IP_ADAPTER_DNS_SERVER_ADDRESS_XP``) erweitert. WICHTIG: das Flag
``GAA_FLAG_SKIP_DNS_SERVER`` (das der Interface-Adapter setzt, weil er DNS NICHT braucht)
darf hier NICHT gesetzt sein -- sonst fuellt Windows ``FirstDnsServerAddress`` nicht und die
Liste bliebe grundsaetzlich leer.

PLATTFORM-WEICHE (hat bereits zweimal die Linux-CI gebrochen): ``mypy --strict`` wertet
``sys.platform`` statisch aus. Auf dem Linux-Runner existiert JEDER Name, der innerhalb
eines ``if sys.platform == "win32":``-Blocks definiert wurde, NICHT -- deshalb steht nicht
nur der ctypes-Import, sondern AUCH jeder Aufruf und jede Referenz auf einen solchen Namen
selbst im positiven Guard. Auf Nicht-Windows ist das Modul importierbar und
``detect_windows_resolvers`` liefert ``[]`` (vertraglicher Leer-Zustand, kein Fehler).

Die reine Filter-/Dedup-Logik (Loopback verwerfen, kanonisieren, stabil deduplizieren)
liegt AUSSERHALB des Guards und ist ohne ctypes mit einfachen Python-Eingaben testbar.
"""

import ipaddress
import sys

# ── Plattformunabhaengige reine Hilfsfunktionen (ohne ctypes testbar) ──────────


def _canonical_ip(raw: str) -> str | None:
    """Kanonisiert eine IP-Adresse via ``ipaddress`` -> kanonischer Str oder ``None``.

    Zieht eine etwaige Zone/Interface-Angabe (``%eth0``) und Klammern ab. Kein gueltiges
    IP-Literal -> ``None``. Loopback (``127.0.0.0/8`` / ``::1``) -> ``None``: als echter
    Upstream-Resolver wertlos (verweist nur auf den lokalen Stub). Deckungsgleich mit dem
    ``_canonical_ip`` des Linux-Zweigs, damit beide Wege dieselbe Kanonisierung leisten.
    """
    candidate = raw.strip().strip("[]")
    if not candidate:
        return None
    candidate = candidate.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if addr.is_loopback:
        return None
    return str(addr)


def _dedupe_stable(ips: list[str]) -> list[str]:
    """Dedupliziert unter Erhalt der ersten Reihenfolge (stabil)."""
    seen: set[str] = set()
    result: list[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def canonicalize_resolvers(raw_ips: list[str]) -> list[str]:
    """Kanonisiert eine Roh-IP-Liste, verwirft Loopback/Unsinn, dedupliziert stabil.

    Reiner Kern (ohne ctypes/API): der Windows-Durchlauf sammelt rohe Adress-Strings aus
    ``FirstDnsServerAddress`` (IPv4 UND IPv6) und reicht sie hier durch. Ergebnis ist eine
    kanonische, loopback-freie, stabil deduplizierte Liste -- exakt das Vertragsformat des
    Linux-Zweigs. Leere Eingabe -> ``[]`` (gueltiges Ergebnis).
    """
    collected: list[str] = []
    for raw in raw_ips:
        canonical = _canonical_ip(raw)
        if canonical is not None:
            collected.append(canonical)
    return _dedupe_stable(collected)


# ── Windows-spezifischer ctypes-Kern (nur unter win32; ausserhalb: Leer-Zustand) ──

if sys.platform == "win32":
    import ctypes
    import socket
    from ctypes import wintypes

    # Konstanten der GetAdaptersAddresses-API (iphlpapi). Wortgetreu aus
    # interfaces_windows.py uebernommen -- OHNE _GAA_FLAG_SKIP_DNS_SERVER, denn genau
    # die DNS-Server-Adressen sollen hier befuellt werden.
    _AF_UNSPEC = 0
    _AF_INET = 2
    _AF_INET6 = 23
    _GAA_FLAG_SKIP_ANYCAST = 0x0002
    _GAA_FLAG_SKIP_MULTICAST = 0x0004
    _GAA_FLAG_SKIP_UNICAST = 0x0001
    _NO_ERROR = 0
    _ERROR_BUFFER_OVERFLOW = 111

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

    class _IP_ADAPTER_DNS_SERVER_ADDRESS_XP(ctypes.Structure):
        """``IP_ADAPTER_DNS_SERVER_ADDRESS_XP``: verkettete DNS-Server-Adressliste.

        Layout deckungsgleich zu ``IP_ADAPTER_GATEWAY_ADDRESS_LH`` des Interface-Adapters
        (Length, Reserved/Flags-DWORD, Next-Zeiger, ``Address`` als ``SOCKET_ADDRESS``) --
        das zweite DWORD heisst hier ``Reserved`` statt ``Flags``, Groesse/Offset identisch.
        """

    _IP_ADAPTER_DNS_SERVER_ADDRESS_XP._fields_ = [
        ("Length", ctypes.c_ulong),
        ("Reserved", wintypes.DWORD),
        ("Next", ctypes.POINTER(_IP_ADAPTER_DNS_SERVER_ADDRESS_XP)),
        ("Address", _SOCKET_ADDRESS),
    ]

    class _IP_ADAPTER_ADDRESSES_LH(ctypes.Structure):
        """``IP_ADAPTER_ADDRESSES_LH``: ein Adapter-Eintrag der verketteten Liste.

        Nur die hier gelesenen Felder sind ausmodelliert; ``Next`` verkettet die Adapter,
        ``FirstDnsServerAddress`` traegt die DNS-Server-Liste. Reihenfolge/Groesse der
        Felder folgen exakt dem Win32-Header (LH-Variante), damit die Offsets stimmen --
        insbesondere darf FirstDnsServerAddress KEIN ``c_void_p`` sein, sondern der echte
        typisierte Zeiger, sonst laesst sich die Liste nicht durchlaufen.
        """

    _IP_ADAPTER_ADDRESSES_LH._fields_ = [
        ("Length", ctypes.c_ulong),
        ("IfIndex", wintypes.DWORD),
        ("Next", ctypes.POINTER(_IP_ADAPTER_ADDRESSES_LH)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.c_void_p),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.POINTER(_IP_ADAPTER_DNS_SERVER_ADDRESS_XP)),
        ("DnsSuffix", ctypes.c_wchar_p),
        ("Description", ctypes.c_wchar_p),
        ("FriendlyName", ctypes.c_wchar_p),
        ("PhysicalAddress", ctypes.c_ubyte * 8),
        ("PhysicalAddressLength", wintypes.DWORD),
        ("Flags", wintypes.DWORD),
        ("Mtu", wintypes.DWORD),
        ("IfType", wintypes.DWORD),
        ("OperStatus", ctypes.c_int),
    ]

    def _sockaddr_to_ip(sockaddr_ptr: "ctypes._Pointer[_SOCKADDR]") -> str | None:
        """Liest eine IPv4- ODER IPv6-Adresse aus einem ``sockaddr``-Zeiger.

        Family bestimmt den Cast (``sockaddr_in``/``sockaddr_in6``) und die
        ``inet_ntop``-Familie. Unbekannte Family -> ``None`` (still verworfen).
        """
        family = sockaddr_ptr.contents.sa_family
        if family == _AF_INET:
            in4 = ctypes.cast(sockaddr_ptr, ctypes.POINTER(_SOCKADDR_IN)).contents
            return socket.inet_ntop(socket.AF_INET, bytes(in4.sin_addr))
        if family == _AF_INET6:
            in6 = ctypes.cast(sockaddr_ptr, ctypes.POINTER(_SOCKADDR_IN6)).contents
            return socket.inet_ntop(socket.AF_INET6, bytes(in6.sin6_addr))
        return None

    def _call_get_adapters_addresses() -> "ctypes.Array[ctypes.c_char] | None":
        """Zwei-Pass-Aufruf von ``GetAdaptersAddresses`` -> Puffer oder ``None``.

        Erster Aufruf mit NULL-Puffer liefert ``ERROR_BUFFER_OVERFLOW`` (111) und die
        benoetigte Groesse; dann Puffer allozieren und zweiter Aufruf. Rueckgabewert
        ungleich ``NO_ERROR`` (0) -> ``None`` (best effort, kein Hochlaufen -- der
        Aufrufer macht daraus ``[]``).
        """
        get_adapters = ctypes.windll.iphlpapi.GetAdaptersAddresses
        # Unicast/Anycast/Multicast werden uebersprungen -- gebraucht werden nur die
        # DNS-Server. GAA_FLAG_SKIP_DNS_SERVER ist bewusst NICHT gesetzt (sonst bliebe
        # FirstDnsServerAddress leer).
        flags = _GAA_FLAG_SKIP_UNICAST | _GAA_FLAG_SKIP_ANYCAST | _GAA_FLAG_SKIP_MULTICAST
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

    def _collect_raw_dns_addresses() -> list[str]:
        """Durchlaeuft alle Adapter und sammelt ihre rohen DNS-Server-Adress-Strings.

        Reihenfolge der API bewahrt (Adapter fuer Adapter, je Adapter die DNS-Liste in
        Reihenfolge). IPv4 UND IPv6. Kanonisierung/Loopback-Filter/Dedup leistet der
        reine ``canonicalize_resolvers``-Kern auf dem Ergebnis.
        """
        buffer = _call_get_adapters_addresses()
        if buffer is None:
            return []
        raw_ips: list[str] = []
        adapter_ptr = ctypes.cast(buffer, ctypes.POINTER(_IP_ADAPTER_ADDRESSES_LH))
        while adapter_ptr:
            adapter = adapter_ptr.contents
            dns_ptr = adapter.FirstDnsServerAddress
            while dns_ptr:
                dns = dns_ptr.contents
                sockaddr_ptr = dns.Address.lpSockaddr
                if sockaddr_ptr:
                    ip = _sockaddr_to_ip(sockaddr_ptr)
                    if ip is not None:
                        raw_ips.append(ip)
                dns_ptr = dns.Next
            adapter_ptr = adapter.Next
        return raw_ips


def detect_windows_resolvers() -> list[str]:
    """Ermittelt die konfigurierten Windows-DNS-Server best-effort -> kanonische IP-Liste.

    Auf Nicht-Windows ist der ctypes-Kern nicht vorhanden -> ``[]`` (vertraglicher
    Leer-Zustand). Auf Windows: ``GetAdaptersAddresses`` rufen, die rohen DNS-Adressen
    einsammeln und ueber ``canonicalize_resolvers`` kanonisieren (Loopback raus, IPv4+IPv6,
    ohne Duplikate, stabile Reihenfolge). Eine LEERE Liste ist ein gueltiges Ergebnis.
    """
    # Der AUFRUF von _collect_raw_dns_addresses muss selbst im positiven
    # sys.platform-Guard stehen, nicht nur dessen Definition: mypy wertet sys.platform
    # statisch aus und behandelt den win32-Block auf Linux als unerreichbar -- dort
    # existiert der Name _collect_raw_dns_addresses NICHT. Ein negatives
    # "if != win32: return []" schuetzt den Namen nicht.
    if sys.platform == "win32":
        return canonicalize_resolvers(_collect_raw_dns_addresses())
    return []
