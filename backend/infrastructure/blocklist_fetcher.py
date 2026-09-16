"""Echter Blocklist-Fetcher: laedt den Listentext einer Quelle per ``urllib`` (stdlib).

Erfuellt das ``application.blocklist.BlocklistFetcher``-Protocol STRUKTURELL (eine
``fetch(url) -> str``-Methode) -- OHNE ``application`` zu importieren (import-linter:
``infrastructure kennt nicht application/api``). Die NAHT ist das Protocol IN
``application``; diese Impl erfuellt es strukturell, der Composition Root verdrahtet sie.

FEHLERSEMANTIK (bewusst, nach import-linter): ein Misserfolg (HTTP-/URL-Fehler, Timeout,
zu grosser oder leerer Body) wird als eigene Infrastruktur-Exception ``FetchFailed``
geworfen. Der ``RefreshSource``-Use-Case faengt im Refresh-Pfad BREIT (``Exception``) --
er muss ``FetchFailed`` NICHT importieren, und diese Infrastruktur kennt
``BlocklistFetchError`` (application) nicht. So bleibt die Trennung sauber in beide
Richtungen.

SCHUTZ: Timeout (Default 30 s), eigener User-Agent, Maximalgroesse (Default 50 MB ->
sonst ``FetchFailed``), ``utf-8``-Dekodierung mit ``errors="replace"`` (kaputte Bytes
zerlegen den Lauf nicht still -- der Parser ignoriert Unsinn ohnehin). KEIN stiller
Fallback (S3): ein Fehlschlag ist ein Fehler.

SSRF-SCHUTZ (F-02): zwei rein additive Schutzschichten VOR dem Netzzugriff, ohne die
Fehlersemantik oder die Naht nach aussen zu aendern:
  1. Schema-Whitelist: nur ``http``/``https``. Jedes andere Schema (``file``, ``ftp``,
     ``gopher``, ``data`` ...) -> ``FetchFailed``.
  2. Ziel-Guard (rebinding-fest): den Host GENAU EINMAL aufloesen
     (``socket.getaddrinfo``), ALLE aufgeloesten IPs gegen eine Sperrliste pruefen
     (privat/loopback/link-local/reserved/multicast/unspecified) und dann gegen GENAU
     die geprueften Adressen verbinden -- der Host wird NICHT erneut aufgeloest (sonst
     DNS-Rebinding zwischen Pruefung und Verbindung moeglich). Der Host-Header bleibt der
     urspruengliche Hostname (vHost); bei ``https`` bleibt SNI/Zertifikatspruefung gegen
     den Hostnamen (Default-``ssl``-Kontext, ``check_hostname=True``) -- die
     TLS-Verify-Semantik wird NICHT geschwaecht.
"""

import http.client
import ipaddress
import socket
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

__all__ = ["FetchFailed", "UrllibBlocklistFetcher"]

_USER_AGENT = "CERNIS-PRO/2.0"
_DEFAULT_TIMEOUT_S = 30.0
_DEFAULT_MAX_BYTES = 50 * 1024 * 1024  # 50 MB Deckel gegen unbeabsichtigt riesige Listen.

_ALLOWED_SCHEMES = frozenset({"http", "https"})


class FetchFailed(Exception):
    """Der Download einer Blocklist-Quelle ist fehlgeschlagen (Infrastruktur-Fehler).

    Eigene Infrastruktur-Exception (KEIN Import aus ``application``): HTTP-/URL-Fehler,
    Timeout, zu grosser oder leerer Body, abgelehntes Schema oder gesperrtes Ziel (SSRF).
    Der ``RefreshSource``-Use-Case faengt sie breit (``Exception``) und uebersetzt sie in
    seinen BROKEN-Status -- die Schicht-Trennung bleibt beidseitig erhalten.
    """


def _ensure_allowed_scheme(url: str) -> None:
    """Wirft ``FetchFailed``, wenn ``url`` kein ``http``/``https``-Schema traegt.

    Reiner Pruef-Helfer (stdlib-only): ``urlsplit`` -> Schema case-insensitiv gegen die
    Whitelist. Alles andere (``file``, ``ftp``, ``gopher``, ``data`` ...) ist ein
    Fehlschlag VOR jedem Netzzugriff -- kein stiller Fallback.
    """
    scheme = urlsplit(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise FetchFailed(f"Schema nicht erlaubt ({scheme or '<leer>'}): {url}")


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True, wenn ``ip`` in eine SSRF-Sperrkategorie faellt -- sonst False.

    Gesperrt: privat, loopback, link-local, reserved, multicast, unspecified. Das deckt
    die klassischen internen Ziele (10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, ``::1`` ...)
    ab, gegen die ein SSRF-Angreifer eine oeffentliche URL richten koennte.
    """
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _resolve_and_guard(host: str, port: int) -> list[tuple[object, ...]]:
    """Loest ``host`` EINMAL auf und liefert die ``getaddrinfo``-Ergebnisse -- oder wirft.

    Rebinding-Festigkeit: der Host wird hier GENAU EINMAL aufgeloest; die Verbindung nutzt
    danach ausschliesslich die hier geprueften ``sockaddr``. Faellt EINE der aufgeloesten
    IPs in eine Sperrkategorie (siehe ``_ip_is_blocked``), ist das Ziel gesperrt ->
    ``FetchFailed``. Sonst die vollstaendige Adressliste zurueckgeben (die IP steckt in
    ``sockaddr[0]``).
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise FetchFailed(f"Aufloesung fehlgeschlagen ({host}): {exc}") from exc

    if not infos:
        raise FetchFailed(f"Keine Adresse fuer Host: {host}")

    for info in infos:
        sockaddr = info[4]
        raw_ip = sockaddr[0]
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError as exc:
            raise FetchFailed(f"Ungueltige aufgeloeste IP ({raw_ip}): {host}") from exc
        if _ip_is_blocked(ip):
            raise FetchFailed(f"Ziel-IP gesperrt (SSRF-Schutz): {host} -> {raw_ip}")

    return list(infos)


def _pinned_create_connection(
    infos: list[tuple[object, ...]],
    timeout: float | None,
) -> socket.socket:
    """Baut einen TCP-Socket GENAU gegen die vorab geprueften Adressen (``infos``).

    Rebinding-fest: es wird KEIN neuer ``getaddrinfo`` ausgefuehrt; die Verbindung geht
    ausschliesslich gegen die in ``_resolve_and_guard`` geprueften ``sockaddr``. Analog zu
    ``socket.create_connection``: erste taugliche Adresse gewinnt, sonst der letzte Fehler.
    """
    last_error: Exception | None = None
    for family, socktype, proto, _canonname, sockaddr in infos:
        sock: socket.socket | None = None
        try:
            sock = socket.socket(int(family), int(socktype), int(proto))  # type: ignore[call-overload]
            sock.settimeout(timeout)
            sock.connect(sockaddr)  # type: ignore[arg-type]
            return sock
        except OSError as exc:
            last_error = exc
            if sock is not None:
                sock.close()
    if last_error is not None:
        raise last_error
    raise OSError("keine Adresse zum Verbinden")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """``HTTPConnection``, die gegen vorab gepruefte IPs verbindet (rebinding-fest).

    ``self.host`` bleibt der urspruengliche Hostname -> der ``Host``-Header (vHost) bleibt
    korrekt. ``connect`` nutzt ausschliesslich die uebergebenen, bereits geprueften
    ``getaddrinfo``-Ergebnisse und loest den Host NICHT erneut auf.
    """

    def __init__(
        self,
        host: str,
        infos: list[tuple[object, ...]],
        timeout: float | None,
    ) -> None:
        super().__init__(host, timeout=timeout)
        self._pinned_infos = infos

    def connect(self) -> None:
        self.sock = _pinned_create_connection(self._pinned_infos, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """``HTTPSConnection``, die gegen vorab gepruefte IPs verbindet (rebinding-fest).

    Wie ``_PinnedHTTPConnection``, zusaetzlich TLS: der Socket wird mit
    ``server_hostname=self.host`` (urspruenglicher Hostname) gewrappt -> SNI und
    Zertifikatspruefung laufen gegen den Hostnamen. Der ``context`` ist der
    Default-``ssl``-Kontext (``check_hostname=True``) -- die TLS-Verifikation wird NICHT
    geschwaecht.
    """

    def __init__(
        self,
        host: str,
        infos: list[tuple[object, ...]],
        timeout: float | None,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host, timeout=timeout, context=context)
        self._pinned_infos = infos
        self._pinned_context = context

    def connect(self) -> None:
        sock = _pinned_create_connection(self._pinned_infos, self.timeout)
        self.sock = self._pinned_context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    """``urllib``-Handler, der die rebinding-feste ``HTTP``-Verbindung injiziert.

    Traegt die vorab geprueften Adressen (``infos``) und leitet ``do_open`` auf eine
    ``_PinnedHTTPConnection`` um -- der Host wird NICHT erneut aufgeloest.
    """

    def __init__(self, infos: list[tuple[object, ...]]) -> None:
        super().__init__()
        self._infos = infos

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        def _conn(host: str, timeout: float | None = None) -> _PinnedHTTPConnection:
            return _PinnedHTTPConnection(host, self._infos, timeout)

        return self.do_open(_conn, req)  # type: ignore[arg-type]


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """``urllib``-Handler, der die rebinding-feste ``HTTPS``-Verbindung injiziert.

    Wie ``_PinnedHTTPHandler``, plus Default-``ssl``-Kontext (``check_hostname=True``): die
    TLS-Verifikation bleibt scharf (gegen den Hostnamen), das Ziel bleibt an die geprueften
    IPs gebunden.
    """

    def __init__(self, infos: list[tuple[object, ...]], context: ssl.SSLContext) -> None:
        super().__init__()
        self._infos = infos
        self._pinned_context = context

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        def _conn(host: str, timeout: float | None = None) -> _PinnedHTTPSConnection:
            return _PinnedHTTPSConnection(host, self._infos, timeout, self._pinned_context)

        return self.do_open(_conn, req)  # type: ignore[arg-type]


class UrllibBlocklistFetcher:
    """Erfuellt ``BlocklistFetcher`` strukturell: laedt den Listentext via ``urllib``.

    ``timeout_s``/``max_bytes`` sind injizierbar (Test/Tuning); die Defaults sind robust.
    """

    def __init__(
        self,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
        max_bytes: int = _DEFAULT_MAX_BYTES,
    ) -> None:
        self._timeout_s = timeout_s
        self._max_bytes = max_bytes

    def fetch(self, url: str) -> str:
        """Laedt ``url`` und liefert den dekodierten Listentext; wirft ``FetchFailed``.

        Prueft ZUERST das Schema (nur ``http``/``https``) und loest dann den Host GENAU
        EINMAL auf; alle aufgeloesten IPs muessen oeffentlich sein (SSRF-Guard). Verbindet
        rebinding-fest gegen die geprueften Adressen. Setzt einen eigenen User-Agent,
        erzwingt das Timeout, liest hoechstens ``max_bytes + 1`` Bytes (ein Byte mehr ->
        Ueberschreitung erkannt) und dekodiert ``utf-8`` mit ``errors="replace"``. Ein
        leerer Body gilt als Fehlschlag (eine leere Liste ist kein gueltiger Stand). Jeder
        URL-/HTTP-/Timeout-Fehler wird in ``FetchFailed`` uebersetzt (kein stiller
        Fallback).
        """
        _ensure_allowed_scheme(url)

        parts = urlsplit(url)
        host = parts.hostname
        if not host:
            raise FetchFailed(f"Kein Host in URL: {url}")
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)

        infos = _resolve_and_guard(host, port)
        opener = self._build_opener(parts.scheme, infos)

        request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            with opener.open(request, timeout=self._timeout_s) as response:
                raw: bytes = response.read(self._max_bytes + 1)
        except urllib.error.URLError as exc:
            # Deckt HTTPError (HTTP-Statusfehler) UND URLError (DNS/Verbindung/Timeout) ab.
            raise FetchFailed(f"Download fehlgeschlagen ({url}): {exc}") from exc
        except (TimeoutError, OSError, ValueError) as exc:
            # Socket-Timeout/IO/ungueltige URL -- ebenfalls ein ehrlicher Fehlschlag.
            raise FetchFailed(f"Download fehlgeschlagen ({url}): {exc}") from exc

        if len(raw) > self._max_bytes:
            raise FetchFailed(f"Liste zu gross (> {self._max_bytes} Bytes): {url}")
        if not raw:
            raise FetchFailed(f"Leere Antwort: {url}")
        return raw.decode("utf-8", errors="replace")

    def _build_opener(
        self,
        scheme: str,
        infos: list[tuple[object, ...]],
    ) -> urllib.request.OpenerDirector:
        """Baut einen ``urllib``-Opener, der rebinding-fest gegen ``infos`` verbindet.

        Der Handler injiziert eine ``HTTP(S)Connection``, die ausschliesslich die vorab
        geprueften Adressen nutzt. Bei ``https`` wird der Default-``ssl``-Kontext
        (``check_hostname=True``) verwendet -- die TLS-Verifikation bleibt scharf.
        """
        handler: urllib.request.BaseHandler
        if scheme == "https":
            handler = _PinnedHTTPSHandler(infos, ssl.create_default_context())
        else:
            handler = _PinnedHTTPHandler(infos)
        return urllib.request.build_opener(handler)
