"""Tests des echten Fetchers (``infrastructure.blocklist_fetcher``) -- KEIN echtes Netz.

Gegen einen lokalen Mini-HTTP-Stub (``http.server`` in einem Thread, an 127.0.0.1 mit
Ephemeral-Port): Happy-Path liefert Text; HTTP-Fehler (404) und ein zu grosser Body
fuehren zu ``FetchFailed``; eine ungueltige URL ebenso. So bleibt der Test deterministisch
und beruehrt nie ein externes Netz.

SSRF-Guard (F-02): der Fetcher loest den Host auf und sperrt private/loopback/... Ziele.
Der lokale Stub laeuft naturgemaess auf ``127.0.0.1`` (loopback) -- deshalb neutralisieren
die Stub-basierten Tests die Blockliste GEZIELT ueber ``_ip_is_blocked`` (Symbol im
Adapter-Modul, Muster wie in den uebrigen Infrastruktur-Tests), sodass der reale, aber
LOKALE Netz-I/O-Pfad wie bisher durchlaeuft. Die Guard-Logik selbst wird separat getestet:
abgelehntes Schema und ein gesperrtes Ziel (gemockter ``getaddrinfo``) -> ``FetchFailed``,
ohne jeden echten Netzzugriff.
"""

import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from infrastructure import blocklist_fetcher
from infrastructure.blocklist_fetcher import FetchFailed, UrllibBlocklistFetcher

_BODY = b"a.example.com\nb.example.com\n"


class _StubHandler(BaseHTTPRequestHandler):
    """Liefert ``/ok`` mit Text, ``/big`` mit grossem Body, sonst 404."""

    def do_GET(self) -> None:  # BaseHTTPRequestHandler-API (Gross-/Kleinschreibung vorgegeben)
        if self.path == "/ok":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(_BODY)
        elif self.path == "/big":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"x" * 4096)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args: object) -> None:
        # Test-Stub still halten (kein stderr-Spam).
        pass


@pytest.fixture
def base_url() -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), _StubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join()


@pytest.fixture
def allow_loopback_target(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutralisiert den SSRF-Ziel-Guard fuer den LOKALEN Stub (127.0.0.1).

    Der Stub laeuft auf loopback; ohne diesen Patch wuerde der Guard ihn korrekt sperren.
    Gemockt wird ``_ip_is_blocked`` AM SYMBOL IM ADAPTER-MODUL (Muster wie in den uebrigen
    Infrastruktur-Tests) -> der Guard laesst das Ziel durch, der reale (aber lokale)
    Netz-I/O-Pfad bleibt unveraendert. Kein externer Netzzugriff.
    """
    monkeypatch.setattr(blocklist_fetcher, "_ip_is_blocked", lambda ip: False)


def test_fetch_happy_liefert_text(base_url: str, allow_loopback_target: None) -> None:
    fetcher = UrllibBlocklistFetcher()
    text = fetcher.fetch(f"{base_url}/ok")
    assert text == _BODY.decode("utf-8")


def test_fetch_http_fehler_wirft_fetchfailed(base_url: str, allow_loopback_target: None) -> None:
    fetcher = UrllibBlocklistFetcher()
    with pytest.raises(FetchFailed):
        fetcher.fetch(f"{base_url}/missing")


def test_fetch_zu_gross_wirft_fetchfailed(base_url: str, allow_loopback_target: None) -> None:
    # max_bytes klein setzen -> der 4096-Byte-Body sprengt den Deckel.
    fetcher = UrllibBlocklistFetcher(max_bytes=100)
    with pytest.raises(FetchFailed):
        fetcher.fetch(f"{base_url}/big")


def test_fetch_ungueltige_url_wirft_fetchfailed(allow_loopback_target: None) -> None:
    fetcher = UrllibBlocklistFetcher(timeout_s=1.0)
    with pytest.raises(FetchFailed):
        fetcher.fetch("http://127.0.0.1:1/nope")


# --- F-02: SSRF-Guard -------------------------------------------------------------


def test_fetch_verbotenes_schema_wirft_fetchfailed() -> None:
    # file:// wird VOR jedem Netzzugriff abgelehnt (Schema-Whitelist: nur http/https).
    fetcher = UrllibBlocklistFetcher()
    with pytest.raises(FetchFailed):
        fetcher.fetch("file:///etc/passwd")


@pytest.mark.parametrize(
    "blocked_ip",
    ["127.0.0.1", "10.0.0.1", "169.254.10.20", "::1"],
    ids=["loopback", "privat", "link-local", "ipv6-loopback"],
)
def test_fetch_gesperrtes_ziel_wirft_fetchfailed(
    monkeypatch: pytest.MonkeyPatch, blocked_ip: str
) -> None:
    """Loest ein oeffentlich aussehender Host auf eine interne IP auf -> ``FetchFailed``.

    ``getaddrinfo`` AM SYMBOL IM ADAPTER-MODUL gemockt (kein echtes Netz): der Host
    ``evil.example.com`` "loest" auf eine gesperrte IP auf. Der Guard muss VOR jeder
    Verbindung ablehnen -- daher genuegt der reine Aufloesungs-Mock, es faellt kein
    Netzzugriff an.
    """
    family = socket.AF_INET6 if ":" in blocked_ip else socket.AF_INET
    sockaddr: tuple[object, ...] = (
        (blocked_ip, 80, 0, 0) if family == socket.AF_INET6 else (blocked_ip, 80)
    )

    def _fake_getaddrinfo(
        host: object, port: object, *args: object, **kwargs: object
    ) -> list[tuple[object, ...]]:
        return [(family, socket.SOCK_STREAM, 0, "", sockaddr)]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    fetcher = UrllibBlocklistFetcher()
    with pytest.raises(FetchFailed):
        fetcher.fetch("http://evil.example.com/list.txt")


def test_fetch_oeffentliches_ziel_laeuft_durch(base_url: str, allow_loopback_target: None) -> None:
    """Ein als oeffentlich gewertetes Ziel laeuft normal durch (gemockter/lokaler I/O).

    ``allow_loopback_target`` neutralisiert den Ziel-Guard (der lokale Stub liegt auf
    loopback), sodass der Fetcher den realen, aber LOKALEN Netz-I/O-Pfad wie im Happy-Path
    durchlaeuft -- die additive Guard-Schicht aendert das Verhalten fuer erlaubte Ziele
    nicht. Kein externer Netzzugriff.
    """
    fetcher = UrllibBlocklistFetcher()
    text = fetcher.fetch(f"{base_url}/ok")
    assert text == _BODY.decode("utf-8")
