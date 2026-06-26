"""Tests des echten Fetchers (``infrastructure.blocklist_fetcher``) -- KEIN echtes Netz.

Gegen einen lokalen Mini-HTTP-Stub (``http.server`` in einem Thread, an 127.0.0.1 mit
Ephemeral-Port): Happy-Path liefert Text; HTTP-Fehler (404) und ein zu grosser Body
fuehren zu ``FetchFailed``; eine ungueltige URL ebenso. So bleibt der Test deterministisch
und beruehrt nie ein externes Netz.
"""

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

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


def test_fetch_happy_liefert_text(base_url: str) -> None:
    fetcher = UrllibBlocklistFetcher()
    text = fetcher.fetch(f"{base_url}/ok")
    assert text == _BODY.decode("utf-8")


def test_fetch_http_fehler_wirft_fetchfailed(base_url: str) -> None:
    fetcher = UrllibBlocklistFetcher()
    with pytest.raises(FetchFailed):
        fetcher.fetch(f"{base_url}/missing")


def test_fetch_zu_gross_wirft_fetchfailed(base_url: str) -> None:
    # max_bytes klein setzen -> der 4096-Byte-Body sprengt den Deckel.
    fetcher = UrllibBlocklistFetcher(max_bytes=100)
    with pytest.raises(FetchFailed):
        fetcher.fetch(f"{base_url}/big")


def test_fetch_ungueltige_url_wirft_fetchfailed() -> None:
    fetcher = UrllibBlocklistFetcher(timeout_s=1.0)
    with pytest.raises(FetchFailed):
        fetcher.fetch("http://127.0.0.1:1/nope")
