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
"""

import urllib.error
import urllib.request

__all__ = ["FetchFailed", "UrllibBlocklistFetcher"]

_USER_AGENT = "CERNIS-PRO/2.0"
_DEFAULT_TIMEOUT_S = 30.0
_DEFAULT_MAX_BYTES = 50 * 1024 * 1024  # 50 MB Deckel gegen unbeabsichtigt riesige Listen.


class FetchFailed(Exception):
    """Der Download einer Blocklist-Quelle ist fehlgeschlagen (Infrastruktur-Fehler).

    Eigene Infrastruktur-Exception (KEIN Import aus ``application``): HTTP-/URL-Fehler,
    Timeout, zu grosser oder leerer Body. Der ``RefreshSource``-Use-Case faengt sie breit
    (``Exception``) und uebersetzt sie in seinen BROKEN-Status -- die Schicht-Trennung
    bleibt beidseitig erhalten.
    """


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

        Setzt einen eigenen User-Agent, erzwingt das Timeout, liest hoechstens
        ``max_bytes + 1`` Bytes (ein Byte mehr -> Ueberschreitung erkannt) und dekodiert
        ``utf-8`` mit ``errors="replace"``. Ein leerer Body gilt als Fehlschlag (eine
        leere Liste ist kein gueltiger Stand). Jeder URL-/HTTP-/Timeout-Fehler wird in
        ``FetchFailed`` uebersetzt (kein stiller Fallback).
        """
        request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_s) as response:
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
