"""Characterization-Contract des Default-Credentials-Checker-Altcode
(``modules/default_creds.py``).

Friert den Ist-Zustand VOR der SEC.4-Heilung ein. Das Modul macht AKTIVE Login-Versuche
(HTTP-Basic + FTP). Dieser Charakterisierer macht NIEMALS einen echten Netz-Login:

  * HTTP: ``urllib.request.build_opener`` (default_creds.py:89) wird gemockt -> ein
    Fake-Opener, dessen ``.open()`` einen kontrollierten Code liefert ODER eine Exception
    wirft. Es wird NIE ein echter Opener gebaut, NIE eine echte Verbindung geoeffnet.
  * FTP: ``ftplib.FTP`` (default_creds.py:129) wird durch eine Fake-Klasse ersetzt ->
    ``connect``/``login``/``quit`` sind No-ops bzw. werfen kontrolliert. Es wird NIE eine
    echte FTP-Verbindung aufgebaut, NIE ein echter Login gegen einen echten Host gemacht.

Damit ist die Auflage erfuellt: kein echter Netz-I/O, keine echten Default-Creds gegen
echte Hosts. Alle Hostnamen in den Tests sind reine Platzhalter, die nie kontaktiert
werden (der gemockte I/O ignoriert sie).

────────────────────────────────────────────────────────────────────────────
EINGEFRORENE AS-IS-VERHALTEN
────────────────────────────────────────────────────────────────────────────

ERFOLGSFALL (Treffer-Vertrag):
  * ``check_http_basic``: Code in (200,201,204,302) -> CredResult(success=True,
    method="http_basic", note=f"HTTP {code}"); ``break`` beim ersten Treffer (max 8
    Versuche, creds[:8]).
  * ``check_ftp``: erfolgreicher login -> CredResult(method="ftp"); ``break`` beim
    ersten Treffer (DEFAULT_CREDS["ftp"][:4]).
  * ``get_creds_for_vendor``: Vendor-Substring matcht DEVICE_CREDS -> dessen Liste,
    sonst DEFAULT_CREDS["web"][:6].
  * ``check_host``-Routing: Port 80/8080/8081/8000/3000/9000 oder "http"->http_basic
    (https=False); 443/8443/4443 oder "https"->https=True; 21 oder "ftp"->check_ftp.

S3-FALLBACKS (AS-IS eingefroren -- SEC.4 heilt):
  * E.4a (default_creds.py:102-103): ``except urllib.error.HTTPError -> return e.code``.
    Das ist TRAGENDE LOGIK, KEIN S3 (401/403 = Credentials falsch, korrekt als
    "kein Treffer" gewertet). Als Vertrag eingefroren.
  * E.4b (default_creds.py:104-105): ``except Exception -> return 0``. Verschluckt JEDEN
    Netzfehler (Timeout/Connection-Refused/DNS) als "Code 0" = "kein Treffer". Nicht
    unterscheidbar von "Host erreichbar, Cred falsch". >> AS-IS, S3-Fallback.
  * E.4c (default_creds.py:134-135): ``except Exception -> return False`` in check_ftp.
    Jeder FTP-Fehler (auch Verbindungsfehler) wird zu "kein Cred". >> AS-IS, S3-Fallback.
"""

import asyncio
from typing import Any

import pytest


@pytest.fixture
def dc() -> Any:
    from modules import default_creds as dc_mod

    return dc_mod


# ── HTTP-Mock: Fake-Opener statt build_opener ─────────────────


class _FakeResponse:
    def __init__(self, code: int) -> None:
        self.code = code


class _FakeOpener:
    """Ersatz fuer den build_opener-Rueckgabewert. .open() ist programmierbar."""

    def __init__(self, behavior: Any) -> None:
        # behavior: callable(req, timeout) -> Response | raises
        self._behavior = behavior

    def open(self, req: Any, timeout: float = 3.0) -> Any:
        return self._behavior(req, timeout)


def _patch_http(monkeypatch: pytest.MonkeyPatch, dc: Any, behavior: Any) -> None:
    """Mockt build_opener -> kein echter Opener, kein echter HTTP-Call."""
    import urllib.request

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: _FakeOpener(behavior))


# ── FTP-Mock: Fake-FTP-Klasse statt ftplib.FTP ────────────────


def _patch_ftp(monkeypatch: pytest.MonkeyPatch, login_ok: bool) -> None:
    """Ersetzt ftplib.FTP -> kein echter FTP-Connect/Login."""
    import ftplib

    class _FakeFTP:
        def connect(self, host: str, port: int, timeout: float = 3.0) -> None:
            return None

        def login(self, user: str = "", passwd: str = "") -> None:
            if not login_ok:
                raise ftplib.error_perm("530 Login incorrect")

        def quit(self) -> None:
            return None

    monkeypatch.setattr(ftplib, "FTP", _FakeFTP)


# ── check_http_basic: Treffer + E.4-Faenge ────────────────────


def test_http_basic_success_on_200(dc: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_http(monkeypatch, dc, lambda req, timeout: _FakeResponse(200))
    results = asyncio.run(dc.check_http_basic("placeholder", 80, [("admin", "admin")]))
    assert len(results) == 1
    r = results[0]
    assert r.success is True
    assert r.method == "http_basic"
    assert r.username == "admin"
    assert r.note == "HTTP 200"


def test_http_basic_breaks_on_first_hit(dc: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # Jeder Versuch wuerde 200 geben -> nur DER ERSTE zaehlt (break).
    _patch_http(monkeypatch, dc, lambda req, timeout: _FakeResponse(200))
    creds = [("admin", "admin"), ("root", "root"), ("user", "user")]
    results = asyncio.run(dc.check_http_basic("placeholder", 80, creds))
    assert len(results) == 1
    assert results[0].username == "admin"  # erster Treffer, dann break


def test_http_basic_401_is_no_hit_E4a(dc: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # E.4a AS-IS (TRAGENDE LOGIK, kein S3): HTTPError 401 -> return e.code=401 ->
    # nicht in (200,201,204,302) -> kein Treffer. Korrekt: Cred ist falsch.
    import urllib.error

    def _http_401(req: Any, timeout: float) -> Any:
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)  # type: ignore[arg-type]

    _patch_http(monkeypatch, dc, _http_401)
    results = asyncio.run(dc.check_http_basic("placeholder", 80, [("admin", "admin")]))
    assert results == []  # 401 = kein Treffer


def test_http_basic_302_counts_as_hit(dc: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # 302 ist im Treffer-Set (Vertrag): viele Geraete redirecten nach Login.
    _patch_http(monkeypatch, dc, lambda req, timeout: _FakeResponse(302))
    results = asyncio.run(dc.check_http_basic("placeholder", 80, [("admin", "")]))
    assert len(results) == 1
    assert results[0].note == "HTTP 302"


def test_http_basic_network_error_swallowed_as_no_hit_E4b(
    dc: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # E.4b AS-IS: beliebiger Netzfehler -> except Exception -> return 0 -> kein Treffer.
    # 0 ist nicht unterscheidbar von "Host erreichbar, Cred falsch". >> SEC.4 heilt.
    def _boom(req: Any, timeout: float) -> Any:
        raise TimeoutError("connect timed out")

    _patch_http(monkeypatch, dc, _boom)
    results = asyncio.run(dc.check_http_basic("placeholder", 80, [("admin", "admin")]))
    assert results == []  # Netzfehler still als "kein Cred" verschluckt


def test_E4b_network_error_and_wrong_cred_are_indistinguishable(
    dc: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # E.4b KERN-VERTRAG (Vorher-Referenz fuer SEC.4): der Netzfehler-Fall (Host nicht
    # erreichbar -> except Exception -> 0) und der echte "Host erreichbar, Cred falsch"-
    # Fall (HTTPError 401 -> e.code=401, nicht im Treffer-Set) liefern BEIDE ``[]`` --
    # im Ergebnis NICHT unterscheidbar. GENAU DAS heilt SEC.4 (Netzfehler -> expliziter
    # Fehler, falsche Cred -> weiterhin []). Ununterscheidbarkeit als ASSERT, nicht nur
    # Kommentar.
    import urllib.error

    # (1) Netzfehler: connect schlaegt fehl.
    def _boom(req: Any, timeout: float) -> Any:
        raise TimeoutError("connect timed out")

    _patch_http(monkeypatch, dc, _boom)
    result_on_error = asyncio.run(dc.check_http_basic("placeholder", 80, [("admin", "admin")]))

    # (2) Echte falsche Cred: Host erreichbar, antwortet 401.
    def _http_401(req: Any, timeout: float) -> Any:
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)  # type: ignore[arg-type]

    _patch_http(monkeypatch, dc, _http_401)
    result_on_wrong_cred = asyncio.run(dc.check_http_basic("placeholder", 80, [("admin", "admin")]))

    # Der Kern: beide Wege liefern dasselbe [] -- ununterscheidbar.
    assert result_on_error == []
    assert result_on_wrong_cred == []
    assert result_on_error == result_on_wrong_cred


# ── check_ftp: Treffer + E.4c-Fang ────────────────────────────


def test_ftp_success(dc: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_ftp(monkeypatch, login_ok=True)
    results = asyncio.run(dc.check_ftp("placeholder", 21))
    assert len(results) == 1
    r = results[0]
    assert r.success is True
    assert r.method == "ftp"
    # erster DEFAULT_CREDS["ftp"]-Eintrag ("anonymous", "").
    assert r.username == "anonymous"


def test_ftp_login_failure_swallowed_as_no_hit_E4c(
    dc: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # E.4c AS-IS: login wirft -> except Exception -> return False -> kein Treffer.
    # Auch ein Verbindungsfehler saehe identisch aus (still). >> SEC.4 heilt.
    _patch_ftp(monkeypatch, login_ok=False)
    results = asyncio.run(dc.check_ftp("placeholder", 21))
    assert results == []


# ── get_creds_for_vendor: Daten-Routing ───────────────────────


def test_get_creds_for_vendor_known(dc: Any) -> None:
    # Vendor-Substring "ubiquiti" -> DEVICE_CREDS["ubiquiti"].
    creds = dc.get_creds_for_vendor("Ubiquiti Networks Inc")
    assert ("ubnt", "ubnt") in creds


def test_get_creds_for_vendor_unknown_falls_back_to_web(dc: Any) -> None:
    # Unbekannter Vendor -> DEFAULT_CREDS["web"][:6].
    creds = dc.get_creds_for_vendor("NoSuchVendor")
    assert creds == dc.DEFAULT_CREDS["web"][:6]


# ── check_host: Port->Service-Routing ─────────────────────────


def test_check_host_routes_http_port_to_basic(dc: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # Port 80 -> check_http_basic (https=False). Treffer durchgereicht.
    calls: list[tuple[int, bool]] = []

    async def _fake_basic(
        host: str, port: int, creds: list[Any], https: bool = False, timeout: float = 3.0
    ) -> list[Any]:
        calls.append((port, https))
        return []

    monkeypatch.setattr(dc, "check_http_basic", _fake_basic)
    asyncio.run(dc.check_host("placeholder", [{"port": 80, "service": "http"}]))
    assert calls == [(80, False)]


def test_check_host_https_service_string_hits_http_branch_AS_IS(
    dc: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # AS-IS-QUIRK (subtil, eingefroren): check_host prueft ZUERST
    # ``if port in (80,...) or "http" in service`` (default_creds.py:168). Da
    # ``"http" in "https"`` als SUBSTRING True ist, faellt Port 443 mit service="https"
    # in den HTTP-Zweig -> https=False (Plain-HTTP gegen 443!). Der elif-https-Zweig
    # wird nur erreicht, wenn service KEIN "http"-Substring hat (siehe naechster Test).
    # >> Funktionaler AS-IS-Befund, kein Test-Fehler. SEC.4 kann es bereinigen.
    calls: list[tuple[int, bool]] = []

    async def _fake_basic(
        host: str, port: int, creds: list[Any], https: bool = False, timeout: float = 3.0
    ) -> list[Any]:
        calls.append((port, https))
        return []

    monkeypatch.setattr(dc, "check_http_basic", _fake_basic)
    asyncio.run(dc.check_host("placeholder", [{"port": 443, "service": "https"}]))
    assert calls == [(443, False)]  # AS-IS: "http" in "https" -> HTTP-Zweig, https=False


def test_check_host_port_443_without_http_service_uses_tls(
    dc: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Gegenprobe: NUR wenn service kein "http"-Substring enthaelt (hier leer), greift
    # der elif-Zweig ``port in (443,8443,4443)`` -> https=True. Beweist, dass der
    # https-Pfad existiert, aber vom Substring-Quirk oben verdeckt wird.
    calls: list[tuple[int, bool]] = []

    async def _fake_basic(
        host: str, port: int, creds: list[Any], https: bool = False, timeout: float = 3.0
    ) -> list[Any]:
        calls.append((port, https))
        return []

    monkeypatch.setattr(dc, "check_http_basic", _fake_basic)
    asyncio.run(dc.check_host("placeholder", [{"port": 443, "service": ""}]))
    assert calls == [(443, True)]  # leerer service -> elif-Zweig -> https=True


def test_check_host_routes_ftp_port(dc: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    async def _fake_ftp(host: str, port: int = 21, timeout: float = 3.0) -> list[Any]:
        calls.append(port)
        return []

    monkeypatch.setattr(dc, "check_ftp", _fake_ftp)
    asyncio.run(dc.check_host("placeholder", [{"port": 21, "service": "ftp"}]))
    assert calls == [21]


def test_check_host_uses_vendor_creds(dc: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # vendor gesetzt -> get_creds_for_vendor-Liste wird an check_http_basic gereicht.
    seen_creds: list[Any] = []

    async def _fake_basic(
        host: str, port: int, creds: list[Any], https: bool = False, timeout: float = 3.0
    ) -> list[Any]:
        seen_creds.extend(creds)
        return []

    monkeypatch.setattr(dc, "check_http_basic", _fake_basic)
    asyncio.run(dc.check_host("placeholder", [{"port": 80, "service": "http"}], vendor="ubiquiti"))
    assert ("ubnt", "ubnt") in seen_creds  # Vendor-spezifische Creds genutzt
