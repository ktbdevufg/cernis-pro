"""Tests fuer ``TlsInspectorAdapter`` (SEC.4) -- v2-Reimpl + Heilung E.5 + tls-crash.

AUFLAGE A2:
  * E.5 (unparsbares Cert-Datum): jetzt geloggt (``cert_date_parse_failed``) UND
    days_remaining=0/is_expired=False wie SEC.1b-Vorher.
  * tls-CRASH: SSLError OHNE .reason -> KEIN AttributeError/500 mehr, sondern sauberes
    TlsFinding(error="SSL Error: ...", grade="F"). Gegen den SEC.1b-Crash-Test gespiegelt.
    MUTATIONSPROBE (dokumentiert): getattr zurueck auf e.reason -> dieser Test rot.
  * Loop ueberlebt: ein Port wirft (error-Befund), einer ist gesund -> beide im Ergebnis.

I/O gemockt (socket.create_connection + ssl.create_default_context) -- kein Handshake.
"""

import datetime
import socket
import ssl
from typing import Any

import pytest
from structlog.testing import capture_logs

from infrastructure.security import tls as tls_mod
from infrastructure.security.tls import TlsInspectorAdapter
from ports.security import TlsFinding


class _FakeSSLSocket:
    def __init__(self, version: str, cipher: tuple[Any, ...], cert: dict[str, Any]) -> None:
        self._v, self._c, self._cert = version, cipher, cert

    def __enter__(self) -> "_FakeSSLSocket":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def version(self) -> str:
        return self._v

    def cipher(self) -> tuple[Any, ...]:
        return self._c

    def getpeercert(self, binary_form: bool = False) -> Any:
        return self._cert


class _FakeContext:
    def __init__(self, ssock: _FakeSSLSocket) -> None:
        self.check_hostname = True
        self.verify_mode = 0
        self._ssock = ssock

    def wrap_socket(self, sock: Any, server_hostname: str = "") -> _FakeSSLSocket:
        return self._ssock


class _FakePlainSocket:
    def __enter__(self) -> "_FakePlainSocket":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


def _patch(monkeypatch: pytest.MonkeyPatch, ssock: _FakeSSLSocket) -> None:
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=5.0: _FakePlainSocket())
    monkeypatch.setattr(ssl, "create_default_context", lambda: _FakeContext(ssock))


def _cert(bad_date: bool = False) -> dict[str, Any]:
    now = datetime.datetime.now(datetime.UTC)
    na = (
        "NOT A DATE"
        if bad_date
        else (now + datetime.timedelta(days=400)).strftime("%b %d %H:%M:%S %Y") + " GMT"
    )
    return {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Example Inc"),),),
        "subjectAltName": [("DNS", "example.com")],
        "notBefore": "Jan 01 00:00:00 2020 GMT",
        "notAfter": na,
    }


# ── Erfolgsfall (Grade) ───────────────────────────────────────


def test_strong_config_grades_a(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _FakeSSLSocket("TLSv1.3", ("AES256", "TLSv1.3", 256), _cert()))
    r = tls_mod._inspect_one("example.com", 443)
    assert r.grade == "A"
    assert r.reachable is True
    assert r.cert is not None and r.cert.subject == "example.com"


# ── E.5: kaputtes Cert-Datum -> still 0/False + Warn-Log ──────


def test_E5_bad_cert_date_keeps_zero_AND_logs(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _FakeSSLSocket("TLSv1.3", ("AES256", "TLSv1.3", 256), _cert(bad_date=True)))
    with capture_logs() as logs:
        r = tls_mod._inspect_one("baddate.example.com", 443)
    # Ergebnis wie SEC.1b-Vorher.
    assert r.cert is not None
    assert r.cert.days_remaining == 0
    assert r.cert.is_expired is False
    assert r.cert.not_after == "NOT A DATE"
    # HEILUNG: geloggt.
    assert any(e["event"] == "cert_date_parse_failed" for e in logs)


def test_E5_valid_cert_date_does_NOT_log(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _FakeSSLSocket("TLSv1.3", ("AES256", "TLSv1.3", 256), _cert()))
    with capture_logs() as logs:
        tls_mod._inspect_one("example.com", 443)
    assert not any(e["event"] == "cert_date_parse_failed" for e in logs)


# ── tls-CRASH: SSLError ohne reason -> sauberes Finding, kein 500 ──


def test_tls_crash_healed_ssl_error_without_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    # SEC.1b fror den Crash ein (SSLError ohne .reason -> AttributeError -> 500).
    # v2 heilt: getattr(e, "reason", None) or str(e) -> sauberes error-Finding, grade F.
    def _boom(addr: Any, timeout: float = 5.0) -> Any:
        raise ssl.SSLError("handshake failed")  # ohne .reason

    monkeypatch.setattr(socket, "create_connection", _boom)
    r = tls_mod._inspect_one("badssl.example.com", 443)  # KEIN AttributeError mehr
    assert r.reachable is False
    assert r.error.startswith("SSL Error")
    assert "handshake failed" in r.error  # str(e)-Fallback, da reason fehlt
    assert r.grade == "F"


def test_tls_ssl_error_with_reason_uses_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(addr: Any, timeout: float = 5.0) -> Any:
        e = ssl.SSLError("x")
        e.reason = "CERTIFICATE_VERIFY_FAILED"
        raise e

    monkeypatch.setattr(socket, "create_connection", _boom)
    r = tls_mod._inspect_one("badssl.example.com", 443)
    assert r.error == "SSL Error: CERTIFICATE_VERIFY_FAILED"
    assert r.grade == "F"


# MUTATIONSPROBE (dokumentiert): ersetzt man in tls.py:_inspect_one
#   ``reason = getattr(exc, "reason", None) or str(exc)``
# zurueck durch ``reason = exc.reason``, wird test_tls_crash_healed... rot
# (AttributeError propagiert wieder, wie im SEC.1b-Crash-Test eingefroren).


# ── Loop ueberlebt: ein Port wirft, einer gesund ─────────────


def test_loop_survives_one_failing_port(monkeypatch: pytest.MonkeyPatch) -> None:
    # _inspect_one WIRFT fuer Port 443 mitten im Loop (unerwarteter Fehler ausserhalb
    # seiner eigenen Faenge) -> der per-Item-try IN der Schleife faengt es + loggt, Port
    # 8443 wird weiter inspiziert. Beweist den Loop-Schutz an der richtigen Stelle.
    from infrastructure.security import tls as tls_module

    good = TlsFinding(host="h", port=8443, reachable=True, grade="A")

    def _fake_inspect(host: str, port: int, timeout: float = 5.0) -> Any:
        if port == 443:
            raise RuntimeError("unexpected inspect error")  # wirft MITTEN im Loop
        return good

    monkeypatch.setattr(tls_module, "_inspect_one", _fake_inspect)

    with capture_logs() as logs:
        results = tls_module.TlsInspectorAdapter()._inspect_host_sync("h", [443, 8443])

    # (a) der GESUNDE Port-Befund (8443, grade A) ist konkret drin.
    assert [(r.port, r.grade) for r in results] == [(8443, "A")]
    # (b) der KAPUTTE (443) ist geloggt + fehlt im Ergebnis.
    assert any(e["event"] == "tls_inspect_failed" and e["port"] == 443 for e in logs)
    assert all(r.port != 443 for r in results)


# MUTATIONSPROBE (dokumentiert): zieht man in tls.py:_inspect_host_sync das per-Item-try
# VOR/UM die ``for port``-Schleife (statt drin), killt der RuntimeError bei Port 443 die
# ganze Schleife -> der 8443-A-Befund fehlt -> dieser Test wird rot.


def test_inspect_host_filters_non_https(monkeypatch: pytest.MonkeyPatch) -> None:
    # Nicht-HTTPS-Ports werden gefiltert -> kein Handshake-Versuch, [].
    import asyncio

    def _boom(*a: Any, **k: Any) -> Any:
        raise AssertionError("should not connect")

    monkeypatch.setattr(socket, "create_connection", _boom)
    assert asyncio.run(TlsInspectorAdapter().inspect_host("h", [22, 80, 3306])) == []
