"""Tests des resolver-TlsCert-Adapters -- reine Helfer + gemockter ssl-Pfad, kein I/O.

Kein echter TLS-Handshake: die reinen Helfer (``_extract_cn``/``_extract_issuer``/
``_san_values``/``_fingerprint``) werden direkt geprueft (Fingerprint gegen bekannte
DER-Bytes -> bekannter SHA-256 in Doppelpunkt-Form), und der Adapter-Kern laeuft gegen
ein gemocktes ``socket.create_connection`` + ``ssl.create_default_context`` (Mock-Muster
wie ``tests/infrastructure/security/test_tls_adapter.py``). Geprueft wird die strenge
Fehlertoleranz des Port-Vertrags: jeder Fehlschlag -> ``None``.
"""

import asyncio
import socket
import ssl
from typing import Any

import pytest

from infrastructure.resolver.tls_cert import (
    TlsCertReader,
    _extract_cn,
    _extract_issuer,
    _fingerprint,
    _san_values,
)

# ── getpeercert()-Beispielstrukturen ──────────────────────────────────────────

# Subject/Issuer-Tupel, wie ``getpeercert()`` sie liefert (verschachtelte Tupel).
_SUBJECT_CN = ((("commonName", "example.com"),),)
_ISSUER_ORG = ((("organizationName", "Example Inc"), ("commonName", "Example CA")),)
_ISSUER_CN_ONLY = ((("commonName", "self.example.com"),),)

# DER-Bytes mit bekanntem SHA-256 (Gross-Doppelpunkt-Form, vorab berechnet).
_KNOWN_DER = b"cernis-pro-test-der"
_KNOWN_FP = (
    "10:78:23:1E:B3:72:ED:C7:BC:56:EF:8A:1F:7F:A7:72:"
    "8D:67:C4:AE:23:6D:50:C1:2B:24:5C:75:F4:9A:F9:90"
)


def _cert_dict(self_signed: bool = False) -> dict[str, Any]:
    """Ein vollstaendiges getpeercert()-dict; self_signed -> subject_cn == issuer-CN."""
    issuer = _ISSUER_CN_ONLY if self_signed else _ISSUER_ORG
    subject = ((("commonName", "self.example.com"),),) if self_signed else _SUBJECT_CN
    return {
        "subject": subject,
        "issuer": issuer,
        "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
        "notBefore": "Jan 01 00:00:00 2020 GMT",
        "notAfter": "Jan 01 00:00:00 2030 GMT",
        "serialNumber": "0A1B2C3D",
    }


# ── _extract_cn / _extract_issuer (reine Helfer) ──────────────────────────────


def test_extract_cn_returns_common_name() -> None:
    assert _extract_cn(_SUBJECT_CN) == "example.com"


def test_extract_cn_missing_is_none() -> None:
    # Eine Struktur ohne commonName -> None (kein erfundener Wert).
    assert _extract_cn(((("organizationName", "Org"),),)) is None


def test_extract_cn_empty_is_none() -> None:
    assert _extract_cn(()) is None
    assert _extract_cn(None) is None


def test_extract_issuer_prefers_org_over_cn() -> None:
    assert _extract_issuer(_ISSUER_ORG) == "Example Inc"


def test_extract_issuer_falls_back_to_cn() -> None:
    assert _extract_issuer(_ISSUER_CN_ONLY) == "self.example.com"


def test_extract_issuer_empty_is_none() -> None:
    assert _extract_issuer(()) is None
    assert _extract_issuer(None) is None


# ── _san_values (reiner Helfer) ───────────────────────────────────────────────


def test_san_values_returns_value_tuple() -> None:
    cert = {"subjectAltName": [("DNS", "a.example.com"), ("DNS", "b.example.com")]}
    assert _san_values(cert) == ("a.example.com", "b.example.com")


def test_san_values_no_san_is_empty() -> None:
    assert _san_values({}) == ()


# ── _fingerprint (reiner Helfer) ──────────────────────────────────────────────


def test_fingerprint_known_der_gives_known_sha256() -> None:
    # Bekannte DER-Bytes -> bekannter SHA-256 in Gross-Doppelpunkt-Form.
    assert _fingerprint(_KNOWN_DER) == _KNOWN_FP


def test_fingerprint_format_is_upper_colon_pairs() -> None:
    fp = _fingerprint(_KNOWN_DER)
    assert fp is not None
    parts = fp.split(":")
    assert len(parts) == 32  # SHA-256 = 32 Byte
    assert all(len(p) == 2 and p == p.upper() for p in parts)


def test_fingerprint_no_der_is_none() -> None:
    assert _fingerprint(None) is None
    assert _fingerprint(b"") is None


# ── Adapter-Kern: gemockter ssl/socket-Pfad ───────────────────────────────────


class _FakeSSLSocket:
    """Imitiert den ssl-Socket: liefert dict (getpeercert) und DER-Bytes (binary_form)."""

    def __init__(self, cert: dict[str, Any], der: bytes | None) -> None:
        self._cert, self._der = cert, der

    def __enter__(self) -> "_FakeSSLSocket":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def getpeercert(self, binary_form: bool = False) -> Any:
        return self._der if binary_form else self._cert


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


def test_fetch_cert_full_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _FakeSSLSocket(_cert_dict(), _KNOWN_DER))
    result = asyncio.run(TlsCertReader().fetch_cert("203.0.113.10", 443))
    assert result is not None
    assert result.subject_cn == "example.com"
    assert result.san == ("example.com", "www.example.com")
    assert result.issuer == "Example Inc"
    assert result.valid_from == "Jan 01 00:00:00 2020 GMT"
    assert result.valid_until == "Jan 01 00:00:00 2030 GMT"
    assert result.serial == "0A1B2C3D"
    assert result.fingerprint_sha256 == _KNOWN_FP
    # subject_cn (example.com) != issuer (Example Inc) -> Feststellung: nicht self-signed.
    assert result.self_signed is False


def test_fetch_cert_self_signed_set_via_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    # subject_cn == issuer (beide "self.example.com") -> detect_self_signed -> True.
    _patch(monkeypatch, _FakeSSLSocket(_cert_dict(self_signed=True), _KNOWN_DER))
    result = asyncio.run(TlsCertReader().fetch_cert("203.0.113.11", 443))
    assert result is not None
    assert result.subject_cn == "self.example.com"
    assert result.issuer == "self.example.com"
    assert result.self_signed is True


def test_fetch_cert_no_der_fingerprint_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # Handshake ok, Cert vorhanden, aber keine DER-Bytes -> fingerprint None (kein Werfen).
    _patch(monkeypatch, _FakeSSLSocket(_cert_dict(), None))
    result = asyncio.run(TlsCertReader().fetch_cert("203.0.113.12", 443))
    assert result is not None
    assert result.fingerprint_sha256 is None


def test_fetch_cert_empty_peercert_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # CERT_OPTIONAL: Handshake ok, aber Gegenstelle ohne Cert ({} ) -> None (kein leeres
    # TlsCertDetails erfinden).
    _patch(monkeypatch, _FakeSSLSocket({}, _KNOWN_DER))
    assert asyncio.run(TlsCertReader().fetch_cert("203.0.113.13", 443)) is None


def test_fetch_cert_timeout_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(addr: Any, timeout: float = 5.0) -> Any:
        raise TimeoutError("timed out")

    monkeypatch.setattr(socket, "create_connection", _boom)
    assert asyncio.run(TlsCertReader().fetch_cert("203.0.113.14", 443)) is None


def test_fetch_cert_ssl_error_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # SSLError OHNE .reason -> trotzdem None (kein AttributeError, kein Werfen).
    def _boom(addr: Any, timeout: float = 5.0) -> Any:
        raise ssl.SSLError("handshake failed")

    monkeypatch.setattr(socket, "create_connection", _boom)
    assert asyncio.run(TlsCertReader().fetch_cert("203.0.113.15", 443)) is None


def test_fetch_cert_connection_refused_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(addr: Any, timeout: float = 5.0) -> Any:
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(socket, "create_connection", _boom)
    assert asyncio.run(TlsCertReader().fetch_cert("203.0.113.16", 443)) is None
