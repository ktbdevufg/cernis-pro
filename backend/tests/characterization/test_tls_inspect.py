"""Characterization-Contract des TLS-Inspektor-Altcode (``modules/tls.py``).

Friert den Ist-Zustand VOR der SEC.4-Heilung ein. Der I/O-Kern ist
``socket.create_connection`` + ``ctx.wrap_socket`` -> ein TLS-``ssock`` mit
``.version()/.cipher()/.getpeercert()`` (tls.py:116-127). Gemockt werden
``socket.create_connection`` UND ``ssl.create_default_context`` am tls-Namespace ->
es passiert NIE ein echter Handshake.

Bewusst dokumentiert (kein Bug): ``ctx.check_hostname=False`` + ``ctx.verify_mode=
CERT_OPTIONAL`` (tls.py:113-114) -- Absicht, damit self-signed/abgelaufene Zertifikate
ueberhaupt inspiziert werden koennen statt den Handshake zu verweigern.

────────────────────────────────────────────────────────────────────────────
EINGEFRORENE AS-IS-VERHALTEN
────────────────────────────────────────────────────────────────────────────

ERFOLGSFALL (Parse + Grade-Vertrag):
  * ``getpeercert()`` liefert das Standard-ssl-dict: ``subject``/``issuer`` als
    Tupel-von-Tupel-von-(key,value), ``subjectAltName`` als Liste (typ, wert),
    ``notBefore``/``notAfter`` als "%b %d %H:%M:%S %Y %Z"-Strings.
  * CertInfo: subject=commonName, issuer=organizationName (sonst commonName),
    is_self_signed = (subject-dict == issuer-dict), san aus subjectAltName,
    days_remaining/is_expired aus notAfter.
  * ``_grade`` A/B/C/F (Score ab 100, Abzuege):
    - TLS-Version: 1.3 0, 1.2 -5, 1.1 -20, 1.0 -30, sonst -40.
    - cipher_bits: <128 -40, <256 -5.
    - cipher-Name RC4/DES/NULL/EXPORT -50, MD5 -10.
    - cert expired -50; days_remaining<14 -20; <30 -5; self-signed -20.
    - Schwelle: >=90 A, >=75 B, >=50 C, sonst F. error/unreachable -> sofort F.

S3-FALLBACK (AS-IS eingefroren -- SEC.4 heilt):
  * E.5 (tls.py:160-161): das INNERE ``except Exception: pass`` beim notAfter-Parse ->
    bei kaputtem Datumsformat bleiben ``days_remaining=0`` + ``is_expired=False`` still
    stehen -> ein abgelaufenes Cert mit unparsbarem Datum wird NICHT als expired
    gewertet. >> AS-IS, S3-Fallback. SEC.4 entscheidet die Heilung.

KEIN S3 (korrekt, separat eingefroren):
  * Die AEUSSEREN Faenge (tls.py:165-172, ssl.SSLError/ConnectionRefused/timeout/
    Exception) schreiben ``result.error`` + setzen grade=F -- sie verschlucken NICHT
    still, sondern signalisieren den Fehler. Das ist der GEWUENSCHTE Zustand.
"""

import datetime
from typing import Any

import pytest


@pytest.fixture
def tls() -> Any:
    from modules import tls as tls_mod

    return tls_mod


class _FakeSSLSocket:
    """Minimaler ssock-Ersatz: version/cipher/getpeercert wie ssl.SSLSocket."""

    def __init__(self, version: str, cipher: tuple[Any, ...], cert: dict[str, Any]) -> None:
        self._version = version
        self._cipher = cipher
        self._cert = cert

    def __enter__(self) -> "_FakeSSLSocket":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def version(self) -> str:
        return self._version

    def cipher(self) -> tuple[Any, ...]:
        return self._cipher

    def getpeercert(self, binary_form: bool = False) -> Any:
        return b"DER" if binary_form else self._cert


class _FakeContext:
    """ssl-Context-Ersatz: wrap_socket gibt den vorbereiteten Fake-ssock."""

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


def _patch_handshake(monkeypatch: pytest.MonkeyPatch, tls: Any, ssock: _FakeSSLSocket) -> None:
    """Mockt BEIDE I/O-Stellen: create_connection (Plain-Socket) + create_default_context."""
    monkeypatch.setattr(
        tls.socket, "create_connection", lambda addr, timeout=5.0: _FakePlainSocket()
    )
    monkeypatch.setattr(tls.ssl, "create_default_context", lambda: _FakeContext(ssock))


def _cert(
    cn: str = "example.com",
    org: str = "Example Inc",
    not_after_days: int = 400,
    self_signed: bool = False,
    bad_date: bool = False,
) -> dict[str, Any]:
    """Baut ein ssl-getpeercert()-dict mit gueltigem (oder kaputtem) notAfter."""
    now = datetime.datetime.now(datetime.UTC)
    if bad_date:
        na = "NOT A DATE"
    else:
        exp = now + datetime.timedelta(days=not_after_days)
        na = exp.strftime("%b %d %H:%M:%S %Y") + " GMT"
    nb = (now - datetime.timedelta(days=10)).strftime("%b %d %H:%M:%S %Y") + " GMT"
    subject = ((("commonName", cn),),)
    issuer = subject if self_signed else ((("organizationName", org),),)
    return {
        "subject": subject,
        "issuer": issuer,
        "subjectAltName": [("DNS", cn), ("DNS", "www." + cn)],
        "notBefore": nb,
        "notAfter": na,
    }


# ── Erfolgsfall: Parse + Grade ────────────────────────────────


def test_inspect_tls_strong_config_grades_a(tls: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    ssock = _FakeSSLSocket(
        "TLSv1.3", ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), _cert(not_after_days=400)
    )
    _patch_handshake(monkeypatch, tls, ssock)
    r = tls.inspect_tls("example.com", 443)
    assert r.reachable is True
    assert r.error == ""
    assert r.tls_version == "TLSv1.3"
    assert r.cipher_name == "TLS_AES_256_GCM_SHA384"
    assert r.cipher_bits == 256
    assert r.cert is not None
    assert r.cert.subject == "example.com"
    assert r.cert.issuer == "Example Inc"
    assert r.cert.is_self_signed is False
    assert "example.com" in r.cert.san
    assert r.cert.is_expired is False
    assert r.grade == "A"  # 1.3 + 256bit + gueltiges Cert


def test_inspect_tls_self_signed_marked_and_graded_down(
    tls: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    ssock = _FakeSSLSocket(
        "TLSv1.3", ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), _cert(self_signed=True)
    )
    _patch_handshake(monkeypatch, tls, ssock)
    r = tls.inspect_tls("example.com")
    assert r.cert is not None
    assert r.cert.is_self_signed is True  # subject==issuer
    # self-signed -20 -> Score 80 -> B (Vertrag: >=75 B).
    assert r.grade == "B"


def test_inspect_tls_weak_version_and_cipher_grades_f(
    tls: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # TLS 1.0 (-30) + RC4 (-50) + 64bit (<128 -40) -> Score <= -20 -> F.
    ssock = _FakeSSLSocket("TLSv1.0", ("RC4-MD5", "TLSv1.0", 64), _cert())
    _patch_handshake(monkeypatch, tls, ssock)
    r = tls.inspect_tls("legacy.example.com")
    assert r.grade == "F"
    assert any("TLS 1.0" in w for w in r.warnings)
    assert any("RC4" in w or "Insecure cipher" in w for w in r.warnings)


def test_inspect_tls_expiring_soon_warns(tls: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # Cert laeuft in 10 Tagen ab -> days_remaining<14 -> -20 + Warnung.
    ssock = _FakeSSLSocket(
        "TLSv1.3", ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), _cert(not_after_days=10)
    )
    _patch_handshake(monkeypatch, tls, ssock)
    r = tls.inspect_tls("expiring.example.com")
    assert r.cert is not None
    assert 0 <= r.cert.days_remaining <= 11
    assert r.cert.is_expired is False
    assert any("expires" in w.lower() for w in r.warnings)


# ── S3-Fallback E.5: kaputtes Cert-Datum still verschluckt ────


def test_bad_cert_date_silently_leaves_zero_days_not_expired(
    tls: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # E.5 AS-IS: notAfter unparsbar -> inneres except: pass -> days_remaining=0,
    # is_expired=False bleiben still stehen. Ein evtl. abgelaufenes Cert wird NICHT
    # als expired erkannt. >> SEC.4 heilt das.
    ssock = _FakeSSLSocket(
        "TLSv1.3", ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), _cert(bad_date=True)
    )
    _patch_handshake(monkeypatch, tls, ssock)
    r = tls.inspect_tls("baddate.example.com")
    assert r.cert is not None
    assert r.cert.days_remaining == 0  # Default, NICHT berechnet
    assert r.cert.is_expired is False  # still: kein expired-Abzug trotz unparsbarem Datum
    # notAfter-String wird trotzdem roh uebernommen (vor dem strptime gesetzt).
    assert r.cert.not_after == "NOT A DATE"


# ── KEIN S3: aeussere Faenge signalisieren den Fehler ─────────


def test_connection_refused_sets_error_and_grade_f(
    tls: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # KEIN S3: ConnectionRefused -> result.error gesetzt, grade F (signalisiert, nicht still).
    def _refuse(addr: Any, timeout: float = 5.0) -> Any:
        raise ConnectionRefusedError

    monkeypatch.setattr(tls.socket, "create_connection", _refuse)
    r = tls.inspect_tls("down.example.com")
    assert r.reachable is False
    assert r.error == "Connection refused"
    assert r.grade == "F"


def test_ssl_error_with_reason_sets_error_and_grade_f(
    tls: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Realistischer Pfad: der echte ssl-Stack setzt e.reason. Dann greift
    # f"SSL Error: {e.reason or str(e)}" sauber -> result.error, grade F.
    import ssl as _ssl

    def _boom(addr: Any, timeout: float = 5.0) -> Any:
        e = _ssl.SSLError("handshake failed")
        e.reason = "CERTIFICATE_VERIFY_FAILED"  # so setzt CPython es real
        raise e

    monkeypatch.setattr(tls.socket, "create_connection", _boom)
    r = tls.inspect_tls("badssl.example.com")
    assert r.reachable is False
    assert r.error == "SSL Error: CERTIFICATE_VERIFY_FAILED"
    assert r.grade == "F"


def test_ssl_error_without_reason_crashes_handler_AS_IS(
    tls: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # VIERTER S3-naher BEFUND (E nannte ihn nicht): der SSLError-HANDLER selbst
    # (tls.py:166 ``result.error = f"SSL Error: {e.reason or str(e)}"``) greift auf
    # ``e.reason`` zu. Eine SSLError OHNE gesetztes ``.reason`` (so kann eine
    # SSLError-Subklasse aus dem ssl-Stack durchaus auftreten) loest im Handler einen
    # AttributeError aus, der NICHT vom aeusseren ``except Exception`` gefangen wird
    # (er entsteht IM SSLError-Handler) -> die Exception propagiert aus inspect_tls
    # heraus = HTTP 500 am nackten Endpunkt (main.py hat keinen exception_handler).
    #
    # >> AS-IS eingefroren: KEIN sauberer Fehlerpfad, sondern ein ungefangener Crash.
    #    SEC.4 heilt das (robustes ``getattr(e, "reason", None) or str(e)`` o.ae.).
    import ssl as _ssl

    def _boom(addr: Any, timeout: float = 5.0) -> Any:
        raise _ssl.SSLError("handshake failed")  # ohne .reason

    monkeypatch.setattr(tls.socket, "create_connection", _boom)
    # PRAEZISE auf die Crash-Bedingung: der AttributeError muss GENAU der ``reason``-
    # Zugriff im SSLError-Handler sein (``match`` bindet an das Attribut). Ein anderer
    # AttributeError (z.B. nach einer kuenftigen Heilung) wuerde diesen Test NICHT
    # faelschlich gruen lassen.
    with pytest.raises(AttributeError, match="reason"):
        tls.inspect_tls("badssl.example.com")
