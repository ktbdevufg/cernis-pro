"""v2-Adapter fuer den Port ``TlsInspector`` -- stdlib-reimplementiert (DF2).

Reimplementiert ``modules/tls.py`` verhaltensgleich (SEC.1b-Charakterisierung) mit
stdlib-only (``ssl``/``socket``), OHNE ``modules``-Import (kein ADR-0007).

S3-/CRASH-HEILUNGEN (Muster i -- robust + sichtbar, Loop ueberlebt):
  * E.5 (Altcode: unparsbares notAfter -> days_remaining=0/is_expired=False still): das
    innere Datums-Parse faengt weiterhin, LOGGT aber ``cert_date_parse_failed`` (vorher
    kein Log). Werte bleiben 0/False (kein erfundenes Datum) -- Ergebnis unveraendert,
    nur sichtbar.
  * tls-CRASH (Altcode: SSLError OHNE .reason -> ``e.reason``-Zugriff im Handler ->
    ungefangener AttributeError -> 500): geheilt via ``getattr(e, "reason", None) or
    str(e)``. Statt 500 jetzt ein sauberes ``TlsFinding(error="SSL Error: ...",
    grade="F")`` (bestehende Felder, kein Wire-Change).
  * Loop-Schutz: ``inspect_host`` iteriert ueber HTTPS-Ports; ein Port-Fehler landet
    sauber als ``error``-Befund, killt die anderen Ports NICHT.

Bewusst dokumentiert (kein Bug, Altcode-treu): ``ctx.check_hostname=False`` +
``CERT_OPTIONAL`` -- damit self-signed/abgelaufene Zertifikate inspiziert werden koennen.

SEC.3-Abweichung eingehalten: ``san``/``warnings`` als ``tuple`` in TlsCertInfo/
TlsFinding (frozen); Wire-Form bleibt JSON-Array (api-Rand).
"""

import datetime
import socket
import ssl
from collections.abc import Sequence
from typing import Any

import structlog

from ports.security import TlsCertInfo, TlsFinding

_logger = structlog.get_logger(__name__)

# HTTPS-faehige Ports (Altcode inspect_host_ports).
_HTTPS_PORTS = {443, 8443, 8080, 4443, 9443, 2096, 2083, 7443}
_CERT_DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def _grade(
    *,
    error: str,
    reachable: bool,
    tls_version: str,
    cipher_bits: int,
    cipher_name: str,
    cert: TlsCertInfo | None,
) -> tuple[str, tuple[str, ...]]:
    """Altcode-_grade-Heuristik (A/B/C/F) -- gibt (grade, warnings) zurueck."""
    if error or not reachable:
        return "F", ()
    score = 100
    warnings: list[str] = []

    if "1.3" in tls_version:
        pass
    elif "1.2" in tls_version:
        score -= 5
    elif "1.1" in tls_version:
        score -= 20
        warnings.append("TLS 1.1 is deprecated")
    elif "1.0" in tls_version:
        score -= 30
        warnings.append("TLS 1.0 is deprecated")
    else:
        score -= 40
        warnings.append(f"Old TLS version: {tls_version}")

    if cipher_bits < 128:
        score -= 40
        warnings.append(f"Weak cipher: {cipher_bits}-bit")
    elif cipher_bits < 256:
        score -= 5

    cipher_upper = cipher_name.upper()
    if (
        "RC4" in cipher_upper
        or "DES" in cipher_upper
        or "NULL" in cipher_upper
        or "EXPORT" in cipher_upper
    ):
        score -= 50
        warnings.append(f"Insecure cipher: {cipher_name}")
    if "MD5" in cipher_upper:
        score -= 10
        warnings.append("MD5 in cipher suite")

    if cert:
        if cert.is_expired:
            score -= 50
            warnings.append("Certificate is EXPIRED")
        elif cert.days_remaining < 14:
            score -= 20
            warnings.append(f"Certificate expires in {cert.days_remaining} days!")
        elif cert.days_remaining < 30:
            score -= 5
            warnings.append(f"Certificate expires soon ({cert.days_remaining} days)")
        if cert.is_self_signed:
            score -= 20
            warnings.append("Self-signed certificate")

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 50:
        grade = "C"
    else:
        grade = "F"
    return grade, tuple(warnings)


def _parse_cert(host: str, cert_dict: dict[str, Any]) -> TlsCertInfo:
    """Baut TlsCertInfo aus dem getpeercert()-dict (Altcode-Parse)."""
    subj = dict(x[0] for x in cert_dict.get("subject", []))
    issuer_d = dict(x[0] for x in cert_dict.get("issuer", []))
    subject = str(subj.get("commonName", ""))
    issuer = str(issuer_d.get("organizationName", issuer_d.get("commonName", "")))
    is_self_signed = subj == issuer_d
    san = tuple(v for _, v in cert_dict.get("subjectAltName", []))

    not_before = cert_dict.get("notBefore", "")
    not_after = cert_dict.get("notAfter", "")
    days_remaining = 0
    is_expired = False
    if not_after:
        try:
            exp = datetime.datetime.strptime(not_after, _CERT_DATE_FMT)
            delta = exp - datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
            days_remaining = delta.days
            is_expired = delta.days < 0
        except Exception as exc:
            # E.5-Heilung (Muster i): vorher stilles pass -- jetzt geloggt, Werte 0/False.
            _logger.warning(
                "cert_date_parse_failed", host=host, not_after=not_after, error=str(exc)
            )

    return TlsCertInfo(
        subject=subject,
        issuer=issuer,
        san=san,
        not_before=not_before,
        not_after=not_after,
        days_remaining=days_remaining,
        is_expired=is_expired,
        is_self_signed=is_self_signed,
    )


def _inspect_one(host: str, port: int, timeout: float = 5.0) -> TlsFinding:
    """Inspiziert EINEN host:port. Faengt alle I/O-Fehler sauber in error/grade=F."""
    reachable = False
    tls_version = ""
    cipher_name = ""
    cipher_bits = 0
    cert: TlsCertInfo | None = None
    error = ""

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL

        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as ssock,
        ):
            reachable = True
            tls_version = ssock.version() or ""
            cipher = ssock.cipher()
            if cipher:
                cipher_name = cipher[0] or ""
                cipher_bits = cipher[2] or 0
            cert_dict = ssock.getpeercert()
            if cert_dict:
                cert = _parse_cert(host, cert_dict)
    except ssl.SSLError as exc:
        # tls-CRASH-Heilung: getattr statt e.reason (eine SSLError ohne .reason loeste
        # im Altcode-Handler einen ungefangenen AttributeError -> 500 aus).
        reason = getattr(exc, "reason", None) or str(exc)
        error = f"SSL Error: {reason}"
    except ConnectionRefusedError:
        error = "Connection refused"
    except TimeoutError:
        error = "Timeout"
    except Exception as exc:
        error = str(exc)[:100]

    grade, warnings = _grade(
        error=error,
        reachable=reachable,
        tls_version=tls_version,
        cipher_bits=cipher_bits,
        cipher_name=cipher_name,
        cert=cert,
    )
    return TlsFinding(
        host=host,
        port=port,
        reachable=reachable,
        tls_version=tls_version,
        cipher_name=cipher_name,
        cipher_bits=cipher_bits,
        cert=cert,
        grade=grade,
        warnings=warnings,
        error=error,
    )


class TlsInspectorAdapter:
    """Erfuellt das ``TlsInspector``-Protocol (TLS-Handshake, stdlib)."""

    async def inspect_host(self, host: str, ports: Sequence[int]) -> list[TlsFinding]:
        import asyncio

        https_ports = [p for p in ports if p in _HTTPS_PORTS]
        if not https_ports:
            return []
        return await asyncio.to_thread(self._inspect_host_sync, host, https_ports[:5])

    def _inspect_host_sync(self, host: str, ports: list[int]) -> list[TlsFinding]:
        results: list[TlsFinding] = []
        for port in ports:
            # Loop-Schutz (Muster i): per-Item-try IN der Schleife -- ein Port-Fehler
            # landet regulaer als error-Befund (grade=F) aus _inspect_one; ein
            # unerwarteter Fehler ausserhalb dessen Faenge killt die ANDEREN Ports NICHT.
            try:
                finding = _inspect_one(host, port)
            except Exception as exc:
                _logger.warning("tls_inspect_failed", host=host, port=port, error=str(exc))
                continue
            # Nur erreichbare ODER fehlerhafte aufnehmen (Altcode: ``if r.reachable or r.error``).
            if finding.reachable or finding.error:
                results.append(finding)
        return results
