"""
CERNIS PRO SSL/TLS Inspector
Checks certificates, cipher suites, and TLS versions for HTTPS ports.
Uses Python's built-in ssl module — no external dependencies.
"""
import ssl
import socket
import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class CertInfo:
    subject: str          = ""
    issuer: str           = ""
    san: list             = field(default_factory=list)  # Subject Alt Names
    not_before: str       = ""
    not_after: str        = ""
    days_remaining: int   = 0
    is_expired: bool      = False
    is_self_signed: bool  = False
    serial: str           = ""


@dataclass
class TLSResult:
    host: str
    port: int
    reachable: bool       = False
    tls_version: str      = ""
    cipher_name: str      = ""
    cipher_bits: int      = 0
    cert: Optional[CertInfo] = None
    grade: str            = ""   # A / B / C / F
    warnings: list        = field(default_factory=list)
    error: str            = ""

    def to_dict(self):
        d = asdict(self)
        return d


def _grade(result: TLSResult) -> str:
    """Simple grading based on TLS version, cipher strength, cert validity."""
    if result.error or not result.reachable:
        return "F"
    score = 100
    warnings = []

    # TLS version
    v = result.tls_version
    if "1.3" in v:
        pass  # best
    elif "1.2" in v:
        score -= 5
    elif "1.1" in v:
        score -= 20
        warnings.append("TLS 1.1 is deprecated")
    elif "1.0" in v:
        score -= 30
        warnings.append("TLS 1.0 is deprecated")
    else:
        score -= 40
        warnings.append(f"Old TLS version: {v}")

    # Cipher strength
    bits = result.cipher_bits
    if bits < 128:
        score -= 40
        warnings.append(f"Weak cipher: {bits}-bit")
    elif bits < 256:
        score -= 5

    # Cipher name
    cipher = result.cipher_name.upper()
    if "RC4" in cipher or "DES" in cipher or "NULL" in cipher or "EXPORT" in cipher:
        score -= 50
        warnings.append(f"Insecure cipher: {result.cipher_name}")
    if "MD5" in cipher:
        score -= 10
        warnings.append("MD5 in cipher suite")

    # Certificate
    if result.cert:
        if result.cert.is_expired:
            score -= 50
            warnings.append("Certificate is EXPIRED")
        elif result.cert.days_remaining < 14:
            score -= 20
            warnings.append(f"Certificate expires in {result.cert.days_remaining} days!")
        elif result.cert.days_remaining < 30:
            score -= 5
            warnings.append(f"Certificate expires soon ({result.cert.days_remaining} days)")
        if result.cert.is_self_signed:
            score -= 20
            warnings.append("Self-signed certificate")

    result.warnings = warnings

    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 50: return "C"
    return "F"


def inspect_tls(host: str, port: int = 443, timeout: float = 5.0) -> TLSResult:
    """Inspect TLS/SSL configuration of a host:port."""
    result = TLSResult(host=host, port=port)

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result.reachable  = True
                result.tls_version = ssock.version() or ""
                cipher = ssock.cipher()
                if cipher:
                    result.cipher_name = cipher[0] or ""
                    result.cipher_bits = cipher[2] or 0

                # Certificate
                cert_der = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
                if cert_dict:
                    ci = CertInfo()

                    # Subject
                    subj = dict(x[0] for x in cert_dict.get("subject", []))
                    ci.subject = subj.get("commonName", "")

                    # Issuer
                    issuer = dict(x[0] for x in cert_dict.get("issuer", []))
                    ci.issuer = issuer.get("organizationName",
                                issuer.get("commonName", ""))

                    # Self-signed check
                    ci.is_self_signed = (subj == issuer)

                    # SANs
                    san_list = cert_dict.get("subjectAltName", [])
                    ci.san = [v for _, v in san_list]

                    # Validity dates
                    fmt = "%b %d %H:%M:%S %Y %Z"
                    try:
                        nb = cert_dict.get("notBefore", "")
                        na = cert_dict.get("notAfter", "")
                        ci.not_before = nb
                        ci.not_after  = na
                        if na:
                            exp = datetime.datetime.strptime(na, fmt)
                            now = datetime.datetime.utcnow()
                            delta = exp - now
                            ci.days_remaining = delta.days
                            ci.is_expired = delta.days < 0
                    except Exception:
                        pass

                    result.cert = ci

    except ssl.SSLError as e:
        result.error = f"SSL Error: {e.reason or str(e)}"
    except ConnectionRefusedError:
        result.error = "Connection refused"
    except socket.timeout:
        result.error = "Timeout"
    except Exception as e:
        result.error = str(e)[:100]

    result.grade = _grade(result)
    return result


async def inspect_host_ports(host: str, ports: list[dict],
                              timeout: float = 4.0) -> list[dict]:
    """Inspect all HTTPS-like ports on a host."""
    import asyncio
    https_ports = [p["port"] for p in ports
                   if p["port"] in [443, 8443, 8080, 4443, 9443, 2096, 2083, 7443]
                   or "https" in p.get("service", "").lower()
                   or "ssl" in p.get("service", "").lower()]

    if not https_ports:
        return []

    results = []
    loop = asyncio.get_event_loop()
    for port in https_ports[:5]:  # max 5 ports
        r = await loop.run_in_executor(None, lambda p=port: inspect_tls(host, p, timeout))
        if r.reachable or r.error:
            results.append(r.to_dict())
    return results
