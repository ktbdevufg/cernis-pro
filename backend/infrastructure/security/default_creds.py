"""v2-Adapter fuer den Port ``DefaultCredsChecker`` -- stdlib-reimplementiert (DF2).

Reimplementiert ``modules/default_creds.py`` verhaltensgleich (SEC.1b-Charakterisierung)
mit stdlib-only (``urllib``/``ftplib``), OHNE ``modules``-Import (kein ADR-0007). Die
Daten-Tabellen ``DEFAULT_CREDS``/``DEVICE_CREDS`` wandern als v2-Konstanten mit.

INTRUSIV: aktive Login-Versuche (HTTP-Basic / FTP) -- SEC.1b/DF5, als Finding
dokumentiert (KEIN technischer Fix in SEC.4; opt-in/rate-limit ist Use-Case/api-Sache).

S3-HEILUNGEN (Muster i -- Warn-Log NUR bei echten Fehlern, Loop ueberlebt):
  * E.4b (Altcode: HTTP-Netzfehler -> 0 -> kein Cred still). PRAEZISE Trennung:
    - HTTPError (401/403 = Cred falsch) bleibt TRAGENDE LOGIK -> kein Treffer, KEIN Log
      (gewolltes Negativ, sonst Log-Spam bei jedem Scan).
    - echter Netzfehler (Timeout/Connection-Refused) -> LOGGT ``cred_http_check_error``
      (vorher still), dann kein Treffer.
  * E.4c (Altcode: FTP-Fehler -> False still). Dito:
    - error_perm (Login falsch) = gewolltes Negativ, KEIN Log.
    - Verbindungs-/sonstiger Fehler -> LOGGT ``cred_ftp_check_error``.
  * Loop-Schutz: ``check_host`` iteriert ueber Ports; ein Port-Fehler killt die anderen
    NICHT.
"""

import asyncio
import base64
import ftplib
import ssl
import urllib.error
import urllib.request
from collections.abc import Sequence

import structlog

from ports.security import CredFinding, PortQuery

_logger = structlog.get_logger(__name__)

# Daten-Tabellen aus modules/default_creds.py als v2-Konstanten (reine Daten).
DEFAULT_CREDS: dict[str, list[tuple[str, str]]] = {
    "web": [
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", "12345"),
        ("admin", "123456"),
        ("root", "root"),
        ("root", ""),
        ("root", "admin"),
        ("user", "user"),
        ("guest", "guest"),
        ("ubnt", "ubnt"),
        ("pi", "raspberry"),
        ("admin", "ubnt"),
        ("admin", "synology"),
        ("admin", "Fritz!Box"),
    ],
    "ssh": [
        ("root", "root"),
        ("root", ""),
        ("admin", "admin"),
        ("pi", "raspberry"),
        ("ubuntu", "ubuntu"),
        ("user", "user"),
    ],
    "ftp": [
        ("anonymous", ""),
        ("anonymous", "anonymous"),
        ("admin", "admin"),
        ("ftp", "ftp"),
    ],
}

DEVICE_CREDS: dict[str, list[tuple[str, str]]] = {
    "ubiquiti": [("ubnt", "ubnt"), ("admin", "ubnt")],
    "synology": [("admin", ""), ("admin", "synology")],
    "qnap": [("admin", "admin"), ("admin", "")],
    "fritzbox": [("admin", ""), ("admin", "Fritz!Box")],
    "raspberry": [("pi", "raspberry"), ("root", "raspberry")],
    "mikrotik": [("admin", ""), ("admin", "admin")],
    "cisco": [("cisco", "cisco"), ("admin", "cisco"), ("", "cisco")],
    "dlink": [("admin", ""), ("admin", "admin"), ("Admin", "")],
    "netgear": [("admin", "password"), ("admin", "1234")],
    "tplink": [("admin", "admin"), ("admin", "")],
    "hikvision": [("admin", "12345"), ("admin", "admin")],
    "dahua": [("admin", "admin"), ("888888", "888888")],
}

_HTTP_HIT_CODES = (200, 201, 204, 302)


def get_creds_for_vendor(vendor: str) -> list[tuple[str, str]]:
    """Vendor-Substring -> DEVICE_CREDS-Liste, sonst generische Web-Defaults (Altcode)."""
    vendor_l = vendor.lower()
    for key, creds in DEVICE_CREDS.items():
        if key in vendor_l:
            return creds
    return DEFAULT_CREDS["web"][:6]


def _check_http_basic(
    host: str, port: int, creds: list[tuple[str, str]], https: bool, timeout: float = 3.0
) -> list[CredFinding]:
    scheme = "https" if https else "http"
    url = f"{scheme}://{host}:{port}/"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_OPTIONAL
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    results: list[CredFinding] = []
    for user, pwd in creds[:8]:  # max 8 Versuche (Altcode)
        cred = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Basic {cred}", "User-Agent": "CERNIS PRO/1.0"},
        )
        try:
            resp = opener.open(req, timeout=timeout)
            code = resp.code
        except urllib.error.HTTPError as exc:
            # E.4b TRAGENDE LOGIK: 401/403 = Cred falsch -> kein Treffer, KEIN Log.
            code = exc.code
        except Exception as exc:
            # E.4b-Heilung (Muster i): echter Netzfehler -> geloggt (vorher still 0).
            _logger.warning("cred_http_check_error", host=host, port=port, error=str(exc))
            code = 0

        if code in _HTTP_HIT_CODES:
            results.append(
                CredFinding(
                    host=host,
                    port=port,
                    service="http",
                    username=user,
                    password=pwd,
                    success=True,
                    method="http_basic",
                    note=f"HTTP {code}",
                )
            )
            break  # erster Treffer -> Stop (Altcode)
    return results


def _check_ftp(host: str, port: int = 21, timeout: float = 3.0) -> list[CredFinding]:
    results: list[CredFinding] = []
    for user, pwd in DEFAULT_CREDS["ftp"][:4]:
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            ftp.login(user, pwd)
            ftp.quit()
            ok = True
        except ftplib.error_perm:
            # E.4c TRAGENDE LOGIK: Login falsch -> kein Treffer, KEIN Log.
            ok = False
        except Exception as exc:
            # E.4c-Heilung (Muster i): Verbindungs-/sonstiger Fehler -> geloggt.
            _logger.warning("cred_ftp_check_error", host=host, port=port, error=str(exc))
            ok = False

        if ok:
            results.append(
                CredFinding(
                    host=host,
                    port=port,
                    service="ftp",
                    username=user,
                    password=pwd,
                    success=True,
                    method="ftp",
                )
            )
            break
    return results


class DefaultCredsCheckerAdapter:
    """Erfuellt das ``DefaultCredsChecker``-Protocol (aktive Logins, stdlib)."""

    async def check_host(
        self, host: str, ports: Sequence[PortQuery], vendor: str = ""
    ) -> list[CredFinding]:
        return await asyncio.to_thread(self._check_host_sync, host, list(ports), vendor)

    def _check_host_sync(self, host: str, ports: list[PortQuery], vendor: str) -> list[CredFinding]:
        creds = get_creds_for_vendor(vendor) if vendor else DEFAULT_CREDS["web"][:6]
        results: list[CredFinding] = []
        for p in ports:
            port = p.port
            service = p.service.lower()
            # Loop-Schutz (Muster i): per-Item-try IN der Schleife -- ein Port-Fehler
            # (in _check_* geloggt + leer, ODER ein unerwarteter Fehler ausserhalb dessen
            # Faenge) killt die ANDEREN Ports NICHT (Routing exakt Altcode check_host).
            try:
                if port in (80, 8080, 8081, 8000, 3000, 9000) or "http" in service:
                    results.extend(_check_http_basic(host, port, creds, https=False))
                elif port in (443, 8443, 4443) or "https" in service:
                    results.extend(_check_http_basic(host, port, creds, https=True))
                elif port == 21 or "ftp" in service:
                    results.extend(_check_ftp(host, port))
            except Exception as exc:
                _logger.warning("cred_port_check_failed", host=host, port=port, error=str(exc))
        return results
