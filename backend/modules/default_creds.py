"""
CERNIS PRO Default Credentials Checker
Tests common default username/password combinations on web interfaces,
SSH, Telnet, FTP for IoT devices, routers, NAS systems.
"""
import asyncio
import socket
from dataclasses import dataclass, asdict

# Common default credential pairs by service type
DEFAULT_CREDS = {
    "web": [
        ("admin",  "admin"),
        ("admin",  ""),
        ("admin",  "password"),
        ("admin",  "1234"),
        ("admin",  "12345"),
        ("admin",  "123456"),
        ("root",   "root"),
        ("root",   ""),
        ("root",   "admin"),
        ("user",   "user"),
        ("guest",  "guest"),
        ("ubnt",   "ubnt"),         # Ubiquiti
        ("pi",     "raspberry"),    # Raspberry Pi
        ("admin",  "ubnt"),
        ("admin",  "synology"),     # Synology NAS
        ("admin",  "Fritz!Box"),    # AVM FritzBox
    ],
    "ssh": [
        ("root",   "root"),
        ("root",   ""),
        ("admin",  "admin"),
        ("pi",     "raspberry"),
        ("ubuntu", "ubuntu"),
        ("user",   "user"),
    ],
    "ftp": [
        ("anonymous", ""),
        ("anonymous", "anonymous"),
        ("admin",     "admin"),
        ("ftp",       "ftp"),
    ],
}

# Device fingerprint → likely credential pair
DEVICE_CREDS = {
    "ubiquiti": [("ubnt", "ubnt"), ("admin", "ubnt")],
    "synology": [("admin", ""), ("admin", "synology")],
    "qnap":     [("admin", "admin"), ("admin", "")],
    "fritzbox": [("admin", ""), ("admin", "Fritz!Box")],
    "raspberry": [("pi", "raspberry"), ("root", "raspberry")],
    "mikrotik": [("admin", ""), ("admin", "admin")],
    "cisco":    [("cisco", "cisco"), ("admin", "cisco"), ("", "cisco")],
    "dlink":    [("admin", ""), ("admin", "admin"), ("Admin", "")],
    "netgear":  [("admin", "password"), ("admin", "1234")],
    "tplink":   [("admin", "admin"), ("admin", "")],
    "hikvision":[("admin", "12345"), ("admin", "admin")],
    "dahua":    [("admin", "admin"), ("888888", "888888")],
}


@dataclass
class CredResult:
    host: str
    port: int
    service: str
    username: str
    password: str
    success: bool
    method: str     # "http_basic" | "http_form" | "ssh" | "ftp"
    note: str = ""

    def to_dict(self):
        return asdict(self)


async def check_http_basic(host: str, port: int, creds: list[tuple],
                            https: bool = False, timeout: float = 3.0) -> list[CredResult]:
    """Test credentials via HTTP Basic Auth."""
    import urllib.request, base64, ssl
    results = []
    scheme = "https" if https else "http"
    url = f"{scheme}://{host}:{port}/"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_OPTIONAL
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    loop = asyncio.get_event_loop()

    for user, pwd in creds[:8]:  # max 8 attempts per host
        def _try(u=user, p=pwd):
            try:
                cred = base64.b64encode(f"{u}:{p}".encode()).decode()
                req = urllib.request.Request(url,
                    headers={"Authorization": f"Basic {cred}",
                             "User-Agent": "CERNIS PRO/1.0"})
                resp = opener.open(req, timeout=timeout)
                return resp.code
            except urllib.error.HTTPError as e:
                return e.code
            except Exception:
                return 0

        code = await loop.run_in_executor(None, _try)
        if code in (200, 201, 204, 302):
            results.append(CredResult(
                host=host, port=port, service="http",
                username=user, password=pwd, success=True,
                method="http_basic",
                note=f"HTTP {code}",
            ))
            break  # Found — stop trying

    return results


async def check_ftp(host: str, port: int = 21, timeout: float = 3.0) -> list[CredResult]:
    """Test FTP anonymous and default credentials."""
    import ftplib
    results = []
    loop = asyncio.get_event_loop()

    for user, pwd in DEFAULT_CREDS["ftp"][:4]:
        def _try(u=user, p=pwd):
            try:
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=timeout)
                ftp.login(u, p)
                ftp.quit()
                return True
            except Exception:
                return False

        ok = await loop.run_in_executor(None, _try)
        if ok:
            results.append(CredResult(
                host=host, port=port, service="ftp",
                username=user, password=pwd, success=True,
                method="ftp",
            ))
            break

    return results


def get_creds_for_vendor(vendor: str) -> list[tuple]:
    """Get likely default credentials based on vendor string."""
    vendor_l = vendor.lower()
    for key, creds in DEVICE_CREDS.items():
        if key in vendor_l:
            return creds
    return DEFAULT_CREDS["web"][:6]


async def check_host(host: str, ports: list[dict],
                     vendor: str = "") -> list[CredResult]:
    """Run default credential checks on a host's open ports."""
    results = []
    creds = get_creds_for_vendor(vendor) if vendor else DEFAULT_CREDS["web"][:6]

    for p in ports:
        port = p["port"]
        service = p.get("service", "").lower()

        if port in (80, 8080, 8081, 8000, 3000, 9000) or "http" in service:
            r = await check_http_basic(host, port, creds, https=False)
            results.extend(r)
        elif port in (443, 8443, 4443) or "https" in service:
            r = await check_http_basic(host, port, creds, https=True)
            results.extend(r)
        elif port == 21 or "ftp" in service:
            r = await check_ftp(host, port)
            results.extend(r)

    return results
