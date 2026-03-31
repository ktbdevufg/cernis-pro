"""
CERNIS PRO Internet Tools
- External IP detection
- Port reachability check (from internet)
- Speed test
- Shodan lookup
- DNS propagation
"""
import asyncio
import socket
import time
import urllib.request
import json
from dataclasses import dataclass, asdict


# ── External IP ───────────────────────────────────────────────

async def get_external_ip() -> dict:
    """Get external IP from multiple sources."""
    loop = asyncio.get_event_loop()
    sources = [
        ("https://api.ipify.org?format=json", "ip"),
        ("https://api4.my-ip.io/ip.json",     "ip"),
        ("https://ifconfig.me/all.json",       "ip_addr"),
    ]
    for url, key in sources:
        try:
            def _fetch(u=url):
                req = urllib.request.Request(u, headers={"User-Agent": "CERNIS PRO/1.0b"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    return json.loads(r.read())
            data = await asyncio.wait_for(loop.run_in_executor(None, _fetch), timeout=6)
            ip = data.get(key, "")
            if ip:
                return {"ip": ip, "source": url}
        except Exception:
            continue
    return {"ip": "", "error": "Could not determine external IP"}


# ── External Port Check ───────────────────────────────────────

async def check_port_external(port: int, protocol: str = "tcp") -> dict:
    """
    Check if a port is reachable from the internet.
    Uses portchecker.co API or similar.
    """
    loop = asyncio.get_event_loop()
    try:
        # Use external port checker API
        url = f"https://portchecker.co/api/v1/query"

        # Get external IP first
        ext = await get_external_ip()
        ext_ip = ext.get("ip", "")
        if not ext_ip:
            return {"open": False, "error": "Could not determine external IP"}

        # Direct TCP check via socket (tests if our port responds externally)
        # This actually tests from inside but gives indication
        # For true external check we use a public API
        def _check():
            try:
                req = urllib.request.Request(
                    f"https://portchecker.co/api/v1/query",
                    data=json.dumps({"host": ext_ip, "ports": [port]}).encode(),
                    headers={"Content-Type": "application/json",
                             "User-Agent": "CERNIS PRO/1.0b"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=10) as r:
                    return json.loads(r.read())
            except Exception as e:
                return {"error": str(e)}

        result = await asyncio.wait_for(loop.run_in_executor(None, _check), timeout=12)

        if "error" in result:
            # Fallback: use portquiz.net (TCP echo server)
            return await _check_via_portquiz(port)

        ports_data = result.get("ports", [{}])
        is_open = ports_data[0].get("status", "closed") == "open" if ports_data else False
        return {
            "ip": ext_ip, "port": port, "open": is_open,
            "protocol": protocol, "source": "portchecker.co"
        }
    except Exception as e:
        return {"open": False, "error": str(e)}


async def _check_via_portquiz(port: int) -> dict:
    """Fallback: connect to portquiz.net which listens on all ports."""
    loop = asyncio.get_event_loop()
    try:
        def _try():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex(("portquiz.net", port))
            sock.close()
            return result == 0
        open_ = await asyncio.wait_for(loop.run_in_executor(None, _try), timeout=8)
        return {"port": port, "open": open_, "source": "portquiz.net",
                "note": "Tests outbound connectivity, not inbound"}
    except Exception as e:
        return {"port": port, "open": False, "error": str(e)}


# ── Speed Test ────────────────────────────────────────────────

async def run_speedtest() -> dict:
    """Simple HTTP-based speed test using a known fast server."""
    loop = asyncio.get_event_loop()

    results = {"download_mbps": 0, "upload_mbps": 0, "ping_ms": 0, "error": ""}

    # Ping test
    try:
        import subprocess, platform
        cmd = ["ping", "-c", "4", "8.8.8.8"] if platform.system() != "Windows" else ["ping", "-n", "4", "8.8.8.8"]
        proc = await asyncio.create_subprocess_exec(*cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        import re
        m = re.search(r"avg[^\d]+([\d.]+)", stdout.decode("utf-8", errors="replace"))
        if m:
            results["ping_ms"] = float(m.group(1))
    except Exception:
        pass

    # Download test (10MB from Cloudflare)
    try:
        def _dl():
            url = "https://speed.cloudflare.com/__down?bytes=10000000"
            req = urllib.request.Request(url, headers={"User-Agent": "CERNIS PRO/1.0b"})
            start = time.time()
            with urllib.request.urlopen(req, timeout=20) as r:
                data = r.read()
            elapsed = time.time() - start
            return len(data), elapsed

        size_bytes, elapsed = await asyncio.wait_for(
            loop.run_in_executor(None, _dl), timeout=25
        )
        results["download_mbps"] = round((size_bytes * 8) / elapsed / 1_000_000, 1)
    except Exception as e:
        results["error"] = str(e)

    # Upload test (1MB to Cloudflare)
    try:
        def _ul():
            import os
            data = os.urandom(1_000_000)
            req = urllib.request.Request(
                "https://speed.cloudflare.com/__up",
                data=data,
                headers={"Content-Type": "application/octet-stream",
                         "User-Agent": "CERNIS PRO/1.0b"},
                method="POST"
            )
            start = time.time()
            with urllib.request.urlopen(req, timeout=20) as r:
                r.read()
            return time.time() - start

        elapsed = await asyncio.wait_for(loop.run_in_executor(None, _ul), timeout=25)
        results["upload_mbps"] = round((1_000_000 * 8) / elapsed / 1_000_000, 1)
    except Exception:
        pass

    return results


# ── Shodan Lookup ─────────────────────────────────────────────

async def shodan_lookup(ip: str, api_key: str = "") -> dict:
    """
    Look up an IP on Shodan.
    Without API key: use Shodan InternetDB (free, no key needed).
    With API key: full Shodan data.
    """
    loop = asyncio.get_event_loop()

    # Free Shodan InternetDB — no API key required
    def _fetch_free(ip_addr=ip):
        try:
            req = urllib.request.Request(
                f"https://internetdb.shodan.io/{ip_addr}",
                headers={"User-Agent": "CERNIS PRO/1.0b"}
            )
            with urllib.request.urlopen(req, timeout=8) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"ip": ip_addr, "ports": [], "tags": [], "vulns": [],
                        "hostnames": [], "cpes": []}
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}

    if not api_key:
        result = await asyncio.wait_for(loop.run_in_executor(None, _fetch_free), timeout=10)
        result["source"] = "Shodan InternetDB (free)"
        return result

    # Full Shodan API
    def _fetch_full(ip_addr=ip, key=api_key):
        try:
            req = urllib.request.Request(
                f"https://api.shodan.io/shodan/host/{ip_addr}?key={key}",
                headers={"User-Agent": "CERNIS PRO/1.0b"}
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            return {
                "ip": ip_addr,
                "org": data.get("org", ""),
                "country": data.get("country_name", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "tags": data.get("tags", []),
                "vulns": list(data.get("vulns", {}).keys()),
                "last_update": data.get("last_update", ""),
                "source": "Shodan API"
            }
        except Exception as e:
            return {"error": str(e)}

    return await asyncio.wait_for(loop.run_in_executor(None, _fetch_full), timeout=12)
