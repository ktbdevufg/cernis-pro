#!/usr/bin/env python3
"""
CERNIS PRO CLI — cernis [command] [options]
Talks to the CERNIS PRO backend API at localhost:8765

Usage:
  cernis scan [CIDR] [--profile quick|standard|deep|iot|security] [--json]
  cernis hosts [--json]
  cernis fritz [--json]
  cernis monitor [--json]
  cernis devices [--json] [--unknown]
  cernis dns <query>
  cernis trace <target>
  cernis tls <host> [port]
  cernis history [--limit N]
  cernis version
"""
import sys
import json
import time
import argparse
import urllib.request
import urllib.parse

BASE = "http://127.0.0.1:8765"
WS_BASE = "ws://127.0.0.1:8765"


def api(path: str, method: str = "GET", data: dict = None) -> dict | list:
    url = BASE + path
    body = json.dumps(data).encode() if data else None
    headers = {"Content-Type": "application/json"} if data else {}
    try:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError:
        print(f"✗ Cannot connect to CERNIS PRO backend at {BASE}", file=sys.stderr)
        print("  Start with: ./start.sh start", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"✗ API error: {e}", file=sys.stderr)
        sys.exit(1)


# ── Colors ────────────────────────────────────────────────────
def c(text, color):
    codes = {"cyan":"\033[96m","green":"\033[92m","red":"\033[91m",
             "yellow":"\033[93m","gray":"\033[90m","bold":"\033[1m","reset":"\033[0m"}
    return f"{codes.get(color,'')}{text}{codes['reset']}"


def header(title):
    print(f"\n{c('⬡ CERNIS PRO', 'cyan')} {c(title, 'bold')}")
    print(c("─" * 60, "gray"))


# ── Commands ──────────────────────────────────────────────────

def cmd_version(args):
    print(f"{c('CERNIS PRO', 'cyan')} v1.0.0 · Professional Network Scanner & Monitor")
    print(f"Backend: {BASE}")


def cmd_scan(args):
    import asyncio

    cidr = args.cidr or "192.168.1.0/24"
    profile = args.profile or "standard"

    PROFILES = {
        "quick":    {"port_scan": False, "mdns_scan": False, "ping_timeout": 0.5, "max_concurrent_ping": 128},
        "standard": {},
        "deep":     {"port_scan": True, "port_mode": "nmap", "smb_scan": True},
        "iot":      {"mdns_duration": 10.0},
        "security": {"smb_scan": True, "custom_ports": [21,22,23,80,139,443,445,3389,5900]},
    }
    config = {"cidr": cidr, "ping_timeout": 1.0, "port_scan": True,
              "mdns_scan": True, "resolve_hostnames": True, **PROFILES.get(profile, {})}

    header(f"Scan {cidr} [{profile}]")
    hosts = []

    try:
        import websockets

        async def run_scan():
            # Verbinde, sende die Config beim Open, empfange Nachrichten in einer
            # Schleife und verarbeite dieselben message-Typen wie zuvor.
            async with websockets.connect(f"{WS_BASE}/ws/scan") as ws:
                await ws.send(json.dumps(config))
                async for raw in ws:
                    m = json.loads(raw)
                    if m["type"] == "host_found":
                        status = c("●", "green")
                        unknown = c(" NEW", "yellow") if m.get("is_unknown") else ""
                        print(f"  {status} {c(m['ip'], 'cyan'):<18} {m.get('vendor',''):<25}{unknown}")
                        hosts.append(m)
                    elif m["type"] == "scan_complete":
                        print(c(f"\n  ✓ {m['total_found']} hosts found", "green"))
                        return
                    elif m["type"] == "error":
                        print(c(f"  ✗ {m['message']}", "red"))
                        return

        try:
            # 300s Gesamt-Timeout ueber die async-Session (die CLI ist synchron).
            asyncio.run(asyncio.wait_for(run_scan(), timeout=300))
        except asyncio.TimeoutError:
            pass

    except ImportError:
        # Fallback: just show last scan from history
        print(c("  websockets not installed, showing last scan:", "yellow"))
        history = api("/api/history?limit=1")
        if history:
            scan = api(f"/api/history/{history[0]['id']}")
            for h in scan.get("hosts", []):
                print(f"  {c('●', 'green')} {c(h['ip'], 'cyan'):<18} {h.get('vendor','')}")

    if args.json:
        print(json.dumps(hosts, indent=2))


def cmd_hosts(args):
    header("Discovered Hosts")
    devices = api("/api/devices")
    if not devices:
        print(c("  No devices in database. Run a scan first.", "gray"))
        return

    if args.unknown:
        devices = [d for d in devices if not d.get("is_known")]

    for d in devices:
        status = c("✓", "green") if d.get("is_known") else c("?", "yellow")
        ip   = c(d.get("last_ip","—"), "cyan")
        mac  = c(d.get("mac",""), "gray")
        vendor = d.get("vendor","")[:25]
        label  = f" [{c(d['label'], 'yellow')}]" if d.get("label") else ""
        print(f"  {status} {ip:<18} {mac:<20} {vendor}{label}")

    if args.json:
        print(json.dumps(devices, indent=2))


def cmd_fritz(args):
    header("FritzBox Status")
    try:
        s = api("/api/fritz/status")
    except SystemExit:
        return

    if not s.get("reachable"):
        print(c("  ✗ FritzBox not connected. Log in via the web UI first.", "red"))
        return

    print(f"  {c('Model', 'gray'):<16} {c(s.get('model','—'), 'cyan')}")
    print(f"  {c('Firmware', 'gray'):<16} {s.get('firmware','—')}")
    print(f"  {c('WAN Status', 'gray'):<16} {c('Connected', 'green') if s.get('wan_connected') else c('Offline','red')}")
    print(f"  {c('External IP', 'gray'):<16} {c(s.get('wan_ip_external','—'), 'cyan')}")
    print(f"  {c('WLAN 2.4GHz', 'gray'):<16} {s.get('wlan_24_ssid','—')} (Ch {s.get('wlan_24_channel','-')}, {s.get('wlan_24_clients',0)} clients)")
    print(f"  {c('WLAN 5GHz', 'gray'):<16} {s.get('wlan_5_ssid','—')} (Ch {s.get('wlan_5_channel','-')}, {s.get('wlan_5_clients',0)} clients)")
    print(f"  {c('Total Hosts', 'gray'):<16} {s.get('total_hosts',0)}")

    if args.json:
        print(json.dumps(s, indent=2))


def cmd_monitor(args):
    header("Monitor Status")
    status = api("/api/monitor/status")
    for tid, info in status.items():
        dot = c("●", "green") if info.get("alive") else c("●", "red")
        label = info.get("label", tid)
        print(f"  {dot} {label}")

    if args.json:
        events = api("/api/monitor/events?limit=10")
        print(json.dumps(events, indent=2))


def cmd_dns(args):
    header(f"DNS Lookup: {args.query}")
    results = api("/api/tools/dns", "POST", {"query": args.query})
    for r in results:
        if r.get("records"):
            print(f"  {c(r['record_type'], 'cyan'):<8} {', '.join(r['records'])}")
        elif r.get("error"):
            print(f"  {c(r['record_type'], 'gray'):<8} {c(r['error'], 'gray')}")


def cmd_trace(args):
    header(f"Traceroute: {args.target}")
    print(c("  Running (may take 30s)…", "gray"))
    hops = api("/api/tools/traceroute", "POST", {"target": args.target})
    for h in hops:
        if h.get("timeout"):
            print(f"  {h['hop']:>3}  {c('* * *', 'gray')}")
        else:
            rtt = f"{h['rtt_ms']:.1f} ms"
            rtt_c = "green" if h["rtt_ms"] < 10 else "yellow" if h["rtt_ms"] < 50 else "red"
            host = h["hostname"] if h["hostname"] != h["ip"] else ""
            print(f"  {h['hop']:>3}  {c(h['ip'], 'cyan'):<18} {c(rtt, rtt_c):<12} {c(host, 'gray')}")


def cmd_tls(args):
    port = int(args.port) if args.port else 443
    header(f"TLS Inspect: {args.host}:{port}")
    result = api("/api/tls/inspect", "POST", {"host": args.host, "port": port})
    if result.get("error"):
        print(c(f"  ✗ {result['error']}", "red"))
        return
    grade = result.get("grade", "?")
    grade_c = "green" if grade == "A" else "yellow" if grade == "B" else "red"
    print(f"  {c('Grade', 'gray'):<16} {c(grade, grade_c)}")
    print(f"  {c('TLS Version', 'gray'):<16} {result.get('tls_version','—')}")
    print(f"  {c('Cipher', 'gray'):<16} {result.get('cipher_name','—')} ({result.get('cipher_bits',0)}-bit)")
    cert = result.get("cert") or {}
    if cert:
        print(f"  {c('Subject', 'gray'):<16} {cert.get('subject','—')}")
        print(f"  {c('Issuer', 'gray'):<16} {cert.get('issuer','—')}")
        days = cert.get("days_remaining", 0)
        days_c = "green" if days > 30 else "yellow" if days > 7 else "red"
        print(f"  {c('Expires', 'gray'):<16} {cert.get('not_after','—')} {c(f'({days}d remaining)', days_c)}")
    for w in result.get("warnings", []):
        print(f"  {c('⚠', 'yellow')} {w}")

    if args.json if hasattr(args, 'json') else False:
        print(json.dumps(result, indent=2))


def cmd_history(args):
    header("Scan History")
    limit = getattr(args, "limit", 10)
    history = api(f"/api/history?limit={limit}")
    for h in history:
        dt = h.get("scanned_at", "")[:16]
        print(f"  {c('#'+str(h['id']), 'cyan'):<8} {dt:<18} {h.get('cidr',''):<20} {c(str(h.get('host_count',0))+' hosts', 'green')}")


# ── Main ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="cernis",
        description="CERNIS PRO v1.0.0 — Professional Network Scanner & Monitor CLI",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Run a network scan")
    p_scan.add_argument("cidr", nargs="?", default=None, help="CIDR (e.g. 192.168.1.0/24)")
    p_scan.add_argument("--profile", "-p", default="standard", choices=["quick","standard","deep","iot","security"])
    p_scan.add_argument("--json", action="store_true")

    # hosts
    p_hosts = sub.add_parser("hosts", help="List known devices")
    p_hosts.add_argument("--json", action="store_true")
    p_hosts.add_argument("--unknown", action="store_true", help="Only unknown devices")

    # fritz
    p_fritz = sub.add_parser("fritz", help="Show FritzBox status")
    p_fritz.add_argument("--json", action="store_true")

    # monitor
    p_mon = sub.add_parser("monitor", help="Show monitor status")
    p_mon.add_argument("--json", action="store_true")

    # dns
    p_dns = sub.add_parser("dns", help="DNS lookup")
    p_dns.add_argument("query", help="Domain or IP")

    # trace
    p_trace = sub.add_parser("trace", help="Traceroute")
    p_trace.add_argument("target", help="Hostname or IP")

    # tls
    p_tls = sub.add_parser("tls", help="TLS/SSL inspection")
    p_tls.add_argument("host", help="Hostname")
    p_tls.add_argument("port", nargs="?", default="443")
    p_tls.add_argument("--json", action="store_true")

    # history
    p_hist = sub.add_parser("history", help="Scan history")
    p_hist.add_argument("--limit", type=int, default=10)

    # version
    sub.add_parser("version", help="Show version")

    args = parser.parse_args()

    cmds = {
        "scan": cmd_scan, "hosts": cmd_hosts, "fritz": cmd_fritz,
        "monitor": cmd_monitor, "dns": cmd_dns, "trace": cmd_trace,
        "tls": cmd_tls, "history": cmd_history, "version": cmd_version,
    }

    if args.command in cmds:
        cmds[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
