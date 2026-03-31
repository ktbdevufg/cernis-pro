"""CERNIS PRO v1.0.0 — Network Scanner & Monitor · FastAPI Backend"""
import sys as _sys
import os as _os

# ── PyInstaller bundle support ────────────────────────────────────
if hasattr(_sys, '_MEIPASS'):
    # Running as PyInstaller bundle
    _bundle_dir = _sys._MEIPASS
    _sys.path.insert(0, _bundle_dir)
    _sys.path.insert(0, _os.path.join(_bundle_dir, 'modules'))
else:
    # Running as script — add parent dir for module imports
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

VERSION = "1.0.0"
import asyncio
import json
import ipaddress
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, Query, Body, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

from modules.interfaces import get_interfaces
from modules.discovery import discover_subnet, get_arp_table
from modules.portscan import scan_ports_socket, scan_with_nmap, TOP_100_PORTS
from modules.mdns import discover_mdns, group_by_ip
from modules.resolver import resolve_hostname, get_smb_info
from modules.vendor import lookup_vendor
from modules.wol import send_wol
from modules.ssdp import discover_ssdp
from modules.storage import (
    init_db, get_setting, set_setting, get_all_settings,
    get_known_devices, upsert_device, delete_device,
    save_scan, get_scan_history, get_scan_by_id,
)
from modules.monitor import (
    MonitorTarget, run_monitor, stop_monitor, configure as configure_monitor,
    subscribe as monitor_subscribe, unsubscribe as monitor_unsubscribe,
    get_current_status, get_monitor_events, get_rtt_history,
)
from modules.arp_guard import (
    scan_arp_once, get_arp_alerts, get_arp_baseline, clear_baseline,
)
from modules.devices_db import (
    init_devices_db, update_device_from_scan, get_all_devices,
    get_device, update_device_meta, get_device_stats,
)
from modules.fritzbox import FritzBox, detect_fritzbox
from modules.crypto import encrypt, decrypt
from modules.cve import lookup_cves_for_host
from modules.report import generate_report, REPORTLAB_AVAILABLE
from modules.snmp import query_host as snmp_query, check_snmp_available
from modules.tls import inspect_tls, inspect_host_ports
from modules.default_creds import check_host as check_default_creds
from modules.nettools import grab_banners_for_host

from modules.metrics import generate_prometheus_metrics, generate_influxdb_lines, generate_homeassistant_state
from modules.agent import get_agents, save_agent, delete_agent, ping_agent, proxy_scan, init_agents_db
from modules.ipv6 import discover_link_local, get_ndp_table, enrich_with_ipv6, scan_ipv6_subnet
from modules.lldp import capture_async as lldp_capture, get_neighbors as lldp_neighbors, topology_graph
from modules.internet import (
    get_external_ip, check_port_external, run_speedtest, shodan_lookup,
)
from modules.pcap import (
    start_capture as pcap_start, stop_capture as pcap_stop,
    get_capture_status, get_recent_packets, get_pcap_path, check_available as pcap_available,
    subscribe as pcap_subscribe, unsubscribe as pcap_unsubscribe,
)
from modules.sla import get_all_sla_stats, get_sla_stats, record_sample, init_sla_db
from modules.alerting import (
    init_alerts_db, get_rules as get_alert_rules, add_rule as add_alert_rule,
    update_rule as update_alert_rule, delete_rule as delete_alert_rule,
    get_alert_history, fire_alert,
)
from modules.nettools import (
    traceroute, dns_lookup, get_all_interfaces_bandwidth,
    detect_rogue_dhcp, get_scan_profiles_default,
)
from modules.scheduler import (
    start_scheduler, stop_scheduler, get_schedules,
    add_schedule, update_schedule, delete_schedule,
    init_schedule_db,
)



def _check_version_upgrade():
    """Clear stale cache/database when app version changes (clean install)."""
    from modules.db_path import DATA_DIR
    from pathlib import Path
    version_file = Path(DATA_DIR) / ".version"
    try:
        old_version = version_file.read_text().strip() if version_file.exists() else ""
    except Exception:
        old_version = ""
    if old_version != VERSION:
        # Version changed or first run — clear old database for clean start
        db_file = Path(DATA_DIR) / "cernis.db"
        if db_file.exists() and old_version:
            print(f"Version upgrade {old_version} → {VERSION}: clearing old database")
            db_file.unlink(missing_ok=True)
        version_file.write_text(VERSION)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _check_version_upgrade()
    init_db()
    init_devices_db()

    # Auto-start monitor with default targets from settings
    targets = _build_monitor_targets()
    configure_monitor(targets, interval=5)
    asyncio.create_task(run_monitor())

    # Start scheduler
    init_schedule_db()
    init_sla_db()
    init_alerts_db()
    init_agents_db()
    async def _scheduled_scan(cidr: str, profile_id: str, schedule_id: int):
        from modules.nettools import get_scan_profiles_default
        from modules.storage import get_setting
        profiles = {p["id"]: p for p in get_scan_profiles_default()}
        custom = get_setting("scan_profiles_custom", []) or []
        for p in custom:
            profiles[p["id"]] = p
        profile = profiles.get(profile_id, profiles["standard"])
        config = {**profile["config"], "cidr": cidr}
        print(f"Scheduled scan: {cidr} [{profile_id}]")
        # Store result via normal scan mechanism
        from modules.discovery import discover_subnet
        from modules.storage import save_scan
        discovered = await discover_subnet(cidr, max_concurrent=64, timeout=1.0)
        save_scan(cidr, [{"ip": h.ip, "mac": h.mac, "rtt_ms": h.rtt_ms} for h in discovered])

    start_scheduler(_scheduled_scan)

    print(f"CERNIS PRO v{VERSION} backend ready.")
    yield
    stop_monitor()
    stop_scheduler()


def _build_monitor_targets() -> list[MonitorTarget]:
    """Build monitor targets from saved settings + available interfaces."""
    ifaces = get_interfaces()
    targets = []

    # Find WLAN and LAN interfaces
    wlan = next((i for i in ifaces if i.name.startswith("en") and i.ipv4), None)
    lan  = next((i for i in ifaces if i.name.startswith("en") and i.gateway and i.name != (wlan.name if wlan else "")), None)

    # Gateway target per interface
    for iface in ifaces:
        if iface.gateway and iface.ipv4:
            targets.append(MonitorTarget(
                id=f"gw_{iface.name}",
                label=f"Gateway ({iface.name})",
                host=iface.gateway,
                interface=iface.name,
                enabled=True,
            ))

    # Internet check
    targets.append(MonitorTarget(
        id="internet_primary",
        label="Internet (Google DNS)",
        host="8.8.8.8",
        interface="",
        enabled=True,
    ))
    targets.append(MonitorTarget(
        id="internet_secondary",
        label="Internet (Cloudflare)",
        host="1.1.1.1",
        interface="",
        enabled=True,
    ))

    # Load custom targets from settings
    custom = get_setting("monitor_custom_targets", [])
    for t in (custom or []):
        targets.append(MonitorTarget(**t))

    return targets


app = FastAPI(title="CERNIS PRO", version=VERSION, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


@app.get("/api/status")
async def api_status():
    return {"status": "ok", "version": VERSION}


# ═══════════════════════════════════════════════════════════════
#  INTERFACES
# ═══════════════════════════════════════════════════════════════

@app.get("/api/interfaces")
async def api_interfaces():
    import sys as _sys_iface
    ifaces = get_interfaces()

    def _get_hw_info_linux(name: str) -> tuple[str, str]:
        """Determine interface type and icon via /sys/class/net on Linux."""
        try:
            # Check if wireless
            import os as _os_iface
            wireless_path = f"/sys/class/net/{name}/wireless"
            if _os_iface.path.exists(wireless_path):
                return "Wi-Fi", "📶"
            # Check type file: 1=Ethernet, 772=loopback, 776=IPv6-in-IPv4 tunnel
            type_path = f"/sys/class/net/{name}/type"
            if _os_iface.path.exists(type_path):
                with open(type_path) as f:
                    t = f.read().strip()
                if t == "772":
                    return "Loopback", "🔁"
                if t == "1":
                    return "Ethernet", "🔌"
            # Fallback: name heuristics
            if name.startswith("wl"):
                return "Wi-Fi", "📶"
            if name.startswith("eth") or name.startswith("en"):
                return "Ethernet", "🔌"
            if name.startswith("lo"):
                return "Loopback", "🔁"
            if name.startswith("tun") or name.startswith("tap"):
                return "VPN/Tunnel", "🔒"
            if name.startswith("br"):
                return "Bridge", "🔗"
            if name.startswith("docker") or name.startswith("veth"):
                return "Virtual", "🖥️"
        except Exception:
            pass
        return "", "🔗"

    def _get_hw_info_macos(name: str) -> tuple[str, str]:
        """Determine interface type and icon via networksetup on macOS."""
        import subprocess, re as _re
        hw_map: dict[str, tuple[str, str]] = {}
        try:
            out = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True, text=True, timeout=5
            ).stdout
            current_port = ""
            for line in out.splitlines():
                pm = _re.match(r"Hardware Port: (.+)", line.strip())
                dm = _re.match(r"Device: (\S+)", line.strip())
                if pm:
                    current_port = pm.group(1).strip()
                elif dm and current_port:
                    iface_name = dm.group(1).strip()
                    p = current_port
                    if "Wi-Fi" in p or "AirPort" in p:
                        icon = "📶"
                    elif "Ethernet" in p:
                        icon = "🔌"
                    elif "Thunderbolt" in p:
                        icon = "⚡"
                    elif "USB" in p:
                        icon = "🔌"
                    elif "Bluetooth" in p:
                        icon = "📘"
                    else:
                        icon = "🔗"
                    hw_map[iface_name] = (p, icon)
                    current_port = ""
        except Exception:
            pass
        return hw_map.get(name, ("", "🔗"))

    result = []
    for i in ifaces:
        d = i.to_dict()
        if _sys_iface.platform.startswith("linux"):
            hw_type, hw_icon = _get_hw_info_linux(i.name)
        elif _sys_iface.platform == "darwin":
            hw_type, hw_icon = _get_hw_info_macos(i.name)
        else:
            hw_type, hw_icon = "", "🔗"
        d["hw_type"] = hw_type
        d["hw_icon"] = hw_icon
        result.append(d)
    return result


# ═══════════════════════════════════════════════════════════════
#  SETTINGS
# ═══════════════════════════════════════════════════════════════

@app.get("/api/settings")
async def api_get_settings():
    return get_all_settings()

@app.put("/api/settings/{key}")
async def api_set_setting(key: str, payload: dict = Body(...)):
    set_setting(key, payload.get("value"))
    return {"ok": True}

@app.patch("/api/settings")
async def api_set_settings_bulk(payload: dict = Body(...)):
    for k, v in payload.items():
        set_setting(k, v)
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════
#  DEVICE DATABASE
# ═══════════════════════════════════════════════════════════════

@app.get("/api/devices/stats")
async def api_device_stats():
    return get_device_stats()

@app.get("/api/devices")
async def api_get_devices(known_only: bool = Query(default=False)):
    return get_all_devices(filter_known=known_only)

@app.get("/api/devices/{mac}")
async def api_get_device(mac: str):
    dev = get_device(mac)
    if not dev:
        return JSONResponse(status_code=404, content={"error": "Not found"})
    return dev

@app.put("/api/devices/{mac}")
async def api_update_device(mac: str, payload: dict = Body(...)):
    update_device_meta(
        mac=mac,
        label=payload.get("label"),
        tags=payload.get("tags"),
        notes=payload.get("notes"),
        category=payload.get("category"),
        is_known=payload.get("is_known"),
    )
    # Also update legacy known_devices table
    upsert_device(mac=mac, label=payload.get("label"), tags=payload.get("tags"),
                  notes=payload.get("notes"), is_known=payload.get("is_known"))
    return {"ok": True}

@app.delete("/api/devices/{mac}")
async def api_delete_device(mac: str):
    delete_device(mac)
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════
#  MONITOR
# ═══════════════════════════════════════════════════════════════

@app.get("/api/monitor/status")
async def api_monitor_status():
    return get_current_status()

@app.get("/api/monitor/events")
async def api_monitor_events(limit: int = Query(default=100, ge=1, le=1000)):
    return get_monitor_events(limit)

@app.get("/api/monitor/rtt/{target_id}")
async def api_monitor_rtt(target_id: str, limit: int = Query(default=120)):
    return get_rtt_history(target_id, limit)

@app.post("/api/monitor/targets")
async def api_add_monitor_target(payload: dict = Body(...)):
    custom = get_setting("monitor_custom_targets", []) or []
    custom.append({
        "id": payload["id"],
        "label": payload["label"],
        "host": payload["host"],
        "interface": payload.get("interface", ""),
        "enabled": payload.get("enabled", True),
    })
    set_setting("monitor_custom_targets", custom)
    # Reconfigure live
    targets = _build_monitor_targets()
    configure_monitor(targets, interval=5)
    return {"ok": True}

@app.delete("/api/monitor/targets/{target_id}")
async def api_remove_monitor_target(target_id: str):
    custom = [t for t in (get_setting("monitor_custom_targets", []) or [])
              if t["id"] != target_id]
    set_setting("monitor_custom_targets", custom)
    targets = _build_monitor_targets()
    configure_monitor(targets, interval=5)
    return {"ok": True}

@app.websocket("/ws/monitor")
async def ws_monitor(websocket: WebSocket):
    """Subscribe to live monitor updates."""
    await websocket.accept()
    monitor_subscribe(websocket)
    # Send current status immediately
    await websocket.send_json({"type": "monitor_status", "status": get_current_status()})
    try:
        while True:
            await asyncio.sleep(30)
    except Exception:
        pass
    finally:
        monitor_unsubscribe(websocket)


# ═══════════════════════════════════════════════════════════════
#  ARP GUARD
# ═══════════════════════════════════════════════════════════════

@app.post("/api/security/arp-scan")
async def api_arp_scan():
    alerts = await scan_arp_once()
    return {"alerts": [a.to_dict() for a in alerts], "count": len(alerts)}

@app.get("/api/security/arp-alerts")
async def api_arp_alerts(limit: int = Query(default=50)):
    return get_arp_alerts(limit)

@app.get("/api/security/arp-baseline")
async def api_arp_baseline():
    return get_arp_baseline()

@app.delete("/api/security/arp-baseline")
async def api_clear_arp_baseline():
    clear_baseline()
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════
#  MISC (WoL, mDNS, SSDP, ARP, Vendor)
# ═══════════════════════════════════════════════════════════════

@app.post("/api/wol")
async def api_wol(payload: dict = Body(...)):
    ok = send_wol(payload.get("mac", ""), payload.get("broadcast", "255.255.255.255"))
    return {"ok": ok}

@app.get("/api/mdns")
async def api_mdns(duration: float = Query(default=5.0, ge=1.0, le=30.0)):
    services = await discover_mdns(duration)
    return [{"ip": s.ip, "name": s.name, "service_type": s.service_type,
             "port": s.port, "hostname": s.hostname,
             "properties": s.properties, "is_ndi": s.is_ndi} for s in services]

@app.get("/api/ssdp")
async def api_ssdp(timeout: float = Query(default=4.0, ge=1.0, le=15.0)):
    devices = await discover_ssdp(timeout)
    return [{"ip": d.ip, "location": d.location, "server": d.server,
             "st": d.st, "usn": d.usn} for d in devices]

@app.get("/api/arp")
async def api_arp():
    return get_arp_table()

@app.get("/api/vendor/{mac}")
async def api_vendor(mac: str):
    return {"mac": mac, "vendor": lookup_vendor(mac)}


# ═══════════════════════════════════════════════════════════════
#  SCAN HISTORY + EXPORT
# ═══════════════════════════════════════════════════════════════

@app.get("/api/history")
async def api_history(limit: int = Query(default=20, ge=1, le=100)):
    return get_scan_history(limit)

@app.get("/api/history/{scan_id}")
async def api_history_detail(scan_id: int):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return JSONResponse(status_code=404, content={"error": "Not found"})
    return scan

@app.get("/api/export/json")
async def api_export_json(scan_id: int = Query(...)):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return JSONResponse(status_code=404, content={"error": "Not found"})
    return JSONResponse(content=scan["hosts"])

@app.get("/api/export/csv")
async def api_export_csv(scan_id: int = Query(...)):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return JSONResponse(status_code=404, content={"error": "Not found"})
    lines = ["ip,mac,vendor,hostname,ports,os_guess,rtt_ms"]
    for h in scan["hosts"]:
        ports = "|".join(str(p["port"]) for p in (h.get("ports") or []))
        lines.append(",".join([h.get("ip",""), h.get("mac",""), h.get("vendor",""),
                                h.get("hostname",""), ports,
                                h.get("os_guess",""), str(h.get("rtt_ms",""))]))
    return Response(content="\n".join(lines), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=cernis_scan_{scan_id}.csv"})




# ═══════════════════════════════════════════════════════════════
#  FRITZBOX
# ═══════════════════════════════════════════════════════════════

_fritz_cache: dict = {}  # host -> FritzBox instance

@app.get("/api/fritz/detect")
async def api_fritz_detect():
    """Auto-detect FritzBox — checks saved host + common addresses."""
    try:
        loop = asyncio.get_event_loop()
        host = await asyncio.wait_for(
            loop.run_in_executor(None, detect_fritzbox), timeout=10.0
        )
        if host:
            # Also save as fritz_host if not already set
            if not get_setting("fritz_host", None):
                set_setting("fritz_host", host)
            return {"found": True, "host": host}
        # Last resort: check if fritz_host is saved and reachable
        saved = get_setting("fritz_host", None)
        if saved:
            import socket as _sock
            try:
                resolved = _sock.getaddrinfo(saved, 49000, _sock.AF_INET, _sock.SOCK_STREAM)
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(2.0)
                if s.connect_ex((resolved[0][4][0], 49000)) == 0:
                    s.close()
                    return {"found": True, "host": saved}
                s.close()
            except Exception:
                pass
        return {"found": False, "host": None, "error": "No FritzBox found on network"}
    except Exception as e:
        return {"found": False, "host": None, "error": str(e)}

@app.post("/api/fritz/connect")
async def api_fritz_connect(payload: dict = Body(...)):
    """Connect to FritzBox with credentials. Validates auth before saving."""
    host     = payload.get("host", "fritz.box")
    user     = payload.get("user", "")
    password = payload.get("password", "")
    try:
        fritz = FritzBox(host, user=user, password=password)
        loop = asyncio.get_event_loop()
        status = await asyncio.wait_for(
            loop.run_in_executor(None, fritz.get_status), timeout=20.0
        )
        if status.auth_error:
            return JSONResponse(status_code=401, content={
                "error": "Authentication failed — check username and password. "
                         "Ensure TR-064 is enabled in FritzBox settings."
            })
        _fritz_cache[host] = fritz
        set_setting("fritz_host", host)
        set_setting("fritz_user", user)
        set_setting("fritz_password", encrypt(password))  # stored encrypted
        return {"ok": True, "status": status.to_dict()}
    except asyncio.TimeoutError:
        return JSONResponse(status_code=503, content={"error": "Connection timeout — check host address"})
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


@app.post("/api/fritz/disconnect")
async def api_fritz_disconnect():
    """Disconnect from FritzBox — clear cached connection and saved credentials."""
    host = get_setting("fritz_host", None)
    if host and host in _fritz_cache:
        del _fritz_cache[host]
    set_setting("fritz_host", "")
    set_setting("fritz_user", "")
    set_setting("fritz_password", "")
    return {"ok": True}

@app.get("/api/fritz/status")
async def api_fritz_status():
    host     = get_setting("fritz_host", "fritz.box")
    user     = get_setting("fritz_user", "")
    password = decrypt(get_setting("fritz_password", ""))  # decrypt on use
    try:
        fritz = _fritz_cache.get(host) or FritzBox(host, user=user, password=password)
        loop = asyncio.get_event_loop()
        status = await asyncio.wait_for(
            loop.run_in_executor(None, fritz.get_status), timeout=20.0
        )
        return status.to_dict()
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})

@app.get("/api/fritz/wlan-clients")
async def api_fritz_wlan_clients():
    host     = get_setting("fritz_host", "fritz.box")
    user     = get_setting("fritz_user", "")
    password = decrypt(get_setting("fritz_password", ""))
    try:
        fritz = _fritz_cache.get(host) or FritzBox(host, user=user, password=password)
        loop = asyncio.get_event_loop()
        clients = await asyncio.wait_for(
            loop.run_in_executor(None, fritz.get_wlan_clients), timeout=15.0
        )
        from modules.vendor import lookup_vendor as lv
        return [{"mac": c.mac, "ip": c.ip, "hostname": c.hostname,
                 "signal_dbm": c.signal_dbm, "speed_mbps": c.speed_mbps,
                 "band": c.band, "vendor": lv(c.mac)} for c in clients]
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})

@app.get("/api/fritz/log")
async def api_fritz_log(limit: int = Query(default=50, ge=1, le=200)):
    host     = get_setting("fritz_host", "fritz.box")
    user     = get_setting("fritz_user", "")
    password = decrypt(get_setting("fritz_password", ""))
    try:
        fritz = _fritz_cache.get(host) or FritzBox(host, user=user, password=password)
        loop = asyncio.get_event_loop()
        entries = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: fritz.get_log(limit)), timeout=10.0
        )
        return [{"id": e.id, "timestamp": e.timestamp, "message": e.message} for e in entries]
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})

@app.get("/api/fritz/hosts")
async def api_fritz_hosts():
    host     = get_setting("fritz_host", "fritz.box")
    user     = get_setting("fritz_user", "")
    password = decrypt(get_setting("fritz_password", ""))
    try:
        fritz = _fritz_cache.get(host) or FritzBox(host, user=user, password=password)
        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, fritz.get_hosts), timeout=15.0
        )
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


# ═══════════════════════════════════════════════════════════════
#  CVE LOOKUP
# ═══════════════════════════════════════════════════════════════

@app.post("/api/cve/lookup")
async def api_cve_lookup(payload: dict = Body(...)):
    """Look up CVEs for a list of open ports."""
    ports = payload.get("ports", [])
    if not ports:
        return []
    loop = asyncio.get_event_loop()
    cves = await loop.run_in_executor(None, lookup_cves_for_host, ports)
    return [c.to_dict() for c in cves]


# ═══════════════════════════════════════════════════════════════
#  PDF REPORT EXPORT
# ═══════════════════════════════════════════════════════════════

@app.get("/api/export/pdf")
async def api_export_pdf(scan_id: int = Query(...)):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return JSONResponse(status_code=404, content={"error": "Scan not found"})
    if not REPORTLAB_AVAILABLE:
        return JSONResponse(status_code=501,
                            content={"error": "reportlab not installed. Run: pip install reportlab"})
    # Optionally include fritz status
    fritz_status = None
    fritz_host = get_setting("fritz_host", None)
    if fritz_host:
        try:
            fritz = _fritz_cache.get(fritz_host) or FritzBox(fritz_host)
            loop = asyncio.get_event_loop()
            fs = await loop.run_in_executor(None, fritz.get_status)
            fritz_status = fs.to_dict() if fs.reachable else None
        except Exception:
            pass

    loop = asyncio.get_event_loop()
    pdf_bytes = await loop.run_in_executor(
        None, lambda: generate_report(scan, fritz_status)
    )
    filename = f"cernis_scan_{scan_id}_{scan.get('scanned_at','')[:10]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/api/fritz/hosts-debug")
async def api_fritz_hosts_debug():
    """Show raw FritzBox host data for debugging."""
    host     = get_setting("fritz_host", "fritz.box")
    user     = get_setting("fritz_user", "")
    password = decrypt(get_setting("fritz_password", ""))
    try:
        fritz = _fritz_cache.get(host) or FritzBox(host, user=user, password=password)
        loop = asyncio.get_event_loop()
        hosts = await asyncio.wait_for(loop.run_in_executor(None, fritz.get_hosts), timeout=15.0)
        # Return first 3 hosts to see field names
        return hosts[:3] if hosts else []
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/fritz/debug")
async def api_fritz_debug():
    """Debug: test individual SOAP calls and return raw results."""
    host     = get_setting("fritz_host", "fritz.box")
    user     = get_setting("fritz_user", "")
    password = decrypt(get_setting("fritz_password", ""))
    fritz = _fritz_cache.get(host) or FritzBox(host, user=user, password=password)

    results = {}
    import xml.etree.ElementTree as ET

    # Test each service
    tests = [
        ("device_info", "GetInfo"),
        ("wan_ppp",     "GetStatusInfo"),
        ("wan_ip",      "GetStatusInfo"),
        ("wan_common",  "GetCommonLinkProperties"),
        ("wlan1",       "GetInfo"),
        ("hosts",       "GetHostNumberOfEntries"),
    ]
    for svc, action in tests:
        try:
            r = fritz._call(svc, action)
            if r is None:
                results[f"{svc}/{action}"] = "None (no response)"
            else:
                # Return first few tags found
                tags = {child.tag.split("}")[-1]: child.text for child in r.iter() if child.text and child.text.strip()}
                results[f"{svc}/{action}"] = tags
        except Exception as e:
            results[f"{svc}/{action}"] = f"ERROR: {e}"
    return results


# ═══════════════════════════════════════════════════════════════
#  SNMP
# ═══════════════════════════════════════════════════════════════

@app.get("/api/snmp/check")
async def api_snmp_check():
    return {"available": check_snmp_available()}

@app.post("/api/snmp/query")
async def api_snmp_query(payload: dict = Body(...)):
    ip = payload.get("ip", "")
    communities = payload.get("communities", ["public", "private"])
    if not ip:
        return JSONResponse(status_code=400, content={"error": "IP required"})
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: snmp_query(ip, communities)),
            timeout=15.0
        )
        return result.to_dict()
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


# ═══════════════════════════════════════════════════════════════
#  NETWORK TOOLS
# ═══════════════════════════════════════════════════════════════

@app.post("/api/tools/traceroute")
async def api_traceroute(payload: dict = Body(...)):
    target = payload.get("target", "")
    max_hops = int(payload.get("max_hops", 30))
    if not target:
        return JSONResponse(status_code=400, content={"error": "target required"})
    try:
        hops = await asyncio.wait_for(traceroute(target, max_hops), timeout=90.0)
        return [{"hop": h.hop, "ip": h.ip, "hostname": h.hostname,
                 "rtt_ms": h.rtt_ms, "timeout": h.timeout} for h in hops]
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})

@app.post("/api/tools/dns")
async def api_dns_lookup(payload: dict = Body(...)):
    query = payload.get("query", "")
    record_types = payload.get("record_types", None)
    if not query:
        return JSONResponse(status_code=400, content={"error": "query required"})
    try:
        results = await asyncio.wait_for(dns_lookup(query, record_types), timeout=15.0)
        return [r.to_dict() for r in results]
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})

@app.get("/api/tools/bandwidth")
async def api_bandwidth():
    return get_all_interfaces_bandwidth()

@app.post("/api/tools/rogue-dhcp")
async def api_rogue_dhcp(payload: dict = Body(default={})):
    gateway = payload.get("gateway", None)
    try:
        servers = await asyncio.wait_for(detect_rogue_dhcp(gateway), timeout=10.0)
        return [{"ip": s.ip, "mac": s.mac, "is_known": s.is_known, "is_rogue": s.is_rogue}
                for s in servers]
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


# ═══════════════════════════════════════════════════════════════
#  SCAN PROFILES
# ═══════════════════════════════════════════════════════════════

@app.get("/api/profiles")
async def api_get_profiles():
    defaults = get_scan_profiles_default()
    custom = get_setting("scan_profiles_custom", []) or []
    return {"defaults": defaults, "custom": custom}

@app.post("/api/profiles")
async def api_save_profile(payload: dict = Body(...)):
    custom = get_setting("scan_profiles_custom", []) or []
    # Replace if same id exists
    custom = [p for p in custom if p.get("id") != payload.get("id")]
    custom.append(payload)
    set_setting("scan_profiles_custom", custom)
    return {"ok": True}

@app.delete("/api/profiles/{profile_id}")
async def api_delete_profile(profile_id: str):
    custom = [p for p in (get_setting("scan_profiles_custom", []) or [])
              if p.get("id") != profile_id]
    set_setting("scan_profiles_custom", custom)
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════
#  SCHEDULED SCANS
# ═══════════════════════════════════════════════════════════════

@app.get("/api/schedules")
async def api_get_schedules():
    return get_schedules()

@app.post("/api/schedules")
async def api_add_schedule(payload: dict = Body(...)):
    schedule_id = add_schedule(
        name=payload.get("name", "Scheduled Scan"),
        cidr=payload.get("cidr", "192.168.1.0/24"),
        profile_id=payload.get("profile_id", "standard"),
        schedule=payload.get("schedule", "interval:1h"),
    )
    return {"ok": True, "id": schedule_id}

@app.patch("/api/schedules/{schedule_id}")
async def api_update_schedule(schedule_id: int, payload: dict = Body(...)):
    update_schedule(schedule_id,
                    enabled=payload.get("enabled"),
                    name=payload.get("name"))
    return {"ok": True}

@app.delete("/api/schedules/{schedule_id}")
async def api_delete_schedule(schedule_id: int):
    delete_schedule(schedule_id)
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════
#  CVE — with public/local distinction
# ═══════════════════════════════════════════════════════════════

@app.post("/api/cve/lookup-v2")
async def api_cve_lookup_v2(payload: dict = Body(...)):
    """CVE lookup with public/local port distinction."""
    ports = payload.get("ports", [])
    external_ip = payload.get("external_ip", "")  # from FritzBox
    fritz_forwards = payload.get("port_forwards", [])  # forwarded ports

    if not ports:
        return []

    # Mark each port as public or local
    forwarded_ports = {int(p) for p in fritz_forwards}
    enriched_ports = []
    for p in ports:
        port_num = p["port"]
        is_public = port_num in forwarded_ports
        enriched_ports.append({**p, "is_public": is_public})

    loop = asyncio.get_event_loop()
    cves = await loop.run_in_executor(None, lookup_cves_for_host, ports)

    result = []
    for cve in cves:
        is_public = cve.port in forwarded_ports
        d = cve.to_dict()
        d["is_public"] = is_public
        d["risk_level"] = "critical" if (is_public and cve.severity in ["CRITICAL","HIGH"]) else                           "high" if is_public else                           "medium" if cve.severity in ["CRITICAL","HIGH"] else "low"
        result.append(d)

    result.sort(key=lambda x: (
        0 if x["risk_level"] == "critical" else
        1 if x["risk_level"] == "high" else
        2 if x["risk_level"] == "medium" else 3
    ))
    return result


# ═══════════════════════════════════════════════════════════════
#  SSL/TLS INSPECTOR
# ═══════════════════════════════════════════════════════════════

@app.post("/api/tls/inspect")
async def api_tls_inspect(payload: dict = Body(...)):
    host = payload.get("host", "")
    port = int(payload.get("port", 443))
    if not host:
        return JSONResponse(status_code=400, content={"error": "host required"})
    loop = asyncio.get_event_loop()
    result = await asyncio.wait_for(
        loop.run_in_executor(None, lambda: inspect_tls(host, port)),
        timeout=10.0
    )
    return result.to_dict()

@app.post("/api/tls/inspect-host")
async def api_tls_inspect_host(payload: dict = Body(...)):
    host  = payload.get("host", "")
    ports = payload.get("ports", [])
    results = await inspect_host_ports(host, ports)
    return results


# ═══════════════════════════════════════════════════════════════
#  SLA / UPTIME
# ═══════════════════════════════════════════════════════════════

@app.get("/api/sla")
async def api_sla_all(days: int = Query(default=30, ge=1, le=90)):
    return get_all_sla_stats(days)

@app.get("/api/sla/{target_id}")
async def api_sla_target(target_id: str, days: int = Query(default=30)):
    return get_sla_stats(target_id, days)


# ═══════════════════════════════════════════════════════════════
#  ALERTING
# ═══════════════════════════════════════════════════════════════

@app.get("/api/alerts/rules")
async def api_alert_rules():
    return get_alert_rules()

@app.post("/api/alerts/rules")
async def api_add_alert_rule(payload: dict = Body(...)):
    rule_id = add_alert_rule(
        name=payload.get("name", "Alert"),
        rule_type=payload.get("rule_type", "host_down"),
        target=payload.get("target", "any"),
        threshold=int(payload.get("threshold", 60)),
        notify_email=bool(payload.get("notify_email", False)),
        notify_macos=bool(payload.get("notify_macos", True)),
    )
    return {"ok": True, "id": rule_id}

@app.patch("/api/alerts/rules/{rule_id}")
async def api_update_alert_rule(rule_id: int, payload: dict = Body(...)):
    update_alert_rule(rule_id, **payload)
    return {"ok": True}

@app.delete("/api/alerts/rules/{rule_id}")
async def api_delete_alert_rule(rule_id: int):
    delete_alert_rule(rule_id)
    return {"ok": True}

@app.get("/api/alerts/history")
async def api_alert_history(limit: int = Query(default=50)):
    return get_alert_history(limit)

@app.get("/api/alerts/smtp")
async def api_get_smtp():
    cfg = get_setting("smtp_config", {}) or {}
    # Never return password
    safe = {k: v for k, v in cfg.items() if k != "password"}
    safe["password"] = "••••••••" if cfg.get("password") else ""
    return safe

@app.put("/api/alerts/smtp")
async def api_set_smtp(payload: dict = Body(...)):
    existing = get_setting("smtp_config", {}) or {}
    if payload.get("password") == "••••••••":
        payload["password"] = existing.get("password", "")
    from modules.crypto import encrypt
    if payload.get("password"):
        payload["password"] = encrypt(payload["password"])
    set_setting("smtp_config", payload)
    return {"ok": True}

@app.post("/api/alerts/test")
async def api_test_alert():
    """Send a test notification — directly tests SMTP without requiring alert rules."""
    smtp_config = get_setting("smtp_config", {}) or {}
    from modules.crypto import decrypt
    if smtp_config.get("password"):
        smtp_config["password"] = decrypt(smtp_config["password"])

    if not smtp_config.get("host") or not smtp_config.get("to"):
        return JSONResponse(status_code=400, content={
            "error": "SMTP not configured — set host and recipient address first"
        })

    # Test SMTP directly instead of going through fire_alert (which requires rules)
    from modules.alerting import notify_email
    body = (f"Test alert from CERNIS PRO\n"
            f"Time: {__import__('time').strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"This confirms your SMTP configuration is working.")
    success = notify_email("Test Alert", body, smtp_config)
    if success:
        return {"ok": True, "message": "Test email sent successfully"}
    return JSONResponse(status_code=503, content={
        "error": "SMTP connection failed — check host, port, username and password"
    })



# ═══════════════════════════════════════════════════════════════
#  DEFAULT CREDENTIALS
# ═══════════════════════════════════════════════════════════════

@app.post("/api/security/default-creds")
async def api_default_creds(payload: dict = Body(...)):
    host   = payload.get("host", "")
    ports  = payload.get("ports", [])
    vendor = payload.get("vendor", "")
    if not host or not ports:
        return JSONResponse(status_code=400, content={"error": "host and ports required"})
    try:
        results = await asyncio.wait_for(
            check_default_creds(host, ports, vendor),
            timeout=30.0
        )
        return [r.to_dict() for r in results]
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


# ═══════════════════════════════════════════════════════════════
#  HTTP BANNER GRABBING
# ═══════════════════════════════════════════════════════════════

@app.post("/api/tools/banner")
async def api_banner(payload: dict = Body(...)):
    host  = payload.get("host", "")
    ports = payload.get("ports", [])
    if not host:
        return JSONResponse(status_code=400, content={"error": "host required"})
    # Normalize ports: accept both [80, 443] and [{"port":80}, ...]
    normalized = []
    for p in ports:
        if isinstance(p, int):
            normalized.append({"port": p})
        elif isinstance(p, dict):
            normalized.append(p)
    try:
        results = await asyncio.wait_for(
            grab_banners_for_host(host, normalized),
            timeout=20.0
        )
        return results
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


# ═══════════════════════════════════════════════════════════════
#  SYSTEM INFO (scapy availability etc.)
# ═══════════════════════════════════════════════════════════════


@app.post("/api/system/install")
async def api_install_package(payload: dict = Body(...)):
    """Install a Python package via pip (optional deps only)."""
    pkg = payload.get("package", "")
    ALLOWED = {"scapy", "pysnmp", "dnspython", "reportlab", "websockets",
               "apscheduler", "fritzconnection", "cryptography"}
    if pkg not in ALLOWED:
        return JSONResponse(status_code=400, content={"error": f"Package '{pkg}' not in allowed list"})
    import subprocess, sys
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", pkg],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            return {"ok": True, "package": pkg, "message": f"{pkg} installed successfully"}
        else:
            return {"ok": False, "package": pkg, "error": result.stderr[:200]}
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})

def _check_nmap_binary() -> bool:
    """Check if nmap binary is installed (not Python module)."""
    import shutil, subprocess
    if shutil.which("nmap"):
        return True
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, timeout=3)
        return True
    except Exception:
        return False

@app.get("/api/system/info")
async def api_system_info():
    """Returns availability of optional dependencies."""
    import importlib
    def has(mod):
        try: importlib.import_module(mod); return True
        except ImportError: return False
    return {
        "version": VERSION,
        "scapy":       has("scapy"),
        "nmap":        _check_nmap_binary(),
        "pysnmp":      has("pysnmp"),
        "fritzconnection": has("fritzconnection"),
        "dnspython":   has("dns"),
        "apscheduler": has("apscheduler"),
        "reportlab":   has("reportlab"),
        "cryptography":has("cryptography"),
        "websockets":  has("websockets"),
        "version":     VERSION,
    }


# ═══════════════════════════════════════════════════════════════
#  INTERNET TOOLS
# ═══════════════════════════════════════════════════════════════

@app.get("/api/internet/external-ip")
async def api_external_ip():
    return await get_external_ip()

@app.post("/api/internet/port-check")
async def api_port_check(payload: dict = Body(...)):
    port = int(payload.get("port", 80))
    return await check_port_external(port)

@app.post("/api/internet/speedtest")
async def api_speedtest():
    try:
        return await asyncio.wait_for(run_speedtest(), timeout=60.0)
    except asyncio.TimeoutError:
        return JSONResponse(status_code=503, content={"error": "Speed test timed out"})

@app.post("/api/internet/shodan")
async def api_shodan(payload: dict = Body(default={})):
    ip      = payload.get("ip", "")
    api_key = payload.get("api_key", "") or get_setting("shodan_api_key", "") or ""
    if not ip:
        ext = await get_external_ip()
        ip = ext.get("ip", "")
    if not ip:
        return JSONResponse(status_code=400, content={"error": "Could not determine IP"})
    return await shodan_lookup(ip, api_key)

@app.put("/api/settings/shodan-key")
async def api_set_shodan_key(payload: dict = Body(...)):
    set_setting("shodan_api_key", payload.get("api_key", ""))
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════
#  FRITZ PORT FORWARDINGS
# ═══════════════════════════════════════════════════════════════

@app.get("/api/fritz/port-forwardings")
async def api_fritz_port_forwardings():
    host     = get_setting("fritz_host", "fritz.box")
    user     = get_setting("fritz_user", "")
    password = decrypt(get_setting("fritz_password", ""))
    try:
        fritz = _fritz_cache.get(host) or FritzBox(host, user=user, password=password)
        loop = asyncio.get_event_loop()
        rules = await asyncio.wait_for(
            loop.run_in_executor(None, fritz.get_port_forwardings),
            timeout=15.0
        )
        return rules
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


# ═══════════════════════════════════════════════════════════════
#  WAKE ON LAN
# ═══════════════════════════════════════════════════════════════

@app.post("/api/wol/send")
async def api_wol_send(payload: dict = Body(...)):
    mac = payload.get("mac", "")
    if not mac:
        return JSONResponse(status_code=400, content={"error": "MAC required"})
    loop = asyncio.get_event_loop()
    try:
        from modules.wol import send_wol
        await loop.run_in_executor(None, send_wol, mac)
        return {"ok": True, "mac": mac}
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})

# ═══════════════════════════════════════════════════════════════
#  METRICS / GRAFANA / PROMETHEUS
# ═══════════════════════════════════════════════════════════════

@app.get("/metrics")
async def prometheus_metrics():
    """Prometheus-compatible metrics endpoint."""
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(generate_prometheus_metrics(), media_type="text/plain; version=0.0.4")

@app.get("/api/export/influxdb")
async def influxdb_export():
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(generate_influxdb_lines(), media_type="text/plain")

@app.get("/api/export/homeassistant")
async def homeassistant_export():
    return generate_homeassistant_state()


# ═══════════════════════════════════════════════════════════════
#  REMOTE AGENTS
# ═══════════════════════════════════════════════════════════════

@app.get("/api/agents")
async def api_get_agents():
    return get_agents()

@app.post("/api/agents")
async def api_add_agent(payload: dict = Body(...)):
    save_agent(payload)
    return {"ok": True}

@app.delete("/api/agents/{agent_id}")
async def api_delete_agent(agent_id: str):
    delete_agent(agent_id)
    return {"ok": True}

@app.get("/api/agents/{agent_id}/ping")
async def api_ping_agent(agent_id: str):
    agents = get_agents()
    agent = next((a for a in agents if a["id"] == agent_id), None)
    if not agent:
        return JSONResponse(status_code=404, content={"error": "Agent not found"})
    from modules.agent import get_agent_token
    token = get_agent_token(agent_id)
    result = await ping_agent(agent["url"], token)
    return result

@app.post("/api/agents/{agent_id}/scan")
async def api_agent_scan(agent_id: str, payload: dict = Body(...)):
    from modules.agent import get_agent_token
    agents = get_agents()
    agent = next((a for a in agents if a["id"] == agent_id), None)
    if not agent:
        return JSONResponse(status_code=404, content={"error": "Agent not found"})
    token = get_agent_token(agent_id)
    try:
        results = await asyncio.wait_for(
            proxy_scan(agent["url"], token, payload),
            timeout=300.0
        )
        return results
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


# ═══════════════════════════════════════════════════════════════
#  IPv6
# ═══════════════════════════════════════════════════════════════

@app.get("/api/ipv6/ndp")
async def api_ndp_table():
    loop = asyncio.get_event_loop()
    table = await loop.run_in_executor(None, get_ndp_table)
    return [{"ipv6": ip, "mac": mac} for ip, mac in table.items()]

@app.post("/api/ipv6/discover")
async def api_ipv6_discover(payload: dict = Body(default={})):
    interface = payload.get("interface", "")
    duration  = float(payload.get("duration", 5.0))
    try:
        hosts = await asyncio.wait_for(
            discover_link_local(interface, duration), timeout=duration + 3
        )
        return [h.to_dict() for h in hosts]
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})

@app.post("/api/ipv6/scan")
async def api_ipv6_scan(payload: dict = Body(...)):
    cidr6 = payload.get("cidr6", "")
    if not cidr6:
        return JSONResponse(status_code=400, content={"error": "cidr6 required"})
    hosts = await scan_ipv6_subnet(cidr6)
    return [h.to_dict() for h in hosts]


# ═══════════════════════════════════════════════════════════════
#  LLDP / CDP TOPOLOGY
# ═══════════════════════════════════════════════════════════════

@app.get("/api/lldp/neighbors")
async def api_lldp_neighbors():
    return lldp_neighbors()

@app.post("/api/lldp/capture")
async def api_lldp_capture(payload: dict = Body(default={})):
    interface = payload.get("interface", "")
    duration  = float(payload.get("duration", 30.0))
    try:
        neighbors = await asyncio.wait_for(
            lldp_capture(interface or None, duration),
            timeout=duration + 5
        )
        return neighbors
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})

@app.get("/api/lldp/topology")
async def api_lldp_topology():
    neighbors = lldp_neighbors()
    # Get latest scan hosts
    history = get_scan_history(limit=1)
    hosts = []
    if history:
        scan = get_scan_by_id(history[0]["id"])
        hosts = scan.get("hosts", []) if scan else []
    return topology_graph(neighbors, hosts)


# ═══════════════════════════════════════════════════════════════
#  PACKET CAPTURE
# ═══════════════════════════════════════════════════════════════

@app.get("/api/pcap/available")
async def api_pcap_available():
    return {"available": pcap_available()}

@app.post("/api/pcap/start")
async def api_pcap_start(payload: dict = Body(default={})):
    interface  = payload.get("interface", "")
    bpf_filter = payload.get("filter", "")
    max_pkts   = int(payload.get("max_packets", 5000))
    ok = await pcap_start(interface or None, bpf_filter, max_pkts)
    return {"ok": ok, "available": pcap_available()}

@app.post("/api/pcap/stop")
async def api_pcap_stop():
    pcap_stop()
    return {"ok": True}

@app.get("/api/pcap/status")
async def api_pcap_status():
    return get_capture_status()

@app.get("/api/pcap/packets")
async def api_pcap_packets(limit: int = Query(default=100, ge=1, le=1000)):
    return get_recent_packets(limit)

@app.get("/api/pcap/download")
async def api_pcap_download():
    path = get_pcap_path()
    if not path:
        return JSONResponse(status_code=404, content={"error": "No capture file available"})
    from fastapi.responses import FileResponse
    return FileResponse(path, media_type="application/octet-stream",
                        filename=os.path.basename(path))

@app.websocket("/ws/pcap")
async def ws_pcap(websocket: WebSocket):
    """Stream live packets to browser."""
    await websocket.accept()

    async def send_packet(ps):
        try:
            await websocket.send_json({"type": "packet", **ps.to_dict()})
        except Exception:
            pass

    pcap_subscribe(send_packet)
    try:
        while True:
            await asyncio.sleep(5)
    except Exception:
        pass
    finally:
        pcap_unsubscribe(send_packet)

# ═══════════════════════════════════════════════════════════════
#  WEBSOCKET — FULL SCAN
# ═══════════════════════════════════════════════════════════════

def _classify_host(ports: list, vendor: str, mac: str, mdns_services: list,
                   hostname: str, fritz_hostname: str = "") -> tuple[str, str]:
    """
    Returns (os_guess, category) where category is one of:
    router | nas | mobile | desktop | server | iot | printer | tv | unknown
    """
    vendor_l   = vendor.lower()
    host_l     = (hostname or fritz_hostname or "").lower()
    port_nums  = {p["port"] for p in ports}
    mdns_types = {s.get("type","").lower() for s in mdns_services}

    # ── Router / Gateway ──────────────────────────────────────
    if any(x in vendor_l for x in ["avm", "asus", "netgear", "tp-link", "d-link",
                                     "ubiquiti", "mikrotik", "cisco", "juniper",
                                     "aruba", "fritz", "linksys", "buffalo"]):
        return "Router/Network Device", "router"
    if any(x in host_l for x in ["router", "gateway", "fritzbox", "fritz"]):
        return "Router/Network Device", "router"

    # ── NAS ───────────────────────────────────────────────────
    if any(x in vendor_l for x in ["synology", "qnap", "western digital", "wd",
                                     "buffalo", "netgear readynas", "seagate"]):
        return "NAS (Linux)", "nas"
    if port_nums & {5000, 5001, 5005, 5006} and 22 in port_nums:
        return "NAS (Linux)", "nas"

    # ── Printer ───────────────────────────────────────────────
    if port_nums & {9100, 515, 631} or "_ipp" in mdns_types or "_pdl-datastream" in mdns_types:
        return "Printer", "printer"
    if any(x in vendor_l for x in ["hewlett", "hp ", "epson", "canon", "brother",
                                     "lexmark", "xerox", "kyocera", "ricoh"]):
        return "Printer", "printer"

    # ── Smart TV ──────────────────────────────────────────────
    if port_nums & {8008, 8009, 8060, 9080} or "_googlecast" in mdns_types:
        return "Smart TV / Chromecast", "tv"
    if any(x in vendor_l for x in ["lg electronics", "sony", "philips", "hisense",
                                     "vestel", "tcl", "vizio"]):
        if not port_nums & {22, 445}: return "Smart TV", "tv"

    # ── Apple mobile (iOS) ────────────────────────────────────
    if any(x in host_l for x in ["iphone", "ipad", "ipod"]):
        return "iOS", "mobile"
    if 62078 in port_nums and "apple" in vendor_l:
        return "iOS", "mobile"

    # ── Apple desktop/laptop ──────────────────────────────────
    if "apple" in vendor_l or any(x in host_l for x in ["macbook", "imac", "mac-mini", "mac-pro"]):
        if port_nums & {548, 5009} or "_afpovertcp" in mdns_types:
            return "macOS", "desktop"
        if "_airplay" in mdns_types or "_raop" in mdns_types:
            return "macOS/iOS", "desktop"
        return "Apple", "desktop"

    # ── Android / Mobile ─────────────────────────────────────
    if any(x in vendor_l for x in ["samsung", "huawei", "xiaomi", "oneplus",
                                     "google", "motorola", "oppo", "realme", "nothing"]):
        return "Android", "mobile"
    if any(x in host_l for x in ["android", "galaxy", "pixel", "iphone", "phone"]):
        return "Android", "mobile"

    # ── Windows ───────────────────────────────────────────────
    if port_nums & {135, 139, 445}:
        if 3389 in port_nums: return "Windows (RDP)", "desktop"
        return "Windows", "desktop"

    # ── Linux Server ─────────────────────────────────────────
    if 22 in port_nums and (80 in port_nums or 443 in port_nums or 8080 in port_nums):
        return "Linux Server", "server"
    if 22 in port_nums and port_nums & {25, 110, 143, 3306, 5432, 6379, 27017}:
        return "Linux Server", "server"

    # ── Raspberry Pi / Linux ──────────────────────────────────
    if "raspberry" in vendor_l or "raspberry" in host_l:
        return "Linux (Raspberry Pi)", "iot"
    if 22 in port_nums and not port_nums & {135, 445}:
        return "Linux", "server"

    # ── IoT ───────────────────────────────────────────────────
    if port_nums & {1883, 8883} or "_mqtt" in mdns_types:
        return "IoT Device (MQTT)", "iot"
    if port_nums & {554, 8554}:
        return "IP Camera / NVR", "iot"
    if any(x in vendor_l for x in ["shelly", "sonoff", "tuya", "espressif",
                                     "tasmota", "home assistant"]):
        return "Smart Home / IoT", "iot"

    return "", "unknown"


def _guess_os(ports: list, vendor: str, mac: str, mdns_services: list,
              hostname: str, fritz_hostname: str = "") -> str:
    os_guess, _ = _classify_host(ports, vendor, mac, mdns_services, hostname, fritz_hostname)
    return os_guess


def _get_category(ports: list, vendor: str, mac: str, mdns_services: list,
                  hostname: str, fritz_hostname: str = "") -> str:
    _, category = _classify_host(ports, vendor, mac, mdns_services, hostname, fritz_hostname)
    return category


@app.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket):
    await websocket.accept()
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=10)
        config = json.loads(raw)
    except Exception as e:
        await websocket.send_json({"type": "error", "message": str(e)})
        return

    cidr_raw      = config.get("cidr", "192.168.1.0/24")
    ping_timeout  = float(config.get("ping_timeout", 1.5))
    do_port_scan  = config.get("port_scan", True)
    port_mode     = config.get("port_mode", "socket")
    do_mdns       = config.get("mdns_scan", True)
    mdns_duration = float(config.get("mdns_duration", 8.0))
    do_resolve    = config.get("resolve_hostnames", True)
    do_smb        = config.get("smb_scan", False)
    do_ssdp       = config.get("ssdp_scan", True)
    max_ping      = int(config.get("max_concurrent_ping", 64))
    max_ports     = int(config.get("max_concurrent_ports", 100))
    custom_ports  = config.get("custom_ports", None)

    # Support comma-separated multi-CIDR
    cidrs = [c.strip() for c in str(cidr_raw).split(",") if c.strip()]
    cidr  = cidrs[0]  # primary CIDR for display

    total_hosts = 0
    for c_ in cidrs:
        try:
            total_hosts += ipaddress.ip_network(c_, strict=False).num_addresses - 2
        except ValueError:
            await websocket.send_json({"type": "error", "message": f"Invalid CIDR: {c_}"})
            return

    await websocket.send_json({"type": "scan_started", "cidr": cidr_raw, "total_hosts": total_hosts})

    known = {d["mac"].upper(): d for d in get_known_devices()}
    mdns_task = asyncio.create_task(discover_mdns(mdns_duration)) if do_mdns else None
    ssdp_task = asyncio.create_task(discover_ssdp(4.0)) if do_ssdp else None

    await websocket.send_json({"type": "phase", "phase": "discovery",
                               "status": "running", "total": total_hosts})

    async def on_progress(completed, total, host):
        if host.is_alive:
            v = lookup_vendor(host.mac) if host.mac else ""
            is_unknown = bool(host.mac and host.mac.upper() not in known)
            await websocket.send_json({
                "type": "host_found", "ip": host.ip,
                "rtt_ms": host.rtt_ms, "mac": host.mac,
                "vendor": v, "is_unknown": is_unknown,
            })
        if completed % 10 == 0 or completed == total:
            await websocket.send_json({
                "type": "progress", "phase": "discovery",
                "completed": completed, "total": total,
                "pct": round(completed / total * 100),
            })

    # Scan all CIDRs in parallel
    scan_tasks = [
        discover_subnet(c_, max_concurrent=max_ping,
                        timeout=ping_timeout, progress_cb=on_progress)
        for c_ in cidrs
    ]
    results_per_cidr = await asyncio.gather(*scan_tasks)
    discovered = []
    for r in results_per_cidr:
        discovered.extend(r)

    fritz_hostname_map = {}  # ip -> hostname from FritzBox
    # ── Merge FritzBox DHCP hosts (catches ping-blocking devices like iPads) ──
    discovered_ips = {h.ip for h in discovered}
    try:
        import ipaddress as _ipaddress
        # Build list of all networks for multi-CIDR
        net_objs = []
        for c_ in cidrs:
            try: net_objs.append(_ipaddress.ip_network(c_, strict=False))
            except Exception: pass
        net_obj = net_objs[0] if net_objs else None
        def _in_any_net(ip_str):
            try:
                addr = _ipaddress.ip_address(ip_str)
                return any(addr in n for n in net_objs)
            except Exception:
                return False
    except Exception:
        net_obj = None
        net_objs = []
        def _in_any_net(ip_str): return True

    try:
        fritz_host_val = get_setting("fritz_host", None)
        fritz_user_val = get_setting("fritz_user", "")
        fritz_pass_val = decrypt(get_setting("fritz_password", ""))
        if fritz_host_val and fritz_pass_val:
            fritz_tmp = _fritz_cache.get(fritz_host_val) or FritzBox(fritz_host_val, user=fritz_user_val, password=fritz_pass_val)
            loop = asyncio.get_event_loop()
            fritz_hosts = await asyncio.wait_for(
                loop.run_in_executor(None, fritz_tmp.get_hosts), timeout=10.0
            )
            added_fritz = 0
            for fh in fritz_hosts:
                fip = fh.get("ip", "")
                if not fip or fip in discovered_ips:
                    continue
                # Only add if in our scan subnet
                if not _in_any_net(fip):
                    continue
                # Create a synthetic host entry
                from modules.discovery import DiscoveredHost
                synth = DiscoveredHost(ip=fip, mac=fh.get("mac",""), rtt_ms=-1, is_alive=True)
                synth.from_fritz = True
                discovered.append(synth)
                discovered_ips.add(fip)
                added_fritz += 1
                await websocket.send_json({
                    "type": "host_found", "ip": fip, "mac": fh.get("mac",""),
                    "vendor": lookup_vendor(fh.get("mac","")) if fh.get("mac") else "",
                    "rtt_ms": -1, "source": "fritzbox"
                })
            if added_fritz:
                await websocket.send_json({
                    "type": "info", "message": f"FritzBox: {added_fritz} additional hosts merged"
                })
    except Exception as _fe:
        pass  # FritzBox merge is best-effort

    # ── Merge ARP table (catches hosts that don't respond to ping) ──
    try:
        import subprocess as _sp
        import re as _re
        arp_out = _sp.run(["arp", "-a"], capture_output=True, text=True, timeout=3).stdout
        for line in arp_out.splitlines():
            m = _re.search(r'[\(](\d+\.\d+\.\d+\.\d+)[\)].*?([\da-f]{1,2}(?::[\da-f]{1,2}){5})', line, _re.IGNORECASE)
            if not m: continue
            aip, amac = m.group(1), m.group(2).lower()
            if aip in discovered_ips: continue
            if not _in_any_net(aip): continue
            from modules.discovery import DiscoveredHost
            synth = DiscoveredHost(ip=aip, mac=amac, rtt_ms=-1, is_alive=True)
            discovered.append(synth)
            discovered_ips.add(aip)
            await websocket.send_json({
                "type": "host_found", "ip": aip, "mac": amac,
                "vendor": lookup_vendor(amac), "rtt_ms": -1, "source": "arp"
            })
    except Exception:
        pass

    await websocket.send_json({"type": "phase", "phase": "discovery",
                               "status": "done", "alive_count": len(discovered)})

    mdns_by_ip, ssdp_by_ip = {}, {}
    if mdns_task:
        try:
            svcs = await asyncio.wait_for(mdns_task, timeout=mdns_duration + 2)
            mdns_by_ip = group_by_ip(svcs)
        except asyncio.TimeoutError:
            pass
    if ssdp_task:
        try:
            for d in await asyncio.wait_for(ssdp_task, timeout=6.0):
                ssdp_by_ip.setdefault(d.ip, []).append(
                    {"server": d.server, "st": d.st, "location": d.location})
        except asyncio.TimeoutError:
            pass

    await websocket.send_json({"type": "phase", "phase": "enrich",
                               "status": "running", "total": len(discovered)})
    ports_to_scan = custom_ports or TOP_100_PORTS
    all_details = []

    for i, host in enumerate(discovered):
        ip = host.ip
        mac_up = (host.mac or "").upper()
        kd = known.get(mac_up, {})

        enriched = {
            "type": "host_detail", "ip": ip, "mac": host.mac,
            "vendor": lookup_vendor(host.mac) if host.mac else "",
            "rtt_ms": host.rtt_ms, "hostname": "",
            "smb_name": "", "smb_domain": "",
            "os_guess": "", "os_accuracy": 0, "scan_method": "socket",
            "ports": [], "mdns_services": [],
            "ssdp_services": ssdp_by_ip.get(ip, []),
            "is_ndi": False,
"is_unknown": bool(host.mac and mac_up not in known),
            "category": "",  # filled after port scan
            "label": kd.get("label", ""),
            "tags": kd.get("tags", []),
            "notes": kd.get("notes", ""),
        }

        # Try DNS first, then fall back to FritzBox hostname
        if do_resolve:
            try:
                hn = await asyncio.wait_for(resolve_hostname(ip), timeout=1.5)
                if hn:
                    enriched["hostname"] = hn
            except Exception:
                pass

        # Always fill hostname from FritzBox if DNS didn't provide one
        if not enriched.get("hostname"):
            enriched["hostname"] = fritz_hostname_map.get(ip, "")

        if do_smb:
            loop = asyncio.get_event_loop()
            try:
                n, dom = await loop.run_in_executor(None, get_smb_info, ip)
                enriched["smb_name"] = n; enriched["smb_domain"] = dom
            except Exception:
                pass

        if do_port_scan:
            if port_mode == "nmap":
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, scan_with_nmap, ip)
            else:
                result = await scan_ports_socket(ip, ports=ports_to_scan, max_concurrent=max_ports)
            enriched["ports"] = [{"port": p.port, "state": p.state, "service": p.service}
                                  for p in result.ports]
            enriched["os_guess"] = result.os_guess
            enriched["os_accuracy"] = result.os_accuracy
            enriched["scan_method"] = result.scan_method

        # OS + Category Fingerprinting
        if not enriched.get("os_guess"):
            enriched["os_guess"] = _guess_os(
                ports=enriched.get("ports", []),
                vendor=enriched.get("vendor", ""),
                mac=enriched.get("mac", ""),
                mdns_services=enriched.get("mdns_services", []),
                hostname=enriched.get("hostname", ""),
                fritz_hostname=fritz_hostname_map.get(ip, ""),
            )
        enriched["category"] = _get_category(
            ports=enriched.get("ports", []),
            vendor=enriched.get("vendor", ""),
            mac=enriched.get("mac", ""),
            mdns_services=enriched.get("mdns_services", []),
            hostname=enriched.get("hostname", ""),
            fritz_hostname=fritz_hostname_map.get(ip, ""),
        )

        if ip in mdns_by_ip:
            svcs = mdns_by_ip[ip]
            enriched["mdns_services"] = [
                {"name": s.name, "type": s.service_type, "port": s.port,
                 "hostname": s.hostname, "is_ndi": s.is_ndi, "properties": s.properties}
                for s in svcs]
            enriched["is_ndi"] = any(s.is_ndi for s in svcs)

        # Update persistent device DB
        update_device_from_scan(enriched)

        await websocket.send_json(enriched)
        await websocket.send_json({
            "type": "progress", "phase": "enrich",
            "completed": i + 1, "total": len(discovered),
            "pct": round((i + 1) / max(len(discovered), 1) * 100),
        })
        all_details.append({k: v for k, v in enriched.items() if k != "type"})

    # Enrich with IPv6 from NDP table
    all_details = enrich_with_ipv6(all_details)
    save_scan(cidr_raw, all_details)
    await websocket.send_json({"type": "scan_complete", "total_found": len(discovered)})


# ── Serve React frontend (macOS App / production) ─────────────
import os as _os

def _find_frontend() -> str | None:
    """Find frontend-dist — handles PyInstaller bundle, macOS app, and dev mode."""
    import sys as _sys_fe
    candidates = []

    # PyInstaller frozen: binary is in cernis-backend/, frontend-dist is sibling
    if hasattr(_sys_fe, '_MEIPASS'):
        # _MEIPASS = the temp/bundle dir where PyInstaller extracts everything
        # frontend-dist is embedded directly in _MEIPASS
        exe_dir = _os.path.dirname(_sys_fe.executable)
        candidates += [
            _os.path.join(_sys_fe._MEIPASS, "frontend-dist"),   # embedded in bundle (primary)
            _os.path.join(exe_dir, "frontend-dist"),            # sibling of exe
            _os.path.join(exe_dir, "..", "frontend-dist"),      # one level up
            _os.path.join(_sys_fe._MEIPASS, "..", "frontend-dist"),
        ]

    # Script mode / venv mode
    candidates += [
        _os.path.join(_os.path.dirname(__file__), "..", "frontend-dist"),   # backend/../frontend-dist
        _os.path.join(_os.path.dirname(__file__), "frontend-dist"),          # same dir
        _os.path.join(_os.path.dirname(__file__), "..", "frontend", "dist"), # dev
    ]

    # Resolve and return first existing directory
    for d in candidates:
        resolved = _os.path.realpath(d)
        if _os.path.isdir(resolved):
            return resolved
    return None

_FRONTEND_DIR = _find_frontend()

if _FRONTEND_DIR:
    _assets_dir = _os.path.join(_FRONTEND_DIR, "assets")
    if _os.path.isdir(_assets_dir):
        app.mount("/assets", StaticFiles(directory=_assets_dir), name="assets")

    @app.get("/")
    async def _serve_root():
        return FileResponse(_os.path.join(_FRONTEND_DIR, "index.html"))

    @app.get("/{full_path:path}")
    async def _serve_spa(full_path: str):
        # Don't intercept API or WebSocket routes
        if full_path.startswith(("api/", "ws/")):
            raise HTTPException(status_code=404)
        file_path = _os.path.join(_FRONTEND_DIR, full_path)
        if _os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(_os.path.join(_FRONTEND_DIR, "index.html"))


if __name__ == "__main__":
    import os as _os_main, sys as _sys_main
    _port = int(_os_main.environ.get("CERNIS_PORT", 8765))
    # PyInstaller frozen mode: use app object directly, not string import
    if getattr(_sys_main, "frozen", False) or hasattr(_sys_main, "_MEIPASS"):
        uvicorn.run(app, host="127.0.0.1", port=_port, reload=False, log_level="info")
    else:
        uvicorn.run("main:app", host="127.0.0.1", port=_port, reload=False, log_level="info")
