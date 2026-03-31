"""
CERNIS PRO FritzBox Integration
Uses the fritzconnection library (pip install fritzconnection)
which handles TR-064 SOAP + Digest Auth correctly for all models.
Supports FritzOS 7.x / 8.x, Fiber models (5590, 5530), DSL and Cable.
"""
import socket
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    from fritzconnection import FritzConnection
    from fritzconnection.core.exceptions import (
        FritzConnectionException, FritzAuthorizationError,
        FritzServiceError, FritzActionError,
    )
    HAS_FRITZ = True
except ImportError:
    HAS_FRITZ = False


# ── Data structures ───────────────────────────────────────────

@dataclass
class FritzStatus:
    reachable: bool       = False
    host: str             = ""
    model: str            = ""
    firmware: str         = ""
    is_fiber: bool        = False
    # WAN
    wan_connected: bool   = False
    wan_uptime_secs: int  = 0
    wan_ip_external: str  = ""
    wan_ip_external_v6: str = ""
    wan_upstream_kbps: int   = 0
    wan_downstream_kbps: int = 0
    wan_bytes_sent: int   = 0
    wan_bytes_recv: int   = 0
    # DSL (only for DSL models)
    dsl_sync: bool            = False
    dsl_downstream_kbps: int  = 0
    dsl_upstream_kbps: int    = 0
    dsl_snr_downstream: float = 0.0
    dsl_snr_upstream: float   = 0.0
    dsl_attn_downstream: float = 0.0
    dsl_attn_upstream: float  = 0.0
    # WLAN
    wlan_24_enabled: bool  = False
    wlan_24_ssid: str      = ""
    wlan_24_channel: int   = 0
    wlan_24_clients: int   = 0
    wlan_5_enabled: bool   = False
    wlan_5_ssid: str       = ""
    wlan_5_channel: int    = 0
    wlan_5_clients: int    = 0
    # Hosts
    total_hosts: int       = 0
    # Auth
    auth_error: bool       = False

    def to_dict(self):
        return asdict(self)


@dataclass
class FritzWlanClient:
    mac: str
    ip: str
    hostname: str  = ""
    signal_dbm: int = 0
    speed_mbps: int = 0
    band: str      = ""


@dataclass
class FritzLogEntry:
    id: int
    timestamp: str
    message: str


# ── Helpers ───────────────────────────────────────────────────

def _safe_call(fc: "FritzConnection", service: str, action: str, **kwargs) -> dict:
    """Call a FritzBox action, return {} on any error.
    Re-raises FritzAuthorizationError so callers can detect missing credentials.
    """
    try:
        return fc.call_action(service, action, **kwargs) or {}
    except FritzAuthorizationError:
        raise  # let callers handle auth failures explicitly
    except Exception:
        return {}


def _is_fiber_model(model: str) -> bool:
    model_l = model.lower()
    return any(x in model_l for x in ["fiber", "5590", "5530", "5580", "cable"])


# ── Auto-detection ────────────────────────────────────────────

def detect_fritzbox(hosts_in_network: list[dict] = None) -> Optional[str]:
    """
    Try to find FritzBox. Returns best hostname/IP or None.
    Strategy (in order of priority):
    1. Previously saved fritz_host
    2. Gateway IP → reverse DNS → check port 49000
    3. AVM vendor hosts from last scan
    4. Common default addresses
    """
    candidates = []

    # 1. Previously saved host
    try:
        from modules.storage import get_setting
        saved = get_setting("fritz_host", None)
        if saved:
            candidates.append(saved)
    except Exception:
        pass

    # 2. Gateway from active interfaces → reverse DNS
    try:
        from modules.interfaces import get_interfaces
        for iface in get_interfaces():
            gw = iface.gateway
            if not gw or gw in candidates:
                continue
            # Try reverse DNS on gateway IP → might give FQDN like fritzbox.mysticplace.de
            try:
                fqdn = socket.gethostbyaddr(gw)[0]
                # Skip useless names that systemd-resolved/Debian return
                # (e.g. "_gateway", "localhost", single-label names without dots)
                if (fqdn and fqdn not in candidates
                        and fqdn not in ("_gateway", "localhost")
                        and not fqdn.startswith("_")):
                    candidates.append(fqdn)  # prefer FQDN over raw IP
            except Exception:
                pass
            if gw not in candidates:
                candidates.append(gw)  # also try raw IP as fallback
    except Exception:
        pass

    # 3. AVM vendor hosts from scan
    if hosts_in_network:
        for h in hosts_in_network:
            v = (h.get("vendor") or "").lower()
            if "avm" in v or "audiovisuell" in v:
                ip = h["ip"]
                if ip not in candidates:
                    candidates.insert(0, ip)

    # 4. Common default addresses
    for default in ["fritz.box", "192.168.178.1", "192.168.1.1", "192.168.0.1"]:
        if default not in candidates:
            candidates.append(default)

    for host in candidates:
        try:
            # Resolve hostname first (handles FQDNs like fritzbox.mysticplace.de)
            try:
                resolved = socket.getaddrinfo(host, 49000, socket.AF_INET,
                                               socket.SOCK_STREAM, socket.IPPROTO_TCP)
                if not resolved:
                    continue
                addr = resolved[0][4][0]
            except socket.gaierror:
                continue

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            result = sock.connect_ex((addr, 49000))
            sock.close()
            if result == 0:
                # Verify it's actually a FritzBox via TR-064 and get best hostname
                if HAS_FRITZ:
                    try:
                        fc = FritzConnection(address=addr, port=49000, timeout=5.0)
                        model = (fc.modelname or "").lower()
                        if "fritz" not in model:
                            continue  # TR-064 answered but not a FritzBox
                        # If we connected via raw IP, check if FritzConnection
                        # knows a better hostname (e.g. fritz.box)
                        return host
                    except Exception:
                        pass  # TR-064 handshake failed, skip
                else:
                    return host
        except Exception:
            pass
    return None


# ── Main API class ────────────────────────────────────────────

class FritzBox:
    def __init__(self, host: str, port: int = 49000, user: str = "", password: str = ""):
        if not HAS_FRITZ:
            raise RuntimeError("fritzconnection not installed. Run: pip install fritzconnection")
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self._fc: Optional[FritzConnection] = None

    def _connect(self) -> "FritzConnection":
        if self._fc is None:
            self._fc = FritzConnection(
                address=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                timeout=8.0,
            )
        return self._fc

    def get_status(self) -> FritzStatus:
        s = FritzStatus(reachable=False, host=self.host)
        try:
            fc = self._connect()
        except Exception as e:
            return s

        s.reachable = True

        # ── Device Info ───────────────────────────────────────
        try:
            r = _safe_call(fc, "DeviceInfo1", "GetInfo")
        except FritzAuthorizationError:
            s.auth_error = True
            return s
        s.model    = r.get("NewModelName", "")
        s.firmware = r.get("NewSoftwareVersion", "")
        s.is_fiber = _is_fiber_model(s.model)

        # ── WAN Status ────────────────────────────────────────
        # Try WANPPPConnection first (Fiber/Cable), fallback to WANIPConnection
        wan_svc = None
        for svc in ["WANPPPConnection1", "WANIPConnection1"]:
            r2 = _safe_call(fc, svc, "GetStatusInfo")
            if r2:
                wan_svc = svc
                s.wan_connected   = r2.get("NewConnectionStatus", "") == "Connected"
                s.wan_uptime_secs = int(r2.get("NewUptime", 0) or 0)
                break

        if wan_svc:
            r3 = _safe_call(fc, wan_svc, "GetExternalIPAddress")
            s.wan_ip_external = r3.get("NewExternalIPAddress", "")
            # IPv6
            r6 = _safe_call(fc, wan_svc, "X_AVM_DE_GetExternalIPv6Address")
            s.wan_ip_external_v6 = r6.get("NewExternalIPv6Address", "")

        # ── WAN Common ────────────────────────────────────────
        rc = _safe_call(fc, "WANCommonInterfaceConfig1", "GetCommonLinkProperties")
        if rc:
            s.wan_downstream_kbps = int(rc.get("NewLayer1DownstreamMaxBitRate", 0) or 0) // 1000
            s.wan_upstream_kbps   = int(rc.get("NewLayer1UpstreamMaxBitRate",   0) or 0) // 1000

        # For Fiber: get max line speed
        if s.is_fiber:
            got_speed = False

            # Approach 1: WANCommonInterfaceConfig - sometimes has real values
            rc2 = _safe_call(fc, "WANCommonInterfaceConfig1", "GetCommonLinkProperties")
            if rc2:
                ds = int(rc2.get("NewLayer1DownstreamMaxBitRate", 0) or 0)
                us = int(rc2.get("NewLayer1UpstreamMaxBitRate",   0) or 0)
                if ds > 10_000_000:
                    s.wan_downstream_kbps = ds // 1000
                    s.wan_upstream_kbps   = us // 1000
                    got_speed = True

            # Approach 2: X_AVM-DE_WANFiber GetInfo — store ALL fields for debugging
            if not got_speed:
                rf = _safe_call(fc, "X_AVM_DE_WANFiber1", "GetInfo")
                if rf:
                    s._fiber_raw = rf  # store for debug endpoint
                    # Scan ALL numeric fields for something that looks like Gbit/s
                    for key, val in rf.items():
                        try:
                            v = int(val or 0)
                            if v >= 100_000_000:  # >= 100 Mbit/s in bps
                                if "down" in key.lower() or "recv" in key.lower() or "rx" in key.lower():
                                    s.wan_downstream_kbps = v // 1000
                                    got_speed = True
                                elif "up" in key.lower() or "send" in key.lower() or "tx" in key.lower():
                                    s.wan_upstream_kbps = v // 1000
                        except (ValueError, TypeError):
                            pass

            # Approach 3: WANPPPConnection MaxBitRate
            if not got_speed:
                rp = _safe_call(fc, "WANPPPConnection1", "GetConnectionTypeInfo")
                if not got_speed:
                    rp2 = _safe_call(fc, "WANPPPConnection1", "GetLinkLayerMaxBitRates")
                    if rp2:
                        ds = int(rp2.get("NewDownstreamMaxBitRate", 0) or 0)
                        us = int(rp2.get("NewUpstreamMaxBitRate",   0) or 0)
                        if ds > 1000:
                            s.wan_downstream_kbps = ds // 1000 if ds > 1000000 else ds * 1000
                            s.wan_upstream_kbps   = us // 1000 if us > 1000000 else us * 1000
                            got_speed = True

            # Approach 4: Hardcode 1 Gbit/s — FritzBox 5590 Fiber is always 1 Gbit/s
            if not got_speed:
                re2 = _safe_call(fc, "WANEthernetLinkConfig1", "GetEthernetLinkStatus")
                if re2.get("NewEthernetLinkStatus") == "Up":
                    s.wan_downstream_kbps = 1_000_000
                    s.wan_upstream_kbps   = 1_000_000

        rs = _safe_call(fc, "WANCommonInterfaceConfig1", "GetTotalBytesSent")
        s.wan_bytes_sent = int(rs.get("NewTotalBytesSent", 0) or 0)

        rr = _safe_call(fc, "WANCommonInterfaceConfig1", "GetTotalBytesReceived")
        s.wan_bytes_recv = int(rr.get("NewTotalBytesReceived", 0) or 0)

        # ── DSL (only for non-Fiber) ──────────────────────────
        if not s.is_fiber:
            rd = _safe_call(fc, "WANDSLInterfaceConfig1", "GetInfo")
            if rd:
                s.dsl_sync             = rd.get("NewStatus", "") in ("Up", "Running")
                s.dsl_downstream_kbps  = int(rd.get("NewDownstreamCurrRate", 0) or 0)
                s.dsl_upstream_kbps    = int(rd.get("NewUpstreamCurrRate",   0) or 0)
                s.dsl_snr_downstream   = round(int(rd.get("NewDownstreamNoiseMargin", 0) or 0) / 10, 1)
                s.dsl_snr_upstream     = round(int(rd.get("NewUpstreamNoiseMargin",   0) or 0) / 10, 1)
                s.dsl_attn_downstream  = round(int(rd.get("NewDownstreamAttenuation", 0) or 0) / 10, 1)
                s.dsl_attn_upstream    = round(int(rd.get("NewUpstreamAttenuation",   0) or 0) / 10, 1)
        else:
            # Fiber: use WANPPPConnection status (more reliable than EthernetLinkConfig)
            re = _safe_call(fc, "WANPPPConnection1", "GetStatusInfo")
            if re:
                s.dsl_sync = re.get("NewConnectionStatus", "") == "Connected"
            else:
                # Fallback to WAN IP connection
                re2 = _safe_call(fc, "WANIPConnection1", "GetStatusInfo")
                s.dsl_sync = re2.get("NewConnectionStatus", "") == "Connected"

        # ── WLAN 2.4 GHz ─────────────────────────────────────
        rw1 = _safe_call(fc, "WLANConfiguration1", "GetInfo")
        if rw1:
            s.wlan_24_enabled = rw1.get("NewEnable", False)
            s.wlan_24_ssid    = rw1.get("NewSSID", "")
            s.wlan_24_channel = int(rw1.get("NewChannel", 0) or 0)
        ra1 = _safe_call(fc, "WLANConfiguration1", "GetTotalAssociations")
        if ra1:
            s.wlan_24_clients = int(ra1.get("NewTotalAssociations", 0) or 0)
        else:
            # Fallback: count from host list
            try:
                count = 0
                for i in range(20):
                    r = fc.call_action("WLANConfiguration1", "GetGenericAssociatedDeviceInfo",
                                       NewAssociatedDeviceIndex=i)
                    if r: count += 1
                    else: break
                s.wlan_24_clients = count
            except Exception:
                pass

        # ── WLAN 5 GHz ────────────────────────────────────────
        rw2 = _safe_call(fc, "WLANConfiguration2", "GetInfo")
        if rw2:
            s.wlan_5_enabled = rw2.get("NewEnable", False)
            s.wlan_5_ssid    = rw2.get("NewSSID", "")
            s.wlan_5_channel = int(rw2.get("NewChannel", 0) or 0)
        ra2 = _safe_call(fc, "WLANConfiguration2", "GetTotalAssociations")
        if ra2:
            s.wlan_5_clients = int(ra2.get("NewTotalAssociations", 0) or 0)
        else:
            try:
                count = 0
                for i in range(20):
                    r = fc.call_action("WLANConfiguration2", "GetGenericAssociatedDeviceInfo",
                                       NewAssociatedDeviceIndex=i)
                    if r: count += 1
                    else: break
                s.wlan_5_clients = count
            except Exception:
                pass

        # ── Hosts ─────────────────────────────────────────────
        rh = _safe_call(fc, "Hosts1", "GetHostNumberOfEntries")
        s.total_hosts = int(rh.get("NewHostNumberOfEntries", 0) or 0)

        return s

    def get_wlan_clients(self) -> list[FritzWlanClient]:
        """Get all active WLAN clients with signal strength."""
        try:
            fc = self._connect()
        except Exception:
            return []

        clients = []
        for band_idx, band_label in [(1, "2.4 GHz"), (2, "5 GHz"), (3, "5 GHz (2)")]:
            svc = f"WLANConfiguration{band_idx}"
            ra = _safe_call(fc, svc, "GetTotalAssociations")
            count = int(ra.get("NewTotalAssociations", 0) or 0)
            for i in range(count):
                try:
                    r = fc.call_action(svc, "GetGenericAssociatedDeviceInfo",
                                       NewAssociatedDeviceIndex=i)
                    if not r:
                        continue
                    client = FritzWlanClient(
                        mac      = r.get("NewAssociatedDeviceMACAddress", ""),
                        ip       = r.get("NewAssociatedDeviceIPAddress", ""),
                        hostname = r.get("NewHostname", ""),
                        band     = band_label,
                    )
                    client.signal_dbm = int(r.get("NewX_AVM-DE_SignalStrength", 0) or 0)
                    client.speed_mbps = int(r.get("NewX_AVM-DE_Speed", 0) or 0)
                    if client.mac:
                        clients.append(client)
                except Exception:
                    continue
        return clients

    def get_hosts(self) -> list[dict]:
        """Get all known hosts from FritzBox DHCP table."""
        try:
            fc = self._connect()
        except Exception:
            return []

        rh = _safe_call(fc, "Hosts1", "GetHostNumberOfEntries")
        count = int(rh.get("NewHostNumberOfEntries", 0) or 0)
        hosts = []
        for i in range(min(count, 300)):
            try:
                r = fc.call_action("Hosts1", "GetGenericHostEntry", NewIndex=i)
                if not r:
                    continue
                hosts.append({
                    "ip":        r.get("NewIPAddress", ""),
                    "mac":       r.get("NewMACAddress", ""),
                    "hostname":  r.get("NewHostName", ""),
                    "active":    bool(r.get("NewActive", False)),
                    "interface": r.get("NewInterfaceType", ""),
                })
            except Exception:
                continue
        return [h for h in hosts if h["ip"] or h["mac"]]


    def get_port_forwardings(self) -> list[dict]:
        """Get all port forwarding rules from FritzBox."""
        try:
            fc = self._connect()
        except Exception:
            return []

        rules = []
        # WANIPConnection or WANPPPConnection
        for svc in ["WANPPPConnection1", "WANIPConnection1"]:
            try:
                count_r = _safe_call(fc, svc.replace("1","1"), "GetPortMappingNumberOfEntries")
                # fritzconnection uses service names differently
                count_r2 = fc.call_action(svc, "GetPortMappingNumberOfEntries")
                count = int(count_r2.get("NewPortMappingNumberOfEntries", 0) or 0)
                for i in range(count):
                    r = fc.call_action(svc, "GetGenericPortMappingEntry",
                                       NewPortMappingIndex=i)
                    if not r:
                        continue
                    rules.append({
                        "enabled":       bool(r.get("NewEnabled", False)),
                        "description":   r.get("NewPortMappingDescription", ""),
                        "protocol":      r.get("NewProtocol", "TCP"),
                        "external_port": int(r.get("NewExternalPort", 0) or 0),
                        "internal_ip":   r.get("NewInternalClient", ""),
                        "internal_port": int(r.get("NewInternalPort", 0) or 0),
                        "duration":      int(r.get("NewLeaseDuration", 0) or 0),
                    })
                break  # found working service
            except Exception:
                continue
        return rules

    def get_log(self, limit: int = 80) -> list[FritzLogEntry]:
        """Get FritzBox event log."""
        try:
            fc = self._connect()
        except Exception:
            return []

        r = _safe_call(fc, "DeviceInfo1", "GetDeviceLog")
        raw = r.get("NewDeviceLog", "")
        entries = []
        import re
        for i, line in enumerate(raw.splitlines()[:limit]):
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^(\d{2}\.\d{2}\.\d{2}\s+\d{2}:\d{2}:\d{2})\s+(.+)$", line)
            if m:
                entries.append(FritzLogEntry(id=i, timestamp=m.group(1), message=m.group(2)))
            else:
                entries.append(FritzLogEntry(id=i, timestamp="", message=line))
        return entries
