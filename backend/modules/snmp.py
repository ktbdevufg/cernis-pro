"""
CERNIS PRO SNMP Discovery Module
Queries devices via SNMP v1/v2c for system info, interfaces, and traffic.
Requires: pip install pysnmp
"""
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    from pysnmp.hlapi import (
        getCmd, nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity,
    )
    HAS_SNMP = True
except ImportError:
    HAS_SNMP = False

# Common OIDs
OID_SYSDESC    = "1.3.6.1.2.1.1.1.0"
OID_SYSNAME    = "1.3.6.1.2.1.1.5.0"
OID_SYSUPTIME  = "1.3.6.1.2.1.1.3.0"
OID_SYSLOC     = "1.3.6.1.2.1.1.6.0"
OID_SYSCONTACT = "1.3.6.1.2.1.1.4.0"
OID_IF_TABLE   = "1.3.6.1.2.1.2.2.1"
OID_IF_DESCR   = "1.3.6.1.2.1.2.2.1.2"
OID_IF_SPEED   = "1.3.6.1.2.1.2.2.1.5"
OID_IF_INOCT   = "1.3.6.1.2.1.2.2.1.10"
OID_IF_OUTOCT  = "1.3.6.1.2.1.2.2.1.16"
OID_IF_OPER    = "1.3.6.1.2.1.2.2.1.8"


@dataclass
class SNMPInterface:
    index: int
    description: str
    speed_mbps: int
    in_octets: int
    out_octets: int
    oper_status: str  # "up" | "down"


@dataclass
class SNMPResult:
    ip: str
    community: str    = ""
    reachable: bool       = False
    sys_name: str         = ""
    sys_desc: str         = ""
    sys_location: str     = ""
    sys_contact: str      = ""
    uptime_secs: int      = 0
    interfaces: list      = field(default_factory=list)
    error: str            = ""

    def to_dict(self):
        return asdict(self)


def _snmp_get(ip: str, community: str, *oids, timeout: int = 2, retries: int = 1):
    """GET one or more OIDs. Returns list of (oid, value) tuples."""
    if not HAS_SNMP:
        return []
    results = []
    try:
        error_indication, error_status, error_index, var_binds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),  # v2c
                UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
                ContextData(),
                *[ObjectType(ObjectIdentity(oid)) for oid in oids],
            )
        )
        if error_indication or error_status:
            return []
        for var_bind in var_binds:
            results.append((str(var_bind[0]), str(var_bind[1])))
    except Exception:
        pass
    return results


def _snmp_walk(ip: str, community: str, oid: str, timeout: int = 3):
    """WALK an OID subtree. Returns list of (oid, value) tuples."""
    if not HAS_SNMP:
        return []
    results = []
    try:
        for (error_indication, error_status, error_index, var_binds) in nextCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, 161), timeout=timeout, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                break
            for var_bind in var_binds:
                results.append((str(var_bind[0]), str(var_bind[1])))
    except Exception:
        pass
    return results


def query_host(ip: str, communities: list[str] = None, timeout: int = 2) -> SNMPResult:
    """Query a single host via SNMP. Tries multiple communities."""
    if not HAS_SNMP:
        return SNMPResult(ip=ip, reachable=False, error="pysnmp not installed")

    communities = communities or ["public", "private", "community"]
    result = SNMPResult(ip=ip, community="")

    # Try each community
    working_community = None
    for community in communities:
        r = _snmp_get(ip, community,
                      OID_SYSNAME, OID_SYSDESC, OID_SYSUPTIME, OID_SYSLOC, OID_SYSCONTACT,
                      timeout=timeout)
        if r:
            working_community = community
            result.community = community
            result.reachable = True
            for oid, val in r:
                if OID_SYSNAME.split(".")[0] in oid or "sysName" in oid:
                    result.sys_name = val
                elif "sysDescr" in oid or OID_SYSDESC.split(".")[0] in oid:
                    result.sys_desc = val[:200]
                elif "sysUpTime" in oid:
                    try:
                        # Uptime in 1/100 seconds
                        result.uptime_secs = int(val.split("(")[-1].rstrip(")")) // 100
                    except Exception:
                        pass
                elif "sysLocation" in oid:
                    result.sys_location = val
                elif "sysContact" in oid:
                    result.sys_contact = val
            break

    if not result.reachable:
        return result

    # Get interfaces
    try:
        descrs  = {oid.split(".")[-1]: val for oid, val in _snmp_walk(ip, working_community, OID_IF_DESCR)}
        speeds  = {oid.split(".")[-1]: val for oid, val in _snmp_walk(ip, working_community, OID_IF_SPEED)}
        inocts  = {oid.split(".")[-1]: val for oid, val in _snmp_walk(ip, working_community, OID_IF_INOCT)}
        outocts = {oid.split(".")[-1]: val for oid, val in _snmp_walk(ip, working_community, OID_IF_OUTOCT)}
        opers   = {oid.split(".")[-1]: val for oid, val in _snmp_walk(ip, working_community, OID_IF_OPER)}

        for idx in descrs:
            try:
                speed_raw = int(speeds.get(idx, "0") or "0")
                oper_raw  = opers.get(idx, "2")
                iface = SNMPInterface(
                    index=int(idx),
                    description=descrs[idx],
                    speed_mbps=speed_raw // 1_000_000,
                    in_octets=int(inocts.get(idx, "0") or "0"),
                    out_octets=int(outocts.get(idx, "0") or "0"),
                    oper_status="up" if oper_raw == "1" else "down",
                )
                result.interfaces.append(asdict(iface))
            except Exception:
                continue
    except Exception:
        pass

    return result


def check_snmp_available() -> bool:
    return HAS_SNMP
