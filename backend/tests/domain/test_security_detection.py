"""Domaenen-Vertrag der ARP-Anomalie-Erkennung (``domain.security.detect_arp_anomalies``).

Dieselbe Wahrheitstabelle wie der SEC.1-Charakterisierer (``test_arp_guard_storage``),
aber gegen die REINE Funktion -- kein DB-Mock, kein get_arp_table/lookup_vendor-Patch
noetig. Die Erkennung bekommt vorberechnete ``ArpEntry`` (ip/mac/vendor) und gibt
``ArpAlert``-Liste.

Eingefrorene Regeln (1:1 zu SEC.1):
  * ip_conflict (tabellen-basiert): EINE MAC auf >1 IP -> high.
  * mac_changed (baseline-basiert): MAC weicht ab -> high wenn alter Vendor bekannt UND
    verschieden, sonst medium.
  * new_device (neue IP): KEIN Alert.
Jede Regel mit Gegenprobe; severity-Stufen high vs medium mit Gegenprobe.
"""

from domain.security import (
    ARP_ALERT_IP_CONFLICT,
    ARP_ALERT_MAC_CHANGED,
    ARP_SEVERITY_HIGH,
    ARP_SEVERITY_MEDIUM,
    ArpEntry,
    detect_arp_anomalies,
)

# ── ip_conflict: feuert / Gegenprobe ──────────────────────────


def test_ip_conflict_fires_on_shared_mac() -> None:
    current = [
        ArpEntry("192.168.1.10", "BB:BB:BB:22:22:22", "BetaInc"),
        ArpEntry("192.168.1.11", "BB:BB:BB:22:22:22", "BetaInc"),
    ]
    alerts = detect_arp_anomalies(current, baseline=[])
    conflicts = [a for a in alerts if a.alert_type == ARP_ALERT_IP_CONFLICT]
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c.severity == ARP_SEVERITY_HIGH  # immer high
    assert c.new_mac == "BB:BB:BB:22:22:22"
    assert c.new_vendor == "BetaInc"
    assert c.old_mac == "" and c.old_vendor == ""
    assert "192.168.1.10" in c.ip and "192.168.1.11" in c.ip
    assert c.message == (
        "MAC BB:BB:BB:22:22:22 (BetaInc) appears on multiple IPs: 192.168.1.10, 192.168.1.11"
    )


def test_ip_conflict_gegenprobe_unique_macs_no_conflict() -> None:
    current = [
        ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp"),
        ArpEntry("192.168.1.11", "BB:BB:BB:22:22:22", "BetaInc"),
    ]
    alerts = detect_arp_anomalies(current, baseline=[])
    assert [a for a in alerts if a.alert_type == ARP_ALERT_IP_CONFLICT] == []


def test_ip_conflict_groups_case_insensitively() -> None:
    # Altcode-treu: Vergleich ueber upper-MAC -> gemischte Schreibweise = dieselbe MAC.
    current = [
        ArpEntry("192.168.1.10", "bb:bb:bb:22:22:22", "BetaInc"),
        ArpEntry("192.168.1.11", "BB:BB:BB:22:22:22", "BetaInc"),
    ]
    alerts = detect_arp_anomalies(current, baseline=[])
    conflicts = [a for a in alerts if a.alert_type == ARP_ALERT_IP_CONFLICT]
    assert len(conflicts) == 1
    assert conflicts[0].new_mac == "BB:BB:BB:22:22:22"  # upper-Key


# ── mac_changed: feuert / Gegenprobe + severity ───────────────


def test_mac_changed_high_when_vendor_changes() -> None:
    current = [ArpEntry("192.168.1.10", "BB:BB:BB:22:22:22", "BetaInc")]
    baseline = [ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp")]
    alerts = detect_arp_anomalies(current, baseline)
    changed = [a for a in alerts if a.alert_type == ARP_ALERT_MAC_CHANGED]
    assert len(changed) == 1
    c = changed[0]
    assert c.severity == ARP_SEVERITY_HIGH  # alter Vendor gesetzt UND verschieden
    assert c.ip == "192.168.1.10"
    assert c.old_mac == "AA:AA:AA:11:11:11"
    assert c.new_mac == "BB:BB:BB:22:22:22"
    assert c.old_vendor == "AcmeCorp"
    assert c.new_vendor == "BetaInc"
    assert c.message == (
        "IP 192.168.1.10: MAC changed from AA:AA:AA:11:11:11 (AcmeCorp) "
        "to BB:BB:BB:22:22:22 (BetaInc)"
    )


def test_mac_changed_medium_when_vendor_same() -> None:
    # neue MAC, gleicher Vendor -> medium (Gegenprobe zu high).
    current = [ArpEntry("192.168.1.10", "AA:AA:AA:99:99:99", "AcmeCorp")]
    baseline = [ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp")]
    alerts = detect_arp_anomalies(current, baseline)
    changed = [a for a in alerts if a.alert_type == ARP_ALERT_MAC_CHANGED]
    assert len(changed) == 1
    assert changed[0].severity == ARP_SEVERITY_MEDIUM


def test_mac_changed_medium_when_old_vendor_unknown() -> None:
    # alter Vendor leer -> medium, selbst wenn der neue Vendor gesetzt ist.
    current = [ArpEntry("192.168.1.10", "BB:BB:BB:22:22:22", "BetaInc")]
    baseline = [ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "")]
    alerts = detect_arp_anomalies(current, baseline)
    changed = [a for a in alerts if a.alert_type == ARP_ALERT_MAC_CHANGED]
    assert len(changed) == 1
    assert changed[0].severity == ARP_SEVERITY_MEDIUM  # old_vendor leer -> nicht high


def test_mac_changed_gegenprobe_same_mac_no_alert() -> None:
    current = [ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp")]
    baseline = [ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp")]
    alerts = detect_arp_anomalies(current, baseline)
    assert [a for a in alerts if a.alert_type == ARP_ALERT_MAC_CHANGED] == []


def test_mac_changed_case_insensitive_no_false_alert() -> None:
    # Baseline upper, current lower -> selbe MAC -> KEIN mac_changed (Vergleich upper).
    current = [ArpEntry("192.168.1.10", "aa:aa:aa:11:11:11", "AcmeCorp")]
    baseline = [ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp")]
    alerts = detect_arp_anomalies(current, baseline)
    assert [a for a in alerts if a.alert_type == ARP_ALERT_MAC_CHANGED] == []


# ── new_device: KEIN Alert (SEC.1-Befund auf Domaenen-Ebene) ──


def test_new_device_produces_no_alert() -> None:
    # Neue IP, nicht in Baseline -> KEIN Alert (Altcode schreibt nur Baseline).
    current = [ArpEntry("192.168.1.50", "CC:CC:CC:33:33:33", "GammaLtd")]
    alerts = detect_arp_anomalies(current, baseline=[])
    assert alerts == []


def test_no_alert_type_new_device_ever_emitted() -> None:
    # Gegenprobe zur toten Konstante: kein Pfad erzeugt alert_type="new_device".
    current = [
        ArpEntry("192.168.1.50", "CC:CC:CC:33:33:33", "GammaLtd"),
        ArpEntry("192.168.1.51", "AA:AA:AA:11:11:11", "AcmeCorp"),
    ]
    alerts = detect_arp_anomalies(current, baseline=[])
    assert all(a.alert_type != "new_device" for a in alerts)


# ── Reihenfolge + Kombination ─────────────────────────────────


def test_conflict_before_changed_in_one_scan() -> None:
    # Ein Scan kann beides erzeugen: ip_conflict zuerst, dann mac_changed (Altcode-Folge).
    current = [
        ArpEntry("192.168.1.10", "BB:BB:BB:22:22:22", "BetaInc"),
        ArpEntry("192.168.1.11", "BB:BB:BB:22:22:22", "BetaInc"),
    ]
    # .10 war in Baseline mit AA -> mac_changed; .11 neu -> kein device-Alert, aber
    # beide teilen BB -> ip_conflict.
    baseline = [ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp")]
    alerts = detect_arp_anomalies(current, baseline)
    types = [a.alert_type for a in alerts]
    assert types[0] == ARP_ALERT_IP_CONFLICT  # conflict zuerst
    assert ARP_ALERT_MAC_CHANGED in types[1:]  # mac_changed danach


def test_empty_current_yields_no_alerts() -> None:
    assert detect_arp_anomalies([], baseline=[]) == []
    assert detect_arp_anomalies([], baseline=[ArpEntry("1.2.3.4", "AA", "X")]) == []
