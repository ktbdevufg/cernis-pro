"""Modelle und ARP-Anomalie-Erkennung der security-Domaene (arp_guard)."""

from domain.security.detection import detect_arp_anomalies
from domain.security.models import (
    ARP_ALERT_IP_CONFLICT,
    ARP_ALERT_MAC_CHANGED,
    ARP_ALERT_NEW_DEVICE,
    ARP_SEVERITY_HIGH,
    ARP_SEVERITY_LOW,
    ARP_SEVERITY_MEDIUM,
    ArpAlert,
    ArpEntry,
)

__all__ = [
    "ARP_ALERT_IP_CONFLICT",
    "ARP_ALERT_MAC_CHANGED",
    "ARP_ALERT_NEW_DEVICE",
    "ARP_SEVERITY_HIGH",
    "ARP_SEVERITY_LOW",
    "ARP_SEVERITY_MEDIUM",
    "ArpAlert",
    "ArpEntry",
    "detect_arp_anomalies",
]
