"""ARP-Anomalie-Erkennung der security-Domaene -- reine, deterministische Logik.

Verhaltensgleich aus dem Altcode portiert (``modules/arp_guard.py``, ``_scan_arp_sync``
Z.146-205): stdlib only, kein I/O, keine DB, keine Uhr, kein ``lookup_vendor``-Call,
kein Import aus anderen Domaenen (independence-Contract, CI-hart).

Die Extraktion zieht NUR die ERKENNUNG heraus -- WELCHE Anomalien vorliegen --, NICHT:
  * den ``lookup_vendor``-Call: der Vendor steckt VORBERECHNET in jedem ``ArpEntry``
    (der SEC.4-Adapter/SEC.5-Use-Case baut die Entries aus get_arp_table + lookup_vendor),
  * den Baseline-Write (``_save_baseline``) -- macht der Use-Case (SEC.5),
  * den ``_clear_alerts``/persist (``_save_alert``) -- macht der Use-Case,
  * die Uhr (``now = time.time()``) -- Zeit ist Rand/Persistenz, kein Erkennungs-Input.

Damit ist ``detect_arp_anomalies`` seiteneffektfrei und ohne Mock testbar.

────────────────────────────────────────────────────────────────────────────
ALTCODE-TREUE ERKENNUNGSREGELN (SEC.1-Vertrag)
────────────────────────────────────────────────────────────────────────────

MAC-Normalisierung: der Altcode vergleicht ge-upper-te MACs (``mac.upper()``). Die
Erkennung tut dasselbe fuer die VERGLEICHE, behaelt aber die Feldwerte altcode-treu:

1. ip_conflict (Tabellen-basiert, NICHT baseline-basiert):
   Gruppiere ``current`` nach upper-MAC. Erscheint EINE MAC auf >1 IP -> EIN Alert:
   ``severity`` IMMER "high"; ``ip`` = ", ".join der IPs (in current-Reihenfolge);
   ``new_mac`` = die upper-MAC (Altcode-Key aus mac_to_ips); ``new_vendor`` = Vendor
   dieser MAC; ``old_mac``/``old_vendor`` = "". Message exakt im Altcode-Wortlaut.

2. mac_changed (baseline-basiert, je IP):
   Fuer jede current-IP, die in der Baseline ist: ist die upper-MAC != Baseline-
   upper-MAC -> Alert. ``severity`` = "high" wenn Baseline-Vendor gesetzt UND
   current-Vendor != Baseline-Vendor, sonst "medium". ``old_mac`` = Baseline-MAC
   (roh, wie gespeichert -- im Altcode bereits upper); ``new_mac`` = current-MAC (ROH,
   ungeuppert); ``old_vendor`` = Baseline-Vendor; ``new_vendor`` = current-Vendor.
   Message exakt im Altcode-Wortlaut.

3. new_device (neue IP, nicht in Baseline):
   ERZEUGT KEINEN ALERT (SEC.1-Befund). Der Altcode schreibt nur die Baseline; die
   reine Erkennung ignoriert solche IPs schlicht. KEIN ``ArpAlert``.

Reihenfolge der Rueckgabe: erst alle ip_conflict (in mac_to_ips-Einfuegereihenfolge),
dann alle mac_changed (in current-Reihenfolge) -- exakt Altcode-Schleifenfolge.
"""

from collections.abc import Mapping, Sequence

from domain.security.models import (
    ARP_ALERT_IP_CONFLICT,
    ARP_ALERT_MAC_CHANGED,
    ARP_SEVERITY_HIGH,
    ARP_SEVERITY_MEDIUM,
    ArpAlert,
    ArpEntry,
)


def detect_arp_anomalies(
    current: Sequence[ArpEntry],
    baseline: Sequence[ArpEntry],
) -> list[ArpAlert]:
    """Erkennt ip_conflict + mac_changed in der aktuellen ARP-Tabelle -- reine Logik.

    ``current`` ist die aktuell beobachtete ARP-Tabelle (ip/mac/vendor pro Zeile,
    Vendor vom Aufrufer vorberechnet). ``baseline`` ist der bekannte Stand (dieselbe
    Form). Gibt die erkannten Alerts in Altcode-Reihenfolge zurueck; schreibt NICHTS
    (kein Baseline-Update, kein persist -- das macht der SEC.5-Use-Case).
    """
    alerts: list[ArpAlert] = []

    # ── 1. ip_conflict: dieselbe (upper-)MAC auf mehreren IPs ──────────────
    # Gruppierung in current-Reihenfolge (dict bewahrt Einfuegereihenfolge), Key=upper.
    mac_to_ips: dict[str, list[str]] = {}
    vendor_by_upper: dict[str, str] = {}
    for entry in current:
        mac_upper = entry.mac.upper()
        mac_to_ips.setdefault(mac_upper, []).append(entry.ip)
        # Vendor je upper-MAC; erster gewinnt (deterministisch, current-Reihenfolge).
        vendor_by_upper.setdefault(mac_upper, entry.vendor)

    for mac_upper, ips in mac_to_ips.items():
        if len(ips) > 1:
            vendor = vendor_by_upper[mac_upper]
            joined = ", ".join(ips)
            alerts.append(
                ArpAlert(
                    alert_type=ARP_ALERT_IP_CONFLICT,
                    ip=joined,
                    old_mac="",
                    new_mac=mac_upper,
                    old_vendor="",
                    new_vendor=vendor,
                    severity=ARP_SEVERITY_HIGH,
                    message=(f"MAC {mac_upper} ({vendor}) appears on multiple IPs: {joined}"),
                )
            )

    # ── 2. mac_changed: bekannte IP, MAC weicht von der Baseline ab ────────
    baseline_by_ip: Mapping[str, ArpEntry] = {entry.ip: entry for entry in baseline}

    for entry in current:
        mac_upper = entry.mac.upper()
        known = baseline_by_ip.get(entry.ip)
        if known is None:
            # new_device: neue IP -> KEIN Alert (SEC.1-Befund, nur Baseline-Write
            # im Use-Case). Hier schlicht ignorieren.
            continue
        known_mac_upper = known.mac.upper()
        if known_mac_upper == mac_upper:
            continue  # MAC unveraendert -> kein Alert
        old_vendor = known.vendor
        vendor = entry.vendor
        # severity: high nur wenn alter Vendor bekannt UND verschieden, sonst medium.
        severity = ARP_SEVERITY_HIGH if old_vendor and vendor != old_vendor else ARP_SEVERITY_MEDIUM
        alerts.append(
            ArpAlert(
                alert_type=ARP_ALERT_MAC_CHANGED,
                ip=entry.ip,
                old_mac=known.mac,  # Baseline-MAC (wie gespeichert)
                new_mac=entry.mac,  # current-MAC ROH (ungeuppert), Altcode-treu
                old_vendor=old_vendor,
                new_vendor=vendor,
                severity=severity,
                message=(
                    f"IP {entry.ip}: MAC changed from {known.mac} ({old_vendor}) "
                    f"to {entry.mac} ({vendor})"
                ),
            )
        )

    return alerts
