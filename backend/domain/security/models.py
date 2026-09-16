"""Domaenenmodelle der security-Domaene (arp_guard) -- reine Wertobjekte.

stdlib only (ADR 0002), kein Framework, kein I/O, kein SQL, KEIN Import aus anderen
Domaenen (independence-Contract, CI-hart). Charakterisierungstreu zum Altcode
``modules/arp_guard.py`` (in SEC.1 als Vertrag eingefroren) -- mit den unten
begruendeten, bewussten Modellierungs-Entscheidungen.

NUR arp_guard wird domaenisiert: cve/tls/default_creds sind reine Adapter mit Netz-I/O
ohne Domaenenlogik und bekommen in SEC.3/SEC.4 nur Port+Adapter, KEIN Domaenenmodell.

────────────────────────────────────────────────────────────────────────────
ENTSCHEIDUNGEN
────────────────────────────────────────────────────────────────────────────

ArpEntry traegt NUR ip/mac/vendor (NICHT first_seen/last_seen):
    Die Erkennung (``detect_arp_anomalies``) vergleicht ausschliesslich ip, mac und
    vendor. ``first_seen``/``last_seen`` sind reine BASELINE-PERSISTENZ-Spalten
    (arp_baseline-Tabelle), die die Erkennung NIE liest. Sie gehoeren damit in den
    Repository-Rand (SEC.4, als Row/dict), nicht ins Domaenenmodell. ArpEntry ist
    eine bewusste VIEW auf das, was die Erkennung braucht -- kein roher Tabellen-Dump.

``alert_type: str`` (NICHT StrEnum), wie A.2 ``rule_type``:
    Konservativ Altcode-treu. Der Altcode nutzt freie Strings. Eine StrEnum waere eine
    Verschaerfung (eigener spaeterer Schritt). Die bekannten Werte als Doku-Konstanten.
    ``ARP_ALERT_NEW_DEVICE`` wird gefuehrt, OBWOHL die Erkennung ihn NIE erzeugt
    (SEC.1-Befund: toter alert_type-Wert; der neue-IP-Pfad schreibt nur die Baseline,
    keinen Alert) -- die Konstante markiert die LATENTE security->alerting-Naht
    (DF1-Nachzuegler, korrespondiert zu ``domain.alerting.RULE_TYPE_NEW_DEVICE``),
    damit der spaetere Trigger-Schritt den Anknuepfpunkt findet. ``detect_arp_anomalies``
    erzeugt real nur ``ip_conflict`` und ``mac_changed``.

``severity: str`` (NICHT StrEnum), dito:
    Altcode nutzt freie Strings "high"/"medium"/"low". Die Erkennung erzeugt real nur
    "high" und "medium" (SEC.1-Vertrag); "low" wird als Altcode-Vokabular-Konstante
    gefuehrt, aber nie produziert.

``ArpAlert`` ohne ``ts``/``datetime`` und ohne ``.to_dict()`` (wie AlertEvent/
MonitorEvent):
    Zeit und Wire-Form sind Rand-/Persistenz-Sache. Der Altcode-``ArpAlert`` trug
    ``timestamp`` + ein ``to_dict()`` mit ``datetime``-Formatierung -- beides lebt in
    v2 im SEC.4-Adapter (arp_alerts-Zeile), NICHT in der Domaene. Es gibt KEIN
    ``last_triggered``-Aequivalent: arp hat keinen Cooldown.
"""

from dataclasses import dataclass

# Von der Erkennung real erzeugte alert_types (Altcode ``_scan_arp_sync``).
ARP_ALERT_IP_CONFLICT = "ip_conflict"
ARP_ALERT_MAC_CHANGED = "mac_changed"
# Toter alert_type-Wert (SEC.1-Befund): im Altcode-Docstring deklariert, aber NIE
# geschrieben. Gefuehrt als Marker der latenten security->alerting-Naht
# (korrespondiert zu domain.alerting.RULE_TYPE_NEW_DEVICE). detect_arp_anomalies
# erzeugt ihn NICHT.
ARP_ALERT_NEW_DEVICE = "new_device"

# severity-Stufen (Altcode-Vokabular). Erkennung erzeugt real nur HIGH/MEDIUM.
ARP_SEVERITY_HIGH = "high"
ARP_SEVERITY_MEDIUM = "medium"
ARP_SEVERITY_LOW = "low"  # nie von der Erkennung erzeugt; Altcode-Vokabular


@dataclass(frozen=True)
class ArpEntry:
    """Eine ARP-Tabellen-Zeile, wie die Erkennung sie vergleicht: ip, mac, vendor.

    Aus dem Altcode entsteht das aus ``get_arp_table()`` ({ip: mac}) + ``lookup_vendor``.
    ``first_seen``/``last_seen`` der arp_baseline-Tabelle sind BEWUSST NICHT hier
    (s. Modul-Docstring) -- reine Persistenz, fuer die Erkennung irrelevant.
    """

    ip: str
    mac: str
    vendor: str = ""


@dataclass(frozen=True)
class ArpAlert:
    """Eine erkannte ARP-Anomalie (reiner Datentraeger, kein ts/to_dict).

    Felder 1:1 zur Altcode-Semantik (SEC.1-Vertrag):
      * ``alert_type``: "ip_conflict" | "mac_changed" (ARP_ALERT_*-Konstanten).
      * ``ip``: bei mac_changed die einzelne IP; bei ip_conflict die ", "-verbundene
        Liste der kollidierenden IPs (Altcode ``", ".join(ips)``).
      * ``old_mac``/``old_vendor``: leer ("") bei ip_conflict; bei mac_changed der
        Baseline-Wert.
      * ``new_mac``/``new_vendor``: die aktuell beobachtete MAC + ihr Vendor.
      * ``severity``: "high" | "medium" (ARP_SEVERITY_*).
      * ``message``: der Altcode-Meldungstext (View-Vokabular, charakterisierungstreu).
    """

    alert_type: str
    ip: str
    old_mac: str
    new_mac: str
    old_vendor: str
    new_vendor: str
    severity: str
    message: str
