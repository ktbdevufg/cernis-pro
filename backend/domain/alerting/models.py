"""Domaenenmodelle der alerting-Domaene -- reine Wertobjekte (stdlib, ADR 0002).

Kein Framework, kein I/O, kein SQL/SMTP/osascript, KEIN Import aus anderen
Domaenen: alerting kennt nur seine eigenen Modelle (independence-Contract, M.8,
CI-hart). Die Datentraeger sind aus dem Altcode ``modules/alerting.py`` uebernommen
(charakterisierungstreu) -- mit zwei bewussten, unten begruendeten Entscheidungen:
``rule_type`` bleibt freier ``str`` (kein StrEnum), und die Flags sind ``bool``
(nicht der Altcode-int 0/1).

ENTSCHEIDUNG ``rule_type: str`` (NICHT StrEnum):
    Anders als ``MonitorEventType`` in monitoring -- das die Domaene SELBST erzeugt
    (geschlossene, von ``classify_transition`` produzierte Menge) -- wird
    ``rule_type`` von AUSSEN hereingereicht (Frontend-POST, ``add_rule``) und von der
    reinen Funktion nur VERGLICHEN. Der Altcode nutzt freie Strings und matcht bei
    unbekanntem Typ schlicht nichts (kein Crash). Eine StrEnum am Domaenen-Eingang
    waere eine bewusste Verschaerfung, die unbekannte rule_types hart machte. ``str``
    ist 1:1 Altcode-treu und die Auswahl-Funktion bleibt fuer beliebige Strings
    robust. Die vier bekannten Typen (host_down/new_device/port_change/cert_expiry)
    sind unten als Konstanten dokumentiert; eine StrEnum ist eine MOEGLICHE spaetere
    Verschaerfung (eigener Schritt, dann mit Rand-Validierung).

ENTSCHEIDUNG Flags als ``bool`` (NICHT int 0/1):
    Die reine Funktion fragt ``enabled``/``notify_email``/``notify_macos`` semantisch
    als Wahrheitswerte ab. ``bool`` ist die ehrliche Domaenen-Modellierung. Der
    Wire-/Speicher-Vertrag int 0/1 (A.1: SQLite-Spalte, Frontend-JSON) ist Rand-Sache:
    die Konvertierung int<->bool passiert im A.4-Adapter / A.5-Use-Case, NICHT in der
    Domaene. Die Wahrheitstabelle der Auswahl-Funktion bleibt identisch zu A.1; A.1
    testet weiter den Altcode-int-Pfad und bleibt unberuehrt.
"""

from dataclasses import dataclass

# Die vier im Altcode/Frontend bekannten rule_types (RULE_TYPES in AlertsView.jsx).
# Hier als Doku-Konstanten, NICHT als geschlossene Menge erzwungen (s. Modul-Docstring).
RULE_TYPE_HOST_DOWN = "host_down"
RULE_TYPE_NEW_DEVICE = "new_device"
RULE_TYPE_PORT_CHANGE = "port_change"
RULE_TYPE_CERT_EXPIRY = "cert_expiry"


@dataclass(frozen=True)
class AlertRule:
    """Eine Alert-Regel (1:1 zur Altcode-Semantik ``modules.alerting.AlertRule``).

    ``threshold`` ist in SEKUNDEN (in A.1 verifiziert -- trotz des irrefuehrenden
    Altcode-Kommentars "days for cert_expiry"; der Code behandelt es ueberall als
    Sekunden, das Frontend labelt "Cooldown: {threshold}s"). Der effektive Cooldown
    ist ``max(threshold, 60)`` (Floor, s. ``matching.py``).

    ``target`` ist entweder ``"any"`` (matcht jedes Ziel) oder ein exakter Wert
    (IP/Host). ``last_triggered`` ist der Unix-Timestamp des letzten Feuerns
    (``0.0`` = nie gefeuert); er bleibt Domaenen-Feld, weil der Cooldown ihn braucht.
    """

    id: int
    name: str
    rule_type: str
    target: str
    threshold: int
    notify_email: bool
    notify_macos: bool
    enabled: bool
    last_triggered: float = 0.0


@dataclass(frozen=True)
class AlertEvent:
    """Ein ausgeloestes Alert-Ereignis (Datentraeger, aus Altcode ``AlertEvent``).

    REINER Datentraeger ohne ``.to_dict()`` (wie ``MonitorEvent`` in monitoring): die
    Wire-/Persistenz-Form (History-Zeile inkl. ``datetime``-Formatierung des
    ``timestamp``) ist Rand-Sache des A.4-Adapters / A.5-Use-Case, nicht der Domaene.
    Die Domaene haelt nur den rohen ``timestamp: float``.
    """

    rule_id: int
    rule_name: str
    rule_type: str
    target: str
    message: str
    timestamp: float
