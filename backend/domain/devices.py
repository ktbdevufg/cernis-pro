"""Domaenenmodell der devices-Domaene: Geraete-Aggregat und reine Merge-Regeln.

Reine Domaenenlogik (stdlib + dataclasses, ADR 0002) -- kein Wissen ueber
Persistenz (SQLite/JSON ist Infrastruktur), kein HTTP und keine Uhr: die Zeit
kommt als ``now``-Parameter herein, der Clock-Port wohnt spaeter in den Adaptern.

Der Kern ist (1) die zentrale MAC-Normalisierung -- heute im Altcode an mehreren
Stellen verstreut, hier die EINE Quelle --, (2) die Upsert-Merge-Regel
``merge_scan`` (ersetzt die ``CASE WHEN ?!=''``-SQL-Logik aus
``modules/devices_db.py``) und (3) die IP-History-Regel ``should_append_ip``.

v2-Schnitt: die alte ``known_devices``-Tabelle entfaellt; es gibt genau EINE
Geraete-Entitaet. ``is_known`` ist allein User-gesteuert -- ein Scan setzt es
NIE zurueck (bewusste Korrektur von BUG 2 der Ist-Analyse).
"""

import re
from dataclasses import dataclass, replace
from datetime import datetime


def normalize_mac(raw: str) -> str:
    """Die EINE Quelle der MAC-Normalisierung: kanonische Form ``AA:BB:CC:DD:EE:FF``.

    Vereinheitlicht Trennzeichen (``:``/``-``/``.``/keine) zu ``:`` und schreibt
    gross. Ist idempotent. Input ohne Hex-Zeichen (leer o. Aae.) -> ``ValueError``,
    weil die MAC die Pflicht-Identitaet eines Geraets ist.
    """
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", raw)
    if not cleaned:
        raise ValueError("MAC darf nicht leer sein")
    upper = cleaned.upper()
    return ":".join(upper[i : i + 2] for i in range(0, len(upper), 2))


@dataclass(frozen=True)
class Device:
    """Schlanke Geraete-Stammdaten (ein Aggregat, KEINE IP-History -- die ist getrennt).

    Scan-getriebene Felder: ``vendor``, ``hostname``, ``os_guess``, ``open_ports``,
    ``last_ip``, ``last_seen``, ``times_seen``. User-kuratierte Felder, die ein
    Scan bewahrt: ``label``, ``tags``, ``notes``, ``is_known``, ``category``.
    """

    mac: str
    first_seen: datetime
    last_seen: datetime
    last_ip: str | None = None
    times_seen: int = 1
    is_known: bool = False
    vendor: str = ""
    label: str = ""
    notes: str = ""
    category: str = ""
    hostname: str = ""
    os_guess: str = ""
    tags: tuple[str, ...] = ()
    open_ports: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "mac", normalize_mac(self.mac))
        if self.times_seen < 0:
            raise ValueError("times_seen darf nicht negativ sein")


@dataclass(frozen=True)
class ScannedHost:
    """Was ein Scan ueber einen Host liefert -- typisierte Eingabe fuer ``merge_scan``.

    Reines Wertobjekt; die Abbildung vom rohen Scan-Dict (JSON-Ports usw.) auf
    dieses Objekt ist Aufgabe der application-/infrastructure-Schicht, nicht der
    Domaene. ``category`` ist bewusst NICHT enthalten: Kategorie ist kuratierte/
    klassifizierte Information, kein Scan-Stammdatum (deckt sich mit dem Altcode,
    der ``category`` beim Scan-Upsert ebenfalls nicht schrieb).
    """

    mac: str
    ip: str | None = None
    vendor: str = ""
    hostname: str = ""
    os_guess: str = ""
    open_ports: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "mac", normalize_mac(self.mac))


@dataclass(frozen=True)
class IpHistoryEntry:
    """Ein Eintrag der IP-Historie eines Geraets (Wertobjekt).

    Nur das Wertobjekt; die Sequenz und ihre Persistenz fuehrt das Repository.
    """

    mac: str
    ip: str
    seen_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "mac", normalize_mac(self.mac))


@dataclass(frozen=True)
class DeviceStats:
    """Aggregierte Zaehler ueber den Geraetebestand (reines Ergebnis-Wertobjekt).

    ``active`` zaehlt Geraete, deren ``last_seen`` innerhalb eines vom Aufrufer
    bestimmten Fensters liegt -- die Zeitgrenze kommt vom Use-Case (z. B.
    ``now - 24h``), nicht aus der Persistenz.
    """

    total: int
    known: int
    unknown: int
    active: int


def _scan_or_keep(scanned: str, existing: str) -> str:
    """``CASE WHEN scanned!='' THEN scanned ELSE existing`` aus dem Altcode.

    Ein Re-Scan, der z. B. keinen Hostnamen aufloesen konnte, soll einen frueher
    ermittelten Wert NICHT loeschen -- die leere Scan-Antwort bewahrt das Alte.
    """
    return scanned if scanned else existing


def merge_scan(existing: Device | None, scanned: ScannedHost, now: datetime) -> Device:
    """Upsert-Merge-Regel als reine Funktion (ersetzt die ``CASE WHEN``-SQL-Logik).

    - ``existing`` None -> Neuentdeckung: ``times_seen=1``,
      ``first_seen=last_seen=now``, ``is_known=False``.
    - ``existing`` vorhanden -> ``last_seen=now``, ``times_seen+1``;
      ``last_ip``/``open_ports`` werden UNBEDINGT aus dem Scan uebernommen,
      ``vendor``/``hostname``/``os_guess`` nur, wenn der Scan einen nicht-leeren
      Wert liefert (sonst Alt-Wert bewahren, s. ``_scan_or_keep``). Die
      Kuratierung (``label``/``tags``/``notes``/``is_known``/``category``) und
      ``first_seen`` bleiben erhalten.

    BUG-2-FIX (bewusst): ``is_known`` wird vom Scan NIE auf False gesetzt. Der
    Altcode liess ``is_known`` beim Scan-Update unangetastet und schrieb beim
    Insert 0; v2 macht das explizit -- ``is_known`` ist allein User-gesteuert.
    Die Zeit kommt ausschliesslich ueber ``now`` (kein ``datetime.now()`` hier).
    """
    if existing is None:
        return Device(
            mac=scanned.mac,
            first_seen=now,
            last_seen=now,
            last_ip=scanned.ip,
            times_seen=1,
            is_known=False,
            vendor=scanned.vendor,
            hostname=scanned.hostname,
            os_guess=scanned.os_guess,
            open_ports=scanned.open_ports,
        )
    return replace(
        existing,
        last_seen=now,
        times_seen=existing.times_seen + 1,
        last_ip=scanned.ip,
        open_ports=scanned.open_ports,
        vendor=_scan_or_keep(scanned.vendor, existing.vendor),
        hostname=_scan_or_keep(scanned.hostname, existing.hostname),
        os_guess=_scan_or_keep(scanned.os_guess, existing.os_guess),
        # first_seen/label/tags/notes/is_known/category bleiben via replace erhalten.
    )


def should_append_ip(existing: Device | None, scanned_ip: str | None) -> bool:
    """IP-History-Regel: anhaengen nur bei IP-Wechsel.

    - ``existing`` None + IP vorhanden -> True (erste IP).
    - gleiche IP wie zuletzt -> False.
    - abweichende IP -> True.
    - keine IP im Scan -> False.

    Reine Funktion; das tatsaechliche Anhaengen erledigt das Repository.
    """
    if not scanned_ip:
        return False
    if existing is None:
        return True
    return existing.last_ip != scanned_ip
