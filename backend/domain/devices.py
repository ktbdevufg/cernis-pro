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
from datetime import datetime, timedelta
from enum import StrEnum


class TrustState(StrEnum):
    """Wertende Vertrauens-Einschaetzung des Nutzers ueber ein Geraet.

    EIGENSTAENDIG und NICHT dasselbe wie ``is_known``: ``is_known`` ist der
    faktische Marker "kenne ich / eingeordnet" (treibt die Gaeste-Wache),
    ``trust_state`` ist die wertende Haltung. Ein Geraet kann bekannt, aber
    nicht vertraut sein (z. B. ein IoT-Geraet, das man ``watch`` setzt).

    Default ist ``NEUTRAL`` -- noch keine Wertung abgegeben. Die Konsistenz-Regel
    (``trusted``/``watch`` impliziert ``is_known``) gehoert NICHT hierher, sondern
    in den Use-Case ``UpdateDeviceMeta``: die Domaene traegt nur den Wert.
    """

    TRUSTED = "trusted"
    NEUTRAL = "neutral"
    WATCH = "watch"


class DeviceSource(StrEnum):
    """Woher der Geraete-Datensatz urspruenglich stammt.

    Ein Scan-Fund ist ``SCAN`` -- so wird ein neu entdecktes Geraet angelegt.
    Ein vom Nutzer von Hand angelegtes Geraet ist ``MANUAL``. Der eigene Host --
    der Rechner, auf dem CERNIS laeuft -- ist ``SELF``; er wird automatisch beim
    Backend-Start in den Bestand aufgenommen, weil ein aktiver Netz-Scan den
    eigenen Host nicht findet. Default ist ``SCAN``, weil der weit ueberwiegende
    Weg ins Inventar der Scan ist; das manuelle Anlegen und der Selbst-Eintrag
    sind die Ausnahmen und werden vom Use-Case bzw. Bootstrap explizit gesetzt.
    """

    SCAN = "scan"
    MANUAL = "manual"
    SELF = "self"


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


BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"


def is_broadcast_mac(raw: str) -> bool:
    """True, wenn die Adresse die Ethernet-Broadcast-Adresse ist.

    Rein und zeitfrei. Vergleicht die KANONISCHE Form, damit Schreibweise und
    Trennzeichen keine Rolle spielen (ff-ff-ff-ff-ff-ff trifft ebenso). Eine
    nicht normalisierbare Eingabe ist keine Broadcast-Adresse und liefert False,
    statt zu werfen -- die Pflicht-Validierung bleibt bei normalize_mac.

    Fachlich: die Broadcast-Adresse ist kein Geraet, sondern eine Adressierungsform.
    Sie gehoert nicht in den Geraetebestand.

    GEWOLLTE DOPPELUNG (Architektur, kein Versehen): ``domain/scanning/addressing.py``
    fuehrt mit ``is_group_mac`` ein Gegenstueck fuer dieselbe fachliche Aussage --
    dort etwas weiter gefasst (jede Gruppen-MAC, nicht nur die Broadcast-MAC). Der
    independence-Contract des import-linter verbietet Quer-Importe zwischen den
    Domaenen-Subpaketen, ``domain/scanning`` darf ``domain/devices`` also nicht
    importieren. Statt die Ringgrenze aufzuweichen, steht die Regel dort ein
    zweites Mal. Aendert sich die fachliche Auslegung, sind BEIDE Stellen
    anzufassen.
    """
    try:
        return normalize_mac(raw) == BROADCAST_MAC
    except ValueError:
        return False


@dataclass(frozen=True)
class Device:
    """Schlanke Geraete-Stammdaten (ein Aggregat, KEINE IP-History -- die ist getrennt).

    Scan-getriebene Felder: ``vendor``, ``hostname``, ``os_guess``, ``open_ports``,
    ``last_ip``, ``last_seen``, ``times_seen``. User-kuratierte Felder, die ein
    Scan bewahrt: ``label``, ``tags``, ``notes``, ``is_known``, ``trust_state``,
    ``category``.
    """

    mac: str
    first_seen: datetime
    last_seen: datetime
    last_ip: str | None = None
    times_seen: int = 1
    is_known: bool = False
    trust_state: TrustState = TrustState.NEUTRAL
    # Gaeste-/Unbekannt-Wache: das Geraet wurde aus der Wache "weggelegt"
    # (ignoriert, NICHT geloescht). Default False = es taucht in der Wache auf,
    # solange es zugleich nicht bekannt ist (``is_known``). Allein
    # User-gesteuert -- ein Scan aendert es NIE (wie is_known/trust_state).
    watch_dismissed: bool = False
    # Lebenszyklus: archiviert = aus allen Wertungen/Listen raus, aber NICHT
    # geloescht (die Historie bleibt). Allein user-/lebenszyklus-gesteuert --
    # ein Scan setzt es NIE (wie is_known/trust_state/watch_dismissed).
    archived: bool = False
    # Herkunft des Datensatzes: ein Scan-Fund ist SCAN (Default), ein manuell
    # angelegtes Geraet MANUAL. Ein Re-Scan aendert die Herkunft nicht.
    source: DeviceSource = DeviceSource.SCAN
    # Wie oft schon nachgefragt wurde, ob archiviert werden soll (0 = noch nie).
    # Treibt die 3x-Regel in register_archive_prompt.
    archive_prompt_count: int = 0
    # Dauerzustand "nicht mehr fragen": einmal True, ruht die Archiv-Nachfrage
    # dauerhaft (z. B. ab dem 3. Nein oder per expliziter User-Entscheidung).
    archive_prompt_dismissed: bool = False
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
        if self.archive_prompt_count < 0:
            raise ValueError("archive_prompt_count darf nicht negativ sein")


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


@dataclass(frozen=True)
class DeviceWithHistory:
    """Ein Geraet samt seiner IP-Historie (reines Ergebnis-Wertobjekt).

    Bringt die getrennt gefuehrten Teile (Stammdaten + History-Sequenz) fuer die
    Detail-Ansicht zusammen, ohne sie im ``Device``-Aggregat zu vermischen.
    """

    device: Device
    ip_history: tuple[IpHistoryEntry, ...] = ()


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
        # Neuentdeckung: trust_state und watch_dismissed werden NICHT gesetzt ->
        # die Defaults NEUTRAL bzw. False greifen. Ein Scan vergibt nie eine
        # Wertung und legt nichts weg; das kommt allein vom User ueber
        # UpdateDeviceMeta/DismissDeviceFromWatch (wie is_known). Eine
        # Neuentdeckung gehoert also frisch in die Wache (watch_dismissed=False).
        # Ebenso werden archived/source/archive_prompt_count/
        # archive_prompt_dismissed NICHT gesetzt -> die Defaults greifen: ein
        # Scan-Fund ist source=SCAN, frisch und nicht archiviert (archived=False,
        # count=0, dismissed=False). Ein Scan archiviert nie.
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
        # first_seen/label/tags/notes/is_known/trust_state/watch_dismissed/
        # category bleiben via replace erhalten -- ein Re-Scan aendert
        # watch_dismissed NIE (ein einmal Weggelegtes bleibt weggelegt, ein
        # noch nicht Weggelegtes bleibt in der Wache).
        # Ebenso bleiben archived/source/archive_prompt_count/
        # archive_prompt_dismissed via replace erhalten -- ein Scan aendert sie
        # NIE: archivieren, die Herkunft und der Nachfrage-Zyklus sind allein
        # user-/lebenszyklus-gesteuert (ein Re-Scan eines archivierten Geraets
        # holt es nicht zurueck).
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


def is_archive_candidate(device: Device, now: datetime, threshold_days: int) -> bool:
    """Kandidatenregel fuer die Archiv-Nachfrage (reine, zeitfreie Funktion).

    True genau dann, wenn das Geraet NICHT archiviert ist UND die Nachfrage
    nicht dauerhaft weggelegt wurde (``archive_prompt_dismissed`` False) UND es
    seit mindestens ``threshold_days`` Tagen nicht mehr gesehen wurde
    (``now - last_seen >= threshold_days``).

    Die Domaene urteilt NUR ueber die Schwelle -- ob tatsaechlich gefragt und
    archiviert wird, entscheidet der muendige Anwender (S3). Die Zeit kommt als
    ``now``-Parameter herein, kein ``datetime.now()`` hier.
    """
    if device.archived or device.archive_prompt_dismissed:
        return False
    return now - device.last_seen >= timedelta(days=threshold_days)


def register_archive_prompt(device: Device, archive: bool) -> Device:
    """Bildet die Nutzerantwort auf eine Archiv-Nachfrage ab (reine Funktion).

    - ``archive=True`` -> das Geraet wird archiviert (``archived=True``); der
      Zaehler bleibt stehen, der Nachfrage-Zyklus endet.
    - ``archive=False`` -> ``archive_prompt_count`` wird um 1 erhoeht. 3x-Regel:
      ab dem 3. Nein (neuer count >= 3) wird zusaetzlich
      ``archive_prompt_dismissed=True`` gesetzt -- danach wird nicht mehr
      gefragt.
    """
    if archive:
        return replace(device, archived=True)
    new_count = device.archive_prompt_count + 1
    return replace(
        device,
        archive_prompt_count=new_count,
        archive_prompt_dismissed=new_count >= 3,
    )
