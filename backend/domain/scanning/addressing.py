"""Eignungspruefung einer Adresse als Geraet (Befund 55) -- reine Domaene.

Kein I/O, keine Messung: hier wird nur ENTSCHIEDEN, ob eine Adresse ueberhaupt
ein Geraet bezeichnen KANN. Die Merges im Scan-Use-Case fragten bisher nur
"liegt die Adresse im gescannten Netz" -- das laesst Adressierungsformen durch,
die per Definition nie ein Geraet sind (Netz- und Broadcast-Adresse, Multicast,
Loopback, link-lokal). Diese Frage ist Domaenenwissen, kein Adapter-Detail --
deshalb steht sie hier und nicht in ``application``.

Abgrenzung zu ``interception.py``: dort wird gerechnet, welche Adressen sich als
Kontroll-Adressen eignen (also gerade NICHT belegt sind); hier, ob eine BEOBACHTETE
Adresse als Geraet in Frage kommt. Die /31- und /32-Sonderfall-Semantik ist in
beiden Modulen dieselbe und stammt aus ``_host_ranges`` -- sie wird hier bewusst
nicht neu ausgelegt, sondern nachvollzogen (siehe ``_excludes_network_and_broadcast``).
"""

from ipaddress import ip_address, ip_network

# Multicast-MAC: das niederwertigste Bit des ERSTEN Oktetts (das I/G-Bit) ist
# gesetzt -- ``ff:ff:ff:ff:ff:ff`` ist davon der Sonderfall, bei dem alle Bits
# gesetzt sind (Broadcast). Beide bezeichnen keine Geraeteidentitaet, sondern
# eine Adressierungsform: ein Rahmen an eine solche MAC geht an eine GRUPPE von
# Empfaengern, nicht an ein bestimmtes Geraet.
#
# GEWOLLTE DOPPELUNG (Architektur, kein Versehen): ``domain/devices.py`` fuehrt
# mit ``BROADCAST_MAC``/``is_broadcast_mac`` ein Gegenstueck fuer dieselbe
# fachliche Aussage. Der independence-Contract des import-linter verbietet
# Quer-Importe zwischen den Domaenen-Subpaketen, ``domain/scanning`` darf
# ``domain/devices`` also nicht importieren. Statt die Ringgrenze aufzuweichen,
# steht die Regel hier ein zweites Mal -- begruendet und beidseitig verlinkt.
# Aendert sich die fachliche Auslegung, sind BEIDE Stellen anzufassen.
_MULTICAST_MAC_BIT = 0x01


def is_group_mac(raw: str) -> bool:
    """True, wenn ``raw`` eine Gruppen-MAC ist (Multicast einschliesslich Broadcast).

    Erkennungsregel: gesetztes niederwertigstes Bit im ersten Oktett (I/G-Bit).
    Die Broadcast-MAC ``ff:ff:ff:ff:ff:ff`` erfuellt das ebenfalls -- sie ist der
    Sonderfall "alle Bits gesetzt" und braucht daher keinen eigenen Zweig.

    Toleriert die ueblichen Schreibweisen (``:``/``-``/``.``/ohne Trenner) und
    Gross-/Kleinschreibung. Eine leere oder unlesbare MAC ist KEINE Gruppen-MAC
    und liefert ``False``, statt zu werfen: eine leere MAC ist ein regulaerer
    Zustand (ein Ping-Host ohne ARP-Eintrag hat keine), und sie darf an dieser
    Pruefung nicht haengenbleiben.
    """
    cleaned = "".join(char for char in raw if char in "0123456789abcdefABCDEF")
    if len(cleaned) < 2:
        return False
    try:
        first_octet = int(cleaned[:2], 16)
    except ValueError:  # pragma: no cover -- nach dem Hex-Filter unerreichbar
        return False
    return bool(first_octet & _MULTICAST_MAC_BIT)


def _excludes_network_and_broadcast(cidr: str) -> bool:
    """True, wenn in ``cidr`` Netz- und Broadcast-Adresse KEINE Hosts sind.

    Dieselbe Sonderfall-Semantik wie ``interception._host_ranges``: ab drei
    Adressen (also bis einschliesslich /30) fallen Netz- und Broadcast-Adresse
    heraus; bei /31 und /32 fuehrt die stdlib (``hosts()``) bewusst ALLE Adressen
    als Hosts -- dort darf nichts ausgeschlossen werden, sonst bliebe von einem
    /32 gar nichts uebrig. Bewusst dieselbe Bedingung ``num_addresses > 2``, damit
    es nicht zwei Auslegungen desselben Kantenfalls gibt.
    """
    return int(ip_network(cidr, strict=False).num_addresses) > 2


def is_device_address(ip_str: str, cidrs: tuple[str, ...]) -> bool:
    """True, wenn ``ip_str`` als Adresse eines Geraets in einem der ``cidrs`` taugt.

    Ersetzt an den Merge-Stellen die Frage "liegt sie im Netz" durch "ist sie eine
    echte Host-Adresse in einem der Netze". Verworfen wird:

    * was ausserhalb ALLER ``cidrs`` liegt (das leistete die bisherige
      Zugehoerigkeitspruefung bereits),
    * die Netz- und die Broadcast-Adresse des jeweiligen CIDR -- mit der /31-/32-
      Ausnahme aus ``_excludes_network_and_broadcast``,
    * Multicast-Adressen: sie adressieren eine Gruppe, nie ein bestimmtes Geraet,
    * Loopback und link-lokale Adressen: sie bezeichnen kein Geraet IM gescannten
      Netz -- Loopback zeigt auf die messende Maschine selbst zurueck, link-lokal
      ist nicht geroutet und entsteht ohne DHCP.

    Die genannten Formen werden auch dann verworfen, wenn ein CIDR sie umfasst:
    ein absichtlich weit gefasstes CIDR macht aus einer Multicast-Adresse kein
    Geraet.

    Eine unparsbare Zeichenkette gilt als nicht geeignet (``False``), wie bisher
    bei der reinen Zugehoerigkeitspruefung -- unsauberer ARP-Output soll hier
    nicht werfen.
    """
    try:
        addr = ip_address(ip_str)
    except ValueError:
        return False

    if addr.is_multicast or addr.is_loopback or addr.is_link_local:
        return False

    for cidr in cidrs:
        net = ip_network(cidr, strict=False)
        if addr not in net:
            continue
        if _excludes_network_and_broadcast(cidr) and addr in (
            net.network_address,
            net.broadcast_address,
        ):
            # In DIESEM Netz ist sie Netz-/Broadcast-Adresse. Kein vorzeitiges
            # False: ueberlappende CIDRs koennen dieselbe Adresse als regulaeren
            # Host fuehren (die Broadcast-Adresse eines /24 ist im umschliessenden
            # /16 eine gewoehnliche Host-Adresse) -- dann gilt sie als geeignet.
            continue
        return True
    return False
