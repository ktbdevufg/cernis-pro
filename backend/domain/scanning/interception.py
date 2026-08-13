"""Auswahl der Kontroll-Adressen fuer die Gegenprobe (Befund 53) -- reine Domaene.

Kein I/O, keine Messung: hier wird nur GERECHNET, welche Adressen sich als
Kontroll-Adressen eignen. Die Messung selbst laeuft im Use-Case ueber den
``PortScannerPort`` -- diese Trennung haelt die Auswahlregel testbar, ohne dass
ein Netz oder ein Adapter im Spiel ist.

Warum es Kontroll-Adressen ueberhaupt braucht: Faengt ein Sicherheitsprogramm auf
der MESSENDEN Maschine bestimmte Ports lokal ab, gelingt der Verbindungsaufbau
gegen jede beliebige Adresse -- auch gegen eine, an der kein Geraet existiert.
Genau das macht die Gegenprobe sichtbar.
"""

from ipaddress import ip_address, ip_network

# Anzahl der Kontroll-Adressen. Bewusst DREI, nicht eine: Dass eine Adresse in der
# Discovery schweigt, beweist NICHT, dass dort nichts laeuft -- ein Geraet kann
# Ping verweigern (Firewall) und trotzdem Dienste anbieten. Ein einzelnes stilles
# Geraet wuerde bei einer einzigen Kontroll-Adresse den ganzen Befund kippen und
# echte offene Ports aller Geraete verschwinden lassen. Bei dreien muss ein Port
# auf ALLEN dreien antworten, damit er als abgefangen gilt -- ein stilles Geraet
# allein reicht dafuer nicht.
CONTROL_ADDRESS_COUNT = 3

# Obergrenze fuer die Zahl der GEPRUEFTEN Kandidaten ueber die gesamte Auswahl.
#
# Warum es sie braucht: Ein Netz kann beliebig gross sein (``ScanConfig`` prueft
# CIDRs nur auf Format, nicht auf Groesse). Ist ein grosses Netz fast vollstaendig
# belegt, muesste die Suche nach freien Adressen sonst unbegrenzt weiterlaufen.
#
# Warum genau dieser Wert: Ein vollstaendig belegtes /24 -- das groesste Netz, das
# im Zielbild dieser Anwendung als EIN Segment realistisch ist -- beruehrt
# ``CONTROL_ADDRESS_COUNT * 254 = 762`` Kandidaten, bis es sicher weiss, dass
# nichts frei ist. Die Grenze liegt mit 10.000 rund um den Faktor 13 darueber:
# jedes reale Netz wird vollstaendig durchsucht, waehrend ein /16 (65.534
# Adressen) oder groesser gedeckelt bleibt. Der Wert ist eine Obergrenze fuer den
# PATHOLOGISCHEN Fall, keine Einstellung -- deshalb eine Konstante.
#
# Was beim Erreichen passiert: Es kommt zurueck, was bis dahin gefunden wurde --
# also WENIGER als ``count``. Fuer den Aufrufer ist das derselbe Fall wie "zu
# wenige Kandidaten": er meldet "nicht geprueft" mit Grund und filtert NICHT.
# Kein stilles Aufgeben und keine Filterung auf duenner Grundlage (ADR 0001).
MAX_PROBED_CANDIDATES = 10_000


def _host_ranges(cidrs: tuple[str, ...]) -> list[tuple[int, int]]:
    """Verschmilzt die CIDRs zu disjunkten, aufsteigenden Ganzzahl-Bereichen.

    Die Host-Adressen eines Netzes bilden immer einen LUECKENLOSEN Zahlenbereich.
    Damit laesst sich der Adressraum als Handvoll ``(erste, letzte)``-Paare
    darstellen, statt ihn aufzuzaehlen: der Speicher haengt an der Zahl der CIDRs,
    nicht an der Netzgroesse.

    Netz- und Broadcast-Adresse fallen hier heraus -- ausser bei /31 und /32, wo
    die stdlib (``hosts()``) bewusst alle Adressen als Hosts fuehrt. Dieselbe
    Kantenfall-Semantik wie zuvor, nur gerechnet statt aufgezaehlt.

    Das Verschmelzen macht ueberlappende CIDRs dublettenfrei: eine Adresse, die in
    zwei CIDRs liegt, kommt im Ergebnis genau einmal vor.
    """
    raw: list[tuple[int, int]] = []
    for cidr in cidrs:
        net = ip_network(cidr, strict=False)
        if net.num_addresses > 2:
            first, last = int(net.network_address) + 1, int(net.broadcast_address) - 1
        else:
            # /31 und /32: kein Netz-/Broadcast-Ausschluss (stdlib-Sonderfall).
            first, last = int(net.network_address), int(net.broadcast_address)
        if first <= last:
            raw.append((first, last))

    raw.sort()
    merged: list[tuple[int, int]] = []
    for first, last in raw:
        # ``<= last + 1`` verschmilzt auch direkt aneinandergrenzende Bereiche --
        # sonst zaehlte dieselbe zusammenhaengende Strecke doppelt.
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], last))
        else:
            merged.append((first, last))
    return merged


def _address_at(ranges: list[tuple[int, int]], position: int) -> int:
    """Liefert die Adresse an der ``position``-ten Stelle des Adressraums.

    Rechnet die Position ueber die Bereichslaengen in eine Adresse um, statt eine
    Liste zu indizieren -- der Kern der Nicht-Materialisierung.
    """
    for first, last in ranges:
        size = last - first + 1
        if position < size:
            return first + position
        position -= size
    raise IndexError(position)


def pick_control_addresses(
    cidrs: tuple[str, ...],
    discovered_ips: frozenset[str],
    count: int = CONTROL_ADDRESS_COUNT,
) -> tuple[str, ...]:
    """Waehlt bis zu ``count`` Kontroll-Adressen aus den ``cidrs``.

    Geeignet ist eine Adresse, die

    * in einem der ``cidrs`` liegt,
    * in der Discovery NICHT geantwortet hat (nicht in ``discovered_ips``),
    * und weder Netz- noch Broadcast-Adresse ihres Netzes ist.

    Die Auswahl streut BEWUSST ueber den Adressraum, statt die ersten drei
    Kandidaten zu nehmen: drei benachbarte Adressen liegen mit hoher
    Wahrscheinlichkeit im selben ungenutzten Block und haengen damit am selben
    Zufall (ein einzelner stiller Nachbar-Cluster). Weit gestreute Adressen sind
    voneinander unabhaengiger, und genau darauf beruht die Mehrheitsregel "auf
    ALLEN dreien".

    Gestreut wird ueber den ADRESSRAUM, nicht ueber die Liste der freien
    Adressen: der Raum wird in ``count`` gleich grosse Abschnitte geteilt, und je
    Abschnitt wird ab dessen Anfang die erste freie Adresse gesucht. Das ist der
    Unterschied zum frueheren Weg, der dieselben Positionen auf der GEFILTERTEN
    Kandidatenliste nahm -- was voraussetzte, die Liste erst vollstaendig zu
    bauen. Bei leerer Discovery liefern beide Wege dasselbe Ergebnis; bei
    belegten Adressen kann die gewaehlte Adresse abweichen (sie bleibt frei,
    ungefunden und gestreut).

    Findet ein Abschnitt bis zu seinem Ende nichts Freies, laeuft die Suche
    ZYKLISCH ueber den restlichen Raum weiter. Das erhaelt die Zusage "so viele
    Adressen wie moeglich": solange ueberhaupt ``count`` freie Adressen
    existieren, kommen auch ``count`` zurueck -- ein Abschnitt gibt nicht auf,
    nur weil sein eigener Bereich belegt ist.

    Der Speicherbedarf haengt an ``count`` und an der Zahl der ``cidrs``, NICHT an
    der Netzgroesse: der Adressraum wird gerechnet (siehe ``_host_ranges``), nie
    aufgezaehlt. Ein /12 kostet damit so wenig wie ein /30.

    Reicht die Zahl der Kandidaten nicht fuer ``count`` -- oder ist die Suche an
    ``MAX_PROBED_CANDIDATES`` gelaufen --, kommt zurueck, was da ist; der Aufrufer
    entscheidet dann ueber den "nicht geprueft"-Zustand. Hier wird NICHT
    stillschweigend auf weniger Adressen heruntergegangen.

    Rueckgabe in aufsteigender Adress-Reihenfolge, dedupliziert (ueberlappende
    CIDRs erzeugen keine doppelte Kontroll-Adresse).
    """
    if count <= 0:
        return ()

    ranges = _host_ranges(cidrs)
    total = sum(last - first + 1 for first, last in ranges)
    if total == 0:
        return ()

    found: list[str] = []
    taken: set[int] = set()
    probed = 0

    for section in range(count):
        # Abschnittsanfaenge 0, total/count, 2*total/count, ... -- dieselbe
        # gleichmaessige Streuung wie zuvor, nur ueber den Raum statt ueber die
        # gefilterte Liste.
        start = section * total // count
        offset = 0
        while offset < total:
            if probed >= MAX_PROBED_CANDIDATES:
                # Grenze erreicht: mit dem zurueckkommen, was gefunden wurde --
                # fuer den Aufrufer der "zu wenige Kandidaten"-Fall. Auch hier
                # sortiert, damit die Zusage "aufsteigend" ausnahmslos gilt.
                found.sort(key=lambda text: int(ip_address(text)))
                return tuple(found)
            probed += 1
            position = (start + offset) % total
            if position not in taken:
                text = str(ip_address(_address_at(ranges, position)))
                if text not in discovered_ips:
                    taken.add(position)
                    found.append(text)
                    break
            offset += 1

    # Die Abschnitte liefern aufsteigend, aber der zyklische Umlauf kann eine
    # Adresse VOR der eines frueheren Abschnitts finden -- daher sortieren. Die
    # Liste ist hoechstens ``count`` lang, das kostet nichts.
    found.sort(key=lambda text: int(ip_address(text)))
    return tuple(found)
