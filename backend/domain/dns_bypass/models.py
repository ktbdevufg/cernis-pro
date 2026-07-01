"""Ergebnis- und Eingabetypen des netzweiten DNS-Umgehungs-Waechters (ADR 0042).

Reine stdlib-frozen-dataclasses -- EIGENE ``Dns*``/``Raw*``-Typen, BEWUSST KEINE
Fremd-Domaenentypen (kein ``dns_watch``/``devices``/``blocklist``). Diese Domaene ist
EIGENSTAENDIG (independence-Contract): sie kennt WEDER die host-lokale dns_watch-Sicht
NOCH die Geraete-Zuordnung NOCH die Blocklist. Die Typen hier sind ihr roher
Ein-/Ausgaberand.

FACHLICHE GRENZE (ADR 0042): die Quelle ist der netzweite Sniffer (Etappe 1), der DNS-
ANFRAGEN sieht (Quell-IP, Ziel-IP, L4, best-effort qname). Diese Domaene entscheidet je
Anfrage nur: Ziel NICHT in der erwarteten-Resolver-Menge -> Umgehung. Die Zuordnung
Quell-IP -> Geraet und die DoH-Blocklist-Bewertung liegen NICHT hier, sondern spaeter im
Composition Root (Regel 5) -- diese Domaene bekommt die Quell-IP als ROHEN Schluessel.
"""

from dataclasses import dataclass

__all__ = [
    "DnsBypassFinding",
    "DnsBypassOverview",
    "RawDnsQuery",
]


@dataclass(frozen=True)
class RawDnsQuery:
    """Eine einzelne vom Sniffer erkannte DNS-Anfrage -- der rohe Eingaberand.

    Quellen-AGNOSTISCH (KEIN Fremd-Domaenentyp): der ``DnsQueryProvider`` liefert genau
    diese schmalen Felder aus Etappe 1, die echte Quelle (der DnsHelperClient-poll) faellt
    erst im Composition Root. ``src_ip`` ist der ROHE Gruppier-Schluessel (welches Geraet
    fragt -- die Zuordnung zum Bestand liegt spaeter im Composition Root); ``dst_ip`` ist
    der angefragte Resolver; ``l4`` ist ``"udp"`` oder ``"tcp"``; ``qname`` ist der
    abgefragte Name (``""`` moeglich -- der Sniffer liefert ihn best-effort).
    """

    src_ip: str
    dst_ip: str
    l4: str
    qname: str


@dataclass(frozen=True)
class DnsBypassFinding:
    """Ein aggregierter Umgehungs-Befund = EINE (``src_ip``, ``dst_ip``)-Gruppe.

    Fasst alle Umgehungs-Anfragen desselben Geraets (``src_ip``) zum selben nicht-
    erwarteten Resolver (``dst_ip``) zu einem Befund zusammen: ``query_count`` ist die
    Anzahl dieser Anfragen; ``sample_qnames`` sind bis zu 5 distinct nicht-leere qnames als
    Beleg, deterministisch in Erst-Vorkommen-Reihenfolge. BEWUSST KEIN
    ``device``/``hostname``/``doh``-Feld hier -- das reichert der Composition Root spaeter
    an (die Domaene sieht nur die rohe Quell-IP).
    """

    src_ip: str
    dst_ip: str
    query_count: int
    sample_qnames: tuple[str, ...]


@dataclass(frozen=True)
class DnsBypassOverview:
    """Die Gesamtsicht ueber die uebergebenen Anfragen: nur die Umgehungen + Zaehler.

    ``findings`` enthaelt NUR Umgehungen (Ziel nicht erwartet), deterministisch sortiert
    (``query_count`` absteigend, dann ``src_ip`` aufsteigend, dann ``dst_ip`` aufsteigend --
    s. Use-Case). ``expected_servers`` ist die zur Klassifikation genutzte erwartete Menge
    (als ehrlicher Beleg, was der Befund bedeutet). ``queries_total`` ist die Gesamtzahl
    uebergebener Anfragen; ``bypass_total`` die Anzahl Anfragen mit nicht-erwartetem Ziel;
    ``expected_total`` die mit erwartetem Ziel; ``bypass_devices`` die Anzahl distinct
    ``src_ip`` mit mindestens einer Umgehung.
    """

    findings: tuple[DnsBypassFinding, ...]
    expected_servers: tuple[str, ...]
    queries_total: int
    bypass_total: int
    expected_total: int
    bypass_devices: int
