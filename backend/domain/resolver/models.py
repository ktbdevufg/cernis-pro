"""Wertobjekte der resolver-Domaene -- Fakten mit Quelle, NIE verschmolzen.

Reine Wertobjekte (stdlib + dataclasses + typing, ADR 0002): kein I/O, keine Uhr,
kein Framework. resolver beantwortet die Frage "wer ist die Gegenstelle?" als eine
SAMMLUNG VON FAKTEN MIT QUELLE -- KEIN verschmolzenes Urteil. Prinzip: keine
Verschmelzung, kein Urteil, Widersprueche bleiben sichtbar (jedes Feld traegt seine
``source``, der Composition Root entscheidet spaeter NICHTS weg).

BEWUSST eigene Typen (independence-Contract): resolver importiert KEINE andere
domain-Subdomaene. Die Rohtypen der Quell-Ports (``RdapRawFacts``, ``GeoAsnRecord``)
leben hier im domain-Ring -- ``ports/resolver`` importiert sie von hier, NICHT
umgekehrt. RIR-/DB-Parsing ist Sache der spaeteren Adapter; die Domaene kennt nur
die schmalen Rohtypen.
"""

from dataclasses import dataclass
from enum import Enum


class SourceTag(Enum):
    """Herkunft eines Fakts -- WELCHE Quelle den Wert geliefert hat.

    Spiegelt das Frontend-``source``-Feld. Jeder ``ResolverFact`` traegt genau einen
    Tag, damit Widersprueche zwischen Quellen sichtbar bleiben (keine Verschmelzung).
    ``DNSDB`` ist reserviert -- der Tag existiert, wird in diesem Teilschritt aber
    NICHT befuellt (passives DNS kommt spaeter).
    """

    DNS = "dns"
    RDAP = "rdap"
    TLS = "tls"
    GEODB = "geodb"
    DNSDB = "dnsdb"


@dataclass(frozen=True)
class ResolverFact[T]:
    """Ein einzelner Fakt MIT Quelle -- der Grundbaustein der resolver-Sicht.

    Generisch ueber den Wert-Typ ``T`` (PEP 695). Spiegelt das Frontend-Paar
    ``{value, source}``: ``value`` ist der ehrliche Wert (``None``, wenn die Quelle
    nichts geliefert hat -- KEIN erfundener Wert), ``source`` der ``SourceTag`` der
    liefernden Quelle. Bewusst kein "merge": zwei Quellen zum selben Belang ergeben
    zwei Fakten, nicht einen Kompromiss.
    """

    value: T | None
    source: SourceTag


@dataclass(frozen=True)
class TlsCertDetails:
    """Schmaler Auszug eines TLS-Zertifikats -- nur die anzeigbaren Felder.

    Alle Felder sind ``None``-faehig: ein Zertifikat muss nicht jedes Feld tragen, und
    ein Fehlschlag beim Abruf liefert schlicht fehlende Werte (KEIN erfundener Inhalt).
    ``san`` ist die Liste der Subject Alternative Names (leeres Tuple = keine).
    ``self_signed`` ist eine reine FESTSTELLUNG (subject == issuer), KEINE Bewertung
    der Sicherheit -- siehe ``logic.detect_self_signed``; ``None`` wenn unbestimmbar.
    """

    subject_cn: str | None = None
    san: tuple[str, ...] = ()
    issuer: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    serial: str | None = None
    fingerprint_sha256: str | None = None
    self_signed: bool | None = None


@dataclass(frozen=True)
class RdapRawFacts:
    """Roh-Ergebnis eines RDAP-Lookups -- WIE der Port es liefert, ungeparst eingeordnet.

    domain-Rohtyp des ``RdapClientPort``: der Port-Vertrag kennt nur diese schmalen
    Felder, das RIR-spezifische Parsen (verschiedene Registries, verschachtelte
    Antworten) ist Sache des spaeteren Adapters. Alle Felder ``str | None`` -- eine
    leere/teilweise Antwort ist gueltig, KEIN Fehler.
    """

    org: str | None = None
    netname: str | None = None
    net_range: str | None = None
    asn: str | None = None
    asn_org: str | None = None
    abuse_contact: str | None = None
    country: str | None = None


@dataclass(frozen=True)
class GeoAsnRecord:
    """Roh-Ergebnis eines lokalen Geo/ASN-DB-Lookups -- domain-Rohtyp des Ports.

    domain-Rohtyp des ``GeoAsnDbPort`` (lokaler DB-Lookup, daher synchron). Alle Felder
    ``str | None`` -- ein nicht gefundener Eintrag liefert ``None``, KEIN Fehler.
    """

    country: str | None = None
    asn: str | None = None
    asn_org: str | None = None


@dataclass(frozen=True)
class RemoteEndpointFacts:
    """Das Aggregat -- ALLE Fakten ueber eine Gegenstelle, je Belang mit Quelle.

    Kein verschmolzenes Objekt: jedes Feld ist ein ``ResolverFact`` und traegt seine
    eigene ``source``. Widersprueche zwischen Quellen (z. B. RDAP-Land vs. GeoDB-Land)
    bleiben als getrennte Felder sichtbar -- der einzige berechnete Zusatz ist
    ``country_conflict``, ein reines abgeleitetes Flag (KEIN Fact, da nichts aus einer
    Quelle stammt, sondern aus dem VERGLEICH der Laenderfelder -- siehe
    ``logic.flag_country_conflict``).

    ``banner`` existiert hier nur, weil der Frontend-Katalog das Feld kennt -- die
    resolver-Domaene befuellt es NICHT selbst (Banner-Grabbing ist Zustaendigkeit der
    diagnostics-Domaene). Es bleibt ein normales Pflichtfeld; der spaetere Composition
    Root setzt es leer.
    """

    ptr: ResolverFact[str]
    forward_confirmed: ResolverFact[bool]
    tls_cert: ResolverFact[TlsCertDetails]
    dyndns: ResolverFact[str]
    org: ResolverFact[str]
    netname: ResolverFact[str]
    net_range: ResolverFact[str]
    asn: ResolverFact[str]
    asn_org: ResolverFact[str]
    abuse_contact: ResolverFact[str]
    country_rdap_net: ResolverFact[str]
    country_org_address: ResolverFact[str]
    country_geodb: ResolverFact[str]
    service_hint: ResolverFact[str]
    banner: ResolverFact[str]
    country_conflict: bool = False
