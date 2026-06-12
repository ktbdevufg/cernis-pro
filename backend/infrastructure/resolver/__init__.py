"""Adapter der resolver-Domaene: Quell-Ports ueber System-Tools/Netz/lokale DB.

Teilschritt 2a: ``DigDnsPtrResolver`` erfuellt ``ports.resolver.PtrResolverPort`` --
Reverse- (PTR) und Vorwaerts-DNS (A/AAAA) ueber das System-``dig``-Binary (Muster
``infrastructure.diagnostics_linux.DigDnsResolver``). Fehlt ``dig`` -> infra-eigene
``ResolverToolMissing``; ein leerer/scheiternder Lookup ist KEIN Fehler.

Teilschritt 2b: ``TlsCertReader`` erfuellt ``ports.resolver.TlsCertPort`` -- wertneutraler
TLS-Zertifikatsabruf (stdlib ssl/socket, Mechanik aus ``infrastructure.security.tls``
NACHGEBAUT, nicht importiert). KEIN Grade/Urteil, streng fehlertolerant (jeder Fehlschlag
-> ``None``).

Teilschritt 2c (dieser Stand): ``RdapClient`` erfuellt ``ports.resolver.RdapClientPort`` --
RIR-toleranter RDAP-Lookup ueber ``httpx`` (rdap.org als Einstieg, ``follow_redirects`` zur
zustaendigen Registry; httpx-Muster aus ``HttpxReachabilityProvider``). Streng
fehlertolerant: jeder Fehlschlag -> leerer ``RdapRawFacts()``; ``asn``/``asn_org`` bewusst
``None`` (kommt aus der Geo-DB 2d, nicht aus RDAP geraten).

Teilschritt 2d (dieser Stand): ``CsvGeoAsnDb`` erfuellt ``ports.resolver.GeoAsnDbPort`` --
rein lokaler, synchroner Geo/ASN-Lookup aus vier CC0/PDDL-CSVs (``backend/data``), einmal
im Konstruktor in sortierte Listen geladen, Lookup per ``bisect``. Fuellt ``country`` +
ASN-Nummer; ``asn_org`` BEWUSST ``None`` (Klartext-Org aus RDAP 2c, A1). Fehlt eine CSV
beim Laden -> ``ResolverDataMissing`` (kein stiller Leer-Fallback).

KEIN ``modules``-Import -> kein ADR-0007 fuer resolver. Alle vier Quell-Adapter stehen.
"""

from infrastructure.resolver.dns_ptr import DigDnsPtrResolver
from infrastructure.resolver.errors import ResolverDataMissing, ResolverToolMissing
from infrastructure.resolver.geo_asn import CsvGeoAsnDb
from infrastructure.resolver.rdap import RdapClient
from infrastructure.resolver.tls_cert import TlsCertReader

__all__ = [
    "CsvGeoAsnDb",
    "DigDnsPtrResolver",
    "RdapClient",
    "ResolverDataMissing",
    "ResolverToolMissing",
    "TlsCertReader",
]
