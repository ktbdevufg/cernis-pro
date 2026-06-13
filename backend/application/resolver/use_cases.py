"""Use-Case der resolver-Domaene -- "wer ist die Gegenstelle?" aus vier Quellen.

Orchestriert die vier Quell-Ports (PTR/Forward-DNS, RDAP, Geo/ASN-DB, TLS) und die
reinen Domaenenfunktionen (``confirm_forward``, ``derive_dyndns``, ``flag_country_
conflict``, ``service_hint_for_port``) zu einem ``RemoteEndpointFacts``-Aggregat. Kennt
``domain/`` und ``ports/``, NIEMALS ``infrastructure/`` (maschinell per import-linter
erzwungen). Die Ports kommen per Constructor-Injection als Protocol-Typ herein -- nie ein
konkreter Adapter.

Der Use-Case ist die EINZIGE Stelle, die die Fakten zusammenstellt und JEDEM Feld seinen
korrekten ``SourceTag`` gibt (keine Verschmelzung, keine Projektion noetig -- das Aggregat
ist resolver-eigen). Er URTEILT nicht: Widersprueche (z. B. RDAP-Land vs. GeoDB-Land)
bleiben als getrennte Felder sichtbar; das einzige abgeleitete Flag ist ``country_
conflict`` (reiner Vergleich, kein Fact).

Nebenlaeufig wo sinnvoll (``asyncio.gather``): RDAP und der Geo/ASN-Lookup sind
unabhaengig und laufen parallel -- RDAP redet ueber das Netz, der Geo/ASN-Lookup ist
SYNCHRON und wird ueber ``asyncio.to_thread`` aus dem Loop gehoben (der Port ist bewusst
sync, damit der lokale DB-Lookup nicht zum Coroutine-Zwang wird).

PTR und TLS sind dagegen GEKOPPELT (nicht mehr voll parallel): der TLS-Abruf braucht den
PTR-Namen als SNI-Servername -- eine IP ist kein gueltiges SNI, SNI-strikte Server
liefern darauf nur ein Dummy-Cert. Also laeuft erst die PTR-Kette (PTR + bei Treffer
Forward-Abgleich, zweiter DNS-Schritt erst wenn ein PTR-Name da ist), danach -- nur bei
gegebenem Port -- der TLS-Abruf mit dem PTR-Namen als SNI. Diese eine Sequenz ist ehrlich
abhaengig; sie laeuft als Ganzes parallel zu RDAP/Geo.
"""

import asyncio
import time

from domain.resolver import (
    GeoAsnRecord,
    RdapRawFacts,
    RemoteEndpointFacts,
    ResolverFact,
    SourceTag,
    TlsCertDetails,
    confirm_forward,
    derive_dyndns,
    flag_country_conflict,
    service_hint_for_port,
)
from ports.resolver import GeoAsnDbPort, PtrResolverPort, RdapClientPort, TlsCertPort


class ResolveEndpoint:
    """Stellt die Fakten ueber eine Gegenstelle aus den vier Quell-Ports zusammen.

    Duenn (Muster ``AnalyzeSnapshot``/``ListAppTraffic``): orchestriert Ports + reine
    Domaene, keine Eigenlogik. Async -- drei der vier Ports reden ueber das Netz; der
    synchrone Geo/ASN-Port wird ueber ``asyncio.to_thread`` eingebunden, damit der Loop
    frei bleibt.
    """

    def __init__(
        self,
        ptr_resolver: PtrResolverPort,
        rdap_client: RdapClientPort,
        geo_asn_db: GeoAsnDbPort,
        tls_cert: TlsCertPort,
    ) -> None:
        self._ptr_resolver = ptr_resolver
        self._rdap_client = rdap_client
        self._geo_asn_db = geo_asn_db
        self._tls_cert = tls_cert

    async def resolve(self, ip: str, port: int | None) -> RemoteEndpointFacts:
        """Holt PTR/Forward, RDAP, Geo/ASN und (bei gegebenem Port) TLS und buendelt sie.

        Drei Zweige laufen nebenlaeufig (``asyncio.gather``): die PTR-und-TLS-Kette (erst
        PTR + bei Treffer Forward-Abgleich, danach -- bei gegebenem Port -- der TLS-Abruf
        mit dem PTR-Namen als SNI), der RDAP-Lookup und der Geo/ASN-Lookup (sync ->
        ``to_thread``). TLS ist an den PTR gekoppelt, weil der Handshake den Namen als SNI
        braucht; RDAP/Geo bleiben unabhaengig. Aus den Rohfakten baut der Use-Case das
        Aggregat: jedes Feld als ``ResolverFact`` mit korrektem ``SourceTag``,
        ``country_conflict`` als abgeleitetes Flag.
        """
        ptr_tls_task = self._resolve_ptr_then_tls(ip, port)
        rdap_task = self._rdap_client.lookup(ip)
        geo_task = asyncio.to_thread(self._geo_asn_db.lookup, ip)

        (ptr_value, forward_ok, tls), rdap, geo = await asyncio.gather(
            ptr_tls_task, rdap_task, geo_task
        )

        return self._assemble(
            ptr_name=ptr_value,
            forward_confirmed=forward_ok,
            rdap=rdap,
            geo=geo,
            tls=tls,
            port=port,
        )

    async def _resolve_ptr_then_tls(
        self, ip: str, port: int | None
    ) -> tuple[str, bool, TlsCertDetails | None]:
        """PTR-Kette und -- daran gekoppelt -- den TLS-Abruf mit PTR-Namen als SNI.

        Erst die PTR-Kette (``_resolve_ptr_chain``), die ``(ptr_name, forward_ok)``
        liefert. Danach der TLS-Abruf, aber NUR wenn ein ``port`` gegeben ist (sonst kein
        TLS-Fakt -> ``None``). Der PTR-Name wird als ``hostname`` (SNI-Servername)
        durchgereicht -- derselbe Name, der schon den Forward-Confirm traegt; ein leerer
        PTR (``""``) wird zu ``None`` und ergibt damit kein SNI. ``fetch_cert`` ist streng
        fehlertolerant (``None`` bei jeglichem Fehlschlag).
        """
        ptr_name, forward_ok = await self._resolve_ptr_chain(ip)
        if port is None:
            return ptr_name, forward_ok, None
        tls = await self._tls_cert.fetch_cert(ip, port, hostname=ptr_name or None)
        return ptr_name, forward_ok, tls

    async def _resolve_ptr_chain(self, ip: str) -> tuple[str, bool]:
        """PTR holen; bei Treffer vorwaerts aufloesen und Forward-Confirmed pruefen.

        Leerer PTR (kein Eintrag) -> ``("", False)``: ohne Namen gibt es nichts vorwaerts
        zu bestaetigen. Mit PTR-Name -> Forward-IPs holen und ``confirm_forward`` (Anti-
        Spoof: die Ziel-IP muss in den Vorwaerts-Aufloesungen stehen).
        """
        ptr_name = await self._ptr_resolver.resolve_ptr(ip)
        if not ptr_name:
            return "", False
        forward_ips = await self._ptr_resolver.resolve_forward(ptr_name)
        return ptr_name, confirm_forward(forward_ips, ip)

    def _assemble(
        self,
        *,
        ptr_name: str,
        forward_confirmed: bool,
        rdap: RdapRawFacts,
        geo: GeoAsnRecord,
        tls: TlsCertDetails | None,
        port: int | None,
    ) -> RemoteEndpointFacts:
        """Baut ``RemoteEndpointFacts`` -- jedes Feld mit korrektem ``SourceTag``.

        Quellen-Zuordnung (Auftrag): ptr/forward_confirmed/dyndns -> DNS; org/netname/
        net_range/abuse_contact/country_rdap_net/country_org_address/asn_org -> RDAP; asn
        (Nummer) + country_geodb -> GEODB; tls_cert -> TLS; service_hint -> DNS (lokale
        Ableitung, neutraler lokaler Tag, keine neue Quelle); banner -> leeres DNS-Fact
        (resolver befuellt es NICHT -- diagnostics-Zustaendigkeit).
        """
        tls_subject_cn = tls.subject_cn if tls is not None else None
        # asn_org: Klartext-Org-Name aus RDAP (A1), bevorzugt das dedizierte asn_org-Feld,
        # sonst der allgemeine Org-Name -- NICHT aus der Geo/ASN-DB (die liefert asn_org
        # bewusst None).
        asn_org = rdap.asn_org if rdap.asn_org is not None else rdap.org

        return RemoteEndpointFacts(
            # ── DNS ──
            ptr=ResolverFact(value=ptr_name or None, source=SourceTag.DNS),
            forward_confirmed=ResolverFact(value=forward_confirmed, source=SourceTag.DNS),
            dyndns=ResolverFact(
                value=derive_dyndns(ptr_name or None, tls_subject_cn), source=SourceTag.DNS
            ),
            service_hint=ResolverFact(value=service_hint_for_port(port), source=SourceTag.DNS),
            banner=ResolverFact(value=None, source=SourceTag.DNS),
            # ── RDAP ──
            org=ResolverFact(value=rdap.org, source=SourceTag.RDAP),
            netname=ResolverFact(value=rdap.netname, source=SourceTag.RDAP),
            net_range=ResolverFact(value=rdap.net_range, source=SourceTag.RDAP),
            asn_org=ResolverFact(value=asn_org, source=SourceTag.RDAP),
            abuse_contact=ResolverFact(value=rdap.abuse_contact, source=SourceTag.RDAP),
            country_rdap_net=ResolverFact(value=rdap.country, source=SourceTag.RDAP),
            # Org-Adresse haben wir nicht separat (kein eigenes RDAP-Feld) -> None-Fact,
            # Quelle bleibt RDAP (dort waere sie verortet).
            country_org_address=ResolverFact(value=None, source=SourceTag.RDAP),
            # ── GEODB ──
            asn=ResolverFact(value=geo.asn, source=SourceTag.GEODB),
            country_geodb=ResolverFact(value=geo.country, source=SourceTag.GEODB),
            # ── TLS ──
            tls_cert=ResolverFact(value=tls, source=SourceTag.TLS),
            # ── abgeleitetes Flag (kein Fact, kein SourceTag) ──
            # Vergleich der bekannten Laenderquellen: RDAP-Netz-Land vs. (None) Org-Adresse
            # vs. GeoDB-Land. Org-Adresse ist None (nicht separat verfuegbar) und faellt im
            # Vergleich weg -- effektiv RDAP-Land vs. GeoDB-Land.
            country_conflict=flag_country_conflict(rdap.country, None, geo.country),
        )


# TTL des prozesslokalen PTR-Caches in Sekunden (Auftrag Paket 5). 3600s = 1h: ein
# PTR-Name aendert sich selten, und die Verkehrsliste fragt dieselben IPs in kurzer
# Folge immer wieder -- der Cache haelt den billigen Lookup vom Loop fern.
_PTR_CACHE_TTL_SECS = 3600.0


class ResolvePtrBatch:
    """Loest zu MEHREREN IPs NUR den PTR-Namen auf -- billig, lokal, fuer die Verkehrsliste.

    Bewusst SCHLANK und getrennt vom reichen ``ResolveEndpoint`` (Paket 5): die
    Verkehrsliste braucht pro Zeile nur den reverse-DNS-Namen, NICHT die teure
    Mehrfach-Aufloesung (RDAP/TLS/Geo). Darum ein eigener Use-Case, der allein den
    ``PtrResolverPort`` nutzt -- denselben Adapter, der schon ``ResolveEndpoint`` traegt
    (Constructor-Injection als Protocol-Typ, nie ein konkreter Adapter, Muster
    ``ResolveEndpoint``).

    Drei Eigenschaften (Auftrag):

    * **Nebenlaeufig:** die eindeutigen IPs werden ueber ``asyncio.gather`` parallel
      aufgeloest (jeder ``resolve_ptr`` redet ueber das Netz -- seriell waere langsam).
    * **Dedupliziert:** gleiche IP nur einmal aufloesen, aber JEDE angefragte IP
      erscheint als Schluessel in der Ergebnis-Map (Reihenfolge/Vollstaendigkeit-Garantie).
    * **TTL-Cache:** ein prozesslokaler, dict-basierter Cache mit Zeit-Ablauf
      (``time.monotonic()``, TTL ``_PTR_CACHE_TTL_SECS``). Ein Cache-Treffer ueberspringt
      den DNS-Lookup. Der Cache ist Use-Case-ZUSTAND (kein Domaenen-Wissen, kein
      Infra-Adapter) und lebt darum hier im application-Ring, gekapselt im Use-Case-Objekt
      -- nicht prozessglobal, sondern an die im Composition Root geteilte Instanz gebunden.

    ``""`` (Port liefert "kein Eintrag") wird in der Ergebnis-Map ehrlich zu ``None``
    projiziert ("kein Name") -- dieselbe ``or None``-Projektion wie in ``ResolveEndpoint``,
    keine neue Domaenenfunktion noetig (dict[str, str | None] genuegt).
    """

    def __init__(self, ptr_resolver: PtrResolverPort) -> None:
        self._ptr_resolver = ptr_resolver
        # Prozesslokaler TTL-Cache: ip -> (ptr_name_or_none, monotone Ablaufzeit). Liegt
        # am Use-Case-Objekt -- die im Composition Root geteilte ResolvePtrBatch-Instanz
        # haelt ihn ueber Requests hinweg (Constructor-Injection bleibt der einzige
        # Zustand, der hier lebt; der Port ist zustandslos).
        self._cache: dict[str, tuple[str | None, float]] = {}

    async def __call__(self, ips: tuple[str, ...]) -> dict[str, str | None]:
        """Liefert ``{ip: ptr_name_or_none}`` -- jede angefragte IP als Schluessel.

        Dedupliziert (gleiche IP nur einmal aufgeloest), nutzt den TTL-Cache (Treffer
        ueberspringen den Lookup) und loest die verbleibenden eindeutigen IPs nebenlaeufig
        (``asyncio.gather``). ``""`` -> ``None`` in der Map.
        """
        now = time.monotonic()
        unique_ips = tuple(dict.fromkeys(ips))  # dedupliziert, Reihenfolge stabil

        # 1) Cache-Treffer (noch gueltig) einsammeln; nur die uebrigen muessen aufloesen.
        resolved: dict[str, str | None] = {}
        to_resolve: list[str] = []
        for ip in unique_ips:
            cached = self._cache.get(ip)
            if cached is not None and cached[1] > now:
                resolved[ip] = cached[0]
            else:
                to_resolve.append(ip)

        # 2) Die uebrigen eindeutigen IPs NEBENLAEUFIG aufloesen (jeder Port-Aufruf ist
        #    Netz-I/O). "" -> None projizieren, Ergebnis cachen (Ablauf jetzt + TTL).
        if to_resolve:
            names = await asyncio.gather(*(self._ptr_resolver.resolve_ptr(ip) for ip in to_resolve))
            expiry = now + _PTR_CACHE_TTL_SECS
            for ip, name in zip(to_resolve, names, strict=True):
                value = name or None
                self._cache[ip] = (value, expiry)
                resolved[ip] = value

        # 3) Fuer JEDE angefragte IP einen Schluessel liefern (auch bei Duplikaten in ips).
        return {ip: resolved[ip] for ip in ips}
