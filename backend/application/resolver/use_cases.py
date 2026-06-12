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

Nebenlaeufig wo sinnvoll (``asyncio.gather``): die vier Quellen sind unabhaengig -- PTR/
RDAP/TLS reden ueber das Netz, der Geo/ASN-Lookup ist SYNCHRON und wird ueber
``asyncio.to_thread`` aus dem Loop gehoben (der Port ist bewusst sync, damit der lokale
DB-Lookup nicht zum Coroutine-Zwang wird). Der Forward-Confirmed-Abgleich haengt am PTR
und laeuft daher INNERHALB der PTR-Kette (zweiter DNS-Schritt erst, wenn ein PTR-Name da
ist) -- diese eine Sequenz ist ehrlich abhaengig, der Rest laeuft parallel dazu.
"""

import asyncio

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

        Die vier Quell-Zweige laufen nebenlaeufig (``asyncio.gather``): die PTR-Kette
        (PTR + bei Treffer Forward-Abgleich), der RDAP-Lookup, der Geo/ASN-Lookup (sync ->
        ``to_thread``) und -- nur wenn ``port`` gegeben ist -- der TLS-Cert-Abruf. Aus den
        Rohfakten baut der Use-Case das Aggregat: jedes Feld als ``ResolverFact`` mit
        korrektem ``SourceTag``, ``country_conflict`` als abgeleitetes Flag.
        """
        # PTR-Kette ist in sich abhaengig (Forward braucht den PTR-Namen) -> EINE Coroutine.
        # Diese laeuft parallel zu RDAP/Geo/TLS.
        ptr_task = self._resolve_ptr_chain(ip)
        rdap_task = self._rdap_client.lookup(ip)
        geo_task = asyncio.to_thread(self._geo_asn_db.lookup, ip)
        # TLS nur, wenn ein Port gegeben ist (sonst kein TLS-Fakt). fetch_cert ist streng
        # fehlertolerant (None bei Fehlschlag) -- wir geben den None-Pfad als fertige
        # Coroutine in dasselbe gather, damit die Form gleich bleibt.
        tls_task = self._tls_cert.fetch_cert(ip, port) if port is not None else _none_cert()

        (ptr_value, forward_ok), rdap, geo, tls = await asyncio.gather(
            ptr_task, rdap_task, geo_task, tls_task
        )

        return self._assemble(
            ptr_name=ptr_value,
            forward_confirmed=forward_ok,
            rdap=rdap,
            geo=geo,
            tls=tls,
            port=port,
        )

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


async def _none_cert() -> TlsCertDetails | None:
    """Fertige Coroutine, die ``None`` liefert -- der kein-Port-Pfad fuer das TLS-gather.

    Haelt die ``gather``-Form unveraendert (vier Awaitables), auch wenn kein Port gegeben
    ist: ohne Port wird KEIN TLS-Abruf gemacht, das Feld ist ehrlich ``None``.
    """
    return None
