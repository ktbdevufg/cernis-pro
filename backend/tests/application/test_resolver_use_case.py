"""Tests des ResolveEndpoint-Use-Case gegen In-Memory-Fakes der vier Ports.

Keine echten Adapter, kein Netz, keine CSVs -- die Fakes erfuellen schlicht die Protocols
(``PtrResolverPort``/``RdapClientPort``/``GeoAsnDbPort``/``TlsCertPort``). Kern der
Behauptungen: ``ResolveEndpoint`` holt alle vier Quellen, stellt sie zu
``RemoteEndpointFacts`` zusammen und gibt JEDEM Feld den korrekten ``SourceTag`` -- die
Quellen-Tags werden explizit geprueft. Faelle: voller Happy-Path (alle Quellen liefern,
forward_confirmed True bei IP-Match), leerer PTR (forward_confirmed False), port=None (kein
TLS), TLS-Fehlschlag (Fake gibt None), country_conflict True bei RDAP-Land != GeoDB-Land.
"""

import asyncio

from application.resolver import ResolveEndpoint
from domain.resolver import (
    GeoAsnRecord,
    RdapRawFacts,
    SourceTag,
    TlsCertDetails,
)

# ── In-Memory-Fakes der vier Ports ───────────────────────────────────────────


class FakePtrResolver:
    """PTR + Forward-DNS aus kontrollierten Maps -- kein dig, kein Netz."""

    def __init__(
        self,
        ptr: str = "",
        forward: tuple[str, ...] = (),
    ) -> None:
        self._ptr = ptr
        self._forward = forward
        self.forward_calls = 0

    async def resolve_ptr(self, ip: str) -> str:
        return self._ptr

    async def resolve_forward(self, hostname: str) -> tuple[str, ...]:
        self.forward_calls += 1
        return self._forward


class FakeRdapClient:
    """Liefert einen kontrollierten RdapRawFacts -- kein httpx, kein Netz."""

    def __init__(self, facts: RdapRawFacts) -> None:
        self._facts = facts

    async def lookup(self, ip: str) -> RdapRawFacts:
        return self._facts


class FakeGeoAsnDb:
    """Synchroner Geo/ASN-Lookup aus einem kontrollierten Record -- keine CSV."""

    def __init__(self, record: GeoAsnRecord) -> None:
        self._record = record

    def lookup(self, ip: str) -> GeoAsnRecord:
        return self._record


class FakeTlsCertReader:
    """Liefert kontrollierte Cert-Details ODER None -- kein TLS-Handshake.

    Haelt jeden Aufruf samt durchgereichtem ``hostname`` (SNI) fest, damit Tests die
    PTR-als-SNI-Weitergabe pruefen koennen.
    """

    def __init__(self, cert: TlsCertDetails | None) -> None:
        self._cert = cert
        self.calls: list[tuple[str, int, str | None]] = []

    async def fetch_cert(
        self, ip: str, port: int, hostname: str | None = None
    ) -> TlsCertDetails | None:
        self.calls.append((ip, port, hostname))
        return self._cert


# ── Helfer ───────────────────────────────────────────────────────────────────


def _full_rdap() -> RdapRawFacts:
    return RdapRawFacts(
        org="ACME Networks",
        netname="ACME-NET",
        net_range="1.2.0.0 - 1.2.255.255",
        asn=None,  # RDAP-Adapter liefert ASN bewusst nicht
        asn_org=None,
        abuse_contact="abuse@acme.test",
        country="DE",
    )


def _full_cert() -> TlsCertDetails:
    return TlsCertDetails(
        subject_cn="host.example.com",
        san=("host.example.com", "www.example.com"),
        issuer="ACME CA",
        valid_from="Jan  1 00:00:00 2025 GMT",
        valid_until="Jan  1 00:00:00 2026 GMT",
        serial="0A0B",
        fingerprint_sha256="AB:CD",
        self_signed=False,
    )


# ── Tests ──────────────────────────────────────────────────────────────────────


def test_happy_path_alle_quellen_und_source_tags() -> None:
    """Alle Quellen liefern; alle Felder + korrekte SourceTags; forward_confirmed True."""
    uc = ResolveEndpoint(
        FakePtrResolver(ptr="host.example.com", forward=("1.2.3.4",)),
        FakeRdapClient(_full_rdap()),
        FakeGeoAsnDb(GeoAsnRecord(country="DE", asn="64500", asn_org=None)),
        FakeTlsCertReader(_full_cert()),
    )

    facts = asyncio.run(uc.resolve("1.2.3.4", 443))

    # Werte
    assert facts.ptr.value == "host.example.com"
    assert facts.forward_confirmed.value is True
    assert facts.org.value == "ACME Networks"
    assert facts.netname.value == "ACME-NET"
    assert facts.net_range.value == "1.2.0.0 - 1.2.255.255"
    assert facts.abuse_contact.value == "abuse@acme.test"
    assert facts.country_rdap_net.value == "DE"
    assert facts.country_org_address.value is None
    assert facts.asn.value == "64500"
    assert facts.asn_org.value == "ACME Networks"  # Klartext-Org aus RDAP (A1)
    assert facts.country_geodb.value == "DE"
    assert facts.tls_cert.value is not None
    assert facts.tls_cert.value.subject_cn == "host.example.com"
    assert facts.service_hint.value == "https"
    assert facts.banner.value is None
    assert facts.country_conflict is False  # DE == DE

    # SourceTags explizit
    assert facts.ptr.source is SourceTag.DNS
    assert facts.forward_confirmed.source is SourceTag.DNS
    assert facts.dyndns.source is SourceTag.DNS
    assert facts.service_hint.source is SourceTag.DNS
    assert facts.banner.source is SourceTag.DNS
    assert facts.org.source is SourceTag.RDAP
    assert facts.netname.source is SourceTag.RDAP
    assert facts.net_range.source is SourceTag.RDAP
    assert facts.asn_org.source is SourceTag.RDAP
    assert facts.abuse_contact.source is SourceTag.RDAP
    assert facts.country_rdap_net.source is SourceTag.RDAP
    assert facts.country_org_address.source is SourceTag.RDAP
    assert facts.asn.source is SourceTag.GEODB
    assert facts.country_geodb.source is SourceTag.GEODB
    assert facts.tls_cert.source is SourceTag.TLS


def test_leerer_ptr_kein_forward_confirmed() -> None:
    """Leerer PTR -> forward_confirmed False, kein zweiter DNS-Schritt, ptr.value None."""
    ptr = FakePtrResolver(ptr="", forward=("1.2.3.4",))
    uc = ResolveEndpoint(
        ptr,
        FakeRdapClient(RdapRawFacts()),
        FakeGeoAsnDb(GeoAsnRecord()),
        FakeTlsCertReader(None),
    )

    facts = asyncio.run(uc.resolve("1.2.3.4", None))

    assert facts.ptr.value is None
    assert facts.forward_confirmed.value is False
    assert ptr.forward_calls == 0  # ohne PTR-Namen kein Forward-Lookup


def test_forward_ohne_ip_match_nicht_bestaetigt() -> None:
    """PTR vorhanden, aber Forward zeigt NICHT auf die Ziel-IP -> forward_confirmed False."""
    uc = ResolveEndpoint(
        FakePtrResolver(ptr="host.example.com", forward=("9.9.9.9",)),
        FakeRdapClient(RdapRawFacts()),
        FakeGeoAsnDb(GeoAsnRecord()),
        FakeTlsCertReader(None),
    )

    facts = asyncio.run(uc.resolve("1.2.3.4", None))

    assert facts.ptr.value == "host.example.com"
    assert facts.forward_confirmed.value is False


def test_port_none_kein_tls() -> None:
    """port=None -> kein TLS-Abruf, tls_cert.value None (fetch_cert NICHT gerufen)."""
    tls = FakeTlsCertReader(_full_cert())
    uc = ResolveEndpoint(
        FakePtrResolver(ptr="host.example.com", forward=("1.2.3.4",)),
        FakeRdapClient(RdapRawFacts()),
        FakeGeoAsnDb(GeoAsnRecord()),
        tls,
    )

    facts = asyncio.run(uc.resolve("1.2.3.4", None))

    assert facts.tls_cert.value is None
    assert facts.tls_cert.source is SourceTag.TLS
    assert tls.calls == []  # ohne Port kein fetch_cert
    assert facts.service_hint.value is None  # kein Port -> kein Dienst-Hinweis


def test_tls_fehlschlag_none() -> None:
    """Port gegeben, aber TLS-Fake gibt None (Fehlschlag) -> tls_cert.value None."""
    tls = FakeTlsCertReader(None)
    uc = ResolveEndpoint(
        FakePtrResolver(ptr="host.example.com", forward=("1.2.3.4",)),
        FakeRdapClient(RdapRawFacts()),
        FakeGeoAsnDb(GeoAsnRecord()),
        tls,
    )

    facts = asyncio.run(uc.resolve("1.2.3.4", 8443))

    assert facts.tls_cert.value is None
    # mit Port WIRD fetch_cert gerufen; PTR-Name als SNI-hostname durchgereicht.
    assert tls.calls == [("1.2.3.4", 8443, "host.example.com")]
    assert facts.service_hint.value == "https-alt"


def test_country_conflict_rdap_vs_geodb() -> None:
    """RDAP-Land != GeoDB-Land -> country_conflict True."""
    uc = ResolveEndpoint(
        FakePtrResolver(ptr="", forward=()),
        FakeRdapClient(RdapRawFacts(country="DE")),
        FakeGeoAsnDb(GeoAsnRecord(country="US")),
        FakeTlsCertReader(None),
    )

    facts = asyncio.run(uc.resolve("1.2.3.4", None))

    assert facts.country_rdap_net.value == "DE"
    assert facts.country_geodb.value == "US"
    assert facts.country_conflict is True


def test_dyndns_aus_ptr_abgeleitet() -> None:
    """Ein DynDNS-PTR-Name wird zu dyndns.value abgeleitet (DNS-Quelle)."""
    uc = ResolveEndpoint(
        FakePtrResolver(ptr="box.myfritz.net", forward=("1.2.3.4",)),
        FakeRdapClient(RdapRawFacts()),
        FakeGeoAsnDb(GeoAsnRecord()),
        FakeTlsCertReader(None),
    )

    facts = asyncio.run(uc.resolve("1.2.3.4", None))

    assert facts.dyndns.value == "box.myfritz.net"
    assert facts.dyndns.source is SourceTag.DNS


def test_ptr_name_wird_als_sni_hostname_durchgereicht() -> None:
    """PTR-Name vorhanden + Port -> fetch_cert bekommt diesen Namen als hostname (SNI)."""
    tls = FakeTlsCertReader(_full_cert())
    uc = ResolveEndpoint(
        FakePtrResolver(ptr="host.example.com", forward=("1.2.3.4",)),
        FakeRdapClient(RdapRawFacts()),
        FakeGeoAsnDb(GeoAsnRecord()),
        tls,
    )

    asyncio.run(uc.resolve("1.2.3.4", 443))

    assert tls.calls == [("1.2.3.4", 443, "host.example.com")]


def test_ohne_ptr_name_kein_sni_hostname() -> None:
    """Kein PTR-Name, aber Port -> fetch_cert wird gerufen, hostname ist None (kein SNI)."""
    tls = FakeTlsCertReader(None)
    uc = ResolveEndpoint(
        FakePtrResolver(ptr="", forward=()),
        FakeRdapClient(RdapRawFacts()),
        FakeGeoAsnDb(GeoAsnRecord()),
        tls,
    )

    asyncio.run(uc.resolve("1.2.3.4", 443))

    assert tls.calls == [("1.2.3.4", 443, None)]  # leerer PTR -> hostname None
