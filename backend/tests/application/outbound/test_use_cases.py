"""Tests von ``BuildOutboundContacts`` gegen In-Memory-Fakes/Spies der drei Quellen.

Kein echtes psutil/PTR/Geo noetig -- wir testen die reine Aggregations-Logik gegen die
drei quellen-agnostischen Callables. Kern der Behauptungen:

(1) Mehrere Verbindungen zur SELBEN IP -> ein Kontakt, ``connection_count`` stimmt;
    ``remote_port``/``app_name``/``pid`` stammen aus der ERSTEN gesehenen Verbindung.
(2) Anreicherung (hostname/country/operator/asn) wird je IP KORREKT zugeordnet (der
    Namens-Provider wird mit allen eindeutigen IPs als Batch gerufen).
(3) Fehlende Anreicherung -- Provider liefert ``None`` ODER wirft -- laesst die Felder
    ``None`` und der Use-Case wirft NICHT (best-effort, S3).
(4) Die Reihenfolge der Kontakte ist deterministisch (``connection_count`` absteigend,
    dann ``remote_ip`` aufsteigend).

Async via ``asyncio.run`` (Projektmuster, kein pytest-asyncio).
"""

import asyncio
from collections.abc import Sequence

from application.outbound import (
    HOST_SCOPE_LOCAL,
    BuildOutboundContacts,
    OutboundOverview,
    RawConnection,
)

# ── In-Memory-Fakes/Spies der drei Quellen ───────────────────────────────────


class FakeConnections:
    """``OutboundConnectionsProvider``-Fake: gibt einen festen Snapshot zurueck."""

    def __init__(self, conns: Sequence[RawConnection]) -> None:
        self._conns = list(conns)
        self.calls = 0

    def __call__(self) -> Sequence[RawConnection]:
        self.calls += 1
        return self._conns


class FakeHostnames:
    """``HostnameProvider``-Fake (async): liefert eine feste ``{ip: hostname|None}``-Map.

    Protokolliert die uebergebenen IPs (fuer den Batch-Nachweis). Eine nicht hinterlegte
    IP fehlt schlicht in der Map -> ``hostname`` bleibt ``None``.
    """

    def __init__(self, mapping: dict[str, str | None]) -> None:
        self._mapping = mapping
        self.seen_ips: list[tuple[str, ...]] = []

    async def __call__(self, ips: Sequence[str]) -> dict[str, str | None]:
        self.seen_ips.append(tuple(ips))
        return {ip: self._mapping[ip] for ip in ips if ip in self._mapping}


class FakeGeoOperator:
    """``GeoOperatorProvider``-Fake (async): IP -> ``(country, operator, asn)``.

    Eine nicht hinterlegte IP liefert ``(None, None, None)`` (fehlende Quelle = None).
    """

    def __init__(self, mapping: dict[str, tuple[str | None, str | None, str | None]]) -> None:
        self._mapping = mapping
        self.seen_ips: list[str] = []

    async def __call__(self, ip: str) -> tuple[str | None, str | None, str | None]:
        self.seen_ips.append(ip)
        return self._mapping.get(ip, (None, None, None))


class RaisingHostnames:
    """``HostnameProvider``-Fake, der wirft -- fuer den best-effort-Nachweis."""

    async def __call__(self, ips: Sequence[str]) -> dict[str, str | None]:
        raise RuntimeError("ptr down")


class RaisingGeoOperator:
    """``GeoOperatorProvider``-Fake, der wirft -- fuer den best-effort-Nachweis."""

    async def __call__(self, ip: str) -> tuple[str | None, str | None, str | None]:
        raise RuntimeError("geo down")


def _run(use_case: BuildOutboundContacts) -> OutboundOverview:
    """Fuehrt den async-Use-Case synchron aus (Projektmuster ``asyncio.run``)."""
    return asyncio.run(use_case())


# ── (1) Gruppierung mehrerer Verbindungen zur selben IP ───────────────────────


def test_gruppiert_verbindungen_je_ip_und_zaehlt() -> None:
    """Drei Verbindungen, zwei zur selben IP -> zwei Kontakte, Zaehler stimmen."""
    conns = [
        RawConnection(remote_ip="1.1.1.1", remote_port=443, app_name="firefox", pid=11),
        RawConnection(remote_ip="1.1.1.1", remote_port=80, app_name="curl", pid=22),
        RawConnection(remote_ip="9.9.9.9", remote_port=53, app_name="systemd", pid=33),
    ]
    use_case = BuildOutboundContacts(
        connections=FakeConnections(conns),
        hostnames=FakeHostnames({}),
        geo_operator=FakeGeoOperator({}),
    )

    overview = _run(use_case)

    by_ip = {c.remote_ip: c for c in overview.contacts}
    assert set(by_ip) == {"1.1.1.1", "9.9.9.9"}
    assert by_ip["1.1.1.1"].connection_count == 2
    assert by_ip["9.9.9.9"].connection_count == 1
    # remote_port/app_name/pid stammen aus der ERSTEN gesehenen Verbindung je IP.
    assert by_ip["1.1.1.1"].remote_port == 443
    assert by_ip["1.1.1.1"].app_name == "firefox"
    assert by_ip["1.1.1.1"].pid == 11
    assert overview.host_scope == HOST_SCOPE_LOCAL


def test_leerer_snapshot_gibt_leere_aber_markierte_sicht() -> None:
    """Keine Verbindungen -> leere ``contacts``, aber ehrlicher ``host_scope``-Marker."""
    use_case = BuildOutboundContacts(
        connections=FakeConnections([]),
        hostnames=FakeHostnames({}),
        geo_operator=FakeGeoOperator({}),
    )

    overview = _run(use_case)

    assert overview.contacts == ()
    assert overview.host_scope == HOST_SCOPE_LOCAL


# ── (2) Anreicherung je IP korrekt zugeordnet ─────────────────────────────────


def test_anreicherung_wird_je_ip_korrekt_zugeordnet() -> None:
    """hostname/country/operator/asn landen bei der richtigen IP; Namen als Batch."""
    conns = [
        RawConnection(remote_ip="1.1.1.1", remote_port=443, app_name="firefox", pid=11),
        RawConnection(remote_ip="9.9.9.9", remote_port=53, app_name="systemd", pid=33),
    ]
    hostnames = FakeHostnames({"1.1.1.1": "one.example", "9.9.9.9": "quad9.example"})
    geo = FakeGeoOperator(
        {
            "1.1.1.1": ("US", "Cloudflare", "AS13335"),
            "9.9.9.9": ("CH", "Quad9", "AS19281"),
        }
    )
    use_case = BuildOutboundContacts(
        connections=FakeConnections(conns), hostnames=hostnames, geo_operator=geo
    )

    overview = _run(use_case)

    by_ip = {c.remote_ip: c for c in overview.contacts}
    assert by_ip["1.1.1.1"].hostname == "one.example"
    assert by_ip["1.1.1.1"].country == "US"
    assert by_ip["1.1.1.1"].operator == "Cloudflare"
    assert by_ip["1.1.1.1"].asn == "AS13335"
    assert by_ip["9.9.9.9"].hostname == "quad9.example"
    assert by_ip["9.9.9.9"].country == "CH"
    assert by_ip["9.9.9.9"].operator == "Quad9"
    assert by_ip["9.9.9.9"].asn == "AS19281"
    # Der Namens-Provider wird EINMAL mit allen eindeutigen IPs gerufen (Batch).
    assert hostnames.seen_ips == [("1.1.1.1", "9.9.9.9")]


# ── (3) Fehlende Anreicherung -> Felder None, kein Wurf ───────────────────────


def test_fehlende_anreicherung_laesst_felder_none() -> None:
    """Provider liefert fuer eine IP nichts -> Felder bleiben ``None`` (kein Wurf)."""
    conns = [RawConnection(remote_ip="2.2.2.2", remote_port=443, app_name=None, pid=None)]
    use_case = BuildOutboundContacts(
        connections=FakeConnections(conns),
        hostnames=FakeHostnames({}),  # keine Namen hinterlegt
        geo_operator=FakeGeoOperator({}),  # keine Geo-Daten hinterlegt
    )

    overview = _run(use_case)

    contact = overview.contacts[0]
    assert contact.remote_ip == "2.2.2.2"
    assert contact.hostname is None
    assert contact.country is None
    assert contact.operator is None
    assert contact.asn is None
    assert contact.app_name is None
    assert contact.pid is None


def test_werfende_quellen_brechen_nicht_ab() -> None:
    """Beide Anreicherungs-Provider werfen -> Felder ``None``, Use-Case wirft NICHT."""
    conns = [RawConnection(remote_ip="3.3.3.3", remote_port=443, app_name="x", pid=1)]
    use_case = BuildOutboundContacts(
        connections=FakeConnections(conns),
        hostnames=RaisingHostnames(),
        geo_operator=RaisingGeoOperator(),
    )

    overview = _run(use_case)

    contact = overview.contacts[0]
    assert contact.hostname is None
    assert contact.country is None
    assert contact.operator is None
    assert contact.asn is None
    # Die nicht-anreicherbaren Basisdaten bleiben aber erhalten.
    assert contact.connection_count == 1
    assert contact.app_name == "x"


# ── (4) Deterministische Reihenfolge ──────────────────────────────────────────


def test_reihenfolge_count_desc_dann_ip_asc() -> None:
    """Sortierung: connection_count absteigend, bei Gleichstand remote_ip aufsteigend."""
    conns = [
        # 8.8.8.8: 1x
        RawConnection(remote_ip="8.8.8.8", remote_port=53, app_name="a", pid=1),
        # 1.1.1.1: 3x (lautester -> zuerst)
        RawConnection(remote_ip="1.1.1.1", remote_port=443, app_name="b", pid=2),
        RawConnection(remote_ip="1.1.1.1", remote_port=443, app_name="b", pid=2),
        RawConnection(remote_ip="1.1.1.1", remote_port=443, app_name="b", pid=2),
        # 9.9.9.9: 1x (gleicher Count wie 8.8.8.8 -> ip-Tie-Break: 8 < 9)
        RawConnection(remote_ip="9.9.9.9", remote_port=53, app_name="c", pid=3),
    ]
    use_case = BuildOutboundContacts(
        connections=FakeConnections(conns),
        hostnames=FakeHostnames({}),
        geo_operator=FakeGeoOperator({}),
    )

    overview = _run(use_case)

    order = [c.remote_ip for c in overview.contacts]
    assert order == ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
