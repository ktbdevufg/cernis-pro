"""Tests von ``BuildDnsWatch`` gegen In-Memory-Fakes/Spies der Quellen.

Keine echte net_connections/PTR/Persistenz noetig -- wir testen die reine
Aggregations-/Klassifikations-Logik gegen die quellen-agnostischen Callables. Kern der
Behauptungen:

(1) Verbindungen werden je ``(remote_ip, category)`` gruppiert; ``connection_count``
    stimmt, ``remote_port``/``app_name``/``pid`` stammen aus der ERSTEN Verbindung der
    Gruppe; nicht-relevante Verbindungen werden ignoriert.
(2) ``counts`` zaehlt die KONTAKTE je Kategorie (nicht ``connection_count``) und deckt
    immer alle drei Kategorien ab.
(3) ``acknowledged`` ist True genau fuer die im Set hinterlegten ``ip:category``-Schluessel.
(4) Die Reihenfolge ist deterministisch (Kategorie offen < moegliche_doh <
    erwartungsgemaess, dann count absteigend, dann remote_ip aufsteigend).
(5) Leere relevante Menge -> leere ``contacts``, ``counts`` alle 0, Listen gefuellt.
(6) Ein werfender Hostname-Provider bricht NICHT ab (best-effort, S3).

Async via ``asyncio.run`` (Projektmuster, kein pytest-asyncio).
"""

import asyncio
from collections.abc import Sequence

from application.dns_watch import (
    HOST_SCOPE_LOCAL,
    BuildDnsWatch,
    DnsWatchOverview,
    HostnameProvider,
    RawDnsConnection,
)

# ── In-Memory-Fakes/Spies der Quellen ─────────────────────────────────────────


class FakeConnections:
    """``DnsConnectionsProvider``-Fake: gibt einen festen Snapshot zurueck."""

    def __init__(self, conns: Sequence[RawDnsConnection]) -> None:
        self._conns = list(conns)
        self.calls = 0

    def __call__(self) -> Sequence[RawDnsConnection]:
        self.calls += 1
        return self._conns


class FakeHostnames:
    """``HostnameProvider``-Fake (async): liefert eine feste ``{ip: hostname|None}``-Map.

    Protokolliert die uebergebenen IPs (fuer den Batch-Nachweis). Eine nicht hinterlegte
    IP fehlt schlicht -> ``hostname`` bleibt ``None``.
    """

    def __init__(self, mapping: dict[str, str | None]) -> None:
        self._mapping = mapping
        self.seen_ips: list[tuple[str, ...]] = []

    async def __call__(self, ips: Sequence[str]) -> dict[str, str | None]:
        self.seen_ips.append(tuple(ips))
        return {ip: self._mapping[ip] for ip in ips if ip in self._mapping}


class RaisingHostnames:
    """``HostnameProvider``-Fake, der wirft -- fuer den best-effort-Nachweis."""

    async def __call__(self, ips: Sequence[str]) -> dict[str, str | None]:
        raise RuntimeError("ptr down")


def _conn(
    remote_ip: str,
    remote_port: int | None,
    app_name: str | None = None,
    pid: int | None = None,
) -> RawDnsConnection:
    return RawDnsConnection(
        remote_ip=remote_ip, remote_port=remote_port, l4=None, app_name=app_name, pid=pid
    )


def _build(
    conns: Sequence[RawDnsConnection],
    *,
    hostnames: HostnameProvider | None = None,
    acknowledged: set[str] | None = None,
    expected: Sequence[str] = (),
    doh: Sequence[str] = (),
) -> BuildDnsWatch:
    """Verdrahtet ``BuildDnsWatch`` mit Fakes; Listen/Set als simple Lambdas."""
    return BuildDnsWatch(
        connections=FakeConnections(conns),
        hostnames=hostnames if hostnames is not None else FakeHostnames({}),
        acknowledged=lambda: set(acknowledged or set()),
        expected_servers=lambda: list(expected),
        doh_providers=lambda: list(doh),
    )


def _run(use_case: BuildDnsWatch) -> DnsWatchOverview:
    """Fuehrt den async-Use-Case synchron aus (Projektmuster ``asyncio.run``)."""
    return asyncio.run(use_case())


# ── (1) Gruppierung + Ignorieren irrelevanter Verbindungen ────────────────────


def test_gruppiert_je_ip_und_kategorie_und_ignoriert_irrelevante() -> None:
    """Drei 53-Verbindungen zur selben offenen IP + eine irrelevante 80-Verbindung."""
    conns = [
        _conn("8.8.8.8", 53, app_name="systemd-resolve", pid=10),
        _conn("8.8.8.8", 53, app_name="curl", pid=20),
        _conn("8.8.8.8", 53, app_name="dig", pid=30),
        _conn("93.184.216.34", 80, app_name="firefox", pid=40),  # irrelevant
    ]
    overview = _run(_build(conns, expected=["192.168.0.1"]))

    assert len(overview.contacts) == 1
    contact = overview.contacts[0]
    assert contact.remote_ip == "8.8.8.8"
    assert contact.category == "offen"
    assert contact.connection_count == 3
    # remote_port/app_name/pid aus der ERSTEN Verbindung der Gruppe.
    assert contact.remote_port == 53
    assert contact.app_name == "systemd-resolve"
    assert contact.pid == 10
    assert overview.host_scope == HOST_SCOPE_LOCAL


def test_gleiche_ip_verschiedene_kategorie_sind_zwei_befunde() -> None:
    """Dieselbe IP auf Port 53 (offen) UND Port 443 (DoH) -> zwei getrennte Befunde."""
    conns = [
        _conn("1.1.1.1", 53),
        _conn("1.1.1.1", 443),
    ]
    overview = _run(_build(conns, doh=["1.1.1.1"]))

    by_cat = {c.category: c for c in overview.contacts}
    assert set(by_cat) == {"offen", "moegliche_doh"}
    assert by_cat["offen"].remote_ip == "1.1.1.1"
    assert by_cat["moegliche_doh"].remote_ip == "1.1.1.1"


# ── (2) counts je Kategorie (Kontakte, nicht connection_count) ────────────────


def test_counts_zaehlt_kontakte_je_kategorie() -> None:
    """counts = Anzahl Kontakte je Kategorie, deckt alle drei ab (auch 0)."""
    conns = [
        _conn("192.168.0.1", 53),  # erwartungsgemaess
        _conn("8.8.8.8", 53),  # offen
        _conn("8.8.8.8", 53),  # selbe Gruppe -> count 2, aber 1 Kontakt
        _conn("9.9.9.9", 53),  # offen (zweiter offener Kontakt)
        _conn("1.1.1.1", 443),  # moegliche_doh
    ]
    overview = _run(_build(conns, expected=["192.168.0.1"], doh=["1.1.1.1"]))

    assert overview.counts == {
        "erwartungsgemaess": 1,
        "offen": 2,
        "moegliche_doh": 1,
    }


# ── (3) acknowledged-Markierung ───────────────────────────────────────────────


def test_acknowledged_markiert_passenden_schluessel() -> None:
    """acknowledged=True nur fuer den hinterlegten ``ip:category``-Schluessel."""
    conns = [
        _conn("8.8.8.8", 53),  # offen -> quittiert
        _conn("9.9.9.9", 53),  # offen -> NICHT quittiert
    ]
    overview = _run(_build(conns, acknowledged={"8.8.8.8:offen"}))

    by_ip = {c.remote_ip: c for c in overview.contacts}
    assert by_ip["8.8.8.8"].acknowledged is True
    assert by_ip["9.9.9.9"].acknowledged is False


def test_acknowledged_schluessel_ist_kategorie_spezifisch() -> None:
    """Ein quittierter 53-Befund quittiert NICHT den 443-Befund derselben IP."""
    conns = [
        _conn("1.1.1.1", 53),  # offen
        _conn("1.1.1.1", 443),  # moegliche_doh
    ]
    overview = _run(_build(conns, acknowledged={"1.1.1.1:offen"}, doh=["1.1.1.1"]))

    by_cat = {c.category: c for c in overview.contacts}
    assert by_cat["offen"].acknowledged is True
    assert by_cat["moegliche_doh"].acknowledged is False


# ── (4) Deterministische Reihenfolge ──────────────────────────────────────────


def test_reihenfolge_kategorie_dann_count_dann_ip() -> None:
    """Auffaelliges zuerst: offen < moegliche_doh < erwartungsgemaess; dann count, dann ip."""
    conns = [
        # erwartungsgemaess (zuletzt, trotz hohem count)
        _conn("192.168.0.1", 53),
        _conn("192.168.0.1", 53),
        _conn("192.168.0.1", 53),
        # offen, count 1, ip 9.9.9.9
        _conn("9.9.9.9", 53),
        # offen, count 2, ip 8.8.8.8 (lauter -> vor 9.9.9.9)
        _conn("8.8.8.8", 53),
        _conn("8.8.8.8", 53),
        # moegliche_doh (zwischen offen und erwartungsgemaess)
        _conn("1.1.1.1", 443),
    ]
    overview = _run(_build(conns, expected=["192.168.0.1"], doh=["1.1.1.1"]))

    order = [(c.category, c.remote_ip) for c in overview.contacts]
    assert order == [
        ("offen", "8.8.8.8"),
        ("offen", "9.9.9.9"),
        ("moegliche_doh", "1.1.1.1"),
        ("erwartungsgemaess", "192.168.0.1"),
    ]


# ── (5) Leere relevante Menge ─────────────────────────────────────────────────


def test_leere_relevante_menge_gibt_leere_aber_gefuellte_sicht() -> None:
    """Nur irrelevante Verbindungen -> leere contacts, counts 0, Listen trotzdem gefuellt."""
    conns = [
        _conn("93.184.216.34", 80),
        _conn("93.184.216.34", 443),  # 443 ohne DoH-IP -> irrelevant
    ]
    overview = _run(_build(conns, expected=["192.168.0.1"], doh=["1.1.1.1"]))

    assert overview.contacts == ()
    assert overview.counts == {"erwartungsgemaess": 0, "offen": 0, "moegliche_doh": 0}
    assert overview.expected_servers == ("192.168.0.1",)
    assert overview.doh_providers == ("1.1.1.1",)
    assert overview.host_scope == HOST_SCOPE_LOCAL


def test_hostname_anreicherung_je_ip_und_batch() -> None:
    """hostname landet bei der richtigen IP; der Namens-Provider wird als Batch gerufen."""
    conns = [
        _conn("8.8.8.8", 53),
        _conn("1.1.1.1", 443),
    ]
    hostnames = FakeHostnames({"8.8.8.8": "dns.google", "1.1.1.1": "one.one.one.one"})
    use_case = BuildDnsWatch(
        connections=FakeConnections(conns),
        hostnames=hostnames,
        acknowledged=lambda: set(),
        expected_servers=lambda: [],
        doh_providers=lambda: ["1.1.1.1"],
    )

    overview = _run(use_case)

    by_ip = {c.remote_ip: c for c in overview.contacts}
    assert by_ip["8.8.8.8"].hostname == "dns.google"
    assert by_ip["1.1.1.1"].hostname == "one.one.one.one"
    # Genau EIN Batch-Aufruf ueber die eindeutigen IPs.
    assert len(hostnames.seen_ips) == 1
    assert set(hostnames.seen_ips[0]) == {"8.8.8.8", "1.1.1.1"}


# ── (6) Defensiver Hostname-Fehler ────────────────────────────────────────────


def test_werfender_hostname_provider_bricht_nicht_ab() -> None:
    """Der Namens-Provider wirft -> hostname None, Use-Case wirft NICHT (best-effort, S3)."""
    conns = [_conn("8.8.8.8", 53, app_name="dig", pid=7)]
    use_case = _build(conns, hostnames=RaisingHostnames())

    overview = _run(use_case)

    contact = overview.contacts[0]
    assert contact.hostname is None
    # Basisdaten bleiben erhalten.
    assert contact.category == "offen"
    assert contact.app_name == "dig"
    assert contact.connection_count == 1
