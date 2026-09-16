"""Tests von ``BuildDnsWatch`` gegen In-Memory-Fakes/Spies der Quellen.

Keine echte net_connections/PTR/Persistenz noetig -- wir testen die reine
Aggregations-/Klassifikations-Logik gegen die quellen-agnostischen Callables. Kern der
Behauptungen:

(1) Verbindungen werden je ``(remote_ip, category)`` gruppiert; ``connection_count``
    stimmt, ``remote_port``/``app_name``/``pid`` stammen aus der ERSTEN Verbindung der
    Gruppe; nicht-relevante Verbindungen werden ignoriert.
(2) ``counts`` zaehlt die AKTIVEN (nicht quittierten) KONTAKTE je Kategorie (nicht
    ``connection_count``) und deckt immer alle sechs Schluessel ab (drei Kategorien +
    drei ``quittiert_<kategorie>``).
(3) ``acknowledged`` ist True genau fuer die im Set hinterlegten ``ip:category``-Schluessel.
(4) Die Reihenfolge ist deterministisch (Kategorie offen < moegliche_doh <
    erwartungsgemaess, dann count absteigend, dann remote_ip aufsteigend).
(5) Leere relevante Menge -> leere ``contacts``, ``counts`` alle 0, Listen gefuellt.
(6) Ein werfender Hostname-Provider bricht NICHT ab (best-effort, S3).
(7) S62 L7b: ein QUITTIERTER Befund zaehlt nicht als offen, sondern in
    ``quittiert_<kategorie>``; die Liste bleibt vollstaendig; ein zurueckgenommenes
    Quittieren zaehlt wieder als offen.

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
    """counts = Anzahl AKTIVER Kontakte je Kategorie, deckt alle sechs Schluessel ab."""
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
        "quittiert_erwartungsgemaess": 0,
        "quittiert_offen": 0,
        "quittiert_moegliche_doh": 0,
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


# ── (7) S62 L7b: quittierte zaehlen nicht als offen ───────────────────────────


def test_quittierter_befund_zaehlt_nicht_als_offen() -> None:
    """Ein quittierter offener Befund faellt aus ``offen`` und in ``quittiert_offen``."""
    conns = [
        _conn("8.8.8.8", 53),  # offen -> quittiert
        _conn("9.9.9.9", 53),  # offen -> bleibt offen
    ]
    overview = _run(_build(conns, acknowledged={"8.8.8.8:offen"}))

    assert overview.counts["offen"] == 1
    assert overview.counts["quittiert_offen"] == 1


def test_quittierter_befund_bleibt_in_der_liste_und_erkennbar() -> None:
    """Verlustfreiheit: die Gegenstelle bleibt in ``contacts`` und traegt ``acknowledged``."""
    conns = [
        _conn("8.8.8.8", 53),  # offen -> quittiert
        _conn("9.9.9.9", 53),  # offen -> bleibt offen
    ]
    overview = _run(_build(conns, acknowledged={"8.8.8.8:offen"}))

    # Nichts wird ausgeblendet: BEIDE Gegenstellen sind weiterhin da ...
    assert {c.remote_ip for c in overview.contacts} == {"8.8.8.8", "9.9.9.9"}
    # ... und die quittierte bleibt als quittiert erkennbar.
    by_ip = {c.remote_ip: c for c in overview.contacts}
    assert by_ip["8.8.8.8"].acknowledged is True
    # Der Bestand je Kategorie ist die Summe beider Zahlen (verlustfrei).
    assert overview.counts["offen"] + overview.counts["quittiert_offen"] == 2


def test_zurueckgenommenes_quittieren_zaehlt_wieder_als_offen() -> None:
    """Ohne Quittier-Schluessel (unack) zaehlt derselbe Befund wieder als offen."""
    conns = [_conn("8.8.8.8", 53)]

    quittiert = _run(_build(conns, acknowledged={"8.8.8.8:offen"}))
    assert quittiert.counts["offen"] == 0
    assert quittiert.counts["quittiert_offen"] == 1

    # ``unack`` laesst den Schluessel aus dem Set fallen (append-only Ableitung im Repo).
    zurueckgenommen = _run(_build(conns, acknowledged=set()))
    assert zurueckgenommen.counts["offen"] == 1
    assert zurueckgenommen.counts["quittiert_offen"] == 0


def test_quittierte_zaehlen_je_kategorie_getrennt() -> None:
    """Auch ``moegliche_doh`` wird gleich behandelt: eigener quittiert-Zaehler."""
    conns = [
        _conn("1.1.1.1", 443),  # moegliche_doh -> quittiert
        _conn("8.8.8.8", 53),  # offen -> quittiert
        _conn("192.168.0.1", 53),  # erwartungsgemaess -> nicht quittiert
    ]
    overview = _run(
        _build(
            conns,
            expected=["192.168.0.1"],
            doh=["1.1.1.1"],
            acknowledged={"1.1.1.1:moegliche_doh", "8.8.8.8:offen"},
        )
    )

    assert overview.counts["offen"] == 0
    assert overview.counts["quittiert_offen"] == 1
    assert overview.counts["moegliche_doh"] == 0
    assert overview.counts["quittiert_moegliche_doh"] == 1
    assert overview.counts["erwartungsgemaess"] == 1
    assert overview.counts["quittiert_erwartungsgemaess"] == 0


def test_quittierter_erwartungsgemaesser_befund_landet_im_eigenen_zaehler() -> None:
    """Auch ``erwartungsgemaess`` ist quittierbar und faellt in seinen eigenen Zaehler.

    Damit ist die Zaehlung fuer ALLE drei Kategorien belegt (``offen`` und
    ``moegliche_doh`` daneben). Die Oberflaeche bietet den Quittier-Knopf seit S64 L14
    fuer jede Kategorie an -- ein Zaehler, der nicht befuellbar waere, waere ein
    Widerspruch. Verlustfrei wie ueberall: der Bestand bleibt die Summe beider Zahlen.
    """
    conns = [
        _conn("192.168.0.1", 53),  # erwartungsgemaess -> quittiert
        _conn("192.168.0.2", 53),  # erwartungsgemaess -> NICHT quittiert
    ]
    overview = _run(
        _build(
            conns,
            expected=["192.168.0.1", "192.168.0.2"],
            acknowledged={"192.168.0.1:erwartungsgemaess"},
        )
    )

    aktiv = overview.counts["erwartungsgemaess"]
    quittiert = overview.counts["quittiert_erwartungsgemaess"]
    assert aktiv == 1
    assert quittiert == 1
    # Der Bestand je Kategorie ist die Summe beider Zahlen (verlustfrei).
    assert aktiv + quittiert == 2
    # Die anderen Kategorien bleiben unberuehrt.
    assert overview.counts["offen"] == 0
    assert overview.counts["quittiert_offen"] == 0
    assert overview.counts["quittiert_moegliche_doh"] == 0


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
    assert overview.counts == {
        "erwartungsgemaess": 0,
        "offen": 0,
        "moegliche_doh": 0,
        "quittiert_erwartungsgemaess": 0,
        "quittiert_offen": 0,
        "quittiert_moegliche_doh": 0,
    }
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
