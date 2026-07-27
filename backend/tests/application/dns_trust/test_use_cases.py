"""Tests der DNS-Vertrauens-Use-Cases gegen In-Memory-Fakes (ADR 0043, Etappe 3).

Getestet gegen schlanke Fakes des Repos + der injizierten Nahtstellen (Muster der
bestehenden application-Tests: kein echtes SQLite/Netz). Kern der Behauptungen:

(1) ``SyncDnsTrustServer`` legt neu an -- ``first_seen == last_seen == now``, Vor-Vertrauen
    ueber ``default_trust_for`` (nur GATEWAY -> TRUSTED, sonst NEUTRAL).
(2) ``SyncDnsTrustServer`` aktualisiert bestehend -- Kategorie/last_seen/display_name werden
    gepflegt, ``trust_state`` und ``first_seen`` bleiben (User-Wertung NIE ueberschreiben).
(3) Die Kategorie-Ableitung folgt den Flags (gateway/public/threat) in fester Prioritaet.
(4) ``SetDnsServerTrust`` bildet alle drei decisions korrekt ab; ein unbekannter
    ``decision``-Wert wirft -- und seit S62 L7c auch eine ``ip``, zu der gar kein Server
    erfasst ist (frueher ein stiller No-Op mit Erfolgsmeldung nach aussen).
(4b) ``SetDnsServerRank`` benennt denselben Nichtvollzug: ein ``rank > 0`` fuer einen
    weder bestaetigten noch bereits rangierten Server wirft, statt den Wunsch still
    fallen zu lassen. Die fachliche Regel selbst bleibt (Rang ordnet nur die erwartete
    Menge); ``rank == 0`` bleibt dort ein echter No-Op.
(5) ``TrustedDnsServerIps`` liefert genau die TRUSTED-IPs in DETERMINISTISCHER Ordnung
    (rangierte nach ``expected_rank`` zuerst, dann unrangierte nach ``ip``). Das ist die
    als "erwartet" angezeigte Beleg-Menge BEIDER Waechter-Sichten (S62 L7a: auch der
    host-lokale Waechter bezieht sie hier); die eigentliche Drei-Zustands-Klassifikation
    testet ``domain.dns_trust.bypass_verdict`` bzw. der Recorder-Tick (ADR 0043, E4).
(6) ``ListDnsTrustServers`` stellt je Server die Plausibilitaet bei (bzw. ``None``).
(7) ``AddDnsTrustServer`` (S63 L7d) legt einen NIE beobachteten Server von Hand an --
    direkt ``TRUSTED`` mit Herkunft ``MANUAL``, die Adresse zuvor kanonisiert. Ein
    Duplikat wirft (kein stiller Upsert ueber die kuratierte Entscheidung), eine
    unbrauchbare Adresse ebenfalls (das Schluesselfeld bleibt sauber).
(8) Der Sync-Update-Zweig hebt ``origin`` auf ``OBSERVED``: wird ein von Hand
    hinterlegter Server real beobachtet, ist er kein Von-Hand-Eintrag mehr.

Die async Use-Cases (``SyncDnsTrustServer`` und ``AddDnsTrustServer``, beide wegen des
``GatewayProvider``) werden ueber ``asyncio.run`` getrieben (Hausmuster der
application-Tests).
"""

import asyncio
from dataclasses import replace

import pytest

from application.dns_trust import (
    AddDnsTrustServer,
    DnsServerPlausibility,
    DnsTrustInvalidIpError,
    DnsTrustServerAlreadyExistsError,
    DnsTrustServerNotConfirmedError,
    DnsTrustServerNotFoundError,
    ListDnsTrustServers,
    SetDnsServerRank,
    SetDnsServerTrust,
    SyncDnsTrustServer,
    TrustedDnsServerIps,
)
from domain.dns_trust import (
    DnsServerCategory,
    DnsServerOrigin,
    DnsTrustState,
    TrustedDnsServer,
)

# ── In-Memory-Fake des DnsTrustRepository ─────────────────────────────────────


class FakeRepo:
    """Erfuellt ``DnsTrustRepository`` strukturell ueber ein Dict (Schluessel: ip)."""

    def __init__(self, servers: list[TrustedDnsServer] | None = None) -> None:
        self._store: dict[str, TrustedDnsServer] = {}
        for server in servers or []:
            self._store[server.ip] = server

    def upsert(self, server: TrustedDnsServer) -> None:
        self._store[server.ip] = server

    def get(self, ip: str) -> TrustedDnsServer | None:
        return self._store.get(ip)

    def list_all(self) -> list[TrustedDnsServer]:
        # Wie das echte Repo: nach first_seen aufsteigend.
        return sorted(self._store.values(), key=lambda s: s.first_seen)

    def set_trust(self, ip: str, state: DnsTrustState, now: float) -> None:
        existing = self._store.get(ip)
        if existing is None:
            return  # definierter No-Op (unbekannte ip)
        # Wie das echte Repo: NUR trust_state + last_seen anfassen, alle uebrigen Felder
        # (inkl. is_platform_placeholder und origin) bleiben unberuehrt -- ``replace``
        # haelt das automatisch durch, auch wenn das Aggregat weitere Felder bekommt.
        self._store[ip] = replace(existing, trust_state=state, last_seen=now)

    def set_rank(self, ip: str, rank: int, now: float) -> None:
        existing = self._store.get(ip)
        if existing is None:
            return  # definierter No-Op (unbekannte ip)
        self._store[ip] = replace(existing, expected_rank=rank, last_seen=now)

    def delete(self, ip: str) -> None:
        self._store.pop(ip, None)

    def clear_all(self) -> None:
        self._store.clear()


# ── Fabriken fuer die Nahtstellen + den Use-Case ──────────────────────────────


def _plausibility(ip: str) -> DnsServerPlausibility | None:
    # Standard-Provider fuer die Sync-Tests: EIN bekanntes Geraet mit Anzeigenamen.
    if ip == "192.168.1.50":
        return DnsServerPlausibility(
            in_inventory=True,
            first_seen_days=12,
            vendor="Raspberry Pi",
            open_ports=(53, 80),
            display_name="Pi-hole",
        )
    return None


def _sync(
    repo: FakeRepo,
    *,
    gateway: str | None = "192.168.1.1",
    public: bool = False,
    threat: bool = False,
) -> SyncDnsTrustServer:
    async def gateway_provider() -> str | None:
        return gateway

    return SyncDnsTrustServer(
        repo=repo,
        gateway=gateway_provider,
        is_public_resolver=lambda ip: public,
        is_threat_listed=lambda ip: threat,
        plausibility=_plausibility,
    )


def _add(
    repo: FakeRepo,
    *,
    gateway: str | None = "192.168.1.1",
    public: bool = False,
    threat: bool = False,
) -> AddDnsTrustServer:
    # Dieselben vier Nahtstellen wie ``_sync`` -- die Kategorie-Ableitung eines von Hand
    # hinterlegten Servers ist exakt die des beobachteten (keine zweite Ableitung).
    async def gateway_provider() -> str | None:
        return gateway

    return AddDnsTrustServer(
        repo=repo,
        gateway=gateway_provider,
        is_public_resolver=lambda ip: public,
        is_threat_listed=lambda ip: threat,
        plausibility=_plausibility,
    )


# ── SyncDnsTrustServer: Neuanlage ─────────────────────────────────────────────


def test_sync_neuanlage_gateway_wird_trusted() -> None:
    repo = FakeRepo()
    server = asyncio.run(_sync(repo)("192.168.1.1", now=1000.0))

    assert server.category is DnsServerCategory.GATEWAY
    assert server.trust_state is DnsTrustState.TRUSTED  # default_trust_for(GATEWAY)
    assert server.first_seen == 1000.0
    assert server.last_seen == 1000.0
    assert repo.get("192.168.1.1") == server


def test_sync_neuanlage_nicht_gateway_wird_neutral() -> None:
    repo = FakeRepo()
    # public resolver -> PUBLIC_RESOLVER, default_trust NEUTRAL.
    server = asyncio.run(_sync(repo, public=True)("8.8.8.8", now=2000.0))

    assert server.category is DnsServerCategory.PUBLIC_RESOLVER
    assert server.trust_state is DnsTrustState.NEUTRAL
    assert server.first_seen == server.last_seen == 2000.0


def test_sync_neuanlage_stellt_display_name_aus_bestand_bei() -> None:
    repo = FakeRepo()
    # 192.168.1.50 hat Bestands-Indizien mit display_name "Pi-hole".
    server = asyncio.run(_sync(repo)("192.168.1.50", now=1000.0))
    assert server.display_name == "Pi-hole"


# ── SyncDnsTrustServer: Kategorie-Ableitung ueber die Flags ───────────────────


def test_sync_kategorie_folgt_flags_prioritaet() -> None:
    repo = FakeRepo()
    # threat schlaegt bei OEFFENTLICHER IP alles: categorize priorisiert THREAT_LISTED.
    threat_server = asyncio.run(
        _sync(repo, gateway="93.184.216.34", threat=True)("93.184.216.34", now=1.0)
    )
    assert threat_server.category is DnsServerCategory.THREAT_LISTED

    # threat auf PRIVATER IP ist Bogon-FP -> verworfen; hier greift GATEWAY weiter.
    private_threat = asyncio.run(_sync(repo, gateway="10.0.0.1", threat=True)("10.0.0.1", now=1.0))
    assert private_threat.category is DnsServerCategory.GATEWAY

    # private, nicht public/gateway/threat -> LOCAL_PRIVATE.
    local_server = asyncio.run(_sync(repo)("192.168.1.77", now=1.0))
    assert local_server.category is DnsServerCategory.LOCAL_PRIVATE

    # oeffentlich, kein Literal-Treffer sonst -> UNKNOWN (public False, nicht privat).
    unknown_server = asyncio.run(_sync(repo)("9.9.9.9", now=1.0))
    assert unknown_server.category is DnsServerCategory.UNKNOWN


def test_sync_gateway_nur_wenn_ip_gleich_gateway() -> None:
    repo = FakeRepo()
    # Gateway-Provider liefert eine andere IP -> is_gateway False.
    server = asyncio.run(_sync(repo, gateway="192.168.1.1")("192.168.1.2", now=1.0))
    assert server.category is DnsServerCategory.LOCAL_PRIVATE


def test_sync_leeres_gateway_ist_kein_gateway() -> None:
    repo = FakeRepo()
    # Leeres/None-Gateway darf eine leere IP nicht faelschlich zum Gateway machen.
    server = asyncio.run(_sync(repo, gateway=None)("192.168.1.9", now=1.0))
    assert server.category is DnsServerCategory.LOCAL_PRIVATE


# ── SyncDnsTrustServer: Update ohne trust-Ueberschreibung ─────────────────────


def test_sync_update_bewahrt_trust_und_first_seen() -> None:
    bestehend = TrustedDnsServer(
        ip="8.8.8.8",
        category=DnsServerCategory.PUBLIC_RESOLVER,
        first_seen=100.0,
        last_seen=100.0,
        trust_state=DnsTrustState.REJECTED,  # bewusste User-Wertung
        display_name="alt",
    )
    repo = FakeRepo([bestehend])

    # Re-Sync: neue Kategorie moeglich, aber trust_state + first_seen MUESSEN bleiben.
    updated = asyncio.run(_sync(repo, public=True)("8.8.8.8", now=500.0))

    assert updated.trust_state is DnsTrustState.REJECTED  # NICHT ueberschrieben
    assert updated.first_seen == 100.0  # bewahrt
    assert updated.last_seen == 500.0  # aktualisiert
    assert updated.category is DnsServerCategory.PUBLIC_RESOLVER


def test_sync_update_leerer_neuer_name_laesst_bestehenden_stehen() -> None:
    bestehend = TrustedDnsServer(
        ip="9.9.9.9",
        category=DnsServerCategory.UNKNOWN,
        first_seen=1.0,
        last_seen=1.0,
        display_name="Behalten",
    )
    repo = FakeRepo([bestehend])
    # 9.9.9.9 hat keine Bestands-Indizien -> detected_name "" -> bestehender bleibt.
    updated = asyncio.run(_sync(repo)("9.9.9.9", now=2.0))
    assert updated.display_name == "Behalten"


# ── SetDnsServerTrust: alle drei decisions ────────────────────────────────────


def test_set_trust_decisions() -> None:
    server = TrustedDnsServer(
        ip="1.1.1.1",
        category=DnsServerCategory.PUBLIC_RESOLVER,
        first_seen=1.0,
        last_seen=1.0,
        trust_state=DnsTrustState.NEUTRAL,
    )
    repo = FakeRepo([server])
    use_case = SetDnsServerTrust(repo)

    def _get() -> TrustedDnsServer:
        # kleiner Helfer: der Server MUSS existieren (wir haben ihn angelegt) -- entlastet
        # mypy von der None-Union des Repo-Vertrags.
        found = repo.get("1.1.1.1")
        assert found is not None
        return found

    use_case("1.1.1.1", "trust", now=10.0)
    assert _get().trust_state is DnsTrustState.TRUSTED
    assert _get().last_seen == 10.0
    assert _get().first_seen == 1.0  # unberuehrt

    use_case("1.1.1.1", "reject", now=20.0)
    assert _get().trust_state is DnsTrustState.REJECTED

    use_case("1.1.1.1", "reset", now=30.0)
    assert _get().trust_state is DnsTrustState.NEUTRAL


def test_set_trust_unbekannte_decision_wirft() -> None:
    repo = FakeRepo()
    with pytest.raises(ValueError):
        SetDnsServerTrust(repo)("1.1.1.1", "maybe", now=1.0)


def test_set_trust_unbekannte_ip_wirft_statt_still_nichts_zu_tun() -> None:
    """S62 L7c: ohne erfassten Server schriebe set_trust 0 Zeilen -- das ist ein Fehler.

    Frueher ein stiller No-Op, der nach aussen als Erfolg zurueckkam (die Schnittstelle
    antwortete 200, die Tabelle blieb unveraendert). Muster ``DeviceNotFoundError``.
    """
    repo = FakeRepo()
    with pytest.raises(DnsTrustServerNotFoundError):
        SetDnsServerTrust(repo)("203.0.113.7", "trust", now=1.0)
    assert repo.get("203.0.113.7") is None


# ── TrustedDnsServerIps: Filter ───────────────────────────────────────────────


def test_trusted_ips_filtert_auf_trusted() -> None:
    repo = FakeRepo(
        [
            TrustedDnsServer(
                "1.1.1.1",
                DnsServerCategory.PUBLIC_RESOLVER,
                1.0,
                1.0,
                trust_state=DnsTrustState.TRUSTED,
            ),
            TrustedDnsServer(
                "8.8.8.8",
                DnsServerCategory.PUBLIC_RESOLVER,
                2.0,
                2.0,
                trust_state=DnsTrustState.NEUTRAL,
            ),
            TrustedDnsServer(
                "192.168.1.1",
                DnsServerCategory.GATEWAY,
                3.0,
                3.0,
                trust_state=DnsTrustState.TRUSTED,
            ),
            TrustedDnsServer(
                "9.9.9.9", DnsServerCategory.UNKNOWN, 4.0, 4.0, trust_state=DnsTrustState.REJECTED
            ),
        ]
    )
    # Beide unrangiert (expected_rank == 0) -> Stichentscheid ist die ip als Zeichenkette:
    # "1.1.1.1" < "192.168.1.1".
    assert TrustedDnsServerIps(repo)() == ["1.1.1.1", "192.168.1.1"]


def test_trusted_ips_leer_wenn_keiner_trusted() -> None:
    repo = FakeRepo()
    assert TrustedDnsServerIps(repo)() == []


def test_trusted_ips_rangierte_zuerst_dann_nach_rang() -> None:
    """S62 L7a: der nutzergesetzte Rang bestimmt die Reihenfolge der Anzeige."""
    repo = FakeRepo(
        [
            TrustedDnsServer(
                "10.0.0.9",
                DnsServerCategory.LOCAL_PRIVATE,
                1.0,
                1.0,
                trust_state=DnsTrustState.TRUSTED,
                expected_rank=2,
            ),
            TrustedDnsServer(
                "10.0.0.1",
                DnsServerCategory.GATEWAY,
                2.0,
                2.0,
                trust_state=DnsTrustState.TRUSTED,
                expected_rank=1,
            ),
        ]
    )
    # Rang 1 vor Rang 2 -- NICHT die first_seen-Ordnung des Repos (die waere umgekehrt).
    assert TrustedDnsServerIps(repo)() == ["10.0.0.1", "10.0.0.9"]


def test_trusted_ips_unrangierte_hinter_rangierten_und_nach_ip() -> None:
    """S62 L7a: unrangierte folgen den rangierten, untereinander stabil nach ip."""
    repo = FakeRepo(
        [
            TrustedDnsServer(
                "10.0.0.200",
                DnsServerCategory.LOCAL_PRIVATE,
                1.0,
                1.0,
                trust_state=DnsTrustState.TRUSTED,
            ),
            TrustedDnsServer(
                "10.0.0.30",
                DnsServerCategory.LOCAL_PRIVATE,
                2.0,
                2.0,
                trust_state=DnsTrustState.TRUSTED,
            ),
            TrustedDnsServer(
                "192.168.5.1",
                DnsServerCategory.GATEWAY,
                3.0,
                3.0,
                trust_state=DnsTrustState.TRUSTED,
                expected_rank=1,
            ),
        ]
    )
    # Der einzige Rangierte zuerst; dahinter die zwei unrangierten als Zeichenketten
    # sortiert ("10.0.0.200" < "10.0.0.30", weil "2" < "3" an der vierten Stelle).
    assert TrustedDnsServerIps(repo)() == ["192.168.5.1", "10.0.0.200", "10.0.0.30"]


def test_trusted_ips_ordnung_ist_unabhaengig_von_der_repo_reihenfolge() -> None:
    """S62 L7a: dieselbe Menge liefert dieselbe Ordnung, egal wie sie im Repo liegt.

    Die Ordnung darf NICHT von der Einfuege-/first_seen-Reihenfolge abhaengen -- sonst
    zeigte derselbe Bestand je nach Prozess-Start eine andere Fusszeile.
    """
    server_a = TrustedDnsServer(
        "203.0.113.4",
        DnsServerCategory.UNKNOWN,
        9.0,
        9.0,
        trust_state=DnsTrustState.TRUSTED,
    )
    server_b = TrustedDnsServer(
        "198.51.100.7",
        DnsServerCategory.UNKNOWN,
        1.0,
        1.0,
        trust_state=DnsTrustState.TRUSTED,
    )
    vorwaerts = TrustedDnsServerIps(FakeRepo([server_a, server_b]))()
    rueckwaerts = TrustedDnsServerIps(FakeRepo([server_b, server_a]))()

    assert vorwaerts == rueckwaerts == ["198.51.100.7", "203.0.113.4"]


# ── ListDnsTrustServers: mit Plausibilitaet ───────────────────────────────────


def test_list_stellt_plausibilitaet_bei() -> None:
    repo = FakeRepo(
        [
            TrustedDnsServer("192.168.1.50", DnsServerCategory.LOCAL_PRIVATE, 1.0, 1.0),
            TrustedDnsServer("8.8.8.8", DnsServerCategory.PUBLIC_RESOLVER, 2.0, 2.0),
        ]
    )
    result = ListDnsTrustServers(repo, _plausibility)()

    # Reihenfolge folgt list_all (first_seen aufsteigend): erst der Pi-hole.
    assert result[0][0].ip == "192.168.1.50"
    assert result[0][1] is not None
    assert result[0][1].display_name == "Pi-hole"
    assert result[0][1].open_ports == (53, 80)

    # 8.8.8.8 ist nicht im Bestand -> Indizien-Seite None.
    assert result[1][0].ip == "8.8.8.8"
    assert result[1][1] is None


# ── SetDnsServerRank: kompakte, kollisionsfreie 1..N-Rangfolge ────────────────


def _trusted(ip: str, first_seen: float, rank: int = 0) -> TrustedDnsServer:
    """Kurz-Fabrik: ein TRUSTED-Server mit optionalem Rang."""
    return TrustedDnsServer(
        ip,
        DnsServerCategory.LOCAL_PRIVATE,
        first_seen,
        first_seen,
        trust_state=DnsTrustState.TRUSTED,
        expected_rank=rank,
    )


def _rank_map(repo: FakeRepo) -> dict[str, int]:
    return {server.ip: server.expected_rank for server in repo.list_all()}


def test_rank_erster_rang_auf_trusted_server() -> None:
    repo = FakeRepo([_trusted("10.0.0.1", 1.0)])
    SetDnsServerRank(repo)("10.0.0.1", 1, now=99.0)
    assert _rank_map(repo) == {"10.0.0.1": 1}


def test_rank_umsortieren_erzeugt_lueckenlose_folge_ohne_doppel() -> None:
    # Drei rangierte Server 1/2/3; der dritte soll auf Platz 1 -> die anderen
    # ruecken nach, Ergebnis ist eine lueckenlose 1..3-Folge ohne Doppelraenge.
    repo = FakeRepo(
        [
            _trusted("10.0.0.1", 1.0, rank=1),
            _trusted("10.0.0.2", 2.0, rank=2),
            _trusted("10.0.0.3", 3.0, rank=3),
        ]
    )
    SetDnsServerRank(repo)("10.0.0.3", 1, now=99.0)
    assert _rank_map(repo) == {"10.0.0.3": 1, "10.0.0.1": 2, "10.0.0.2": 3}
    raenge = sorted(_rank_map(repo).values())
    assert raenge == [1, 2, 3]  # lueckenlos, keine Doppel


def test_rank_null_entfernt_und_schliesst_die_luecke() -> None:
    repo = FakeRepo(
        [
            _trusted("10.0.0.1", 1.0, rank=1),
            _trusted("10.0.0.2", 2.0, rank=2),
            _trusted("10.0.0.3", 3.0, rank=3),
        ]
    )
    SetDnsServerRank(repo)("10.0.0.2", 0, now=99.0)
    # Der mittlere ist raus (0), die uebrigen bilden wieder 1..2 ohne Luecke.
    assert _rank_map(repo) == {"10.0.0.1": 1, "10.0.0.2": 0, "10.0.0.3": 2}


def test_rank_negativ_wirft() -> None:
    repo = FakeRepo([_trusted("10.0.0.1", 1.0)])
    with pytest.raises(ValueError):
        SetDnsServerRank(repo)("10.0.0.1", -1, now=99.0)


def test_rank_absenken_tauscht_mit_dem_inhaber() -> None:
    # Gemeldeter Bug: A(1) auf Rang 2 setzen (Runter-Pfeil) war ein No-Op. Erwartet
    # ist der echte Tausch: A nimmt Platz 2 ein, B weicht nach vorn auf 1.
    repo = FakeRepo(
        [
            _trusted("10.0.0.1", 1.0, rank=1),  # A
            _trusted("10.0.0.2", 2.0, rank=2),  # B
        ]
    )
    SetDnsServerRank(repo)("10.0.0.1", 2, now=99.0)
    assert _rank_map(repo) == {"10.0.0.2": 1, "10.0.0.1": 2}


def test_rank_anheben_tauscht_mit_dem_inhaber() -> None:
    # Umkehrfall (Hoch-Pfeil): B(2) auf Rang 1 -> B nimmt Platz 1 ein, A weicht
    # nach hinten auf 2. Beide Richtungen sind echte Tausche, lueckenlos, ohne Doppel.
    repo = FakeRepo(
        [
            _trusted("10.0.0.1", 1.0, rank=1),  # A
            _trusted("10.0.0.2", 2.0, rank=2),  # B
        ]
    )
    SetDnsServerRank(repo)("10.0.0.2", 1, now=99.0)
    assert _rank_map(repo) == {"10.0.0.2": 1, "10.0.0.1": 2}


def test_rank_bewahrt_rang_eines_nicht_trusted_servers() -> None:
    # Verlustfrei: ein rangierter, aber (voruebergehend) NEUTRAL gestellter Server
    # behaelt seinen Platz in der Ordnung.
    neutral_rangiert = TrustedDnsServer(
        "10.0.0.9",
        DnsServerCategory.LOCAL_PRIVATE,
        1.0,
        1.0,
        trust_state=DnsTrustState.NEUTRAL,
        expected_rank=1,
    )
    repo = FakeRepo([neutral_rangiert, _trusted("10.0.0.2", 2.0)])
    SetDnsServerRank(repo)("10.0.0.2", 2, now=99.0)
    assert _rank_map(repo) == {"10.0.0.9": 1, "10.0.0.2": 2}


# ── SetDnsServerRank: der Nichtvollzug wird benannt (S62 L7c) ─────────────────
# Bis L7c ungetestete Luecke: ein Server, der WEDER bestaetigt ist NOCH bereits einen
# Rang traegt, fiel aus der betroffenen Menge und der Rang-Wunsch verschwand still --
# nach aussen als Erfolg. Die fachliche Regel selbst (Rang nur innerhalb der
# erwarteten Menge) bleibt unveraendert; ehrlich wird nur ihre Rueckmeldung.


def _neutral(ip: str, first_seen: float, rank: int = 0) -> TrustedDnsServer:
    """Kurz-Fabrik: ein NEUTRAL-Server (nicht bestaetigt) mit optionalem Rang."""
    return TrustedDnsServer(
        ip,
        DnsServerCategory.LOCAL_PRIVATE,
        first_seen,
        first_seen,
        trust_state=DnsTrustState.NEUTRAL,
        expected_rank=rank,
    )


def test_rank_auf_weder_trusted_noch_rangiert_wirft() -> None:
    """Der gemessene Fall F2: neutral + rank 0 -> Rang 1 kam nie an, Erfolg gemeldet."""
    repo = FakeRepo([_neutral("172.18.0.156", 1.0), _trusted("10.0.0.1", 2.0, rank=1)])
    with pytest.raises(DnsTrustServerNotConfirmedError):
        SetDnsServerRank(repo)("172.18.0.156", 1, now=99.0)
    # Nichts geschrieben -- weder am Ziel noch an der bestehenden Ordnung.
    assert _rank_map(repo) == {"172.18.0.156": 0, "10.0.0.1": 1}


def test_rank_auf_abgelehnten_server_wirft() -> None:
    """Auch REJECTED ist nicht bestaetigt -- gleiche Behandlung wie NEUTRAL."""
    abgelehnt = TrustedDnsServer(
        "203.0.113.9",
        DnsServerCategory.UNKNOWN,
        1.0,
        1.0,
        trust_state=DnsTrustState.REJECTED,
    )
    repo = FakeRepo([abgelehnt])
    with pytest.raises(DnsTrustServerNotConfirmedError):
        SetDnsServerRank(repo)("203.0.113.9", 1, now=99.0)
    assert _rank_map(repo) == {"203.0.113.9": 0}


def test_rank_auf_gar_nicht_erfasste_ip_wirft_not_found() -> None:
    """Getrennter Grund: gar kein Server erfasst -> NotFound (404), nicht 409."""
    repo = FakeRepo([_trusted("10.0.0.1", 1.0, rank=1)])
    with pytest.raises(DnsTrustServerNotFoundError):
        SetDnsServerRank(repo)("203.0.113.7", 1, now=99.0)
    assert _rank_map(repo) == {"10.0.0.1": 1}


def test_rank_null_auf_nicht_bestaetigten_server_bleibt_noop() -> None:
    """``rank == 0`` ist dort KEIN Nichtvollzug: unrangiert ist bereits der Zielzustand."""
    repo = FakeRepo([_neutral("172.18.0.156", 1.0), _trusted("10.0.0.1", 2.0, rank=1)])
    SetDnsServerRank(repo)("172.18.0.156", 0, now=99.0)  # kein Wurf
    assert _rank_map(repo) == {"172.18.0.156": 0, "10.0.0.1": 1}


def test_rank_auf_bestaetigten_server_bleibt_unveraendert_erfolgreich() -> None:
    """Gegenprobe: der gueltige Weg schreibt weiterhin (kein Verhalten geaendert).

    Nur die Ziel-ip traegt einen Rang-Wunsch; der unrangierte Nachbar bleibt unrangiert
    (dokumentiertes Bestandsverhalten: wer keinen Wunsch hat, erhaelt 0).
    """
    repo = FakeRepo([_trusted("10.0.0.1", 1.0), _trusted("10.0.0.2", 2.0)])
    SetDnsServerRank(repo)("10.0.0.2", 1, now=99.0)
    assert _rank_map(repo) == {"10.0.0.2": 1, "10.0.0.1": 0}


def test_rank_auf_rangierten_aber_nicht_trusted_server_bleibt_erlaubt() -> None:
    """Verlustfreiheit bleibt: wer bereits einen Rang traegt, darf ihn aendern."""
    repo = FakeRepo([_neutral("10.0.0.9", 1.0, rank=1), _trusted("10.0.0.2", 2.0, rank=2)])
    SetDnsServerRank(repo)("10.0.0.9", 2, now=99.0)  # kein Wurf
    assert _rank_map(repo) == {"10.0.0.2": 1, "10.0.0.9": 2}


# ── AddDnsTrustServer: Anlegen von Hand (S63 L7d) ─────────────────────────────


def test_add_legt_manuellen_server_trusted_an() -> None:
    """Von Hand hinterlegt: direkt TRUSTED, Herkunft MANUAL, first_seen == last_seen == now.

    Der Nutzer erklaert "diesen Server erwarte ich", bevor ihn ein Waechter gesehen hat --
    darum NICHT der ``default_trust_for``-Weg des Sync (der eine Bestaetigung abwartet).
    """
    repo = FakeRepo()
    server = asyncio.run(_add(repo)("192.168.5.5", now=1000.0))

    assert server.trust_state is DnsTrustState.TRUSTED
    assert server.origin is DnsServerOrigin.MANUAL
    assert server.first_seen == server.last_seen == 1000.0
    assert server.expected_rank == 0
    # Und er liegt wirklich im Bestand (nicht nur zurueckgegeben).
    assert repo.get("192.168.5.5") == server


def test_add_leitet_kategorie_ueber_dieselben_flags_ab() -> None:
    """Die Kategorie kommt aus der VORHANDENEN Ableitung -- keine zweite Logik.

    Gegenprobe ueber drei Flag-Lagen: privat ohne Treffer -> LOCAL_PRIVATE, als Gateway
    gemeldet -> GATEWAY, als oeffentlicher Resolver gemeldet -> PUBLIC_RESOLVER.
    """
    privat = asyncio.run(_add(FakeRepo())("192.168.5.5", now=1.0))
    assert privat.category is DnsServerCategory.LOCAL_PRIVATE

    gateway = asyncio.run(_add(FakeRepo(), gateway="192.168.1.1")("192.168.1.1", now=1.0))
    assert gateway.category is DnsServerCategory.GATEWAY

    oeffentlich = asyncio.run(_add(FakeRepo(), public=True)("9.9.9.9", now=1.0))
    assert oeffentlich.category is DnsServerCategory.PUBLIC_RESOLVER


def test_add_uebernimmt_den_uebergebenen_namen() -> None:
    """Der mitgeschickte Name hat Vorrang -- auch vor einem Bestands-Treffer."""
    repo = FakeRepo()
    server = asyncio.run(_add(repo)("192.168.5.5", now=1.0, display_name="Mein Resolver"))
    assert server.display_name == "Mein Resolver"


def test_add_faellt_ohne_namen_auf_den_bestand_zurueck() -> None:
    """Ohne Namen greift der best-effort Bestands-Name (die IP KANN ein Geraet sein)."""
    repo = FakeRepo()
    server = asyncio.run(_add(repo)("192.168.1.50", now=1.0))
    assert server.display_name == "Pi-hole"


def test_add_ohne_namen_und_ohne_bestand_bleibt_leer() -> None:
    """Kein Name, kein Bestands-Treffer -> "" (nichts erfinden, S3)."""
    repo = FakeRepo()
    server = asyncio.run(_add(repo)("192.168.5.5", now=1.0))
    assert server.display_name == ""


def test_add_auf_bereits_erfasste_ip_wirft() -> None:
    """Duplikat -> Fehler, KEIN stiller Upsert (S3).

    Der bestehende Eintrag bleibt unangetastet: ein ``upsert`` haette seinen kuratierten
    ``trust_state`` und sein ``first_seen`` ueberschrieben.
    """
    repo = FakeRepo([_neutral("10.0.0.1", 5.0)])
    with pytest.raises(DnsTrustServerAlreadyExistsError):
        asyncio.run(_add(repo)("10.0.0.1", now=1000.0))

    unveraendert = repo.get("10.0.0.1")
    assert unveraendert is not None
    assert unveraendert.trust_state is DnsTrustState.NEUTRAL
    assert unveraendert.first_seen == 5.0


@pytest.mark.parametrize("kaputt", ["", "   ", "nicht-ip", "1:2", "999.999.999.999", "::::"])
def test_add_mit_unbrauchbarer_ip_wirft_und_schreibt_nichts(kaputt: str) -> None:
    """Unbrauchbare Adresse -> Fehler; das Schluesselfeld bleibt sauber (keine tote Zeile)."""
    repo = FakeRepo()
    with pytest.raises(DnsTrustInvalidIpError):
        asyncio.run(_add(repo)(kaputt, now=1.0))
    assert repo.list_all() == []


def test_add_kanonisiert_vor_duplikat_pruefung_und_anlage() -> None:
    """Die KANONISCHE Form ist der Schluessel -- sonst belegte dieselbe Adresse zwei Zeilen.

    ``::0001`` und ``::1`` sind dieselbe Adresse: die erste Anlage landet unter ``::1``,
    die zweite (abweichend geschriebene) trifft darum den Duplikat-Schutz.
    """
    repo = FakeRepo()
    server = asyncio.run(_add(repo)("::0001", now=1.0))
    assert server.ip == "::1"
    assert repo.get("::1") is not None

    with pytest.raises(DnsTrustServerAlreadyExistsError):
        asyncio.run(_add(repo)("::0001", now=2.0))
    assert len(repo.list_all()) == 1


def test_add_kennzeichnet_plattform_platzhalter() -> None:
    """``is_platform_placeholder`` laeuft ueber dieselbe reine Funktion wie im Sync."""
    repo = FakeRepo()
    server = asyncio.run(_add(repo)("fec0:0:0:ffff::1", now=1.0))
    assert server.is_platform_placeholder is True


# ── origin-Uebergang: beobachtet schlaegt von Hand (S63 L7d) ──────────────────


def test_sync_hebt_manuellen_server_auf_observed() -> None:
    """Wird ein von Hand hinterlegter Server real beobachtet, ist er nicht mehr MANUAL.

    Die Herkunft "noch nie beobachtet" trifft dann nicht mehr zu -- der Eintrag verlaesst
    den Von-Hand-Bereich der Oberflaeche. Der kuratierte ``trust_state`` bleibt erhalten.
    """
    repo = FakeRepo()
    asyncio.run(_add(repo)("192.168.5.5", now=1000.0))

    aktualisiert = asyncio.run(_sync(repo)("192.168.5.5", now=2000.0))

    assert aktualisiert.origin is DnsServerOrigin.OBSERVED
    # trust_state und first_seen bleiben unberuehrt (Bestandsverhalten).
    assert aktualisiert.trust_state is DnsTrustState.TRUSTED
    assert aktualisiert.first_seen == 1000.0
    assert aktualisiert.last_seen == 2000.0


def test_sync_hebt_migrierten_server_auf_observed() -> None:
    """Gleiche Logik fuer den Altbestand: real gesehen = observed."""
    repo = FakeRepo(
        [
            TrustedDnsServer(
                ip="10.0.0.5",
                category=DnsServerCategory.LOCAL_PRIVATE,
                first_seen=1.0,
                last_seen=1.0,
                trust_state=DnsTrustState.TRUSTED,
                origin=DnsServerOrigin.MIGRATED,
            )
        ]
    )
    aktualisiert = asyncio.run(_sync(repo)("10.0.0.5", now=2000.0))
    assert aktualisiert.origin is DnsServerOrigin.OBSERVED


def test_sync_neuanlage_ist_observed() -> None:
    """Der Sync legt weiterhin als OBSERVED an (Default, kein manuelles Setzen)."""
    repo = FakeRepo()
    server = asyncio.run(_sync(repo)("192.168.1.77", now=1.0))
    assert server.origin is DnsServerOrigin.OBSERVED
