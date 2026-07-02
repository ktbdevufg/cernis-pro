"""Tests der DNS-Vertrauens-Use-Cases gegen In-Memory-Fakes (ADR 0043, Etappe 3).

Getestet gegen schlanke Fakes des Repos + der injizierten Nahtstellen (Muster der
bestehenden application-Tests: kein echtes SQLite/Netz). Kern der Behauptungen:

(1) ``SyncDnsTrustServer`` legt neu an -- ``first_seen == last_seen == now``, Vor-Vertrauen
    ueber ``default_trust_for`` (nur GATEWAY -> TRUSTED, sonst NEUTRAL).
(2) ``SyncDnsTrustServer`` aktualisiert bestehend -- Kategorie/last_seen/display_name werden
    gepflegt, ``trust_state`` und ``first_seen`` bleiben (User-Wertung NIE ueberschreiben).
(3) Die Kategorie-Ableitung folgt den Flags (gateway/public/threat) in fester Prioritaet.
(4) ``SetDnsServerTrust`` bildet alle drei decisions korrekt ab; ein Unbekannter wirft.
(5) ``TrustedDnsServerIps`` liefert genau die TRUSTED-IPs.
(6) ``ListDnsTrustServers`` stellt je Server die Plausibilitaet bei (bzw. ``None``).

Der einzige async Use-Case (``SyncDnsTrustServer``, wegen ``GatewayProvider``) wird ueber
``asyncio.run`` getrieben (Hausmuster der application-Tests).
"""

import asyncio

import pytest

from application.dns_trust import (
    DnsServerPlausibility,
    ListDnsTrustServers,
    SetDnsServerTrust,
    SyncDnsTrustServer,
    TrustedDnsServerIps,
)
from domain.dns_trust import (
    DnsServerCategory,
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
        self._store[ip] = TrustedDnsServer(
            ip=existing.ip,
            category=existing.category,
            first_seen=existing.first_seen,
            last_seen=now,
            trust_state=state,
            display_name=existing.display_name,
            notes=existing.notes,
        )

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
    # threat schlaegt alles (auch gateway): categorize priorisiert THREAT_LISTED.
    threat_server = asyncio.run(_sync(repo, gateway="10.0.0.1", threat=True)("10.0.0.1", now=1.0))
    assert threat_server.category is DnsServerCategory.THREAT_LISTED

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


def test_set_trust_unbekannte_ip_ist_noop() -> None:
    repo = FakeRepo()
    SetDnsServerTrust(repo)("203.0.113.7", "trust", now=1.0)  # kein Wurf
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
    assert TrustedDnsServerIps(repo)() == {"1.1.1.1", "192.168.1.1"}


def test_trusted_ips_leer_wenn_keiner_trusted() -> None:
    repo = FakeRepo()
    assert TrustedDnsServerIps(repo)() == set()


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
