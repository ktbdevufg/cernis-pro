"""End-to-end-Test der dns_trust-API (ADR 0043, Etappe 5) gegen app.py via TestClient.

Deckt ``GET /api/dns-trust`` (Lese-Runner als Fake-Double, geprueft wird der Wire-Vertrag
der ``TrustedDnsServerOut`` inkl. Plausibilitaets-Projektion) und
``POST /api/dns-trust/decision`` ab. Der Schreibpfad laeuft -- wie ``test_dns_watch_api.py``
-- gegen ein echtes tmp_path-DB-Repo (so wird der Adapter-Schreibpfad + der
``SetDnsServerTrust``-Use-Case mitgeprueft), der Runner wird analog app.py per
``dependency_overrides`` verdrahtet. Muell (ungueltige ``decision``) -> 422.

Seit S62 L7c melden beide Schreibwege einen Nichtvollzug ehrlich, statt Erfolg fuer
etwas zu quittieren, das nicht geschieht: eine ``ip`` ohne erfassten Server -> 404
(Muster ``api/devices.py``), ein ``rank > 0`` fuer einen weder bestaetigten noch bereits
rangierten Server -> 409 (Muster ``api/outbound_log.py``). Die gueltigen Wege sind
unveraendert und werden hier weiter mitgeprueft.

Seit S63 L7d kommt ``POST /api/dns-trust`` dazu: ein noch nie beobachteter Server laesst
sich von Hand hinterlegen (direkt vertraut, Herkunft ``manual``). Auch dieser Weg laeuft
im Test ueber den ECHTEN Use-Case gegen ein tmp-DB-Repo -- inkl. Kanonisierung der
Adresse, Duplikat-Schutz (409, kein stiller Upsert) und unbrauchbarer Eingabe (422).
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.dns_trust import (
    DnsServerPlausibilityOut,
    TrustedDnsServerOut,
    provide_dns_trust_create,
    provide_dns_trust_decision,
    provide_dns_trust_list,
    provide_dns_trust_rank,
)
from app import create_app
from application.dns_trust import AddDnsTrustServer, SetDnsServerRank, SetDnsServerTrust
from domain.dns_trust import (
    DnsServerCategory,
    DnsServerOrigin,
    DnsTrustState,
    TrustedDnsServer,
)
from infrastructure.config import AppConfig
from infrastructure.dns_trust_repository import SqliteDnsTrustRepository

IP = "192.168.0.1"
# Ein erfasster, aber NICHT bestaetigter Server ohne Rang (S62 L7c F2).
IP_NEUTRAL = "192.168.0.156"


class _FakeDnsTrustListRunner:
    """Fake-Runner: liefert eine feste, schon api-projizierte Liste (keine echten Quellen)."""

    def __init__(self, servers: list[TrustedDnsServerOut]) -> None:
        self._servers = servers
        self.calls = 0

    def __call__(self) -> list[TrustedDnsServerOut]:
        self.calls += 1
        return self._servers


@pytest.fixture
def app() -> Iterator[FastAPI]:
    """Frisch gebaute App (Lifespan via TestClient pro Test -- kein Loop noetig)."""
    yield create_app(AppConfig())


# ── GET: Wire-Vertrag der Server-Liste (inkl. Plausibilitaet) ──────────────────


def test_get_dns_trust_liefert_200_und_json_form(app: FastAPI) -> None:
    """``/api/dns-trust`` -> HTTP 200 + erwartete JSON-Form (Server + Plausibilitaet|None)."""
    servers = [
        TrustedDnsServerOut(
            ip="10.0.0.1",
            category="gateway",
            trust_state="trusted",
            first_seen=100.0,
            last_seen=200.0,
            display_name="FritzBox",
            notes="",
            is_platform_placeholder=False,
            expected_rank=1,
            origin="observed",
            plausibility=DnsServerPlausibilityOut(
                in_inventory=True,
                first_seen_days=12,
                vendor="AVM",
                open_ports=[53, 80],
                display_name="FritzBox",
            ),
        ),
        TrustedDnsServerOut(
            ip="fec0:0:0:ffff::1",
            category="unknown",
            trust_state="neutral",
            first_seen=300.0,
            last_seen=300.0,
            display_name="",
            notes="",
            is_platform_placeholder=True,
            expected_rank=0,
            origin="manual",
            plausibility=None,
        ),
    ]
    runner = _FakeDnsTrustListRunner(servers)
    app.dependency_overrides[provide_dns_trust_list] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/dns-trust")

    assert response.status_code == 200
    assert runner.calls == 1
    assert response.json() == [
        {
            "ip": "10.0.0.1",
            "category": "gateway",
            "trust_state": "trusted",
            "first_seen": 100.0,
            "last_seen": 200.0,
            "display_name": "FritzBox",
            "notes": "",
            "is_platform_placeholder": False,
            "expected_rank": 1,
            "origin": "observed",
            "plausibility": {
                "in_inventory": True,
                "first_seen_days": 12,
                "vendor": "AVM",
                "open_ports": [53, 80],
                "display_name": "FritzBox",
            },
        },
        {
            "ip": "fec0:0:0:ffff::1",
            "category": "unknown",
            "trust_state": "neutral",
            "first_seen": 300.0,
            "last_seen": 300.0,
            "display_name": "",
            "notes": "",
            "is_platform_placeholder": True,
            "expected_rank": 0,
            "origin": "manual",
            "plausibility": None,
        },
    ]


def test_get_dns_trust_leere_liste(app: FastAPI) -> None:
    """Ohne kuratierte Server -> 200 + leere Liste."""
    runner = _FakeDnsTrustListRunner([])
    app.dependency_overrides[provide_dns_trust_list] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/dns-trust")

    assert response.status_code == 200
    assert response.json() == []


# ── POST /decision: Schreibpfad gegen echtes tmp-DB-Repo ───────────────────────


@pytest.fixture
def decision_context(app: FastAPI, tmp_path: Path) -> tuple[FastAPI, SqliteDnsTrustRepository]:
    repo = SqliteDnsTrustRepository(tmp_path / "cernis.db")
    # EIN bestehender Server (NEUTRAL), an dem die Entscheidung sichtbar wird.
    repo.upsert(
        TrustedDnsServer(
            ip=IP,
            category=DnsServerCategory.LOCAL_PRIVATE,
            first_seen=100.0,
            last_seen=100.0,
            trust_state=DnsTrustState.NEUTRAL,
        )
    )
    # Schreib-Runner wie im Composition Root: (ip, decision) -> SetDnsServerTrust mit
    # fester now. Bewusst der ECHTE Use-Case (nicht repo.set_trust direkt): nur so laeuft
    # der Test ueber dieselbe Naht wie app.py und sieht dessen Fehlerwuerfe (S62 L7c).
    trust_use_case = SetDnsServerTrust(repo)
    app.dependency_overrides[provide_dns_trust_decision] = lambda: (
        lambda ip, decision: trust_use_case(ip, decision, 999.0)
    )
    return app, repo


def _body(**over: object) -> dict[str, object]:
    base: dict[str, object] = {"ip": IP, "decision": "trust"}
    base.update(over)
    return base


@pytest.mark.parametrize(
    ("decision", "expected"),
    [
        ("trust", DnsTrustState.TRUSTED),
        ("reject", DnsTrustState.REJECTED),
        ("reset", DnsTrustState.NEUTRAL),
    ],
)
def test_decision_schreibt_und_ist_sichtbar(
    decision_context: tuple[FastAPI, SqliteDnsTrustRepository],
    decision: str,
    expected: DnsTrustState,
) -> None:
    application, repo = decision_context
    client = TestClient(application)
    resp = client.post("/api/dns-trust/decision", json=_body(decision=decision))
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    stored = repo.get(IP)
    assert stored is not None
    assert stored.trust_state is expected


def test_invalide_decision_ist_422(
    decision_context: tuple[FastAPI, SqliteDnsTrustRepository],
) -> None:
    application, _ = decision_context
    client = TestClient(application)
    resp = client.post("/api/dns-trust/decision", json=_body(decision="loeschen"))
    assert resp.status_code == 422


def test_unbekannte_ip_ist_404_statt_stillem_erfolg(
    decision_context: tuple[FastAPI, SqliteDnsTrustRepository],
) -> None:
    """S62 L7c F1: Entscheidung fuer eine nicht erfasste ip -> 404, KEIN stiller Erfolg.

    Bis L7c antwortete dieser Weg 200 ``{"ok": true}``, ohne eine Zeile zu schreiben
    (gemessen mit 9.9.9.9). Jetzt benennt er den Nichtvollzug -- 404 nach dem Muster
    ``api/devices.py`` (unbekannte MAC -> 404). Kein 500.
    """
    application, repo = decision_context
    client = TestClient(application)
    resp = client.post("/api/dns-trust/decision", json=_body(ip="203.0.113.7", decision="trust"))
    assert resp.status_code == 404
    assert "(E-503)" in resp.json()["detail"]
    assert repo.get("203.0.113.7") is None


# ── POST /rank: Rang-Schreibpfad gegen echtes tmp-DB-Repo ─────────────────────


@pytest.fixture
def rank_context(app: FastAPI, tmp_path: Path) -> tuple[FastAPI, SqliteDnsTrustRepository]:
    repo = SqliteDnsTrustRepository(tmp_path / "cernis.db")
    # EIN bestehender TRUSTED-Server, an dem der Rang sichtbar wird.
    repo.upsert(
        TrustedDnsServer(
            ip=IP,
            category=DnsServerCategory.LOCAL_PRIVATE,
            first_seen=100.0,
            last_seen=100.0,
            trust_state=DnsTrustState.TRUSTED,
        )
    )
    # UND ein erfasster, aber nicht bestaetigter Server ohne Rang (S62 L7c F2): fuer ihn
    # kam der Rang bis L7c nie an, gemeldet wurde trotzdem Erfolg.
    repo.upsert(
        TrustedDnsServer(
            ip=IP_NEUTRAL,
            category=DnsServerCategory.LOCAL_PRIVATE,
            first_seen=200.0,
            last_seen=200.0,
            trust_state=DnsTrustState.NEUTRAL,
        )
    )
    # Rang-Runner wie im Composition Root: (ip, rank) -> SetDnsServerRank mit fester now.
    rank_use_case = SetDnsServerRank(repo)
    app.dependency_overrides[provide_dns_trust_rank] = lambda: (
        lambda ip, rank: rank_use_case(ip, rank, 999.0)
    )
    return app, repo


def test_rank_schreibt_und_ist_sichtbar(
    rank_context: tuple[FastAPI, SqliteDnsTrustRepository],
) -> None:
    application, repo = rank_context
    client = TestClient(application)
    resp = client.post("/api/dns-trust/rank", json={"ip": IP, "rank": 1})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    stored = repo.get(IP)
    assert stored is not None
    assert stored.expected_rank == 1


def test_negativer_rank_ist_422(
    rank_context: tuple[FastAPI, SqliteDnsTrustRepository],
) -> None:
    """``rank < 0`` scheitert an der Body-Validierung (Field ge=0) -> 422."""
    application, _ = rank_context
    client = TestClient(application)
    resp = client.post("/api/dns-trust/rank", json={"ip": IP, "rank": -1})
    assert resp.status_code == 422


def test_rank_auf_nicht_bestaetigten_server_ist_409(
    rank_context: tuple[FastAPI, SqliteDnsTrustRepository],
) -> None:
    """S62 L7c F2: Rang fuer einen weder bestaetigten noch rangierten Server -> 409.

    Bis L7c antwortete dieser Weg 200 ``{"ok": true}``, der Wert kam nie an (gemessen mit
    172.18.0.156, Rang 1 angefordert, danach weiterhin 0). Der Zustand laesst die Aktion
    nicht zu -> 409 nach dem Muster ``api/outbound_log.py``. Die fachliche Regel selbst
    bleibt unveraendert.
    """
    application, repo = rank_context
    client = TestClient(application)
    resp = client.post("/api/dns-trust/rank", json={"ip": IP_NEUTRAL, "rank": 1})
    assert resp.status_code == 409
    assert "(E-503)" in resp.json()["detail"]
    # Nichts geschrieben -- weder am Ziel noch am bestaetigten Nachbarn.
    stored = repo.get(IP_NEUTRAL)
    assert stored is not None
    assert stored.expected_rank == 0


def test_rank_auf_gar_nicht_erfasste_ip_ist_404(
    rank_context: tuple[FastAPI, SqliteDnsTrustRepository],
) -> None:
    """Getrennter Grund: gar kein Server erfasst -> 404 (nicht 409)."""
    application, repo = rank_context
    client = TestClient(application)
    resp = client.post("/api/dns-trust/rank", json={"ip": "203.0.113.7", "rank": 1})
    assert resp.status_code == 404
    assert "(E-503)" in resp.json()["detail"]
    assert repo.get("203.0.113.7") is None


def test_rank_null_auf_nicht_bestaetigten_server_bleibt_200(
    rank_context: tuple[FastAPI, SqliteDnsTrustRepository],
) -> None:
    """``rank == 0`` dort ist KEIN Nichtvollzug: unrangiert ist bereits der Zielzustand."""
    application, repo = rank_context
    client = TestClient(application)
    resp = client.post("/api/dns-trust/rank", json={"ip": IP_NEUTRAL, "rank": 0})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    stored = repo.get(IP_NEUTRAL)
    assert stored is not None
    assert stored.expected_rank == 0


# ── POST "": Anlege-Weg von Hand (S63 L7d) ────────────────────────────────────


@pytest.fixture
def create_context(app: FastAPI, tmp_path: Path) -> tuple[FastAPI, SqliteDnsTrustRepository]:
    """Anlege-Runner wie im Composition Root, gegen echtes tmp-DB-Repo.

    Bewusst der ECHTE Use-Case mit fester ``now`` (Muster ``decision_context``): nur so
    laeuft der Test ueber dieselbe Naht wie app.py -- inkl. Kanonisierung, Duplikat-Schutz
    und der beiden Fehlerwuerfe. Die vier Nahtstellen sind hier feste Doubles (kein
    Gateway, kein oeffentlicher Resolver, keine Bedrohungsliste, kein Bestands-Treffer).
    """
    repo = SqliteDnsTrustRepository(tmp_path / "cernis.db")
    # EIN bereits erfasster Server, an dem der Duplikat-Schutz sichtbar wird.
    repo.upsert(
        TrustedDnsServer(
            ip=IP,
            category=DnsServerCategory.LOCAL_PRIVATE,
            first_seen=100.0,
            last_seen=100.0,
            trust_state=DnsTrustState.NEUTRAL,
        )
    )

    async def _kein_gateway() -> str | None:
        return None

    add_use_case = AddDnsTrustServer(
        repo=repo,
        gateway=_kein_gateway,
        is_public_resolver=lambda _ip: False,
        is_threat_listed=lambda _ip: False,
        plausibility=lambda _ip: None,
    )

    async def _runner(ip: str, name: str) -> None:
        await add_use_case(ip, 999.0, name)

    app.dependency_overrides[provide_dns_trust_create] = lambda: _runner
    return app, repo


def test_create_legt_manuellen_server_an(
    create_context: tuple[FastAPI, SqliteDnsTrustRepository],
) -> None:
    """S63 L7d: ein nie beobachteter Server laesst sich von Hand hinterlegen -> 200.

    Er entsteht direkt als ``trusted`` mit Herkunft ``manual`` -- der Nutzer erwartet ihn,
    gesehen hat ihn niemand. Der mitgeschickte Name wird als ``display_name`` uebernommen.
    """
    application, repo = create_context
    client = TestClient(application)
    resp = client.post("/api/dns-trust", json={"ip": "192.168.5.5", "name": "Pi-hole"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    stored = repo.get("192.168.5.5")
    assert stored is not None
    assert stored.trust_state is DnsTrustState.TRUSTED
    assert stored.origin is DnsServerOrigin.MANUAL
    assert stored.display_name == "Pi-hole"
    assert stored.first_seen == stored.last_seen == 999.0


def test_create_ohne_namen_ist_erlaubt(
    create_context: tuple[FastAPI, SqliteDnsTrustRepository],
) -> None:
    """Der Name ist optional (Body-Default ``""``) -> ohne Bestands-Treffer bleibt er leer."""
    application, repo = create_context
    client = TestClient(application)
    resp = client.post("/api/dns-trust", json={"ip": "192.168.5.6"})
    assert resp.status_code == 200
    stored = repo.get("192.168.5.6")
    assert stored is not None
    assert stored.display_name == ""


def test_create_auf_bereits_erfasste_ip_ist_409(
    create_context: tuple[FastAPI, SqliteDnsTrustRepository],
) -> None:
    """Duplikat -> 409, KEIN stiller Upsert (S3).

    Der bestehende Eintrag bleibt vollstaendig unangetastet: ein ``upsert`` haette seinen
    kuratierten ``trust_state`` (hier NEUTRAL) auf TRUSTED gehoben und ``first_seen``
    ueberschrieben -- genau die Nutzer-Entscheidung, die das Modell traegt.
    """
    application, repo = create_context
    client = TestClient(application)
    resp = client.post("/api/dns-trust", json={"ip": IP, "name": "Zweitname"})
    assert resp.status_code == 409
    assert "(E-506)" in resp.json()["detail"]
    stored = repo.get(IP)
    assert stored is not None
    assert stored.trust_state is DnsTrustState.NEUTRAL
    assert stored.first_seen == 100.0
    assert stored.display_name == ""


@pytest.mark.parametrize("kaputt", ["", "   ", "nicht-ip", "1:2", "999.999.999.999"])
def test_create_mit_unbrauchbarer_ip_ist_422(
    create_context: tuple[FastAPI, SqliteDnsTrustRepository],
    kaputt: str,
) -> None:
    """Unbrauchbare Adresse -> 422, nichts geschrieben (das Schluesselfeld bleibt sauber)."""
    application, repo = create_context
    client = TestClient(application)
    resp = client.post("/api/dns-trust", json={"ip": kaputt, "name": ""})
    assert resp.status_code == 422
    assert repo.list_all() == [repo.get(IP)]


def test_create_kanonisiert_die_adresse(
    create_context: tuple[FastAPI, SqliteDnsTrustRepository],
) -> None:
    """Die kanonische Form ist der Schluessel: ``::0001`` landet als ``::1`` im Bestand."""
    application, repo = create_context
    client = TestClient(application)
    resp = client.post("/api/dns-trust", json={"ip": "::0001", "name": ""})
    assert resp.status_code == 200
    assert repo.get("::1") is not None
    # Und die abweichende Schreibweise trifft danach den Duplikat-Schutz.
    zweite = client.post("/api/dns-trust", json={"ip": "::0001", "name": ""})
    assert zweite.status_code == 409
