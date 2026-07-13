"""End-to-end-Test der dns_trust-API (ADR 0043, Etappe 5) gegen app.py via TestClient.

Deckt ``GET /api/dns-trust`` (Lese-Runner als Fake-Double, geprueft wird der Wire-Vertrag
der ``TrustedDnsServerOut`` inkl. Plausibilitaets-Projektion) und
``POST /api/dns-trust/decision`` ab. Der Schreibpfad laeuft -- wie ``test_dns_watch_api.py``
-- gegen ein echtes tmp_path-DB-Repo (so wird der Adapter-Schreibpfad + der
``SetDnsServerTrust``-Use-Case mitgeprueft), der Runner wird analog app.py per
``dependency_overrides`` verdrahtet. Muell (ungueltige ``decision``) -> 422; eine
unbekannte ``ip`` ist ein definierter No-Op (kein 500).
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.dns_trust import (
    DnsServerPlausibilityOut,
    TrustedDnsServerOut,
    provide_dns_trust_decision,
    provide_dns_trust_list,
)
from app import create_app
from domain.dns_trust import (
    DnsServerCategory,
    DnsTrustState,
    TrustedDnsServer,
)
from infrastructure.config import AppConfig
from infrastructure.dns_trust_repository import SqliteDnsTrustRepository

IP = "192.168.0.1"


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
    # Schreib-Runner wie im Composition Root: (ip, decision) -> set_trust mit fester now.
    app.dependency_overrides[provide_dns_trust_decision] = lambda: (
        lambda ip, decision: repo.set_trust(
            ip,
            {
                "trust": DnsTrustState.TRUSTED,
                "reject": DnsTrustState.REJECTED,
                "reset": DnsTrustState.NEUTRAL,
            }[decision],
            999.0,
        )
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


def test_unbekannte_ip_ist_kein_500(
    decision_context: tuple[FastAPI, SqliteDnsTrustRepository],
) -> None:
    """Entscheidung fuer eine unbekannte ip -> definierter No-Op (200, kein 500)."""
    application, repo = decision_context
    client = TestClient(application)
    resp = client.post("/api/dns-trust/decision", json=_body(ip="203.0.113.7", decision="trust"))
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert repo.get("203.0.113.7") is None
