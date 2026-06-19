"""Tests fuer die cve-Use-Cases (ADR 0037): Drip-Worker + Lese-Use-Cases.

Worker (``RunCveMonitor.tick``): Drosselung (ein faelliger Host pro tick), Faelligkeit
(Faelle 1-3 + NOT_DUE), first_seen-Bewahrung beim Re-Check, Hosts ohne Ports, leerer
Bestand (kein Lookup), strenge Fehlertoleranz (Lookup-Fehler -> Pruefstand NICHT
fortgeschrieben, Loop ueberlebt). Lese-Use-Cases: ack-Filter + is_new, Status-Zahlen.

Echte SQLite-Adapter (tmp_path) als Repos; Fakes fuer die Provider-Ports. Die Zeit wird
ueber ``now_provider`` deterministisch injiziert (kein monkeypatch noetig).
"""

import asyncio
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from application.cve.use_cases import (
    GetActiveFindings,
    GetCveMonitorStatus,
    RunCveMonitor,
)
from domain.cve.models import CveFindingRecord
from infrastructure.cve_acknowledgements_db import SqliteCveAcknowledgementRepository
from infrastructure.cve_checkstate_db import SqliteCveCheckStateRepository
from infrastructure.cve_findings_db import SqliteCveFindingRepository
from ports.cve import InventoryHost, InventoryPort, LookupCve

MAC = "aa:bb:cc:dd:ee:ff"
MAC2 = "11:22:33:44:55:66"
HOUR = 3600.0

Repos = tuple[
    SqliteCveFindingRepository,
    SqliteCveCheckStateRepository,
    SqliteCveAcknowledgementRepository,
]


class _FakeInventory:
    def __init__(self, hosts: list[InventoryHost]) -> None:
        self._hosts = hosts

    def list_hosts(self) -> list[InventoryHost]:
        return self._hosts


class _FakeLookup:
    """Liefert je Aufruf konfigurierte CVEs; zaehlt Aufrufe; kann werfen (NVD down)."""

    def __init__(self, cves: list[LookupCve], fail: bool = False) -> None:
        self._cves = cves
        self._fail = fail
        self.calls = 0

    async def lookup(self, ports: Sequence[InventoryPort]) -> list[LookupCve]:
        self.calls += 1
        if self._fail:
            raise RuntimeError("NVD down")
        return self._cves


@pytest.fixture
def repos(tmp_path: Path) -> Repos:
    db = tmp_path / "cernis.db"
    return (
        SqliteCveFindingRepository(db),
        SqliteCveCheckStateRepository(db),
        SqliteCveAcknowledgementRepository(db),
    )


def _host(mac: str = MAC, ports: tuple[int, ...] = (22,)) -> InventoryHost:
    return InventoryHost(
        mac=mac, ip="192.168.1.10", ports=tuple(InventoryPort(p, "svc") for p in ports)
    )


def _cve(cve_id: str = "CVE-2024-0001", port: int = 22) -> LookupCve:
    return LookupCve(
        cve_id=cve_id,
        description="d",
        severity="HIGH",
        cvss_score=7.5,
        published="2024-01-01",
        port=port,
    )


def _at(ts: float) -> Callable[[], float]:
    return lambda: ts


def _worker(
    repos: Repos,
    hosts: list[InventoryHost],
    lookup: _FakeLookup,
    now: float = 1000.0,
    refresh: float = 24 * HOUR,
) -> RunCveMonitor:
    findings, checkstate, _ = repos
    return RunCveMonitor(
        inventory=_FakeInventory(hosts),
        lookup=lookup,
        findings=findings,
        checkstate=checkstate,
        refresh_interval_provider=_at(refresh),
        now_provider=_at(now),
    )


# ── Worker: Fall 1 (neuer Host) prueft + persistiert ──────────────────────────


def test_tick_neuer_host_wird_geprueft_und_persistiert(repos: Repos) -> None:
    findings, checkstate, _ = repos
    lookup = _FakeLookup([_cve()])
    asyncio.run(_worker(repos, [_host()], lookup).tick())
    assert lookup.calls == 1
    rows = findings.list_all()
    assert len(rows) == 1
    assert rows[0].first_seen_ts == 1000.0
    assert rows[0].last_seen_ts == 1000.0
    state = checkstate.get(MAC)
    assert state is not None
    assert state.checked_ports == frozenset({22})


# ── Worker: NOT_DUE prueft NICHT (Resume/Idempotenz) ──────────────────────────


def test_tick_frisch_geprueft_kein_zweiter_lookup(repos: Repos) -> None:
    lookup = _FakeLookup([_cve()])
    worker = _worker(repos, [_host()], lookup)
    asyncio.run(worker.tick())
    asyncio.run(worker.tick())  # gleicher now, gleiche Ports -> NOT_DUE
    assert lookup.calls == 1


# ── Worker: Drosselung -- nur EIN faelliger Host pro tick ─────────────────────


def test_tick_drosselt_auf_einen_host(repos: Repos) -> None:
    _, checkstate, _ = repos
    lookup = _FakeLookup([_cve()])
    worker = _worker(repos, [_host(MAC), _host(MAC2)], lookup)
    asyncio.run(worker.tick())
    assert lookup.calls == 1  # nur EIN Host pro tick
    asyncio.run(worker.tick())  # erster nun NOT_DUE -> zweiter wird geprueft
    assert lookup.calls == 2
    assert checkstate.get(MAC) is not None
    assert checkstate.get(MAC2) is not None


# ── Worker: leerer Bestand / Host ohne Ports -> KEIN Lookup ───────────────────


def test_tick_leerer_bestand_kein_lookup(repos: Repos) -> None:
    lookup = _FakeLookup([_cve()])
    asyncio.run(_worker(repos, [], lookup).tick())
    assert lookup.calls == 0


def test_tick_host_ohne_ports_uebersprungen(repos: Repos) -> None:
    _, checkstate, _ = repos
    lookup = _FakeLookup([_cve()])
    asyncio.run(_worker(repos, [_host(MAC, ports=())], lookup).tick())
    assert lookup.calls == 0
    assert checkstate.get(MAC) is None


# ── Worker: first_seen bleibt beim Re-Check (Ports geaendert) ─────────────────


def test_re_check_behaelt_first_seen(repos: Repos) -> None:
    findings, _, _ = repos
    lookup = _FakeLookup([_cve()])
    asyncio.run(_worker(repos, [_host(MAC, ports=(22,))], lookup, now=1000.0).tick())
    # Ports geaendert -> Fall 2 faellig; gleiche CVE wieder gefunden, spaeterer now.
    asyncio.run(_worker(repos, [_host(MAC, ports=(22, 80))], lookup, now=5000.0).tick())
    rows = findings.list_all()
    assert len(rows) == 1
    assert rows[0].first_seen_ts == 1000.0  # bewahrt
    assert rows[0].last_seen_ts == 5000.0  # frisch


# ── Worker: NVD down -> ehrlich, Pruefstand NICHT fortgeschrieben, Loop lebt ──


def test_tick_lookup_fehler_killt_loop_nicht(repos: Repos) -> None:
    findings, checkstate, _ = repos
    lookup = _FakeLookup([], fail=True)
    asyncio.run(_worker(repos, [_host()], lookup).tick())  # wirft NICHT
    assert findings.list_all() == []  # kein erfundener Befund
    assert checkstate.get(MAC) is None  # Host bleibt faellig


# ── GetActiveFindings: ack-Filter + is_new ────────────────────────────────────


def _seed(
    findings: SqliteCveFindingRepository,
    cve_id: str,
    port: int,
    first: float,
    severity: str = "HIGH",
) -> None:
    findings.upsert(
        CveFindingRecord(
            mac=MAC,
            cve_id=cve_id,
            port=port,
            severity=severity,
            cvss_score=7.0,
            description="",
            url="",
            published="",
            first_seen_ts=first,
            last_seen_ts=first,
        )
    )


def test_active_findings_filtert_quittierte(repos: Repos) -> None:
    findings, _, acks = repos
    _seed(findings, "CVE-1", 22, first=999.0)
    _seed(findings, "CVE-2", 22, first=0.0, severity="LOW")
    acks.record(MAC, "CVE-1", 22, "ack")
    active = GetActiveFindings(findings, acks, now_provider=_at(1000.0))()
    assert {f.cve_id for f in active} == {"CVE-2"}


def test_active_findings_is_new_flag(repos: Repos) -> None:
    findings, _, acks = repos
    now = 1000.0 + 25 * HOUR
    _seed(findings, "CVE-OLD", 22, first=1000.0)  # vor >24h -> nicht neu
    _seed(findings, "CVE-NEW", 80, first=1000.0 + 24 * HOUR)  # vor 1h -> neu
    by_id = {f.cve_id: f for f in GetActiveFindings(findings, acks, now_provider=_at(now))()}
    assert by_id["CVE-OLD"].is_new is False
    assert by_id["CVE-NEW"].is_new is True


# ── GetCveMonitorStatus ───────────────────────────────────────────────────────


def test_status_zahlen(repos: Repos) -> None:
    findings, checkstate, acks = repos
    inventory = _FakeInventory([_host(MAC), _host(MAC2)])
    checkstate.record(MAC, frozenset({22}), 1000.0)  # MAC geprueft, MAC2 neu
    status = GetCveMonitorStatus(
        inventory,
        checkstate,
        findings,
        acks,
        refresh_interval_provider=_at(24 * HOUR),
        now_provider=_at(1000.0),
    )()
    assert status.hosts_total == 2
    assert status.hosts_due == 1  # nur MAC2 faellig
    assert status.hosts_checked == 1
