"""Strukturtest der cve-Ports (ADR 0037): Fakes/Adapter erfuellen die Protocols.

Muster ``test_analysis_ports.py``:
* **statisch (mypy):** ``_assert_*``-Funktionen binden die Instanz an den Port-TYP;
  eine falsche Signatur schlaegt ``uv run mypy`` fehl -- das ist die eigentliche Pruefung.
* **dynamisch (pytest):** Smoke ueber die echten SQLite-Adapter (Persistenz-Ports) und
  asyncio fuer den async Lookup-Provider.

KEIN ``@runtime_checkable`` -> kein isinstance-Check; die Konformitaet traegt mypy.
"""

import asyncio
from collections.abc import Sequence
from pathlib import Path

from domain.cve.models import HostCheckState
from infrastructure.cve_acknowledgements_db import SqliteCveAcknowledgementRepository
from infrastructure.cve_checkstate_db import SqliteCveCheckStateRepository
from infrastructure.cve_findings_db import SqliteCveFindingRepository
from ports.cve import (
    CveAcknowledgementRepository,
    CveCheckStateRepository,
    CveFindingRepository,
    CveLookupProvider,
    HostInventoryProvider,
    InventoryHost,
    InventoryPort,
    LookupCve,
)

# ── Fakes fuer die Provider-Ports (keine echten Quellen im Test) ────────────


class _FakeInventory:
    def list_hosts(self) -> list[InventoryHost]:
        return [InventoryHost(mac="aa", ip="1.2.3.4", ports=(InventoryPort(22, "ssh"),))]


class _FakeLookup:
    async def lookup(self, ports: Sequence[InventoryPort]) -> list[LookupCve]:
        return [
            LookupCve(
                cve_id="CVE-2024-0001",
                description="d",
                severity="HIGH",
                cvss_score=7.5,
                published="2024-01-01",
                port=ports[0].port if ports else 0,
            )
        ]


# ── Statische Konformitaet (mypy) ───────────────────────────────────────────


def _assert_finding_repo(_: CveFindingRepository) -> None: ...
def _assert_checkstate_repo(_: CveCheckStateRepository) -> None: ...
def _assert_ack_repo(_: CveAcknowledgementRepository) -> None: ...
def _assert_inventory(_: HostInventoryProvider) -> None: ...
def _assert_lookup(_: CveLookupProvider) -> None: ...


# ── Dynamischer Smoke ───────────────────────────────────────────────────────


def test_adapter_erfuellen_persistenz_ports(tmp_path: Path) -> None:
    findings = SqliteCveFindingRepository(tmp_path / "f.db")
    checkstate = SqliteCveCheckStateRepository(tmp_path / "c.db")
    acks = SqliteCveAcknowledgementRepository(tmp_path / "a.db")
    _assert_finding_repo(findings)
    _assert_checkstate_repo(checkstate)
    _assert_ack_repo(acks)
    # Smoke der Lese-Pfade (leere DB -> leere Sammlungen, kein Fehler).
    assert findings.list_all() == []
    assert checkstate.all_states() == []
    assert acks.acknowledged_keys() == set()


def test_fakes_erfuellen_provider_ports() -> None:
    inventory = _FakeInventory()
    lookup = _FakeLookup()
    _assert_inventory(inventory)
    _assert_lookup(lookup)
    hosts = inventory.list_hosts()
    assert hosts[0].mac == "aa"
    found = asyncio.run(lookup.lookup(hosts[0].ports))
    assert found[0].cve_id == "CVE-2024-0001"


def test_host_check_state_ist_frozen() -> None:
    state = HostCheckState(mac="aa", last_checked_ts=1.0, checked_ports=frozenset({22}))
    assert state.checked_ports == frozenset({22})
