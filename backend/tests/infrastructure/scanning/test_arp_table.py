"""Tests fuer ``ArpTableAdapter`` -- gemockte ``modules.discovery.get_arp_table``.

Getestet wird der duenne Executor-Wrapper OHNE echtes Netz: ``get_arp_table``
(sync) wird AM IMPORT-ORT IM ADAPTER-MODUL gemockt (nicht in
``modules.discovery``), wie in S.4a/S.4b.

Schwerpunkte:
* Feld-/Form-Treue: die Roh-Tabelle ``{ip: mac}`` kommt unveraendert durch.
* Edge: leere Tabelle -> ``{}`` (vertraglicher Leer-Zustand, kein Fehler).
* ``run_in_executor``-Beweis: die blockierende Funktion laeuft NICHT im
  Event-Loop-Thread (Thread-Identitaet ungleich Loop-Thread).

Async-Smokes via ``asyncio.run`` (kein ``pytest-asyncio``, wie S.3/S.4a).
"""

import asyncio
import threading

import pytest

from infrastructure.scanning import arp_table
from infrastructure.scanning.arp_table import ArpTableAdapter
from ports.scanning import ArpTablePort

# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_arp_table_protocol() -> None:
    adapter: ArpTablePort = ArpTableAdapter()
    assert adapter is not None


# ── Feld-/Form-Treue ──────────────────────────────────────────────────────


def test_returns_raw_ip_mac_map(monkeypatch: pytest.MonkeyPatch) -> None:
    table = {"192.168.1.2": "aa:bb:cc:dd:ee:01", "192.168.1.3": "aa:bb:cc:dd:ee:02"}
    monkeypatch.setattr(arp_table, "get_arp_table", lambda: table)

    result = asyncio.run(ArpTableAdapter().get_arp_table())

    assert result == table


def test_empty_table_returns_empty_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    # Leerer/nicht lesbarer ARP-Cache -> {} (kein Fehler, kein None).
    monkeypatch.setattr(arp_table, "get_arp_table", dict)

    assert asyncio.run(ArpTableAdapter().get_arp_table()) == {}


# ── run_in_executor-Beweis ────────────────────────────────────────────────


def test_runs_blocking_call_off_the_loop_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    """``get_arp_table`` (blockierend) darf nicht im Event-Loop-Thread laufen."""
    threads: dict[str, int] = {}

    def fake_get_arp_table() -> dict[str, str]:
        threads["worker"] = threading.get_ident()
        return {}

    monkeypatch.setattr(arp_table, "get_arp_table", fake_get_arp_table)

    async def _run() -> None:
        threads["loop"] = threading.get_ident()
        await ArpTableAdapter().get_arp_table()

    asyncio.run(_run())

    assert threads["worker"] != threads["loop"]
