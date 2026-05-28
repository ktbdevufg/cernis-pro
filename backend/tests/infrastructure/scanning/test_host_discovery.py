"""Tests fuer ``HostDiscoveryAdapter`` -- gemockte ``modules.discovery``.

Getestet wird die Variante-A-Schleife OHNE echtes Netz: ``ping_host`` (async) und
``get_arp_table`` (sync) werden AM IMPORT-ORT IM ADAPTER-MODUL gemockt (nicht in
``modules.discovery``), wie in S.4a.

Verhaltenstreue-Schwerpunkte:
* Tick-Semantik: ``completed`` zaehlt ALLE abgearbeiteten Hosts (auch tote),
  ``total`` = alle Adressen des CIDR.
* ``DiscoveryHostFound`` nur fuer lebende Hosts, MIT der ARP-MAC -- und ERST nach
  allen Ticks (ARP-Zuordnung passiert nach der Ping-Schleife).
* ``rtt_ms``-Sentinel ``-1.0`` (modules) -> ``None`` (domain).
* Edge: /32 -> die stdlib liefert GENAU 1 Host (die Adresse selbst), /31 ->
  2 Hosts (RFC 3021 P2P). Also je 1 bzw. 2 Ticks; Funde nur, wenn der Host lebt.

Async-Smokes via ``asyncio.run`` (kein ``pytest-asyncio``, wie S.3/S.4a).
"""

import asyncio

import pytest

from domain.scanning import DiscoveredHost, DiscoveryEvent, DiscoveryHostFound, DiscoveryTick
from infrastructure.scanning import host_discovery
from infrastructure.scanning.host_discovery import HostDiscoveryAdapter
from modules.discovery import DiscoveredHost as RawHost
from ports.scanning import HostDiscoveryPort


def _collect(cidr: str, timeout: float = 1.0, max_concurrent: int = 8) -> list[DiscoveryEvent]:
    """Treibt den async-Generator vollstaendig und sammelt alle Events."""
    adapter = HostDiscoveryAdapter()

    async def _run() -> list[DiscoveryEvent]:
        return [ev async for ev in adapter.discover(cidr, timeout, max_concurrent)]

    return asyncio.run(_run())


def _patch(
    monkeypatch: pytest.MonkeyPatch,
    *,
    alive: set[str],
    arp: dict[str, str],
    rtt: float = 5.0,
) -> None:
    """Mockt ping_host (async) + get_arp_table (sync) am Adapter-Import-Ort."""

    async def fake_ping(ip: str, timeout: float) -> RawHost:
        is_alive = ip in alive
        return RawHost(ip=ip, is_alive=is_alive, rtt_ms=rtt if is_alive else -1.0)

    monkeypatch.setattr(host_discovery, "ping_host", fake_ping)
    monkeypatch.setattr(host_discovery, "get_arp_table", lambda: arp)


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_host_discovery_protocol() -> None:
    _: HostDiscoveryPort = HostDiscoveryAdapter()


# ── Tick-Semantik ────────────────────────────────────────────────────────────


def test_ticks_count_all_hosts_alive_and_dead(monkeypatch: pytest.MonkeyPatch) -> None:
    # /29 -> 6 nutzbare Hosts (.1 .. .6). Nur zwei leben.
    _patch(monkeypatch, alive={"10.0.0.1", "10.0.0.3"}, arp={})
    events = _collect("10.0.0.0/29")

    ticks = [e for e in events if isinstance(e, DiscoveryTick)]
    assert len(ticks) == 6  # ALLE Hosts geticked (auch tote)
    assert all(t.total == 6 for t in ticks)
    # completed laeuft 1..6 vollstaendig durch (Reihenfolge egal, Menge zaehlt)
    assert sorted(t.completed for t in ticks) == [1, 2, 3, 4, 5, 6]


def test_found_only_for_alive_and_after_all_ticks(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, alive={"10.0.0.1", "10.0.0.3"}, arp={})
    events = _collect("10.0.0.0/29")

    found = [e for e in events if isinstance(e, DiscoveryHostFound)]
    assert len(found) == 2  # nur die zwei lebenden
    assert {f.host.ip for f in found} == {"10.0.0.1", "10.0.0.3"}

    # ALLE Funde kommen NACH allen Ticks (ARP-Phase ist nach der Ping-Schleife).
    last_tick = max(i for i, e in enumerate(events) if isinstance(e, DiscoveryTick))
    first_found = min(i for i, e in enumerate(events) if isinstance(e, DiscoveryHostFound))
    assert first_found > last_tick


# ── ARP-MAC-Zuordnung ────────────────────────────────────────────────────────


def test_arp_mac_assigned_after_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        alive={"10.0.0.1", "10.0.0.2"},
        arp={"10.0.0.1": "aa:bb:cc:dd:ee:01"},  # nur .1 in ARP
    )
    found = {
        f.host.ip: f.host for f in _collect("10.0.0.0/29") if isinstance(f, DiscoveryHostFound)
    }
    assert found["10.0.0.1"].mac == "aa:bb:cc:dd:ee:01"
    assert found["10.0.0.2"].mac == ""  # nicht in ARP -> leer, keine MAC vorgetaeuscht


def test_rtt_sentinel_becomes_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # Lebender Host mit Sentinel-RTT -1.0 -> domain rtt_ms None.
    async def fake_ping(ip: str, timeout: float) -> RawHost:
        return RawHost(ip=ip, is_alive=(ip == "10.0.0.1"), rtt_ms=-1.0)

    monkeypatch.setattr(host_discovery, "ping_host", fake_ping)
    monkeypatch.setattr(host_discovery, "get_arp_table", lambda: {})
    found = [f for f in _collect("10.0.0.0/29") if isinstance(f, DiscoveryHostFound)]
    assert len(found) == 1
    assert found[0].host.rtt_ms is None


def test_real_rtt_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, alive={"10.0.0.1"}, arp={}, rtt=12.5)
    found = [f for f in _collect("10.0.0.0/29") if isinstance(f, DiscoveryHostFound)]
    assert found[0].host.rtt_ms == 12.5
    assert isinstance(found[0].host, DiscoveredHost)


# ── Edge-Faelle ──────────────────────────────────────────────────────────────


def test_slash32_single_host(monkeypatch: pytest.MonkeyPatch) -> None:
    # /32 -> stdlib liefert GENAU 1 Host (die Adresse selbst): 1 Tick.
    _patch(monkeypatch, alive={"10.0.0.5"}, arp={"10.0.0.5": "aa:bb:cc:dd:ee:05"})
    events = _collect("10.0.0.5/32")

    ticks = [e for e in events if isinstance(e, DiscoveryTick)]
    found = [e for e in events if isinstance(e, DiscoveryHostFound)]
    assert [t.completed for t in ticks] == [1]
    assert ticks[0].total == 1
    assert len(found) == 1
    assert found[0].host.ip == "10.0.0.5"
    assert found[0].host.mac == "aa:bb:cc:dd:ee:05"


def test_slash31_two_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    # /31 -> RFC 3021 P2P: stdlib liefert BEIDE Adressen -> 2 Ticks.
    _patch(monkeypatch, alive=set(), arp={})
    events = _collect("10.0.0.0/31")

    ticks = [e for e in events if isinstance(e, DiscoveryTick)]
    assert len(ticks) == 2
    assert all(t.total == 2 for t in ticks)
    assert not [e for e in events if isinstance(e, DiscoveryHostFound)]  # keiner lebt


def test_no_alive_hosts_only_ticks(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, alive=set(), arp={"10.0.0.1": "aa:bb:cc:dd:ee:01"})
    events = _collect("10.0.0.0/29")
    assert all(isinstance(e, DiscoveryTick) for e in events)
    assert len(events) == 6  # nur Ticks, keine Funde trotz ARP-Eintrag
