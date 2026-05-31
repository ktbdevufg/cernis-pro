"""Tests fuer ``Ipv6EnrichmentAdapter`` -- gemockte ``modules.ipv6.enrich_with_ipv6``.

``enrich_with_ipv6`` wird AM IMPORT-ORT IM ADAPTER-MODUL gemockt (nicht in
``modules.ipv6``), wie in S.4a-d. Der Mock arbeitet dict-basiert (wie der Altcode):
er reichert die uebergebenen dicts in-place um ``ipv6``/``ipv6_all`` an.

Schwerpunkte:
* Port-Konformitaet.
* Mapping BEIDE Richtungen: ``EnrichedHost`` -> dict -> ``enrich`` -> ``EnrichedHost``
  mit befuellten ``ipv6``/``ipv6_all``, ALLE anderen Felder unveraendert.
* ``ipv6_all`` (Liste aus modules) -> ``tuple`` (frozen-tauglich).
* SYNCHRONER Aufruf laeuft im Executor (nicht im Loop-Thread).
* Edge: leere Eingabe -> leere Ausgabe; Host ohne MAC-Match bleibt ohne IPv6.

Async-Smokes via ``asyncio.run`` (kein ``pytest-asyncio``, wie S.4a-d).
"""

import asyncio
import threading
from typing import Any

import pytest

from domain.scanning import EnrichedHost, PortInfo
from infrastructure.scanning import ipv6_enrichment
from infrastructure.scanning.ipv6_enrichment import Ipv6EnrichmentAdapter
from ports.scanning import Ipv6EnrichmentPort

# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_ipv6_protocol() -> None:
    _: Ipv6EnrichmentPort = Ipv6EnrichmentAdapter()


# ── Mapping beide Richtungen ────────────────────────────────────────────────


def test_enrich_fills_ipv6_and_preserves_other_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    # Mock wie der Altcode: reichert dicts in-place an (nur die mit passender MAC).
    def fake_enrich(hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for h in hosts:
            if h.get("mac") == "AA:BB:CC:DD:EE:01":
                h["ipv6"] = "2001:db8::5"
                h["ipv6_all"] = ["2001:db8::5", "fe80::1"]  # Liste (wie modules)
        return hosts

    monkeypatch.setattr(ipv6_enrichment, "enrich_with_ipv6", fake_enrich)

    host = EnrichedHost(
        ip="10.0.0.5",
        mac="AA:BB:CC:DD:EE:01",
        vendor="Acme",
        rtt_ms=1.5,
        hostname="nas.local",
        ports=(PortInfo(port=22, state="open", service="ssh"),),
        tags=("prod",),
        category="nas",
    )
    result = asyncio.run(Ipv6EnrichmentAdapter().enrich([host]))

    assert len(result) == 1
    got = result[0]
    # IPv6 befuellt, ipv6_all als tuple:
    assert got.ipv6 == "2001:db8::5"
    assert got.ipv6_all == ("2001:db8::5", "fe80::1")
    assert isinstance(got.ipv6_all, tuple)
    # ALLE anderen Felder unveraendert -- Vergleich gegen den Host MIT IPv6:
    assert got == EnrichedHost(
        ip="10.0.0.5",
        mac="AA:BB:CC:DD:EE:01",
        vendor="Acme",
        rtt_ms=1.5,
        hostname="nas.local",
        ipv6="2001:db8::5",
        ipv6_all=("2001:db8::5", "fe80::1"),
        ports=(PortInfo(port=22, state="open", service="ssh"),),
        tags=("prod",),
        category="nas",
    )


def test_host_without_match_stays_without_ipv6(monkeypatch: pytest.MonkeyPatch) -> None:
    # Kein MAC-Match -> der Altcode setzt KEINE ipv6-Keys.
    def fake_enrich(hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return hosts  # nichts angereichert

    monkeypatch.setattr(ipv6_enrichment, "enrich_with_ipv6", fake_enrich)

    host = EnrichedHost(ip="10.0.0.9", mac="ZZ:ZZ:ZZ:ZZ:ZZ:ZZ")
    result = asyncio.run(Ipv6EnrichmentAdapter().enrich([host]))
    assert result[0].ipv6 == ""  # Default, kein KeyError
    assert result[0].ipv6_all == ()


def test_preserves_order_and_count(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ipv6_enrichment, "enrich_with_ipv6", lambda hosts: hosts)
    hosts = [
        EnrichedHost(ip="10.0.0.1", mac="AA:00:00:00:00:01"),
        EnrichedHost(ip="10.0.0.2", mac="AA:00:00:00:00:02"),
        EnrichedHost(ip="10.0.0.3", mac="AA:00:00:00:00:03"),
    ]
    result = asyncio.run(Ipv6EnrichmentAdapter().enrich(hosts))
    assert [h.ip for h in result] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_runs_in_executor_not_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    call_thread: dict[str, int] = {}

    def fake_enrich(hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        call_thread["tid"] = threading.get_ident()
        return hosts

    monkeypatch.setattr(ipv6_enrichment, "enrich_with_ipv6", fake_enrich)

    async def _run() -> None:
        loop_tid = threading.get_ident()
        await Ipv6EnrichmentAdapter().enrich([EnrichedHost(ip="10.0.0.1", mac="AA:00:00:00:00:01")])
        assert call_thread["tid"] != loop_tid  # im Executor, nicht im Loop

    asyncio.run(_run())


def test_empty_input_empty_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ipv6_enrichment, "enrich_with_ipv6", lambda hosts: hosts)
    assert asyncio.run(Ipv6EnrichmentAdapter().enrich([])) == []
