"""Beweis: der geplante Scan (app._scheduled_scan) nimmt den migrierten Pfad (E1).

Vor E1 lief _scheduled_scan an RunNetworkScan vorbei (discover_subnet + save_scan,
ohne Enrich/devices-Projektion). Diese Tests halten den neuen Vertrag fest:

* _scheduled_scan baut die Bausteine ueber die gebundene Fabrik-Naht
  (_scheduled_scan_bausteine), iteriert den Use-Case-Eventstrom und loest pro
  HostEnriched BEIDE Nachbearbeitungen aus (devices-Projektion via record_host,
  analysis-Host-Historie via record_seen) -- in dieser Reihenfolge.
* Ein Fehler im Scan reisst den Scheduler NICHT (kein Wurf, nur Log).
* Ohne gebundene Naht (vor create_app) ist der Aufruf ein lauter No-Op.

Fakes statt echter Adapter (Muster test_app_bootstrap: monkeypatch am app-Modul).
Der Fake-Use-Case liefert einen minimalen Eventstrom mit zwei HostEnriched.
"""

import asyncio
from typing import Any

import pytest

import app as app_module
from domain.scanning import (
    EnrichedHost,
    HostEnriched,
    ScanCompleted,
    ScanStarted,
)


def _enriched(ip: str, mac: str) -> EnrichedHost:
    return EnrichedHost(ip=ip, mac=mac, vendor="", rtt_ms=None, hostname="")


class _FakeRunScan:
    """Fake-RunNetworkScan: fester Eventstrom, merkt sich die Config."""

    def __init__(self, hosts: list[EnrichedHost]) -> None:
        self._hosts = hosts
        self.configs: list[Any] = []

    async def run(self, config: Any) -> Any:
        self.configs.append(config)
        yield ScanStarted(cidr=",".join(config.cidrs), total_hosts=0)
        for host in self._hosts:
            yield HostEnriched(host=host)
        yield ScanCompleted(total_found=len(self._hosts))


def test_scheduled_scan_nutzt_use_case_und_beide_nachbearbeitungen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hosts = [_enriched("10.0.0.1", "AA:BB:CC:00:00:01"), _enriched("10.0.0.2", "AA:BB:CC:00:00:02")]
    fake_scan = _FakeRunScan(hosts)
    aufrufe: list[tuple[str, str]] = []

    def record_host(scanned: Any) -> None:
        aufrufe.append(("host", scanned.mac))

    def record_seen(mac: str) -> None:
        aufrufe.append(("seen", mac))

    monkeypatch.setattr(
        app_module,
        "_scheduled_scan_bausteine",
        lambda: (fake_scan, record_host, record_seen),
    )

    asyncio.run(app_module._scheduled_scan("192.168.1.0/24", "standard", 1))

    # Der Use-Case wurde mit dem geplanten CIDR gefahren (Defaults der ScanConfig).
    assert len(fake_scan.configs) == 1
    assert fake_scan.configs[0].cidrs == ("192.168.1.0/24",)
    # Pro HostEnriched BEIDE Nachbearbeitungen, Reihenfolge wie ws_scan.py
    # (erst devices-Projektion, dann Host-Historie).
    assert aufrufe == [
        ("host", "AA:BB:CC:00:00:01"),
        ("seen", "AA:BB:CC:00:00:01"),
        ("host", "AA:BB:CC:00:00:02"),
        ("seen", "AA:BB:CC:00:00:02"),
    ]


def test_scheduled_scan_fehler_reisst_scheduler_nicht(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _KaputterScan:
        async def run(self, config: Any) -> Any:
            raise RuntimeError("kaputt")
            yield  # pragma: no cover -- macht die Methode zum Async-Generator

    monkeypatch.setattr(
        app_module,
        "_scheduled_scan_bausteine",
        lambda: (_KaputterScan(), lambda s: None, lambda m: None),
    )
    # Darf NICHT werfen (best-effort: Fehler wird geloggt, Scheduler laeuft weiter).
    asyncio.run(app_module._scheduled_scan("192.168.1.0/24", "standard", 1))


def test_scheduled_scan_ohne_naht_ist_lauter_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(app_module, "_scheduled_scan_bausteine", None)
    # Kein Wurf; der Fall wird als Verdrahtungsfehler geloggt.
    asyncio.run(app_module._scheduled_scan("192.168.1.0/24", "standard", 1))


# ── Scan-Ende weckt den CVE-Worker (S86-A4/B1) ────────────────────────────────


def test_scheduled_scan_weckt_den_cve_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    """TEST 9: auch der GEPLANTE Scan stoesst den Worker an -- ueber den verdrahteten Weg.

    Gegen die echte Modul-Naht ``app._cve_monitor_wecken`` (die app.py im Lifespan auf
    ``RunCveMonitor.wake`` bindet), nicht gegen eine Nachbildung. Wer nur ws_scan.py
    anfasst, laesst genau diesen Weg aussen vor.
    """
    hosts = [_enriched("10.0.0.1", "AA:BB:CC:00:00:01")]
    monkeypatch.setattr(
        app_module,
        "_scheduled_scan_bausteine",
        lambda: (_FakeRunScan(hosts), lambda s: None, lambda m: None),
    )
    geweckt: list[int] = []
    monkeypatch.setattr(app_module, "_cve_monitor_wecken", lambda: geweckt.append(1))

    asyncio.run(app_module._scheduled_scan("192.168.1.0/24", "standard", 1))

    assert geweckt == [1]  # genau EIN Weckruf, am Scan-Ende


def test_scheduled_scan_ohne_weck_naht_laeuft_durch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nicht verdrahtete Weck-Naht (vor create_app/ohne bootstrap): kein Wurf, kein Wecken."""
    hosts = [_enriched("10.0.0.1", "AA:BB:CC:00:00:01")]
    aufrufe: list[tuple[str, str]] = []
    monkeypatch.setattr(
        app_module,
        "_scheduled_scan_bausteine",
        lambda: (
            _FakeRunScan(hosts),
            lambda s: aufrufe.append(("host", s.mac)),
            lambda m: None,
        ),
    )
    monkeypatch.setattr(app_module, "_cve_monitor_wecken", None)

    asyncio.run(app_module._scheduled_scan("192.168.1.0/24", "standard", 1))

    assert aufrufe == [("host", "AA:BB:CC:00:00:01")]  # Scan lief vollstaendig


def test_scheduled_scan_weck_fehler_reisst_den_scan_nicht(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TEST 10 (geplanter Weg): eine werfende Weck-Naht laesst den Scan unversehrt.

    Wichtig: der Weckruf liegt INNERHALB des scan-eigenen try/except. Ohne das eigene
    best-effort-Fangen wuerde der Fehler dort als "scheduled_scan_failed" landen -- der
    Scan waere abgebrochen statt durchgelaufen. Darum wird hier geprueft, dass die
    Nachbearbeitung des LETZTEN Hosts vollstaendig ist und der Fehler als Weck-Fehler
    (nicht als Scan-Fehler) geloggt wurde.
    """
    logged: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(
        app_module.logger, "warning", lambda event, **kw: logged.append((event, kw))
    )
    hosts = [_enriched("10.0.0.1", "AA:BB:CC:00:00:01")]
    aufrufe: list[tuple[str, str]] = []
    monkeypatch.setattr(
        app_module,
        "_scheduled_scan_bausteine",
        lambda: (
            _FakeRunScan(hosts),
            lambda s: aufrufe.append(("host", s.mac)),
            lambda m: aufrufe.append(("seen", m)),
        ),
    )

    def kaputt() -> None:
        raise RuntimeError("worker weg")

    monkeypatch.setattr(app_module, "_cve_monitor_wecken", kaputt)

    asyncio.run(app_module._scheduled_scan("192.168.1.0/24", "standard", 1))

    # Der Scan ist vollstaendig durchgelaufen (beide Nachbearbeitungen liefen).
    assert aufrufe == [("host", "AA:BB:CC:00:00:01"), ("seen", "AA:BB:CC:00:00:01")]
    # Geloggt als WECK-Fehler, NICHT als scheduled_scan_failed.
    marker = [name for name, _ in logged]
    assert "cve_monitor_wecken_fehlgeschlagen" in marker
    assert "scheduled_scan_failed" not in marker
