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


# ── Netzgroessen-Obergrenze auf dem GEPLANTEN Weg (S88-P2, Aufgabe 3) ─────────


def test_geplanter_scan_wird_von_der_netzgroessen_schranke_abgewiesen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """3.1: Die Schranke sitzt in ScanConfig und greift damit AUCH hier.

    Belegt statt behauptet: der geplante Scan baut seine ``ScanConfig`` in app.py
    selbst (``ScanConfig(cidrs=(cidr,))``). Eine Pruefung allein in ws_scan.py waere
    hier umgangen -- diese sitzt in der Domaene und greift auf beiden Wegen. Der
    Use-Case wird folglich NIE aufgerufen: die Config kommt gar nicht erst zustande.
    """
    fake_scan = _FakeRunScan([_enriched("10.0.0.1", "AA:BB:CC:00:00:01")])
    monkeypatch.setattr(
        app_module,
        "_scheduled_scan_bausteine",
        lambda: (fake_scan, lambda s: None, lambda m: None),
    )

    asyncio.run(app_module._scheduled_scan("10.0.0.0/8", "standard", 1))

    # Der Scan lief NICHT an -- die Config-Konstruktion warf davor.
    assert fake_scan.configs == []


def test_geplanter_scan_meldet_das_zu_grosse_netz_NUR_ins_protokoll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """3.2 (Messung, KEINE Behebung): der Fehler erreicht NIEMANDEN ausser dem Log.

    Gemessen, nicht vermutet: ``_scheduled_scan`` faengt in app.py jede Exception und
    loggt sie als ``scheduled_scan_failed`` -- best-effort, damit ein geplanter Lauf
    den Scheduler nicht reisst. Fuer die Netzgroessen-Schranke heisst das: der Anwender
    erfaehrt NICHTS. Es gibt auf diesem Weg keinen Nutzerkanal (kein WS-Frame, keine
    Benachrichtigung, kein Zustandsfeld am Schedule).

    Das ist der GEMESSENE Ist-Zustand, nicht der Sollzustand. Ihn zu beheben waere ein
    eigener Auftrag (ein Nutzerkanal fuer gescheiterte geplante Scans) und ist hier
    ausdruecklich NICHT geschehen. Dieser Test haelt den Ist-Zustand fest, damit die
    Luecke sichtbar bleibt und eine spaetere Behebung ihn bewusst umschreiben muss.
    """
    logged: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(
        app_module.logger, "warning", lambda event, **kw: logged.append((event, kw))
    )
    monkeypatch.setattr(
        app_module,
        "_scheduled_scan_bausteine",
        lambda: (_FakeRunScan([]), lambda s: None, lambda m: None),
    )

    # Kein Wurf nach aussen: der Scheduler laeuft weiter.
    asyncio.run(app_module._scheduled_scan("10.0.0.0/8", "standard", 1))

    # Der EINZIGE Empfaenger ist das Protokoll.
    treffer = [kw for name, kw in logged if name == "scheduled_scan_failed"]
    assert len(treffer) == 1
    # Der Log-Eintrag traegt den Entwicklertext der Domaene -- er ist damit
    # diagnostizierbar, aber eben nur fuer den, der ins Protokoll sieht.
    assert "Network too large" in treffer[0]["error"]
    assert treffer[0]["cidr"] == "10.0.0.0/8"


# ── S88-P4: der geplante Scan meldet seinen Ausgang ──────────────────────────
# Vor S88-P4 endete ein gescheiterter geplanter Scan in ``scheduled_scan_failed`` im
# Log -- ohne jeden Nutzerkanal. Und weil ``last_run`` VOR dem Scan und AUSSERHALB des
# try gebucht wird, war die Zeile danach von der eines geglueckten Laufs nicht zu
# unterscheiden. Diese Tests fahren gegen die ECHTE Modul-Naht
# ``app._scheduled_scan_ergebnisbuchung``, nicht gegen eine Nachbildung.


class _BuchendesErgebnis:
    """Nimmt die Ergebnisbuchungen entgegen (Stelle des echten RecordScheduleResult)."""

    def __init__(self) -> None:
        self.buchungen: list[tuple[str, int, str | None]] = []

    def erfolg(self, schedule_id: int) -> None:
        self.buchungen.append(("ok", schedule_id, None))

    def fehlschlag(self, schedule_id: int, error: str) -> None:
        self.buchungen.append(("failed", schedule_id, error))


def test_geglueckter_scan_bucht_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    buchung = _BuchendesErgebnis()
    monkeypatch.setattr(app_module, "_scheduled_scan_ergebnisbuchung", lambda: buchung)
    monkeypatch.setattr(
        app_module,
        "_scheduled_scan_bausteine",
        lambda: (
            _FakeRunScan([_enriched("10.0.0.1", "AA:BB:CC:00:00:01")]),
            lambda s: None,
            lambda m: None,
        ),
    )

    asyncio.run(app_module._scheduled_scan("192.168.1.0/24", "standard", 7))

    assert buchung.buchungen == [("ok", 7, None)]


def test_gescheiterter_scan_bucht_failed_mit_wortlaut(monkeypatch: pytest.MonkeyPatch) -> None:
    class _KaputterScan:
        async def run(self, config: Any) -> Any:
            raise RuntimeError("nmap nicht gefunden")
            yield  # pragma: no cover -- macht die Methode zum Async-Generator

    buchung = _BuchendesErgebnis()
    monkeypatch.setattr(app_module, "_scheduled_scan_ergebnisbuchung", lambda: buchung)
    monkeypatch.setattr(
        app_module,
        "_scheduled_scan_bausteine",
        lambda: (_KaputterScan(), lambda s: None, lambda m: None),
    )

    asyncio.run(app_module._scheduled_scan("192.168.1.0/24", "standard", 7))

    assert buchung.buchungen == [("failed", 7, "nmap nicht gefunden")]


def test_beide_ausgaenge_sind_unterscheidbar(monkeypatch: pytest.MonkeyPatch) -> None:
    """4.5: derselbe Zeitplan, zwei Laeufe -- der Ausgang unterscheidet sie."""

    class _ZweiterLaufKaputt:
        def __init__(self) -> None:
            self.laeufe = 0

        async def run(self, config: Any) -> Any:
            self.laeufe += 1
            if self.laeufe == 2:
                raise RuntimeError("Netz nicht erreichbar")
            yield ScanCompleted(total_found=0)

    scan = _ZweiterLaufKaputt()
    buchung = _BuchendesErgebnis()
    monkeypatch.setattr(app_module, "_scheduled_scan_ergebnisbuchung", lambda: buchung)
    monkeypatch.setattr(
        app_module,
        "_scheduled_scan_bausteine",
        lambda: (scan, lambda s: None, lambda m: None),
    )

    asyncio.run(app_module._scheduled_scan("192.168.1.0/24", "standard", 7))
    asyncio.run(app_module._scheduled_scan("192.168.1.0/24", "standard", 7))

    assert buchung.buchungen == [
        ("ok", 7, None),
        ("failed", 7, "Netz nicht erreichbar"),
    ]


def test_unverdrahteter_scan_bucht_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein Lauf, der wegen fehlender Verdrahtung nicht stattfand, ist ein Fehlschlag --
    ohne diese Buchung saehe die Zeile aus wie ein geglueckter Lauf."""
    buchung = _BuchendesErgebnis()
    monkeypatch.setattr(app_module, "_scheduled_scan_ergebnisbuchung", lambda: buchung)
    monkeypatch.setattr(app_module, "_scheduled_scan_bausteine", None)

    asyncio.run(app_module._scheduled_scan("192.168.1.0/24", "standard", 7))

    assert buchung.buchungen == [("failed", 7, "scheduled_scan_unverdrahtet")]


def test_ohne_verdrahtete_buchungsnaht_kein_wurf(monkeypatch: pytest.MonkeyPatch) -> None:
    """Vor create_app ist die Naht None -- der Scan laeuft trotzdem durch (best-effort)."""
    monkeypatch.setattr(app_module, "_scheduled_scan_ergebnisbuchung", None)
    monkeypatch.setattr(
        app_module,
        "_scheduled_scan_bausteine",
        lambda: (_FakeRunScan([]), lambda s: None, lambda m: None),
    )

    asyncio.run(app_module._scheduled_scan("192.168.1.0/24", "standard", 7))
