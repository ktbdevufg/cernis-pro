"""Tests fuer die cve-Use-Cases (ADR 0037): Drip-Worker + Lese-Use-Cases.

Worker (``RunCveMonitor.tick``): Drosselung (ein Host MIT NVD-Aufruf pro tick),
Faelligkeit (Faelle 1-3 + NOT_DUE), first_seen-Bewahrung beim Re-Check, leerer Bestand
(kein Lookup), strenge Fehlertoleranz (Lookup-Fehler -> Pruefstand NICHT fortgeschrieben,
Bestand unveraendert, Loop ueberlebt). Dazu Befund 56 -- ERSETZEN statt ergaenzen:
weggefallene Befunde verschwinden, gesehene Hosts OHNE offene Ports werden lookup-frei
und ungedrosselt geraeumt, nicht gefuehrte Hosts bleiben unberuehrt, und entfallende
Quittierungen bekommen ein ``unack``. Lese-Use-Cases: ack-Filter + is_new, Status-Zahlen.

Echte SQLite-Adapter (tmp_path) als Repos; Fakes fuer die Provider-Ports. Die Zeit wird
ueber ``now_provider`` deterministisch injiziert (kein monkeypatch noetig).
"""

import asyncio
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from application.cve.use_cases import (
    GetAcknowledgedFindings,
    GetActiveFindings,
    GetCveMonitorStatus,
    RunCveMonitor,
)
from domain.cve.models import CveFindingRecord
from infrastructure.clock import SystemClock
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
    """Liefert je Aufruf konfigurierte CVEs; zaehlt Aufrufe; kann werfen (NVD down).

    ``cves`` ist die Antwort fuer JEDEN Aufruf. ``antworten`` ist die Alternative, wenn
    ein Test eine sich AENDERNDE NVD-Antwort braucht (Befund 56: ein Port faellt weg):
    die Liste wird der Reihe nach abgearbeitet, die letzte Antwort gilt danach weiter.
    """

    def __init__(
        self,
        cves: list[LookupCve],
        fail: bool = False,
        antworten: list[list[LookupCve]] | None = None,
    ) -> None:
        self._cves = cves
        self._fail = fail
        self._antworten = antworten
        self.calls = 0

    async def lookup(self, ports: Sequence[InventoryPort]) -> list[LookupCve]:
        self.calls += 1
        if self._fail:
            raise RuntimeError("NVD down")
        if self._antworten is None:
            return self._cves
        index = min(self.calls - 1, len(self._antworten) - 1)
        return self._antworten[index]


@pytest.fixture
def repos(tmp_path: Path) -> Repos:
    db = tmp_path / "cernis.db"
    return (
        SqliteCveFindingRepository(db),
        SqliteCveCheckStateRepository(db),
        SqliteCveAcknowledgementRepository(db, SystemClock()),
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


def _seed(
    findings: SqliteCveFindingRepository,
    cve_id: str,
    port: int,
    first: float,
    severity: str = "HIGH",
    mac: str = MAC,
) -> None:
    """Legt einen Befund DIREKT im Repo an (Vorbestand, ohne den Worker zu laufen)."""
    findings.upsert(
        CveFindingRecord(
            mac=mac,
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


def _worker(
    repos: Repos,
    hosts: list[InventoryHost],
    lookup: _FakeLookup,
    now: float = 1000.0,
    refresh: float = 24 * HOUR,
) -> RunCveMonitor:
    findings, checkstate, acks = repos
    return RunCveMonitor(
        inventory=_FakeInventory(hosts),
        lookup=lookup,
        findings=findings,
        checkstate=checkstate,
        acknowledgements=acks,
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


def test_tick_gesehener_host_ohne_ports_verliert_befunde_ohne_lookup(repos: Repos) -> None:
    """Befund 56/B3: portloser GESEHENER Host wird abgeglichen, nicht uebersprungen.

    Fruehere Erwartung (bis Befund 56): ``checkstate.get(MAC) is None`` -- der Host wurde
    stillschweigend uebersprungen und behielt seine Befunde fuer immer. Jetzt gilt: keine
    offenen Ports = keine Befunde, und der Pruefstand wird fortgeschrieben.
    """
    findings, checkstate, _ = repos
    _seed(findings, "CVE-ALT", 22, first=500.0)
    lookup = _FakeLookup([_cve()])

    asyncio.run(_worker(repos, [_host(MAC, ports=())], lookup).tick())

    assert lookup.calls == 0  # KEIN NVD-Aufruf -- rein lokaler Abgleich
    assert findings.list_for_host(MAC) == []  # Befunde vollstaendig weg
    state = checkstate.get(MAC)
    assert state is not None
    assert state.checked_ports == frozenset()


def test_portloser_host_ist_im_naechsten_tick_nicht_mehr_faellig(repos: Repos) -> None:
    """Keine Dauerbeschaeftigung: derselbe portlose Host ist danach NOT_DUE.

    Belegt B3: nach dem Fortschreiben des Pruefstands (leeres Port-Set, frischer
    ``last_checked_ts``) liefert ``due_reason`` NOT_DUE -- ein zweiter tick raeumt nicht
    erneut auf und schreibt den Stand nicht erneut fort.
    """
    findings, checkstate, _ = repos
    lookup = _FakeLookup([_cve()])
    worker = _worker(repos, [_host(MAC, ports=())], lookup, now=1000.0)
    asyncio.run(worker.tick())
    erster_stand = checkstate.get(MAC)
    assert erster_stand is not None

    _seed(findings, "CVE-EINGESCHMUGGELT", 22, first=2000.0)  # Sonde: bleibt sie liegen?
    asyncio.run(worker.tick())  # gleicher now, gleiches (leeres) Port-Set -> NOT_DUE

    assert lookup.calls == 0
    # Der zweite tick hat den Host NICHT angefasst -- sonst waere die Sonde weg.
    assert [r.cve_id for r in findings.list_for_host(MAC)] == ["CVE-EINGESCHMUGGELT"]
    zweiter_stand = checkstate.get(MAC)
    assert zweiter_stand is not None
    assert zweiter_stand.last_checked_ts == erster_stand.last_checked_ts


def test_portlose_hosts_sind_nicht_gedrosselt(repos: Repos) -> None:
    """ALLE faelligen portlosen Hosts kommen im SELBEN tick dran (kein Netzverkehr)."""
    findings, checkstate, _ = repos
    _seed(findings, "CVE-1", 22, first=500.0)
    _seed(findings, "CVE-2", 22, first=500.0, mac=MAC2)
    lookup = _FakeLookup([_cve()])

    asyncio.run(_worker(repos, [_host(MAC, ports=()), _host(MAC2, ports=())], lookup).tick())

    assert lookup.calls == 0
    assert findings.list_all() == []  # BEIDE geraeumt, nicht nur der erste
    assert checkstate.get(MAC) is not None
    assert checkstate.get(MAC2) is not None


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


def test_tick_lookup_fehler_laesst_bestehende_befunde_unveraendert(repos: Repos) -> None:
    """Die harte Randbedingung von Befund 56: ein NVD-Ausfall loescht NICHTS.

    Der vorhandene Fehler-Test oben prueft nur die LEERE Datenbank -- er wuerde auch dann
    gruen bleiben, wenn der Worker erst loeschte und dann am Lookup scheiterte. Hier liegt
    ein Vorbestand, und der muss vollstaendig stehen bleiben.
    """
    findings, checkstate, _ = repos
    _seed(findings, "CVE-BESTAND", 22, first=500.0)
    lookup = _FakeLookup([], fail=True)

    asyncio.run(_worker(repos, [_host(MAC, ports=(22,))], lookup).tick())

    rows = findings.list_for_host(MAC)
    assert len(rows) == 1
    assert rows[0].cve_id == "CVE-BESTAND"
    assert rows[0].first_seen_ts == 500.0
    assert checkstate.get(MAC) is None  # Host bleibt faellig


# ── Worker: ERSETZEN statt ergaenzen (Befund 56) ──────────────────────────────


def test_weggefallener_port_verliert_befunde_bleibender_behaelt_first_seen(
    repos: Repos,
) -> None:
    """Kern von Befund 56: Zustandsanzeige, kein Journal.

    Erster tick findet CVEs auf Port 22 UND 80. Beim zweiten tick ist Port 80 zu, NVD
    meldet nur noch Port 22 -- der 80er-Befund MUSS verschwinden, der 22er behaelt sein
    ``first_seen_ts`` (er ist nicht "neu", nur weil der Stand ersetzt wurde).
    """
    findings, _, _ = repos
    lookup = _FakeLookup(
        [],
        antworten=[
            [_cve("CVE-22", port=22), _cve("CVE-80", port=80)],
            [_cve("CVE-22", port=22)],
        ],
    )
    asyncio.run(_worker(repos, [_host(MAC, ports=(22, 80))], lookup, now=1000.0).tick())
    assert {(r.cve_id, r.port) for r in findings.list_for_host(MAC)} == {
        ("CVE-22", 22),
        ("CVE-80", 80),
    }

    # Port 80 zu -> Fall 2 (Ports geaendert) faellig, spaeterer now.
    asyncio.run(_worker(repos, [_host(MAC, ports=(22,))], lookup, now=5000.0).tick())

    rows = findings.list_for_host(MAC)
    assert [(r.cve_id, r.port) for r in rows] == [("CVE-22", 22)]  # 80er weg
    assert rows[0].first_seen_ts == 1000.0  # bewahrt
    assert rows[0].last_seen_ts == 5000.0  # frisch


def test_nicht_gefuehrter_host_behaelt_seine_befunde(repos: Repos) -> None:
    """Nur GESEHENE Geraete werden angefasst -- ein unbekannter Host bleibt unberuehrt."""
    findings, _, _ = repos
    _seed(findings, "CVE-FREMD", 443, first=500.0, mac=MAC2)  # nicht im Bestand
    lookup = _FakeLookup([_cve("CVE-22", port=22)])

    asyncio.run(_worker(repos, [_host(MAC, ports=(22,))], lookup, now=1000.0).tick())

    fremd = findings.list_for_host(MAC2)
    assert len(fremd) == 1
    assert fremd[0].cve_id == "CVE-FREMD"
    assert fremd[0].first_seen_ts == 500.0


def test_doppeltes_lookup_tripel_erzeugt_genau_eine_zeile(repos: Repos) -> None:
    """B1: derselbe (cve_id, port) zweimal aus dem Lookup darf den Schreibpfad nicht sprengen.

    ``replace_for_host`` fuegt mit blankem INSERT ein; der PRIMARY KEY (mac, cve_id, port)
    wuerde bei einer Dublette werfen, die Transaktion zuruecknehmen und die Ausnahme aus
    ``_check_host`` heraustragen (dessen ``try`` nur den Lookup umschliesst). Der Use-Case
    macht die Menge darum vorher eindeutig: EINE Zeile, keine Ausnahme, und der uebrige
    Befundstand des Hosts ist korrekt ersetzt.
    """
    findings, checkstate, _ = repos
    lookup = _FakeLookup(
        [_cve("CVE-22", port=22), _cve("CVE-22", port=22), _cve("CVE-80", port=80)]
    )

    asyncio.run(_worker(repos, [_host(MAC, ports=(22, 80))], lookup, now=1000.0).tick())

    rows = findings.list_for_host(MAC)
    assert [(r.cve_id, r.port) for r in rows] == [("CVE-22", 22), ("CVE-80", 80)]
    assert len(rows) == 2  # die Dublette hat GENAU eine Zeile erzeugt
    state = checkstate.get(MAC)
    assert state is not None  # Pruefstand fortgeschrieben -> kein Abbruch im Schreibpfad
    assert state.checked_ports == frozenset({22, 80})


# ── Worker: Quittierungen laufen mit (Befund 56/B4) ───────────────────────────


def test_entfallener_quittierter_befund_bekommt_unack(repos: Repos) -> None:
    """Eine Quittierung darf beim Wiederauftauchen nicht STILL wieder greifen.

    Der 80er-Befund ist quittiert und faellt weg -> ein ``unack`` wird angehaengt (das
    append-only Log selbst bleibt unangetastet, ADR 0031). Taucht dasselbe Tripel spaeter
    wieder auf, ist es NICHT mehr quittiert -- der Nutzer sieht es erneut.
    """
    findings, _, acks = repos
    lookup = _FakeLookup(
        [],
        antworten=[
            [_cve("CVE-22", port=22), _cve("CVE-80", port=80)],
            [_cve("CVE-22", port=22)],  # 80er faellt weg
            [_cve("CVE-22", port=22), _cve("CVE-80", port=80)],  # 80er kommt wieder
        ],
    )
    asyncio.run(_worker(repos, [_host(MAC, ports=(22, 80))], lookup, now=1000.0).tick())
    acks.record(MAC, "CVE-80", 80, "ack")
    assert (MAC.upper(), "CVE-80", 80) in acks.acknowledged_keys()

    # Port 80 zu -> der quittierte Befund entfaellt.
    asyncio.run(_worker(repos, [_host(MAC, ports=(22,))], lookup, now=5000.0).tick())
    assert (MAC.upper(), "CVE-80", 80) not in acks.acknowledged_keys()

    # Port 80 wieder offen -> derselbe Befund taucht wieder auf, UNquittiert.
    asyncio.run(_worker(repos, [_host(MAC, ports=(22, 80))], lookup, now=9000.0).tick())
    aktiv = {f.cve_id for f in GetActiveFindings(findings, acks, now_provider=_at(9000.0))()}
    assert "CVE-80" in aktiv  # sichtbar, nicht still versteckt


def test_bleibender_quittierter_befund_behaelt_quittierung(repos: Repos) -> None:
    """Gegenprobe: wer BLEIBT, behaelt seine Quittierung (kein unack auf Verdacht)."""
    findings, _, acks = repos
    lookup = _FakeLookup(
        [],
        antworten=[
            [_cve("CVE-22", port=22), _cve("CVE-80", port=80)],
            [_cve("CVE-22", port=22), _cve("CVE-80", port=80)],
        ],
    )
    asyncio.run(_worker(repos, [_host(MAC, ports=(22, 80))], lookup, now=1000.0).tick())
    acks.record(MAC, "CVE-80", 80, "ack")

    # Ports geaendert (Fall 2) -> erneut geprueft, beide Befunde kommen wieder.
    asyncio.run(_worker(repos, [_host(MAC, ports=(22, 80, 443))], lookup, now=5000.0).tick())

    assert (MAC.upper(), "CVE-80", 80) in acks.acknowledged_keys()  # weiter quittiert
    aktiv = {f.cve_id for f in GetActiveFindings(findings, acks, now_provider=_at(5000.0))()}
    assert aktiv == {"CVE-22"}  # der quittierte bleibt ausgeblendet


def test_portloser_host_unackt_seine_entfallenen_quittierungen(repos: Repos) -> None:
    """Auch der lookup-freie Weg (B3) zieht die Quittierungen mit."""
    findings, _, acks = repos
    _seed(findings, "CVE-ALT", 22, first=500.0)
    acks.record(MAC, "CVE-ALT", 22, "ack")
    lookup = _FakeLookup([_cve()])

    asyncio.run(_worker(repos, [_host(MAC, ports=())], lookup).tick())

    assert lookup.calls == 0
    assert findings.list_for_host(MAC) == []
    assert (MAC.upper(), "CVE-ALT", 22) not in acks.acknowledged_keys()


# ── GetActiveFindings: ack-Filter + is_new ────────────────────────────────────


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


# ── GetAcknowledgedFindings: Spiegelbild zu GetActiveFindings ──────────────────


def test_acknowledged_findings_behaelt_nur_quittierte(repos: Repos) -> None:
    findings, _, acks = repos
    _seed(findings, "CVE-1", 22, first=999.0)
    _seed(findings, "CVE-2", 22, first=0.0, severity="LOW")
    acks.record(MAC, "CVE-1", 22, "ack")  # nur CVE-1 quittiert
    acked = GetAcknowledgedFindings(findings, acks, now_provider=_at(1000.0))()
    assert {f.cve_id for f in acked} == {"CVE-1"}


def test_acknowledged_und_active_sind_spiegelbild(repos: Repos) -> None:
    findings, _, acks = repos
    _seed(findings, "CVE-1", 22, first=999.0)
    _seed(findings, "CVE-2", 22, first=0.0, severity="LOW")
    acks.record(MAC, "CVE-1", 22, "ack")
    active = {f.cve_id for f in GetActiveFindings(findings, acks, now_provider=_at(1000.0))()}
    acked = {f.cve_id for f in GetAcknowledgedFindings(findings, acks, now_provider=_at(1000.0))()}
    assert active == {"CVE-2"}
    assert acked == {"CVE-1"}
    assert active.isdisjoint(acked)  # kein Befund in beiden Listen


def test_acknowledged_leer_wenn_nichts_quittiert(repos: Repos) -> None:
    findings, _, acks = repos
    _seed(findings, "CVE-1", 22, first=999.0)
    assert GetAcknowledgedFindings(findings, acks, now_provider=_at(1000.0))() == []


def test_acknowledged_unack_nimmt_befund_wieder_raus(repos: Repos) -> None:
    findings, _, acks = repos
    _seed(findings, "CVE-1", 22, first=999.0)
    acks.record(MAC, "CVE-1", 22, "ack")
    acks.record(MAC, "CVE-1", 22, "unack")  # juengster gewinnt -> nicht mehr quittiert
    assert GetAcknowledgedFindings(findings, acks, now_provider=_at(1000.0))() == []


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
