"""Tests der Aufraeumen-nach-Netz-Use-Cases (S88-P3).

``GruppiereGeraeteNachNetz`` -- die Rechnung ueber ``last_ip`` (Auftrag 4.4).
``EntferneGeraeteMenge``     -- die Mengen-Loeschung (Auftrag 4.5 + 1.2).

Gegen Fakes, nicht gegen SQLite: hier steht die Orchestrierung zur Pruefung, nicht
die Persistenz. Dass die Loeschung real alle neun Tabellen trifft, misst der
tragende Test in ``tests/infrastructure/test_device_purge.py`` gegen eine echte
Datei.
"""

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from application.maintenance import (
    OHNE_IP,
    EntferneGeraeteMenge,
    GruppiereGeraeteNachNetz,
)
from domain.devices import Device

NOW = datetime(2026, 8, 14, 12, 0, 0, tzinfo=UTC)


def _device(mac: str, last_ip: str | None) -> Device:
    return Device(
        mac=mac,
        first_seen=NOW,
        last_seen=NOW,
        last_ip=last_ip,
        times_seen=1,
        is_known=False,
    )


class _FakeDevices:
    """Liefert eine feste Geraeteliste; merkt sich, wie ``get_all`` gerufen wurde."""

    def __init__(self, devices: list[Device]) -> None:
        self._devices = devices
        self.aufrufe: list[bool] = []

    def get_all(self, known_only: bool) -> list[Device]:
        self.aufrufe.append(known_only)
        return list(self._devices)

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"Die Gruppierung darf {name!r} nicht rufen")


class _FakePurge:
    """Merkt sich JEDEN Aufruf -- damit die Keine-Schleife-Zusicherung messbar wird."""

    def __init__(self, entfernt: int = 0) -> None:
        self.aufrufe: list[list[str]] = []
        self._entfernt = entfernt

    def purge_devices(self, macs: Iterable[str]) -> int:
        self.aufrufe.append(list(macs))
        return self._entfernt


# ── 4.4 Die Gruppierung: drei Netze plus Geraete ohne IP ─────────────────────


def test_drei_netze_plus_ohne_ip_mit_richtigen_zahlen() -> None:
    """Der Kern von 4.4: drei /24-Gruppen und die Restgruppe, jede mit ihrer Anzahl."""
    devices = [
        # 192.168.1.0/24 -- drei Geraete
        _device("AA:BB:CC:00:00:01", "192.168.1.5"),
        _device("AA:BB:CC:00:00:02", "192.168.1.99"),
        _device("AA:BB:CC:00:00:03", "192.168.1.254"),
        # 10.0.0.0/24 -- zwei Geraete
        _device("AA:BB:CC:00:00:04", "10.0.0.1"),
        _device("AA:BB:CC:00:00:05", "10.0.0.7"),
        # 172.16.5.0/24 -- ein Geraet
        _device("AA:BB:CC:00:00:06", "172.16.5.42"),
        # ohne brauchbare IP -- zwei Geraete
        _device("AA:BB:CC:00:00:07", ""),
        _device("AA:BB:CC:00:00:08", "   "),
    ]

    gruppen = GruppiereGeraeteNachNetz(_FakeDevices(devices))()

    assert [(g.netz, g.anzahl) for g in gruppen] == [
        ("10.0.0.0/24", 2),
        ("172.16.5.0/24", 1),
        ("192.168.1.0/24", 3),
        (OHNE_IP, 2),
    ]


def test_jede_gruppe_traegt_ihre_macs() -> None:
    """Die MACs sind das, was spaeter geloescht wird -- sie muessen stimmen."""
    devices = [
        _device("AA:BB:CC:00:00:01", "192.168.1.5"),
        _device("AA:BB:CC:00:00:02", "192.168.1.6"),
        _device("AA:BB:CC:00:00:09", "10.0.0.1"),
    ]

    gruppen = {g.netz: g for g in GruppiereGeraeteNachNetz(_FakeDevices(devices))()}

    assert gruppen["192.168.1.0/24"].macs == ("AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02")
    assert gruppen["10.0.0.0/24"].macs == ("AA:BB:CC:00:00:09",)
    # anzahl und macs duerfen nie auseinanderlaufen.
    for gruppe in gruppen.values():
        assert gruppe.anzahl == len(gruppe.macs)


# ── 2.2 Geraete ohne brauchbare IP verschwinden NICHT still ──────────────────


def test_geraete_ohne_brauchbare_ip_bilden_eine_eigene_gruppe() -> None:
    """Sie fallen nicht unter den Tisch -- sonst waeren sie nie aufzuraeumen."""
    devices = [
        _device("AA:BB:CC:00:00:01", ""),
        _device("AA:BB:CC:00:00:02", "kaputt"),
        _device("AA:BB:CC:00:00:03", "999.999.999.999"),
    ]

    gruppen = GruppiereGeraeteNachNetz(_FakeDevices(devices))()

    assert len(gruppen) == 1
    assert gruppen[0].netz == OHNE_IP
    assert gruppen[0].anzahl == 3


def test_ein_geraet_ohne_jede_ip_faellt_in_die_ohne_ip_gruppe() -> None:
    """``last_ip=None`` ist der Domaenen-Default -- ein von Hand angelegtes Geraet.

    Es hat nie eine IP gehabt und darf trotzdem nicht unter den Tisch fallen: sonst
    waere genau dieses Geraet ueber das Aufraeumen nie zu erreichen.
    """
    gruppen = GruppiereGeraeteNachNetz(_FakeDevices([_device("AA:BB:CC:00:00:01", None)]))()

    assert [(g.netz, g.anzahl) for g in gruppen] == [(OHNE_IP, 1)]


def test_eine_ipv6_adresse_faellt_in_die_ohne_ip_gruppe() -> None:
    """Ein /24 ist ein IPv4-Begriff -- fuer IPv6 waere es eine erfundene Zuordnung."""
    gruppen = GruppiereGeraeteNachNetz(_FakeDevices([_device("AA:BB:CC:00:00:01", "fe80::1")]))()

    assert [g.netz for g in gruppen] == [OHNE_IP]


def test_leerer_bestand_liefert_keine_gruppen() -> None:
    """Kein Geraet, keine Gruppe -- kein erfundener Leer-Posten."""
    assert GruppiereGeraeteNachNetz(_FakeDevices([]))() == []


# ── 2.3 Archivierte Geraete: dem Bestand folgen ──────────────────────────────


def test_die_gruppierung_fragt_die_aktive_liste_ab() -> None:
    """``get_all(known_only=False)`` -- exakt die Liste, die der Anwender vor sich hat.

    Gemessen (2.3): ``SqliteDeviceRepository.get_all`` filtert ``archived = 0``, und
    die Geraeteverwaltung fuehrt das Archiv als eigene Tabelle. Wer aufraeumt, raeumt
    also genau das ab, was er sieht -- ein archiviertes Geraet ist schon weggeraeumt
    und darf nicht unbemerkt mit geloescht werden.
    """
    fake = _FakeDevices([_device("AA:BB:CC:00:00:01", "192.168.1.5")])

    GruppiereGeraeteNachNetz(fake)()

    assert fake.aufrufe == [False], "Die Gruppierung muss die AKTIVE Liste abfragen"


# ── 2.1 Die Gruppengroesse ist /24 ───────────────────────────────────────────


def test_das_dritte_oktett_trennt_die_gruppen() -> None:
    """/24 heisst: 192.168.1.x und 192.168.2.x sind ZWEI Netze, nicht eines."""
    devices = [
        _device("AA:BB:CC:00:00:01", "192.168.1.5"),
        _device("AA:BB:CC:00:00:02", "192.168.2.5"),
    ]

    gruppen = GruppiereGeraeteNachNetz(_FakeDevices(devices))()

    assert [g.netz for g in gruppen] == ["192.168.1.0/24", "192.168.2.0/24"]


def test_die_netze_stehen_in_adress_reihenfolge_nicht_alphabetisch() -> None:
    """192.168.9.0/24 vor 192.168.10.0/24 -- alphabetisch waere es umgekehrt."""
    devices = [
        _device("AA:BB:CC:00:00:01", "192.168.10.5"),
        _device("AA:BB:CC:00:00:02", "192.168.9.5"),
    ]

    gruppen = GruppiereGeraeteNachNetz(_FakeDevices(devices))()

    assert [g.netz for g in gruppen] == ["192.168.9.0/24", "192.168.10.0/24"]


def test_die_ohne_ip_gruppe_steht_immer_am_ende() -> None:
    """Sie ist kein Netz, sondern der Restposten -- und wird als solcher gelesen."""
    devices = [
        _device("AA:BB:CC:00:00:01", ""),
        _device("AA:BB:CC:00:00:02", "192.168.1.5"),
        _device("AA:BB:CC:00:00:03", "10.0.0.1"),
    ]

    gruppen = GruppiereGeraeteNachNetz(_FakeDevices(devices))()

    assert gruppen[-1].netz == OHNE_IP


# ── 1.2 KEINE Schleife: genau EIN Aufruf an den Loeschweg ────────────────────


def test_die_menge_geht_in_genau_einem_aufruf_an_den_loeschweg() -> None:
    """Der Kern von 1.2: EIN Aufruf, nicht 23.

    Waere hier eine Schleife, saehe man drei Aufrufe mit je einer MAC. Genau das
    verhindert dieser Test dauerhaft -- eine spaetere "Vereinfachung" auf
    ``for mac in macs: delete(mac)`` faellt hier auf, bevor sie in Produktion einen
    halben Bestand hinterlaesst.
    """
    purge = _FakePurge(entfernt=3)
    macs = ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02", "AA:BB:CC:00:00:03"]

    entfernt = EntferneGeraeteMenge(purge)(macs)

    assert len(purge.aufrufe) == 1, "Die Loeschung muss in EINEM Aufruf passieren"
    assert purge.aufrufe[0] == macs
    assert entfernt == 3


# ── 4.5 Leere Auswahl ────────────────────────────────────────────────────────


def test_eine_leere_auswahl_ist_kein_fehler_und_loescht_nichts() -> None:
    """Wer ohne Haekchen bestaetigt, hat nichts gewaehlt -- das ist kein Fehlverhalten."""
    purge = _FakePurge(entfernt=0)

    assert EntferneGeraeteMenge(purge)([]) == 0

    # Der Loeschweg wird trotzdem gerufen (er entscheidet selbst, dass nichts zu tun
    # ist) -- aber er bekommt eine leere Menge und raeumt nichts ab.
    assert purge.aufrufe == [[]]


def test_unbekannte_macs_sind_kein_fehler() -> None:
    """Idempotent wie ``DELETE /{mac}`` -- gemessenes Bestandsverhalten (1.4).

    Eine veraltete Liste (paralleler Scan, zweites Fenster) darf die Loeschung der
    uebrigen Geraete nicht verhindern.
    """
    purge = _FakePurge(entfernt=0)

    assert EntferneGeraeteMenge(purge)(["00:11:22:33:44:55"]) == 0
