"""Tests fuer die Auswahl der Kontroll-Adressen (Befund 53) -- reine Domaene.

Kein Netz, keine Adapter: ``pick_control_addresses`` rechnet nur. Geprueft werden
die drei Zusagen der Auswahlregel -- Ausschluss der gefundenen Adressen, Ausschluss
von Netz-/Broadcast-Adresse, und die Streuung ueber den Adressraum -- sowie die
Kantenfaelle, in denen es NICHT genug Kandidaten gibt (dort kommt bewusst weniger
als ``count`` zurueck; ueber den "nicht geprueft"-Zustand entscheidet der Aufrufer).

Dazu die Zusage, die die Auswahl unabhaengig von der NETZGROESSE macht: der
Adressraum wird gerechnet, nicht aufgezaehlt. Das ist hier gemessen (Zahl der
beruehrten Kandidaten), nicht behauptet -- siehe
``test_large_network_is_not_materialised``.
"""

from ipaddress import ip_address, ip_network
from itertools import pairwise

import pytest

from domain.scanning import interception as interception_module
from domain.scanning.interception import (
    CONTROL_ADDRESS_COUNT,
    MAX_PROBED_CANDIDATES,
    pick_control_addresses,
)


def test_picks_three_addresses_by_default() -> None:
    picked = pick_control_addresses(("192.168.1.0/24",), frozenset())
    assert len(picked) == CONTROL_ADDRESS_COUNT == 3


def test_excludes_discovered_addresses() -> None:
    """Adressen, die in der Discovery geantwortet haben, sind keine Kandidaten."""
    # /29 hat die Host-Adressen .1 bis .6; vier davon sind belegt -> genau .3/.5
    # bleiben uebrig, also nur zwei Kandidaten.
    discovered = frozenset({"192.168.1.1", "192.168.1.2", "192.168.1.4", "192.168.1.6"})
    picked = pick_control_addresses(("192.168.1.0/29",), discovered)

    assert set(picked).isdisjoint(discovered)
    assert set(picked) == {"192.168.1.3", "192.168.1.5"}


def test_excludes_network_and_broadcast_address() -> None:
    """Netz- und Broadcast-Adresse scheiden aus (``hosts()`` klammert beide aus)."""
    picked = pick_control_addresses(("192.168.1.0/24",), frozenset())

    assert "192.168.1.0" not in picked  # Netz-Adresse
    assert "192.168.1.255" not in picked  # Broadcast-Adresse


def test_addresses_are_spread_not_adjacent() -> None:
    """Die drei Adressen liegen weit auseinander, nicht direkt nebeneinander.

    Begruendung der Streuung: drei benachbarte Adressen liegen mit hoher
    Wahrscheinlichkeit im selben ungenutzten Block und haengen am selben Zufall.
    """
    picked = pick_control_addresses(("192.168.1.0/24",), frozenset())
    numeric = sorted(int(ip_address(text)) for text in picked)

    # In einem /24 mit 254 freien Adressen liegen die Abstaende bei ~84 -- weit
    # mehr als die 1, die drei benachbarte Adressen haetten.
    gaps = [b - a for a, b in pairwise(numeric)]
    assert all(gap > 10 for gap in gaps), f"zu dicht beieinander: {picked}"


def test_returns_fewer_when_not_enough_candidates() -> None:
    """Zu wenige freie Adressen -> es kommt weniger zurueck, KEIN Auffuellen.

    Der Aufrufer erkennt daran den "nicht geprueft"-Fall; hier wird NICHT still
    auf zwei Adressen heruntergegangen.
    """
    # /30: zwei Host-Adressen, eine belegt -> genau eine Kandidatin.
    picked = pick_control_addresses(("192.168.1.0/30",), frozenset({"192.168.1.1"}))
    assert picked == ("192.168.1.2",)


def test_returns_empty_when_network_is_full() -> None:
    """Volles Netz (alles gefunden) -> gar keine Kandidatin."""
    discovered = frozenset({"192.168.1.1", "192.168.1.2"})
    assert pick_control_addresses(("192.168.1.0/30",), discovered) == ()


def test_multiple_cidrs_are_pooled() -> None:
    """Mehrere CIDRs bilden EINEN Kandidatenpool (die Gegenprobe gilt fuer den Scan)."""
    picked = pick_control_addresses(("10.0.0.0/30", "10.0.1.0/30"), frozenset())

    assert len(picked) == 3
    assert set(picked) <= {"10.0.0.1", "10.0.0.2", "10.0.1.1", "10.0.1.2"}


def test_overlapping_cidrs_yield_no_duplicate_control_address() -> None:
    """Ueberlappende CIDRs erzeugen keine doppelte Kontroll-Adresse."""
    picked = pick_control_addresses(("10.0.0.0/29", "10.0.0.0/28"), frozenset())

    assert len(picked) == len(set(picked)) == 3


def test_result_is_deterministic() -> None:
    """Gleiche Eingabe -> gleiches Ergebnis (kein Zufall in der Auswahl)."""
    first = pick_control_addresses(("192.168.1.0/24",), frozenset({"192.168.1.7"}))
    second = pick_control_addresses(("192.168.1.0/24",), frozenset({"192.168.1.7"}))
    assert first == second


def test_cidr_order_does_not_change_the_selection() -> None:
    """Die Reihenfolge der CIDRs beeinflusst die Auswahl nicht (Sortierung nach Adresse)."""
    forward = pick_control_addresses(("10.0.0.0/30", "10.0.1.0/30"), frozenset())
    backward = pick_control_addresses(("10.0.1.0/30", "10.0.0.0/30"), frozenset())
    assert forward == backward


def test_zero_count_returns_nothing() -> None:
    assert pick_control_addresses(("192.168.1.0/24",), frozenset(), count=0) == ()


def _count_touched_candidates(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Zaehlt, wie viele Kandidaten die Auswahl tatsaechlich anfasst.

    Gemessen wird an ``ip_address`` IM MODUL: das ist die einzige Stelle, an der
    aus einer Position eine konkrete Adresse wird. Wer ``n`` Adressen
    materialisiert, kommt an diesem Zaehler nicht vorbei -- der Zaehler misst
    also die Sache selbst und nicht einen Nebeneffekt.

    Grenze des Belegs: er zeigt, dass die Auswahl keine Adress-OBJEKTE je
    Netzadresse baut. Er wuerde eine Materialisierung nicht bemerken, die ohne
    ``ip_address`` auskaeme (etwa eine reine Ganzzahl-Liste). Dagegen steht die
    zweite Messung im Test: die Laufzeit-unabhaengige Beobachtung, dass ein /16
    und ein /29 dieselbe Zahl an Beruehrungen brauchen -- eine Ganzzahl-Liste
    ueber 65.534 Eintraege waere daran erkennbar, weil sie mit der Netzgroesse
    wachsen muesste.
    """
    calls: list[int] = []

    def counting(value: object) -> object:
        calls.append(1)
        # Bewusst das stdlib-``ip_address``, nicht der (gerade ersetzte) Name im
        # Modul -- sonst riefe der Zaehler sich selbst auf.
        return ip_address(value)  # type: ignore[arg-type]

    monkeypatch.setattr(interception_module, "ip_address", counting)
    return calls


def test_large_network_is_not_materialised(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein /16 liefert drei Adressen, ohne das Netz aufzuzaehlen.

    Ein /16 hat 65.534 Host-Adressen. Der frueher gebaute Kandidatenpool haette
    ebenso viele Zeichenketten erzeugt; hier duerfen es nur eine Handvoll sein.
    """
    calls = _count_touched_candidates(monkeypatch)

    picked = pick_control_addresses(("10.1.0.0/16",), frozenset())

    assert len(picked) == CONTROL_ADDRESS_COUNT
    # Drei Treffer, jeder beim ersten Versuch: drei Beruehrungen fuer die Auswahl,
    # plus die Sortierung der DREI Treffer am Ende. Die Schranke haelt bewusst
    # grossen Abstand zu 65.534 -- sie prueft die Groessenordnung, nicht die
    # exakte Zahl.
    assert len(calls) < 50, f"zu viele Kandidaten beruehrt: {len(calls)}"


def test_touched_candidates_do_not_grow_with_network_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ein /12 kostet so wenig wie ein /29 -- der Aufwand haengt nicht am Netz.

    Das ist der eigentliche Beleg der Nachbesserung: nicht "wenig", sondern
    "unabhaengig von der Netzgroesse". Ein /12 hat ueber eine Million Adressen,
    ein /29 hat sechs.
    """
    calls = _count_touched_candidates(monkeypatch)

    pick_control_addresses(("192.168.1.0/29",), frozenset())
    small = len(calls)
    calls.clear()

    pick_control_addresses(("10.0.0.0/12",), frozenset())
    large = len(calls)

    assert large == small, f"/12 beruehrt {large}, /29 beruehrt {small}"


def test_full_network_stops_at_the_limit_instead_of_searching_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Grosses, fast volles Netz: die Suche endet an der Obergrenze.

    Ohne Grenze muesste die Auswahl hier alle 65.534 Adressen durchgehen -- drei
    Mal, einmal je Abschnitt. Mit Grenze bricht sie bei
    ``MAX_PROBED_CANDIDATES`` ab und liefert weniger als ``count``; der Aufrufer
    macht daraus "nicht geprueft" mit Grund (kein stilles Aufgeben).
    """
    calls = _count_touched_candidates(monkeypatch)
    full = frozenset(str(addr) for addr in ip_network("10.1.0.0/16").hosts())
    calls.clear()  # das Aufbauen der Test-Vorgabe zaehlt nicht zur Auswahl

    picked = pick_control_addresses(("10.1.0.0/16",), full)

    assert picked == ()
    assert len(picked) < CONTROL_ADDRESS_COUNT  # -> Aufrufer meldet "nicht geprueft"
    assert len(calls) <= MAX_PROBED_CANDIDATES, f"Grenze ueberschritten: {len(calls)}"


def test_partially_full_large_network_returns_what_is_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An der Grenze kommt zurueck, was gefunden wurde -- nicht nichts.

    Eine einzige freie Adresse am Anfang des /16: die wird gefunden, danach laeuft
    die Suche in die Grenze. Ergebnis ist die eine Adresse, nicht das leere
    Tupel -- "zu wenige Kandidaten", keine Filterung auf duenner Grundlage.
    """
    calls = _count_touched_candidates(monkeypatch)
    full = frozenset(str(addr) for addr in ip_network("10.1.0.0/16").hosts())
    calls.clear()

    picked = pick_control_addresses(("10.1.0.0/16",), full - {"10.1.0.1"})

    assert picked == ("10.1.0.1",)
    # ``+ CONTROL_ADDRESS_COUNT``: die abschliessende Sortierung ruft
    # ``ip_address`` noch einmal je GEFUNDENER Adresse auf. Das haengt an
    # ``count``, nicht an der Netzgroesse, und zaehlt darum nicht zu den
    # geprueften Kandidaten.
    assert len(calls) <= MAX_PROBED_CANDIDATES + CONTROL_ADDRESS_COUNT


def test_full_small_network_stays_below_the_limit() -> None:
    """Ein vollstaendig belegtes /24 wird GANZ durchsucht, ohne an die Grenze zu stossen.

    Die Gegenprobe zur Grenze: sie darf reale Netze nicht abschneiden. Ein volles
    /24 beruehrt ``3 * 254 = 762`` Kandidaten -- weit unter
    ``MAX_PROBED_CANDIDATES``. Das Ergebnis ist leer, weil das Netz voll ist, und
    nicht, weil die Suche abgebrochen wurde.
    """
    full = frozenset(str(addr) for addr in ip_network("192.168.1.0/24").hosts())

    assert pick_control_addresses(("192.168.1.0/24",), full) == ()
    assert MAX_PROBED_CANDIDATES > 3 * 254


def test_sections_search_on_when_their_own_block_is_taken() -> None:
    """Ein belegter Abschnitt gibt nicht auf -- solange drei frei sind, kommen drei.

    Hier ist die gesamte untere Haelfte eines /24 belegt. Der erste Abschnitt
    findet in seinem eigenen Bereich nichts und sucht zyklisch weiter. Ohne
    dieses Weitersuchen kaemen zu wenige Adressen zurueck und die Gegenprobe
    fiele grundlos auf "nicht geprueft".
    """
    lower_half = frozenset(f"192.168.1.{last}" for last in range(1, 128))

    picked = pick_control_addresses(("192.168.1.0/24",), lower_half)

    assert len(picked) == CONTROL_ADDRESS_COUNT
    assert set(picked).isdisjoint(lower_half)
