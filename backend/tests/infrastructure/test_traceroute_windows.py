"""Tests der nativen Windows-Routenmessung (iphlpapi via ctypes).

Geprueft wird die PLATTFORMUNABHAENGIGE Ablauflogik aus
``infrastructure.traceroute_windows`` OHNE echte Windows-API und OHNE echtes Netz: die
native Schicht ist als Callable ``(ttl) -> _Probe`` gekapselt und wird hier gemockt
(Muster ``test_icmp_windows.py``). Alles laeuft deterministisch auch auf dem
Linux-CI-Runner.

Die gemessenen Statuswerte, gegen die hier geprueft wird, stammen aus einer Messung am
laufenden System (unprivilegiert): Zwischenhop ``11013`` (IP_TTL_EXPIRED_TRANSIT), Ziel
``0`` (IP_SUCCESS), nicht antwortender Hop Rueckgabewert ``0`` bzw. ``11010``
(IP_REQ_TIMED_OUT).
"""

import asyncio
import socket
import sys

import pytest

from domain.diagnostics import TracerouteHop
from infrastructure import traceroute_windows
from infrastructure.traceroute_windows import (
    TracerouteUnavailable,
    WindowsTraceroutePermission,
    WindowsTracerouteRunner,
    _build_hop_chain,
    _classify_probe,
    _Probe,
    _resolve_ipv4,
    _run_native,
)

# Die gemessenen Statuswerte, unter sprechenden Namen.
_ZIEL = 0  # IP_SUCCESS
_ZWISCHENHOP = 11013  # IP_TTL_EXPIRED_TRANSIT
_ZEITUEBERSCHREITUNG = 11010  # IP_REQ_TIMED_OUT


def _antwort(status: int, adresse: str, rtt: int = 5) -> _Probe:
    """Eine Antwort der nativen Schicht (Rueckgabewert 1 = genau ein Reply)."""
    return _Probe(returned=1, status=status, address=adresse, rtt_ms=rtt)


def _luecke() -> _Probe:
    """Ein nicht antwortender Hop: Rueckgabewert 0, keine gueltigen Daten im Puffer."""
    return _Probe(returned=0, status=_ZEITUEBERSCHREITUNG, address=None, rtt_ms=0)


def _kette_aus(proben: list[_Probe]) -> tuple[TracerouteHop, ...]:
    """Laesst ``_build_hop_chain`` genau die gereichten Proben der Reihe nach messen."""
    return _build_hop_chain(lambda ttl: proben[ttl - 1], max_ttl=len(proben))


# ── _classify_probe: eine Messung -> (Hop, Kette-zu-Ende) ────────────────────


def test_zwischenhop_traegt_adresse_und_laeuft_weiter() -> None:
    # Status 11013 -> Hop mit Adresse/Laufzeit, Kette NICHT zu Ende.
    hop, fertig = _classify_probe(_antwort(_ZWISCHENHOP, "192.168.1.1", 3), 1)
    assert hop == TracerouteHop(hop=1, address="192.168.1.1", rtt_ms=3.0)
    assert fertig is False


def test_ziel_beendet_die_kette() -> None:
    # Status 0 -> Hop mit Adresse UND Abbruch (weitere TTLs waeren sinnlos).
    hop, fertig = _classify_probe(_antwort(_ZIEL, "1.1.1.1", 12), 6)
    assert hop == TracerouteHop(hop=6, address="1.1.1.1", rtt_ms=12.0)
    assert fertig is True


def test_keine_antwort_wird_ehrliche_luecke_und_beendet_nicht() -> None:
    # Rueckgabewert 0 -> address/rtt_ms None, KEIN erfundener Wert, Kette laeuft weiter.
    hop, fertig = _classify_probe(_luecke(), 4)
    assert hop == TracerouteHop(hop=4, address=None, rtt_ms=None)
    assert fertig is False


def test_zeitueberschreitungs_status_ist_ebenfalls_luecke() -> None:
    # Auch MIT Rueckgabewert > 0 ist IP_REQ_TIMED_OUT eine Luecke, keine Adresse.
    hop, fertig = _classify_probe(_antwort(_ZEITUEBERSCHREITUNG, "0.0.0.0", 99), 2)
    assert hop == TracerouteHop(hop=2, address=None, rtt_ms=None)
    assert fertig is False


def test_antwort_ohne_adresse_wird_luecke_statt_geratener_wert() -> None:
    # Fremder Fehlerstatus ohne verwertbare Adresse -> Luecke, kein Raten (S3).
    hop, fertig = _classify_probe(_antwort(11002, None, 7), 3)  # type: ignore[arg-type]
    assert hop == TracerouteHop(hop=3, address=None, rtt_ms=None)
    assert fertig is False


# ── _build_hop_chain: die Kette als Ganzes ───────────────────────────────────


def test_kurze_kette_mit_erreichtem_ziel() -> None:
    """Drei Hops, das Ziel antwortet -- die Kette endet SOFORT beim Ziel."""
    kette = _build_hop_chain(
        lambda ttl: {
            1: _antwort(_ZWISCHENHOP, "192.168.1.1", 1),
            2: _antwort(_ZWISCHENHOP, "10.0.0.1", 8),
            3: _antwort(_ZIEL, "1.1.1.1", 14),
        }[ttl],
        max_ttl=30,
    )
    assert kette == (
        TracerouteHop(hop=1, address="192.168.1.1", rtt_ms=1.0),
        TracerouteHop(hop=2, address="10.0.0.1", rtt_ms=8.0),
        TracerouteHop(hop=3, address="1.1.1.1", rtt_ms=14.0),
    )


def test_luecke_in_der_mitte_beendet_die_kette_nicht() -> None:
    """Der Kernfall: ein stummer Hop in der Mitte, danach laeuft die Kette WEITER.

    Genau das trennt eine ehrliche Messung von einer abgebrochenen: Hop 2 und 3 antworten
    nicht, Hop 4 und das Ziel danach schon.
    """
    kette = _kette_aus(
        [
            _antwort(_ZWISCHENHOP, "192.168.1.1", 1),
            _luecke(),
            _luecke(),
            _antwort(_ZWISCHENHOP, "80.150.0.1", 20),
            _antwort(_ZIEL, "9.9.9.9", 25),
        ]
    )
    assert kette == (
        TracerouteHop(hop=1, address="192.168.1.1", rtt_ms=1.0),
        TracerouteHop(hop=2, address=None, rtt_ms=None),
        TracerouteHop(hop=3, address=None, rtt_ms=None),
        TracerouteHop(hop=4, address="80.150.0.1", rtt_ms=20.0),
        TracerouteHop(hop=5, address="9.9.9.9", rtt_ms=25.0),
    )
    # Ausdruecklich: die Luecken sind GEFUEHRT, nicht weggelassen -- Hop-Nummern bleiben
    # luecklos fortlaufend.
    assert [h.hop for h in kette] == [1, 2, 3, 4, 5]


def test_ziel_nie_erreicht_endet_bei_hoechst_ttl() -> None:
    """Antwortet niemand, endet die Kette bei der Hoechst-TTL -- ohne Ausnahme."""
    kette = _build_hop_chain(lambda ttl: _luecke(), max_ttl=30)
    assert len(kette) == 30
    assert all(h.address is None and h.rtt_ms is None for h in kette)
    assert kette[-1].hop == 30


def test_hoechst_ttl_wird_nicht_ueberschritten() -> None:
    """Auch wenn immer ein Zwischenhop antwortet, endet die Messung bei max_ttl."""
    gemessene_ttls: list[int] = []

    def probe(ttl: int) -> _Probe:
        gemessene_ttls.append(ttl)
        return _antwort(_ZWISCHENHOP, f"10.0.0.{ttl}", ttl)

    kette = _build_hop_chain(probe, max_ttl=30)
    assert gemessene_ttls == list(range(1, 31))
    assert len(kette) == 30


def test_nach_dem_ziel_wird_nicht_weiter_gemessen() -> None:
    """Beim Ziel endet die Messung -- es wird keine TTL mehr gesendet."""
    gemessene_ttls: list[int] = []

    def probe(ttl: int) -> _Probe:
        gemessene_ttls.append(ttl)
        return _antwort(_ZIEL if ttl == 2 else _ZWISCHENHOP, "1.1.1.1")

    _build_hop_chain(probe, max_ttl=30)
    assert gemessene_ttls == [1, 2]


def test_erschoepftes_budget_liefert_die_bisherige_kette_ehrlich() -> None:
    """Ist das Gesamtbudget erreicht, endet die Messung -- ohne Ausnahme, ohne Resthop.

    Die Uhr wird injiziert: nach der zweiten Messung ist das Budget ueberschritten. Die
    Kette traegt dann genau die bis dahin ermittelten Hops (E6).
    """
    uhr = iter([0.0, 1.0, 99.0, 99.0, 99.0])

    kette = _build_hop_chain(
        lambda ttl: _antwort(_ZWISCHENHOP, f"10.0.0.{ttl}", ttl),
        max_ttl=30,
        budget_secs=55.0,
        monotonic=lambda: next(uhr),
    )
    assert kette == (
        TracerouteHop(hop=1, address="10.0.0.1", rtt_ms=1.0),
        TracerouteHop(hop=2, address="10.0.0.2", rtt_ms=2.0),
    )


def test_die_erste_messung_laeuft_auch_bei_bereits_erschoepftem_budget() -> None:
    """Kein leeres Ergebnis, nur weil die Uhr schon weit steht -- mindestens ein Hop."""
    uhr = iter([0.0, 999.0, 999.0])
    kette = _build_hop_chain(
        lambda ttl: _antwort(_ZWISCHENHOP, "10.0.0.1", 1),
        max_ttl=30,
        budget_secs=55.0,
        monotonic=lambda: next(uhr),
    )
    assert len(kette) == 1


# ── _resolve_ipv4 ────────────────────────────────────────────────────────────


def test_aufloesung_liefert_erste_ipv4(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, None, None, "", ("93.184.216.34", 0))],
    )
    assert _resolve_ipv4("example.test") == "93.184.216.34"


def test_gescheiterte_aufloesung_liefert_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> list[object]:
        raise socket.gaierror("unresolvable")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert _resolve_ipv4("gibts.invalid") is None


# ── WindowsTracerouteRunner: der Port-Vertrag Ende-zu-Ende ───────────────────


def test_runner_liefert_die_gemessene_kette(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(traceroute_windows, "_resolve_ipv4", lambda host: "1.1.1.1")
    kette = (
        TracerouteHop(hop=1, address="192.168.1.1", rtt_ms=1.0),
        TracerouteHop(hop=2, address="1.1.1.1", rtt_ms=9.0),
    )
    monkeypatch.setattr(traceroute_windows, "_run_native", lambda ip, t, m: kette)

    ergebnis = asyncio.run(WindowsTracerouteRunner().run("1.1.1.1", False))
    assert ergebnis.target == "1.1.1.1"
    assert ergebnis.hops == kette


def test_privileged_true_hinein_ergibt_privileged_false_im_ergebnis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """E2: der Wunschwert wird fuer die Messung ignoriert, das Ergebnis sagt die Wahrheit.

    ``privileged`` bedeutet laut Domaene, WIE gemessen wurde. Auf Windows gibt es keinen
    privilegierten Zweitmodus -- gemessen wurde unprivilegiert, also ``False``.
    """
    monkeypatch.setattr(traceroute_windows, "_resolve_ipv4", lambda host: "1.1.1.1")
    monkeypatch.setattr(traceroute_windows, "_run_native", lambda ip, t, m: ())

    for wunsch in (True, False):
        ergebnis = asyncio.run(WindowsTracerouteRunner().run("1.1.1.1", wunsch))
        assert ergebnis.privileged is False, f"Wunschwert {wunsch} darf nicht durchschlagen"


def test_gescheiterte_aufloesung_ist_ehrlicher_fehler_keine_leere_kette(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """E7: unaufloesbarer Name -> Fehler. Eine leere Kette waere die Luege 'nichts gefunden'."""
    monkeypatch.setattr(traceroute_windows, "_resolve_ipv4", lambda host: None)

    def darf_nicht_laufen(ip: str, t: int, m: int) -> tuple[TracerouteHop, ...]:
        raise AssertionError("ohne Aufloesung darf nicht gemessen werden")

    monkeypatch.setattr(traceroute_windows, "_run_native", darf_nicht_laufen)

    with pytest.raises(TracerouteUnavailable):
        asyncio.run(WindowsTracerouteRunner().run("gibts.invalid", False))


def test_gescheitertes_handle_ist_ehrlicher_fehler(monkeypatch: pytest.MonkeyPatch) -> None:
    """E7: scheitert IcmpCreateFile, wird das gemeldet -- nicht als leeres Ergebnis getarnt."""
    monkeypatch.setattr(traceroute_windows, "_resolve_ipv4", lambda host: "1.1.1.1")

    def kein_handle(ip: str, t: int, m: int) -> tuple[TracerouteHop, ...]:
        raise TracerouteUnavailable("Das ICMP-Handle konnte nicht angelegt werden.")

    monkeypatch.setattr(traceroute_windows, "_run_native", kein_handle)

    with pytest.raises(TracerouteUnavailable):
        asyncio.run(WindowsTracerouteRunner().run("1.1.1.1", False))


def test_messung_laeuft_nicht_in_der_ereignisschleife(monkeypatch: pytest.MonkeyPatch) -> None:
    """E5: die blockierende Messschleife laeuft in einem Arbeitsfaden, nie im Loop.

    Belegt ueber den Thread-Namen: laeuft der native Kern im Hauptfaden, waere es genau der
    Fehler, der in Paket W-g den Paketmitschnitt lahmgelegt hat.
    """
    import threading

    monkeypatch.setattr(traceroute_windows, "_resolve_ipv4", lambda host: "1.1.1.1")
    gemessen_in: list[int] = []

    def merke_faden(ip: str, t: int, m: int) -> tuple[TracerouteHop, ...]:
        gemessen_in.append(threading.get_ident())
        return ()

    monkeypatch.setattr(traceroute_windows, "_run_native", merke_faden)

    asyncio.run(WindowsTracerouteRunner().run("1.1.1.1", False))
    assert gemessen_in and gemessen_in[0] != threading.get_ident()


# ── WindowsTraceroutePermission: nichts fehlt, nichts nachzureichen (E3) ─────


def test_rechte_adapter_meldet_verfuegbar_und_ohne_mangel() -> None:
    """Auf Windows steckt die Faehigkeit im Betriebssystem -- kein Hinweis, kein Angebot."""
    rechte = WindowsTraceroutePermission()
    assert rechte.is_available() is True
    assert rechte.check_permission() is None


def test_rechte_naht_ergibt_ok_true_und_leeren_fehlertext() -> None:
    """Der Use-Case macht daraus die Wire-Form, die das Frontend als 'kein Hinweis' liest."""
    from application.diagnostics import CheckTraceroutePermission

    assert CheckTraceroutePermission(WindowsTraceroutePermission())() == {"ok": True, "error": ""}


# ── Nicht-Windows-Ersatz: gleicher Name, ehrlicher Fehler statt Luege ────────


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Auf Windows ruft _run_native die echte iphlpapi -- hier nur der Ersatz.",
)
def test_nativer_kern_meldet_ausserhalb_windows_ehrlich_unverfuegbar() -> None:
    # Der Nicht-Windows-Zweig bindet denselben Namen und liefert KEINE leere Kette.
    with pytest.raises(TracerouteUnavailable):
        _run_native("1.1.1.1", 1500, 30)
