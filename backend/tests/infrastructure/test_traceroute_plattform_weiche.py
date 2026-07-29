"""Tests der traceroute-Plattformweiche im Composition Root (S66-W-h1).

PRODUKTLINIE (wie bei der Npcap-Weiche in ``sniffd_client/test_plattform_weiche.py``,
deren Vorgehen dieses Modul uebernimmt): Alle CERNIS-Installationen derselben Version
haben denselben Funktionsumfang. Auf Windows gibt es kein ``traceroute``-Binary; die
Faehigkeit steckt dort in ``iphlpapi.dll``. Fehlende Portierungsarbeit ist kein
zulaessiger Grund fuer eine fehlende Funktion -- also traegt die Windows-Naht nativ.

DER EIGENTLICHE PUNKT DIESES MODULS: die traceroute-Verdrahtung faellt in ``app.py`` an
ZWEI Stellen -- einmal fuer ``/api/diagnostics/traceroute`` (+ Rechte-Naht) und einmal
fuer ``/api/diagnostics/route`` (Route zum Ziel, ADR 0036). Genau daran ist der bisherige
Zustand haengen geblieben: eine uebersehene Stelle ergibt eine geheilte und eine weiterhin
tote Naht, und das faellt in einem Test, der nur EINE Naht prueft, nicht auf. Deshalb wird
hier geprueft, dass BEIDE Naehte DENSELBEN Adapter waehlen.

Zwei Ebenen, bewusst getrennt (Muster ``tests/api/test_event_loop_naht.py``):

1. LAUFZEIT: die ECHTE Composition Root ``create_app`` wird gebaut und die tatsaechlich
   verdrahteten Adapter werden aus den ``dependency_overrides`` herausgeholt -- gefaelscht
   wird nichts, geprueft wird die reale Verdrahtung auf DIESER Plattform.
2. STATISCH: ein AST-Waechter belegt plattformunabhaengig (also auch auf dem
   Linux-CI-Runner), dass in ``app.py`` kein zweiter ``SystemTracerouteRunner()`` an der
   Weiche vorbei instanziiert wird. Die Laufzeit-Ebene deckt das Bekannte, der Waechter
   die kuenftige Neuauflage.
"""

import ast
import asyncio
import pathlib
import sys
from typing import Any

import pytest
from fastapi import FastAPI

from api.diagnostics import (
    provide_build_route_geo,
    provide_check_traceroute_permission,
    provide_run_traceroute,
)
from app import create_app
from infrastructure.config import AppConfig
from infrastructure.diagnostics_linux import LinuxTraceroutePermission, SystemTracerouteRunner

_APP_PY = pathlib.Path(__file__).resolve().parents[2] / "app.py"


@pytest.fixture(scope="module")
def gebaute_app() -> FastAPI:
    """Die ECHTE Composition Root -- keine Attrappe, keine ueberschriebene Abhaengigkeit."""
    return create_app(AppConfig())


def _runner_aus_closure(callable_obj: Any, gesucht: str) -> Any:
    """Holt den verdrahteten Adapter aus der Closure eines Composition-Root-Callables.

    Die beiden Naht-Callables (``_run_traceroute``/``_build_route_geo``) schliessen den
    gewaehlten Adapter als freie Variable ein. Ueber ``__code__.co_freevars`` +
    ``__closure__`` laesst sich genau der Adapter herausholen, den die Weiche ausgewaehlt
    hat -- ohne die Naht zu faelschen und ohne eine Messung auszuloesen.
    """
    freie = callable_obj.__code__.co_freevars
    assert gesucht in freie, f"{gesucht} nicht in Closure {freie}"
    return callable_obj.__closure__[freie.index(gesucht)].cell_contents


# ── 1. Laufzeit: beide Naehte, EIN Adapter ───────────────────────────────────


def test_beide_naehte_waehlen_denselben_traceroute_adapter(gebaute_app: FastAPI) -> None:
    """Der Kernfall: ``/traceroute`` und ``/route`` nutzen DASSELBE Adapter-Objekt.

    Nicht nur denselben Typ -- dasselbe Objekt (``is``). Damit kann die Weiche gar nicht
    an einer der beiden Stellen uebersehen werden: es gibt nur noch eine Auswahl.
    """
    run_naht = gebaute_app.dependency_overrides[provide_run_traceroute]()
    route_naht = gebaute_app.dependency_overrides[provide_build_route_geo]()

    runner_a = _runner_aus_closure(run_naht, "_traceroute_runner")
    runner_b = _runner_aus_closure(route_naht, "_traceroute_runner")

    assert runner_a is runner_b, "Die beiden Naehte haben verschiedene Adapter erwischt"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-Zweig der Weiche")
def test_auf_windows_traegt_der_native_adapter(gebaute_app: FastAPI) -> None:
    """Auf Windows waehlen BEIDE Naehte den nativen Adapter, nicht den Linux-Binary-Adapter.

    Ohne die Weiche stand hier ``SystemTracerouteRunner``, dessen ``shutil.which``-Riegel
    auf Windows immer greift -- beide Naehte antworteten mit einem Fehler.
    """
    from infrastructure.traceroute_windows import (
        WindowsTraceroutePermission,
        WindowsTracerouteRunner,
    )

    run_naht = gebaute_app.dependency_overrides[provide_run_traceroute]()
    route_naht = gebaute_app.dependency_overrides[provide_build_route_geo]()

    assert isinstance(_runner_aus_closure(run_naht, "_traceroute_runner"), WindowsTracerouteRunner)
    assert isinstance(
        _runner_aus_closure(route_naht, "_traceroute_runner"), WindowsTracerouteRunner
    )

    rechte = gebaute_app.dependency_overrides[provide_check_traceroute_permission]()
    assert isinstance(rechte._permission, WindowsTraceroutePermission)
    # Und die Rechte-Naht meldet folgerichtig: nichts fehlt.
    assert rechte() == {"ok": True, "error": ""}


@pytest.mark.skipif(sys.platform == "win32", reason="Nicht-Windows-Zweig der Weiche")
def test_ausserhalb_windows_bleibt_alles_wie_bisher(gebaute_app: FastAPI) -> None:
    """Auf Linux/macOS traegt unveraendert der Binary-Adapter -- die Weiche aendert dort nichts."""
    run_naht = gebaute_app.dependency_overrides[provide_run_traceroute]()
    route_naht = gebaute_app.dependency_overrides[provide_build_route_geo]()

    assert isinstance(_runner_aus_closure(run_naht, "_traceroute_runner"), SystemTracerouteRunner)
    assert isinstance(_runner_aus_closure(route_naht, "_traceroute_runner"), SystemTracerouteRunner)

    rechte = gebaute_app.dependency_overrides[provide_check_traceroute_permission]()
    assert isinstance(rechte._permission, LinuxTraceroutePermission)


def test_windows_runner_erfuellt_den_port_ohne_vertragsbruch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Beide Adapter erfuellen denselben Port -- gleiche Signatur, gleicher Ergebnistyp.

    Plattformunabhaengig geprueft (auch auf dem Linux-Runner): die Windows-Klasse wird
    importiert und ihre Naht gegen einen gefaelschten nativen Kern gefahren. Bricht der
    Vertrag (z. B. ein anderer Rueckgabetyp), faellt es hier auf, nicht erst in Produktion.
    """
    from domain.diagnostics import TracerouteHop, TracerouteResult
    from infrastructure import traceroute_windows
    from infrastructure.traceroute_windows import WindowsTracerouteRunner

    monkeypatch.setattr(traceroute_windows, "_resolve_ipv4", lambda host: "1.1.1.1")
    monkeypatch.setattr(
        traceroute_windows,
        "_run_native",
        lambda ip, t, m: (TracerouteHop(hop=1, address="1.1.1.1", rtt_ms=4.0),),
    )
    ergebnis = asyncio.run(WindowsTracerouteRunner().run("1.1.1.1", False))

    assert isinstance(ergebnis, TracerouteResult)
    assert ergebnis.hops == (TracerouteHop(hop=1, address="1.1.1.1", rtt_ms=4.0),)


# ── 2. Statischer Waechter: kein zweiter Adapter an der Weiche vorbei ────────


def test_kein_traceroute_adapter_wird_an_der_weiche_vorbei_gebaut() -> None:
    """In ``app.py`` darf KEIN ``SystemTracerouteRunner()`` ausserhalb der Weiche entstehen.

    Der Waechter laeuft auf JEDER Plattform (also auch im Linux-CI) und faengt die
    kuenftige Neuauflage des Fehlers: eine dritte traceroute-Naht, die sich wieder einen
    eigenen Adapter baut und damit auf Windows tot bliebe. Erlaubt ist genau EINE
    Instanziierung -- die im ``else``-Zweig der Plattformweiche.

    OHNE die Behebung schlaegt dieser Test fehl: vorher stand ``SystemTracerouteRunner()``
    an ZWEI Stellen im Baum, an keiner davon in einer Plattformweiche.
    """
    baum = ast.parse(_APP_PY.read_text(encoding="utf-8"))

    stellen = [
        knoten
        for knoten in ast.walk(baum)
        if isinstance(knoten, ast.Call)
        and isinstance(knoten.func, ast.Name)
        and knoten.func.id == "SystemTracerouteRunner"
    ]
    assert len(stellen) == 1, (
        f"{len(stellen)} Instanziierungen von SystemTracerouteRunner in app.py "
        f"(Zeilen {[k.lineno for k in stellen]}) -- erlaubt ist genau die in der "
        "Plattformweiche. Eine zweite bliebe auf Windows tot."
    )


def test_die_weiche_steht_im_composition_root_und_fragt_sys_platform() -> None:
    """Die Auswahl faellt ueber ``sys.platform`` und der win32-Import steht INNERHALB.

    Beides ist Bedingung, keines ersetzt das andere: ``sys.platform`` ist die Weiche
    selbst, und der Import im positiven Zweig haelt die statische Pruefung auf Linux vom
    win32-Modul fern (mypy wertet ``sys.platform`` statisch aus).
    """
    quelle = _APP_PY.read_text(encoding="utf-8")
    baum = ast.parse(quelle)

    weichen = [
        knoten
        for knoten in ast.walk(baum)
        if isinstance(knoten, ast.If)
        and any(
            isinstance(t, ast.Attribute)
            and t.attr == "platform"
            and isinstance(t.value, ast.Name)
            and t.value.id == "sys"
            for t in ast.walk(knoten.test)
        )
        and any(
            isinstance(n, ast.ImportFrom) and n.module == "infrastructure.traceroute_windows"
            for n in ast.walk(knoten)
        )
    ]
    assert len(weichen) == 1, (
        "Genau EINE sys.platform-Weiche mit dem traceroute_windows-Import erwartet, "
        f"gefunden: {len(weichen)}"
    )

    # Der Import steht im POSITIVEN Zweig (body), nicht im else -- sonst importierte
    # ausgerechnet Linux das win32-Modul.
    weiche = weichen[0]
    assert any(
        isinstance(n, ast.ImportFrom) and n.module == "infrastructure.traceroute_windows"
        for zweig in weiche.body
        for n in ast.walk(zweig)
    ), "Der traceroute_windows-Import muss im positiven Zweig der Weiche stehen"
