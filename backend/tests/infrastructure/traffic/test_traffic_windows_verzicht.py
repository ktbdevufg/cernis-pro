"""Tests des Windows-Rechte-Adapters und seiner Naht bis in die Wire-Form (S67-W-p).

DER BEFUND, DER DAZU FUEHRTE (Finding 12): Auf Windows stand ueber dem Per-App-Verkehr
der macOS-Text -- und der behauptete ausdruecklich, unter Windows sei die Messung
moeglich. Ursache war ein Kurzschluss: die Plattform-Weiche in ``app.py`` kannte nur
darwin und else, Windows bekam den Linux-Rechte-Adapter, dessen ``is_available`` auf
Windows ``False`` liefert, und der Use-Case setzte daraufhin hart ``NOT_APPLICABLE``
mit ``cause=None`` -- also genau die Signatur der echten Plattformgrenze (macOS).

WAS AUF WINDOWS WIRKLICH GILT: die Messung waere ueber die Ereignisablaufverfolgung
technisch moeglich, verlangt aber dauerhaft erhoehte Rechte. CERNIS verzichtet bewusst
darauf (Karls Entscheidung). Das ist ein eigener, benennbarer Fall --
``NOT_APPLICABLE`` mit der Ursache ``PRIVILEGE_DECLINED``.

Vier Ebenen, bewusst getrennt (Muster ``test_traceroute_plattform_weiche.py``):

1. ADAPTER: der Windows-Adapter meldet den vorgesehenen Zustand mit der neuen Ursache
   -- plattformunabhaengig geprueft (also auch auf dem Linux-CI-Runner).
2. NAHT: der ECHTE Use-Case gegen den ECHTEN Adapter, bis in die Wire-Form. Kein
   Nachbau der Auswertung.
3. WAECHTER: ein AST-Waechter belegt plattformunabhaengig, dass die Plattform-Weiche im
   Composition Root einen win32-Zweig hat und den Windows-Adapter bindet.
4. UNVERAENDERT: Linux und macOS liefern weiterhin exakt ihre bisherigen Zustaende und
   Ursachen -- die Aenderung darf sie nicht mitnehmen.
"""

import ast
import pathlib

import pytest

import infrastructure.traffic_permission as tp
from application.traffic.use_cases import CheckTrafficPermission
from domain.traffic import TrafficPermissionCause, TrafficPermissionState
from infrastructure.traffic_macos import (
    TrafficPermissionAdapter as MacosTrafficPermissionAdapter,
)
from infrastructure.traffic_permission import (
    TrafficPermissionAdapter as LinuxTrafficPermissionAdapter,
)
from infrastructure.traffic_windows import (
    TrafficPermissionAdapter as WindowsTrafficPermissionAdapter,
)

_APP_PY = pathlib.Path(__file__).resolve().parents[3] / "app.py"


# ── 1. Der Adapter selbst ────────────────────────────────────────────────────


def test_windows_adapter_meldet_verzicht_mit_neuer_ursache() -> None:
    """KERN: ``NOT_APPLICABLE`` + ``PRIVILEGE_DECLINED`` + nicht-leerer Grund.

    Der Zustand sagt "nicht behebbar" (die Oberflaeche soll keinen Weg anbieten), die
    Ursache trennt den Verzicht von der echten Plattformgrenze (macOS, ``cause``
    ``None``) -- ohne sie waere der Fall in der Wire-Form nicht unterscheidbar.
    """
    befund = WindowsTrafficPermissionAdapter().permission_state()

    assert befund.state is TrafficPermissionState.NOT_APPLICABLE
    assert befund.cause is TrafficPermissionCause.PRIVILEGE_DECLINED
    assert befund.reason, "Der Verzicht braucht eine Begruendung, kein stilles Nichts"


def test_windows_adapter_haelt_stufe_1_offen() -> None:
    """``is_available`` bleibt ``True``: die Verbindungssicht laeuft rechtefrei.

    Ein ``False`` wuerde den ganzen Feature-Bereich sperren, obwohl der groessere Teil
    davon (welches Programm mit welcher Gegenstelle spricht) auf Windows vollstaendig
    arbeitet.
    """
    assert WindowsTrafficPermissionAdapter().is_available() is True


def test_windows_adapter_bietet_keine_rechteerweiterung_an() -> None:
    """Kein Rechte-Rat, kein Befehl, kein Versprechen im Text (Karls Entscheidung).

    Der Text darf den Verzicht BENENNEN, aber keinen Weg aus ihm heraus zeigen -- und
    schon gar keinen Terminal-Befehl. Geprueft wird der Grundtext beider Nahtstellen.
    """
    adapter = WindowsTrafficPermissionAdapter()
    texte = [adapter.check_permission() or "", adapter.permission_state().reason]

    for text in texte:
        klein = text.lower()
        for verboten in (
            "sudo",
            "runas",
            "als administrator",
            "administrator ausf",
            "powershell",
            "cmd.exe",
            "starten sie",
            "spaeter",
            "später",
        ):
            assert verboten not in klein, f"Rechte-/Handlungs-Rat '{verboten}' im Windows-Text"


# ── 2. Die Naht: echter Use-Case, echter Adapter, bis in die Wire-Form ───────


def test_rechte_weg_liefert_auf_windows_die_neue_ursache_bis_in_die_wire_form() -> None:
    """Der ECHTE Use-Case gegen den ECHTEN Windows-Adapter -- kein Nachbau.

    Das ist die Stelle, an der der frueher Kurzschluss zuschlug: ``is_available``
    False -> harter ``not_applicable`` ohne Ursache. Jetzt traegt die Wire-Form die
    Aussage des Adapters durch.
    """
    wire = CheckTrafficPermission(WindowsTrafficPermissionAdapter())()

    assert wire["ok"] is False
    assert wire["state"] == "not_applicable"
    assert wire["cause"] == "privilege_declined"
    assert wire["error"], "Die Wire-Form darf den Grund nicht verschlucken"


def test_kurzschluss_ueberschreibt_die_aussage_des_adapters_nicht() -> None:
    """Auch ein Adapter mit ``is_available() == False`` behaelt Grund und Ursache.

    Der Kurzschluss im Use-Case darf den Zustand festlegen (nicht nutzbar =
    ``not_applicable``), aber nicht die Begruendung ersetzen. Geprueft mit einem
    Adapter, der genau diese Kombination meldet -- die Bedingung, unter der der
    Kurzschluss frueher jede Aussage verworfen hat.
    """

    class VerzichtOhneVerfuegbarkeit:
        """Meldet nicht verfuegbar UND traegt trotzdem Grund und Ursache."""

        def is_available(self) -> bool:
            return False

        def check_permission(self) -> str | None:
            return "Eigener Grund"

        def permission_state(self):  # type: ignore[no-untyped-def]
            return WindowsTrafficPermissionAdapter().permission_state()

    wire = CheckTrafficPermission(VerzichtOhneVerfuegbarkeit())()

    assert wire["state"] == "not_applicable"
    assert wire["cause"] == "privilege_declined"
    assert wire["error"] == WindowsTrafficPermissionAdapter().permission_state().reason


def test_schweigender_adapter_bekommt_weiterhin_den_neutralen_ersatztext() -> None:
    """Ohne eigene Begruendung bleibt der bisherige neutrale Satz -- kein leeres Feld.

    Die Lockerung des Kurzschlusses darf nicht dazu fuehren, dass ein Adapter ohne
    Grundtext eine leere Meldung durchreicht.
    """
    from domain.traffic import TrafficPermissionResult

    class Schweigend:
        def is_available(self) -> bool:
            return False

        def check_permission(self) -> str | None:
            return None

        def permission_state(self) -> TrafficPermissionResult:
            return TrafficPermissionResult(state=TrafficPermissionState.NOT_APPLICABLE)

    wire = CheckTrafficPermission(Schweigend())()

    assert wire["state"] == "not_applicable"
    assert wire["cause"] is None
    assert wire["error"] == "Per-App-Traffic ist auf dieser Plattform nicht verfuegbar."


# ── 3. Statischer Waechter auf die Plattform-Weiche ──────────────────────────


def test_die_traffic_weiche_hat_einen_win32_zweig_mit_dem_windows_adapter() -> None:
    """Die Weiche fragt ``sys.platform`` und bindet ``traffic_windows`` IM win32-Zweig.

    Laeuft auf JEDER Plattform (also auch im Linux-CI) und faengt genau den Zustand,
    der zu diesem Finding gefuehrt hat: eine Weiche, die Windows in den else-Zweig
    fallen laesst. Der Import muss im win32-Zweig stehen -- mypy wertet ``sys.platform``
    statisch aus, ein Import ausserhalb bruechte die Pruefung auf Linux.

    Vorbild: ``test_traceroute_plattform_weiche``.
    """
    baum = ast.parse(_APP_PY.read_text(encoding="utf-8"))

    def _fragt_sys_platform(knoten: ast.If) -> bool:
        return any(
            isinstance(t, ast.Attribute)
            and t.attr == "platform"
            and isinstance(t.value, ast.Name)
            and t.value.id == "sys"
            for t in ast.walk(knoten.test)
        )

    def _importiert_traffic_windows(knoten: ast.AST) -> bool:
        return any(
            isinstance(n, ast.ImportFrom) and n.module == "infrastructure.traffic_windows"
            for n in ast.walk(knoten)
        )

    weichen = [
        knoten
        for knoten in ast.walk(baum)
        if isinstance(knoten, ast.If)
        and _fragt_sys_platform(knoten)
        and _importiert_traffic_windows(knoten)
    ]
    assert weichen, (
        "Keine sys.platform-Weiche in app.py importiert infrastructure.traffic_windows "
        "-- Windows fiele wieder in den else-Zweig und bekaeme den Linux-Rechte-Adapter."
    )

    # Der Import muss im Zweig einer win32-Bedingung stehen, nicht irgendwo im Baum.
    # Bei ``elif`` verschachtelt ast das als If im orelse des aeusseren If -- die
    # gesuchte Bedingung ist also die des Knotens, dessen BODY den Import traegt.
    traeger = [
        knoten
        for knoten in weichen
        if any(_importiert_traffic_windows(zweig) for zweig in knoten.body)
    ]
    assert len(traeger) == 1, (
        f"Genau EIN Zweig soll traffic_windows importieren, gefunden: {[k.lineno for k in traeger]}"
    )

    bedingung = traeger[0].test
    assert isinstance(bedingung, ast.Compare)
    assert any(isinstance(v, ast.Constant) and v.value == "win32" for v in bedingung.comparators), (
        "Der Zweig mit dem traffic_windows-Import muss auf sys.platform == 'win32' pruefen"
    )


# ── 4. Linux und macOS bleiben verhaltensgleich ──────────────────────────────


def test_linux_bleibt_unveraendert_granted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Linux mit vorhandenem ``ss``: unveraendert ``granted``, kein Grund, keine Ursache."""
    monkeypatch.setattr(tp, "_ss_vorhanden", lambda: True)
    monkeypatch.setattr(
        LinuxTrafficPermissionAdapter, "is_available", lambda self: True, raising=True
    )

    befund = LinuxTrafficPermissionAdapter().permission_state()
    wire = CheckTrafficPermission(LinuxTrafficPermissionAdapter())()

    assert befund.state is TrafficPermissionState.GRANTED
    assert befund.cause is None
    assert wire == {"ok": True, "error": "", "state": "granted", "cause": None}


def test_linux_bleibt_unveraendert_tool_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Linux ohne ``ss``: unveraendert ``needs_privileges`` + ``tool_missing``."""
    monkeypatch.setattr(tp, "_ss_vorhanden", lambda: False)
    monkeypatch.setattr(
        LinuxTrafficPermissionAdapter, "is_available", lambda self: True, raising=True
    )

    befund = LinuxTrafficPermissionAdapter().permission_state()
    wire = CheckTrafficPermission(LinuxTrafficPermissionAdapter())()

    assert befund.state is TrafficPermissionState.NEEDS_PRIVILEGES
    assert befund.cause is TrafficPermissionCause.TOOL_MISSING
    assert wire["ok"] is False
    assert wire["state"] == "needs_privileges"
    assert wire["cause"] == "tool_missing"


def test_macos_bleibt_unveraendert_not_applicable_ohne_ursache() -> None:
    """macOS: unveraendert ``not_applicable`` OHNE Ursache -- die echte Plattformgrenze.

    Das ist die Abgrenzung, die den ganzen Fix traegt: derselbe Zustand wie Windows,
    aber eine andere (naemlich keine) Ursache. Faellt sie weg, bekaeme macOS den
    Windows-Text oder umgekehrt.
    """
    befund = MacosTrafficPermissionAdapter().permission_state()
    wire = CheckTrafficPermission(MacosTrafficPermissionAdapter())()

    assert befund.state is TrafficPermissionState.NOT_APPLICABLE
    assert befund.cause is None
    assert wire["ok"] is False
    assert wire["state"] == "not_applicable"
    assert wire["cause"] is None
    assert "macOS" in wire["error"]  # type: ignore[operator]


def test_die_drei_plattformen_sind_paarweise_unterscheidbar() -> None:
    """Kein Zustand/Ursache-Paar kommt doppelt vor -- sonst waere ein Fall blind.

    Genau daran krankte der alte Zustand: Windows und macOS lieferten dieselbe
    Signatur (``not_applicable``/``None``), und die Oberflaeche konnte sie nicht
    trennen.
    """
    signaturen = {
        "windows": WindowsTrafficPermissionAdapter().permission_state(),
        "macos": MacosTrafficPermissionAdapter().permission_state(),
    }
    paare = {name: (b.state, b.cause) for name, b in signaturen.items()}

    assert len(set(paare.values())) == len(paare), f"Nicht unterscheidbare Signaturen: {paare}"
