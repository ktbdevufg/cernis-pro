"""Naht-Test: waehlt die Oberflaeche je Rechte-Befund den richtigen Text? (S67-W-p)

DER BEFUND (Finding 12): Auf Windows stand ueber dem Per-App-Verkehr der macOS-Text,
der ausdruecklich behauptete, unter Windows sei die Messung moeglich. Die Auswahl
entschied zuerst nach dem ZUSTAND -- und ``not_applicable`` traegt zwei verschiedene
Faelle: die echte Plattformgrenze (macOS) und den bewussten Rechte-Verzicht (Windows).
Der erste Zweig fing beide ab.

WAS HIER GEPRUEFT WIRD, UND WARUM AUS pytest: Die Auswahl ist eine Frontend-Funktion
(``frontend/src/api/traffic.js``), die Zustaende und Ursachen aber kommen aus der
Domaene (``domain/traffic.py``). Die Naht zwischen beiden ist genau die Stelle, an der
dieses Finding entstanden ist -- und sie faellt durch jedes Raster, das nur eine Seite
prueft. Das Frontend hat kein eigenes Testframework (``frontend/package.json`` kennt
nur dev/build/preview); die CI faehrt ``pytest``. Darum laeuft die Pruefung von hier
aus und ruft die ECHTE Auswahlfunktion ueber ``node`` auf -- kein Nachbau der Logik in
Python, kein zweiter Wahrheitsstand.

Geprueft wird gegen die ECHTEN Sprachdateien in BEIDEN Sprachen: ein gewaehlter
Schluessel, den ``de.json`` oder ``en.json`` nicht kennt, ist eine leere Anzeige.
"""

import json
import pathlib
import shutil
import subprocess

import pytest

from domain.traffic import TrafficPermissionCause, TrafficPermissionState

_FRONTEND = pathlib.Path(__file__).resolve().parents[2] / "frontend"
_TRAFFIC_JS = _FRONTEND / "src" / "api" / "traffic.js"
_I18N = _FRONTEND / "src" / "i18n"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not _TRAFFIC_JS.is_file(),
    reason="node oder frontend/src/api/traffic.js nicht vorhanden",
)


def _schluessel_aus_dem_echten_frontend(befund: dict[str, object]) -> str:
    """Ruft die ECHTE ``trafficPermissionSchluessel`` aus ``api/traffic.js`` ueber node.

    Das Modul wird als ES-Modul importiert (``package.json`` faehrt Vite/ESM). Nur
    diese eine Funktion wird aufgerufen -- sie ist rein (Befund rein, Schluessel raus)
    und zieht keinen Netz-/DOM-Kram nach, obwohl das Modul auch ``fetch``-Funktionen
    exportiert (Import allein fuehrt sie nicht aus).
    """
    modul = _TRAFFIC_JS.resolve().as_uri()
    skript = (
        f"import {{ trafficPermissionSchluessel }} from {json.dumps(modul)};\n"
        f"process.stdout.write(trafficPermissionSchluessel({json.dumps(befund)}));\n"
    )
    ergebnis = subprocess.run(
        ["node", "--input-type=module", "-e", skript],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=_FRONTEND,
    )
    assert ergebnis.returncode == 0, f"node scheiterte: {ergebnis.stderr}"
    return ergebnis.stdout.strip()


def _text(sprache: str, schluessel: str) -> str:
    """Loest einen punktierten Schluessel in der echten Sprachdatei auf.

    Fehlt ein Glied, wirft der Zugriff -- genau das soll er: ein Schluessel ohne Text
    ist eine leere Anzeige, kein zu tolerierender Zustand.
    """
    daten: object = json.loads((_I18N / f"{sprache}.json").read_text(encoding="utf-8"))
    for glied in schluessel.split("."):
        assert isinstance(daten, dict), f"{schluessel}: '{glied}' ist kein Objekt"
        assert glied in daten, f"{schluessel}: '{glied}' fehlt in {sprache}.json"
        daten = daten[glied]
    assert isinstance(daten, str) and daten.strip(), f"{schluessel} ist leer in {sprache}.json"
    return daten


# Die vollstaendige Fallunterscheidung: Befund -> erwarteter Schluessel. Die Werte
# stammen aus den Domaenen-Enums, nicht aus abgeschriebenen Zeichenketten -- laeuft
# ein Wire-Wert auseinander, faellt es hier auf.
_FAELLE = [
    pytest.param(
        {
            "state": str(TrafficPermissionState.NOT_APPLICABLE),
            "cause": str(TrafficPermissionCause.PRIVILEGE_DECLINED),
        },
        "beobachten.traffic.durchsatzRechteVerzicht",
        id="windows-verzicht",
    ),
    pytest.param(
        {"state": str(TrafficPermissionState.NOT_APPLICABLE), "cause": None},
        "beobachten.traffic.durchsatzNichtMessbar",
        id="macos-plattformgrenze",
    ),
    pytest.param(
        {
            "state": str(TrafficPermissionState.NEEDS_PRIVILEGES),
            "cause": str(TrafficPermissionCause.TOOL_MISSING),
        },
        "beobachten.traffic.durchsatzWerkzeugFehlt",
        id="linux-werkzeug-fehlt",
    ),
    pytest.param(
        {
            "state": str(TrafficPermissionState.NEEDS_PRIVILEGES),
            "cause": str(TrafficPermissionCause.MEASUREMENT_FAILED),
        },
        "beobachten.traffic.durchsatzMessungFehlgeschlagen",
        id="messlauf-gescheitert",
    ),
    pytest.param(
        {"state": str(TrafficPermissionState.NEEDS_PRIVILEGES), "cause": None},
        "beobachten.traffic.durchsatzOhneWerte",
        id="ohne-ursache-neutral",
    ),
    pytest.param(
        {"state": "etwas_kuenftiges", "cause": "etwas_kuenftiges"},
        "beobachten.traffic.durchsatzOhneWerte",
        id="unbekannt-faellt-auf-neutral",
    ),
]


@pytest.mark.parametrize(("befund", "erwartet"), _FAELLE)
def test_auswahl_waehlt_je_ursache_und_zustand_den_richtigen_schluessel(
    befund: dict[str, object], erwartet: str
) -> None:
    """Die echte Frontend-Auswahl trifft je Befund den vorgesehenen Schluessel.

    Der erste Fall ist der Kern des Findings: derselbe Zustand wie macOS, aber die
    Ursache ``privilege_declined`` -- und damit ein anderer Text. Ohne die
    Ursache-zuerst-Reihenfolge liefe er in den macOS-Zweig.
    """
    assert _schluessel_aus_dem_echten_frontend(befund) == erwartet


@pytest.mark.parametrize(("befund", "erwartet"), _FAELLE)
@pytest.mark.parametrize("sprache", ["de", "en"])
def test_jeder_gewaehlte_schluessel_hat_in_beiden_sprachen_einen_text(
    sprache: str, befund: dict[str, object], erwartet: str
) -> None:
    """Was die Auswahl waehlt, muss in de.json UND en.json stehen -- sonst bleibt es leer."""
    schluessel = _schluessel_aus_dem_echten_frontend(befund)

    assert schluessel == erwartet
    assert _text(sprache, schluessel)


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_der_windows_text_nennt_windows_und_verspricht_nichts(sprache: str) -> None:
    """Der neue Text sagt, was gilt -- ohne Rechte-Rat, Befehl oder Vertroestung.

    Karls Entscheidung (S67): kein Vorwurf an Windows, keine Entschuldigung, kein
    Versprechen fuer spaeter, kein Terminal-Befehl, keine Schaltflaeche zur
    Rechteerweiterung. Der Text darf den Verzicht benennen, aber keinen Weg aus ihm
    heraus zeigen.
    """
    text = _text(sprache, "beobachten.traffic.durchsatzRechteVerzicht")
    klein = text.lower()

    assert "windows" in klein, "Der Text soll die Plattform benennen"
    for verboten in (
        "sudo",
        "runas",
        "administrator",
        "powershell",
        "cmd.exe",
        "künftig",
        "kuenftig",
        "später",
        "spaeter",
        "in a future",
        "for now",
        "leider",
        "unfortunately",
    ):
        assert verboten not in klein, f"'{verboten}' im Windows-Text ({sprache})"


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_der_macos_text_behauptet_nicht_mehr_windows_koenne_es(sprache: str) -> None:
    """Der macOS-Text nennt Windows nicht mehr als Plattform, auf der es ginge.

    Das war die zweite Haelfte des Findings: derselbe Satz behauptete am Anzeigeort
    das Gegenteil dessen, was auf Windows gilt.
    """
    text = _text(sprache, "beobachten.traffic.durchsatzNichtMessbar")

    assert "Windows" not in text, f"Der macOS-Text nennt Windows weiterhin ({sprache}): {text}"


# Die Ueberschriften der beiden Sonderfall-Absaetze, je Sprache. Sie sind der
# Anker der Auswahl: der Test adressiert einen BENANNTEN Abschnitt, keine
# Wortmenge. Damit ist der Windows-Abschnitt strukturell ausgeschlossen und darf
# ``macOS`` und ``Schnittstelle`` frei verwenden, wo er sie zur Einordnung braucht.
_UEBERSCHRIFTEN = {
    "de": {"macos": "Besonderheit bei macOS", "windows": "Besonderheit bei Windows"},
    "en": {"macos": "Special case on macOS", "windows": "Special case on Windows"},
}


def _abschnitt(text: str, ueberschrift: str) -> str | None:
    """Gibt den Absatz zurueck, der mit ``ueberschrift`` beginnt -- sonst ``None``."""
    for absatz in text.split("\n\n"):
        if absatz.startswith(ueberschrift):
            return absatz
    return None


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_die_hilfe_behauptet_nicht_mehr_windows_koenne_es(sprache: str) -> None:
    """Dieselbe Richtigstellung in der Hilfe-Inhaltsdatei, beide Sprachen.

    Der falsche Satz stand ein zweites Mal im Hilfetext -- dieselbe Ursache, dieselbe
    Wirkung. Geprueft wird der Abschnitt, der die macOS-Besonderheit erklaert; er wird
    ueber seine UEBERSCHRIFT gewaehlt, nicht ueber vorkommende Woerter. Der Abschnitt
    zur Windows-Besonderheit ist damit kein Kandidat und bleibt sprachlich frei.

    Beide Ueberschriften werden ausdruecklich eingefordert: verschwindet eine von
    ihnen, faellt der Test -- er darf nicht mangels Fundstelle still durchlaufen.
    """
    hilfe = json.loads(
        (_FRONTEND / "src" / "lib" / "help_content.json").read_text(encoding="utf-8")
    )
    text = hilfe["help.traffic.uebersicht"][sprache]["lang"]
    ueberschriften = _UEBERSCHRIFTEN[sprache]

    macos_abschnitt = _abschnitt(text, ueberschriften["macos"])
    assert macos_abschnitt is not None, (
        f"Kein Abschnitt mit der Ueberschrift '{ueberschriften['macos']}' in der Hilfe ({sprache})"
    )
    assert _abschnitt(text, ueberschriften["windows"]) is not None, (
        f"Kein Abschnitt mit der Ueberschrift '{ueberschriften['windows']}' "
        f"in der Hilfe ({sprache})"
    )

    assert "Windows" not in macos_abschnitt, (
        f"Der macOS-Abschnitt nennt Windows weiterhin als koennende Plattform "
        f"({sprache}): {macos_abschnitt}"
    )
