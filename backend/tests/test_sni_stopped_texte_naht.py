"""Naht-Test: findet jeder Selbst-Abbruch-Marker seinen Wortlaut? (S88-P5)

DER ANLASS: Das Backend beendet die SNI-Beobachtung in zwei Lagen von SELBST und
benennt sie ueber ``stopped_reason`` mit den stabilen Markern ``SNI_POLL_FAILED``
und ``SNI_HELPER_DEAD`` (``infrastructure/sni/sni_sniffer.py``); ``null`` heisst
kein Selbst-Abbruch. Das Muster ist das von ``NPCAP_MISSING``: das Backend benennt
die LAGE, den WORTLAUT besitzt das Frontend. Zwischen beidem liegt eine Naht --
ein Marker ohne Text auf der anderen Seite ist eine leere Anzeige, und kein Build
und kein Backend-Test faellt darueber.

WARUM AUS pytest: Das Frontend hat kein eigenes Testframework
(``frontend/package.json`` kennt nur dev/build/preview); die CI faehrt ``pytest``.
Muster und Begruendung wie in ``backend/tests/test_traffic_permission_texte_naht.py``
-- die Auswahl wird ueber ``node`` aus dem ECHTEN Modul gerufen, nicht in Python
nachgebaut, sonst entstuende hier ein zweiter Wahrheitsstand.

Die Marker-Konstanten kommen aus dem Backend-Modul, nicht aus abgeschriebenen
Zeichenketten: laeuft ein Wire-Wert auseinander, faellt es hier auf.
"""

import json
import pathlib
import subprocess

import pytest

from infrastructure.sni.sni_sniffer import _STOPPED_HELPER_DEAD, _STOPPED_POLL_FAILED
from tests import naht_frontend

_FRONTEND = pathlib.Path(__file__).resolve().parents[2] / "frontend"
_SNI_JS = _FRONTEND / "src" / "api" / "sni.js"
_I18N = _FRONTEND / "src" / "i18n"

# Gemeinsame Bedingung (S89-A1/A5): siehe ``tests/naht_frontend.py``. Kein Buendeln
# hier, darum keine node_modules-Pakete. ``dateien`` traegt nur ``sni.js`` -- die
# Einstiegsquelle, die das Skript unten selbst faehrt. ``api/client.js``, das node
# ueber deren Import mitzieht, steht bewusst nicht hier: transitive Quellen gehoeren
# in keine Liste, ihr Fehlen ist der laute node-Fehler (S89-A5).
_riegel = naht_frontend.riegel(dateien=(_SNI_JS,))

# Der echte Halbgeviertstrich (U+2014). Karls Wortlaut fordert ihn ausdruecklich --
# ein Bindestrich (U+002D) ist ein anderes Zeichen und hier ein Fehler.
_GEDANKENSTRICH = "—"


def _schluessel_aus_dem_echten_frontend(marker: object) -> str | None:
    """Ruft die ECHTE ``sniStoppedSchluessel`` aus ``api/sni.js`` ueber node.

    Das Modul wird als ES-Modul importiert (``package.json`` faehrt Vite/ESM). Nur
    diese eine Funktion wird aufgerufen -- sie ist rein (Marker rein, Schluessel
    raus) und zieht keinen Netz-/DOM-Kram nach, obwohl das Modul auch
    ``fetch``-Funktionen exportiert (Import allein fuehrt sie nicht aus).

    ``null`` (kein Selbst-Abbruch) kommt als ``None`` zurueck, nicht als leerer
    String -- die beiden Faelle sind hier ausdruecklich zu unterscheiden.
    """
    modul = _SNI_JS.resolve().as_uri()
    skript = (
        f"import {{ sniStoppedSchluessel }} from {json.dumps(modul)};\n"
        f"const r = sniStoppedSchluessel({json.dumps(marker)});\n"
        "process.stdout.write(JSON.stringify(r ?? null));\n"
    )
    ergebnis = subprocess.run(
        ["node", "--input-type=module", "-e", skript],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=_FRONTEND,
    )
    assert ergebnis.returncode == 0, f"node scheiterte: {ergebnis.stderr}"
    gelesen: object = json.loads(ergebnis.stdout)
    assert gelesen is None or isinstance(gelesen, str)
    return gelesen


def _text(sprache: str, schluessel: str) -> str:
    """Loest einen punktierten Schluessel in der echten Sprachdatei auf.

    Fehlt ein Glied, faellt der Zugriff -- genau das soll er: ein Schluessel ohne
    Text ist eine leere Anzeige, kein zu tolerierender Zustand.
    """
    daten: object = json.loads((_I18N / f"{sprache}.json").read_text(encoding="utf-8"))
    for glied in schluessel.split("."):
        assert isinstance(daten, dict), f"{schluessel}: '{glied}' ist kein Objekt"
        assert glied in daten, f"{schluessel}: '{glied}' fehlt in {sprache}.json"
        daten = daten[glied]
    assert isinstance(daten, str) and daten.strip(), f"{schluessel} ist leer in {sprache}.json"
    return daten


# Marker -> erwarteter Schluessel. Die Marker stammen aus dem Backend-Modul.
_FAELLE = [
    pytest.param(
        _STOPPED_POLL_FAILED,
        "beobachten.traffic.sniStoppedPollFailed",
        id="poll-failed",
    ),
    pytest.param(
        _STOPPED_HELPER_DEAD,
        "beobachten.traffic.sniStoppedHelperDead",
        id="helper-dead",
    ),
]

# Der zeichengenaue Wortlaut, den Karl entschieden hat (Fassung B, S88-P5).
_WORTLAUTE = {
    "de": {
        "beobachten.traffic.sniStoppedPollFailed": (
            "Aufzeichnung beendet — Datenquelle antwortet nicht. Erneut starten."
        ),
        "beobachten.traffic.sniStoppedHelperDead": (
            "Aufzeichnung beendet — Mitschnitt-Helfer beendet. Erneut starten."
        ),
    },
    "en": {
        "beobachten.traffic.sniStoppedPollFailed": (
            "Capture stopped — data source not responding. Start again."
        ),
        "beobachten.traffic.sniStoppedHelperDead": (
            "Capture stopped — capture helper ended. Start again."
        ),
    },
}


@pytest.mark.parametrize(("marker", "erwartet"), _FAELLE)
def test_jeder_marker_waehlt_seinen_schluessel(marker: str, erwartet: str) -> None:
    """Die echte Frontend-Auswahl trifft je Marker den vorgesehenen Schluessel."""
    assert _schluessel_aus_dem_echten_frontend(marker) == erwartet


@pytest.mark.parametrize(("marker", "erwartet"), _FAELLE)
@pytest.mark.parametrize("sprache", ["de", "en"])
def test_beide_marker_ergeben_in_beiden_sprachen_den_wortlaut(
    sprache: str, marker: str, erwartet: str
) -> None:
    """Aufgabe 3.1: zeichengenau, gegen die ECHTEN Sprachdateien, in beiden Sprachen."""
    schluessel = _schluessel_aus_dem_echten_frontend(marker)

    assert schluessel == erwartet
    assert _text(sprache, schluessel) == _WORTLAUTE[sprache][erwartet]


@pytest.mark.parametrize("marker", ["SNI_ETWAS_KUENFTIGES", "", "irgendwas"])
def test_unbekannter_marker_ergibt_keinen_leeren_text(marker: str) -> None:
    """Aufgabe 3.2: ein unbekannter Marker fuehrt NIE zu einer leeren Anzeige.

    Der leere String ist ausdruecklich mit dabei: er ist der Rand zwischen 'kein
    Selbst-Abbruch' (nichts anzeigen) und 'Abbruch mit unbekanntem Grund'. Er faellt
    auf 'nichts anzeigen' -- das ist kein leerer Kasten, sondern gar kein Kasten.
    """
    schluessel = _schluessel_aus_dem_echten_frontend(marker)

    if marker == "":
        assert schluessel is None, "Ein leerer Marker ist kein Abbruch -- nichts anzeigen"
        return

    assert schluessel == "beobachten.traffic.sniStoppedUnbekannt"
    for sprache in ("de", "en"):
        assert _text(sprache, schluessel)


def test_kein_marker_zeigt_nichts_an() -> None:
    """``null`` heisst kein Selbst-Abbruch -- die Auswahl liefert dann keinen Schluessel."""
    assert _schluessel_aus_dem_echten_frontend(None) is None


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_alle_drei_schluessel_stehen_in_beiden_sprachen(sprache: str) -> None:
    """Auch der Rueckfalltext ist ein Wortlaut und muss in BEIDEN Katalogen stehen."""
    for schluessel in (
        "beobachten.traffic.sniStoppedPollFailed",
        "beobachten.traffic.sniStoppedHelperDead",
        "beobachten.traffic.sniStoppedUnbekannt",
    ):
        assert _text(sprache, schluessel)


def test_die_deutschen_texte_tragen_den_echten_gedankenstrich() -> None:
    """Aufgabe 3.4 (Teil 1): echter Halbgeviertstrich, kein Bindestrich.

    Geprueft an den Bytes des gelesenen Texts, nicht am abgeschriebenen Literal:
    ein umgestellter Bindestrich sieht im Quelltext fast gleich aus.
    """
    for schluessel in (
        "beobachten.traffic.sniStoppedPollFailed",
        "beobachten.traffic.sniStoppedHelperDead",
    ):
        for sprache in ("de", "en"):
            text = _text(sprache, schluessel)
            assert _GEDANKENSTRICH in text, (
                f"{schluessel} ({sprache}) traegt keinen Halbgeviertstrich: {text!r}"
            )
            assert " - " not in text, (
                f"{schluessel} ({sprache}) traegt einen Bindestrich statt des "
                f"Halbgeviertstrichs: {text!r}"
            )


def test_die_deutschen_texte_stehen_unescaped_in_der_datei() -> None:
    """Aufgabe 3.4 (Teil 2): echte Zeichen in de.json, keine ``\\uXXXX``-Ersatzschreibung.

    Geprueft wird der ROHE Dateiinhalt der Zeile, nicht der geladene String: eine
    Datei, die Umlaut oder Gedankenstrich als Escape ablegt, liefert nach
    ``json.loads`` denselben String -- der Unterschied faellt nur an den Bytes auf.
    Die drei Wortlaute tragen heute keinen Umlaut; die Forderung steht trotzdem,
    damit ein spaeter geaenderter Text nicht unbemerkt in Escape-Schreibung landet.
    """
    roh = (_I18N / "de.json").read_text(encoding="utf-8")

    for schluessel in (
        "sniStoppedPollFailed",
        "sniStoppedHelperDead",
        "sniStoppedUnbekannt",
    ):
        zeilen = [z for z in roh.splitlines() if f'"{schluessel}"' in z]
        assert len(zeilen) == 1, f"{schluessel} steht {len(zeilen)}x roh in de.json (erwartet: 1)"
        assert "\\u" not in zeilen[0], (
            f"{schluessel} traegt eine Escape-Schreibung statt echter Zeichen: {zeilen[0]!r}"
        )
