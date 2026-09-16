"""Naht-Test: erreicht der Abweisungstext fuer ein zu grosses Netz den Anwender? (S88-P2)

DER FALL: Die Domaene weist einen Scan ab, dessen Netze in der SUMME mehr als
``MAX_SCAN_ADRESSEN`` (4096) Adressen umfassen. Der Anwender soll dazu einen
erklaerenden Text in SEINER Sprache sehen, samt der Zahl, die er angegeben hat.

DIE NAHT, die hier geprueft wird, hat drei Glieder, und jedes einzelne kann sie
reissen, ohne dass ein Test auf einer Seite es merkt:

1. Die Domaene (``NetzZuGrossError``) traegt die gemessene Summe als ATTRIBUT --
   nicht als zu parsenden Text (Muster ``KeyMissingError.key_file``, Befund 65).
2. ``ws_scan.py`` uebersetzt sie in die maschinenlesbaren Frame-Felder ``grund``
   und ``anzahl``.
3. Das Frontend (``lib/scanFehler.js``) waehlt daran den i18n-Schluessel, und die
   Sprachdateien tragen dazu einen Text MIT dem Platzhalter ``{{anzahl}}``.

WARUM AUS pytest: Das Frontend hat kein eigenes Testframework
(``frontend/package.json`` kennt nur dev/build/preview); die CI faehrt ``pytest``.
Darum laeuft die Pruefung von hier aus und ruft die ECHTE Frontend-Funktion ueber
``node`` auf -- kein Nachbau der Logik in Python, kein zweiter Wahrheitsstand.
Muster: ``backend/tests/test_werkzeug_fehler_texte_naht.py``.
"""

import json
import pathlib
import subprocess
from typing import Any

import pytest

from domain.scanning import MAX_SCAN_ADRESSEN, NetzZuGrossError, ScanConfig
from tests import naht_frontend

_FRONTEND = pathlib.Path(__file__).resolve().parents[2] / "frontend"
_SCAN_FEHLER_JS = _FRONTEND / "src" / "lib" / "scanFehler.js"
_I18N = _FRONTEND / "src" / "i18n"

# Gemeinsame Bedingung (S89-A1/A5): siehe ``tests/naht_frontend.py``. Kein Buendeln
# hier, darum keine node_modules-Pakete. ``scanFehler.js`` ist die Einstiegsquelle,
# die ``_anzeige`` unten selbst ueber node faehrt; sie hat keine eigenen Importe,
# also zieht dieser Lauf nichts Transitives nach.
_riegel = naht_frontend.riegel(dateien=(_SCAN_FEHLER_JS,))

# Der i18n-Schluessel des Abweisungstextes (auch in scanFehler.js benannt).
_SCHLUESSEL = "beobachten.scan.netzZuGross"


def _anzeige(nachricht: object, frame: object, sprache: str = "de") -> dict[str, Any]:
    """Ruft die ECHTE ``waehleScanFehlerAnzeige`` aus ``lib/scanFehler.js`` ueber node.

    Die Zahlenformatierung wird als ``toLocaleString(sprache)`` hereingereicht --
    genau das, was ObserveView.jsx an dieser Stelle tut (Muster LoggingPanel.jsx).
    """
    modul = _SCAN_FEHLER_JS.resolve().as_uri()
    skript = (
        f"import {{ waehleScanFehlerAnzeige }} from {json.dumps(modul)};\n"
        f"const a = waehleScanFehlerAnzeige("
        f"{json.dumps(nachricht)}, {json.dumps(frame)}, "
        f"(n) => Number(n).toLocaleString({json.dumps(sprache)}));\n"
        f"process.stdout.write(JSON.stringify(a));\n"
    )
    ergebnis = subprocess.run(
        ["node", "--input-type=module", "-e", skript],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=_FRONTEND,
    )
    assert ergebnis.returncode == 0, f"node scheiterte: {ergebnis.stderr}"
    geladen: object = json.loads(ergebnis.stdout)
    assert isinstance(geladen, dict)
    return geladen


def _text(sprache: str, schluessel: str) -> str:
    """Loest einen punktierten Schluessel in der echten Sprachdatei auf.

    Fehlt ein Glied, faellt der Test -- ein Schluessel ohne Text ist eine leere Anzeige.
    """
    daten: object = json.loads((_I18N / f"{sprache}.json").read_text(encoding="utf-8"))
    for glied in schluessel.split("."):
        assert isinstance(daten, dict), f"{schluessel}: '{glied}' ist kein Objekt"
        assert glied in daten, f"{schluessel}: '{glied}' fehlt in {sprache}.json"
        daten = daten[glied]
    assert isinstance(daten, str) and daten.strip(), f"{schluessel} ist leer in {sprache}.json"
    return daten


# ── Die Naht: Domaenen-Attribut -> Frame -> i18n-Schluessel + Zahl ────────────


def test_die_gemessene_zahl_der_domaene_erreicht_die_anzeige() -> None:
    """Die Zahl kommt aus der ECHTEN Ausnahme, nicht abgeschrieben.

    Damit prueft der Test bei jedem Wortlaut- oder Rechenwechsel weiterhin die echte
    Groesse: waechst die Summenrechnung anders, faellt hier auf.
    """
    with pytest.raises(NetzZuGrossError) as exc_info:
        ScanConfig(cidrs=("10.0.0.0/16",))
    fehler = exc_info.value

    # So baut ws_scan.py das Frame (dieselben Felder, dieselbe Quelle).
    frame = {
        "type": "error",
        "message": str(fehler),
        "grund": "netzZuGross",
        "anzahl": fehler.anzahl,
    }
    anzeige = _anzeige(str(fehler), frame)

    assert anzeige["textKey"] == _SCHLUESSEL, (
        "Das Frontend waehlt nicht den uebersetzten Text -- der Anwender saehe "
        "stattdessen den englischen Entwicklertext der Domaene."
    )
    assert anzeige["text"] is None, "Bei gewaehltem Schluessel darf kein Rohtext gesetzt sein"
    # 65536 mit deutscher Tausendertrennung.
    assert anzeige["werte"] == {"anzahl": "65.536"}


def test_die_zahl_wird_sprachabhaengig_getrennt() -> None:
    """2.4: DE trennt mit Punkt, EN mit Komma -- gemessen, nicht behauptet."""
    frame = {"type": "error", "message": "x", "grund": "netzZuGross", "anzahl": 65536}
    assert _anzeige("x", frame, "de")["werte"] == {"anzahl": "65.536"}
    assert _anzeige("x", frame, "en")["werte"] == {"anzahl": "65,536"}


def test_jeder_andere_scan_fehler_bleibt_beim_bisherigen_weg() -> None:
    """Kein Rueckfall auf einen erfundenen Grund: der Bestandspfad ist unberuehrt.

    Der "Invalid CIDR"-Fall traegt kein ``grund``-Feld -- er kommt weiterhin als
    Rohtext des Backends an, genau wie vor dieser Etappe.
    """
    frame = {"type": "error", "message": "Invalid CIDR: nonsense"}
    anzeige = _anzeige("Invalid CIDR: nonsense", frame)
    assert anzeige["textKey"] is None
    assert anzeige["text"] == "Invalid CIDR: nonsense"


def test_ohne_frame_bleibt_der_transporttext() -> None:
    """Transportfehler ohne Frame (Verbindung weg): unveraendertes Verhalten."""
    anzeige = _anzeige("Scan-Verbindung unterbrochen", None)
    assert anzeige["textKey"] is None
    assert anzeige["text"] == "Scan-Verbindung unterbrochen"


def test_unbrauchbare_anzahl_faellt_nicht_auf_den_uebersetzten_text_zurueck() -> None:
    """Ein ``grund`` ohne brauchbare Zahl darf keinen Text mit Luecke erzeugen.

    Lieber der ehrliche Entwicklertext als ein Satz, in dem "{{anzahl}}" oder
    "undefined" steht (ADR 0001: keine stillen Fallbacks).
    """
    frame = {"type": "error", "message": "Network too large", "grund": "netzZuGross"}
    anzeige = _anzeige("Network too large", frame)
    assert anzeige["textKey"] is None
    assert anzeige["text"] == "Network too large"


# ── Die Sprachdateien tragen den Text, in beiden Sprachen, mit Platzhalter ────


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_beide_sprachen_tragen_den_text_mit_platzhalter(sprache: str) -> None:
    """Der gewaehlte Schluessel muss in BEIDEN Sprachdateien einen Text haben.

    Und dieser Text muss den Platzhalter tragen -- ohne ihn erfuehre der Anwender
    nie, WIE VIELE Adressen er angegeben hat, und die ganze Naht waere umsonst.
    """
    text = _text(sprache, _SCHLUESSEL)
    assert "{{anzahl}}" in text, f"{sprache}.json: der Text traegt den Platzhalter nicht"


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_der_text_nennt_die_grenze_und_den_grund(sprache: str) -> None:
    """Der Text nennt die Obergrenze in der landesueblichen Schreibweise.

    Die Grenze wird gegen die ECHTE Konstante geprueft: wer ``MAX_SCAN_ADRESSEN``
    aendert, ohne die Texte anzupassen, faellt hier auf -- sonst naennte die Anzeige
    dauerhaft eine Zahl, die nicht mehr gilt.
    """
    text = _text(sprache, _SCHLUESSEL)
    erwartet = "4.096" if sprache == "de" else "4,096"
    assert erwartet in text, f"{sprache}.json nennt die Obergrenze nicht als {erwartet}"
    assert str(MAX_SCAN_ADRESSEN) == "4096", (
        "Die Obergrenze wurde geaendert -- die Texte in de.json/en.json nennen "
        "weiterhin 4.096 bzw. 4,096 und muessen mitgezogen werden."
    )


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_der_text_hat_zwei_absaetze(sprache: str) -> None:
    """Karls Fassung D hat ZWEI Absaetze: die Abweisung und die Begruendung.

    Der Umbruch traegt bis in die Anzeige (ObserveView.css: white-space: pre-line);
    verschwaende er hier, klebten beide Absaetze in einer Zeile zusammen.
    """
    text = _text(sprache, _SCHLUESSEL)
    assert "\n\n" in text, f"{sprache}.json: der Absatzumbruch fehlt"
