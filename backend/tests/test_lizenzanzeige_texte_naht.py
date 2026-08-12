"""Naht-Test: kennen BEIDE Sprachdateien jeden Schluessel, den die Lizenzanzeige waehlt?

DER BEFUND (S84-A9, Befund 54b und die vier Anzeigedefekte): die Lizenzanzeige hat
in dieser Etappe neue Zustaende und neue Bedienelemente bekommen -- den vierten
Vorhandenseins-Zustand ``nicht_ermittelbar``, die drei Abstufungen des Feldes
``bezugsart``, die Filteroption fuer die Eintraege ohne Lizenzangabe, die
Gruppen-Option des Herkunftsfilters und den Schalter aus Abschnitt 2. Jeder davon
ist ein Schluessel, und ein Schluessel, den ``de.json`` oder ``en.json`` nicht
kennt, ist in der Anzeige eine leere Stelle oder der rohe Schluesselname.

WARUM AUS pytest, obwohl es Frontend-Text ist: das Frontend hat kein eigenes
Testframework (``frontend/package.json`` kennt nur dev/build/preview), die CI
faehrt ``pytest``. Dasselbe Vorgehen wie in
``test_traffic_permission_texte_naht.py``.

WARUM DIE ZUSTANDSNAMEN AUS DEM BACKEND KOMMEN und nicht hier noch einmal
aufgeschrieben werden: die Werte entstehen im Use-Case
(``application/license_manifest/use_cases.py``) bzw. im Sammler
(``scripts/gen_license_manifest.py``). Aus ihnen baut die Anzeige den
i18n-Schluessel zusammen (``lizenzen.vorhanden.<zustand>``,
``lizenzen.bezugsart.<art>``). Ein zweiter Wahrheitsstand hier faenge genau den
Fall nicht, um den es geht: dass jemand einen Zustand hinzufuegt und die
Sprachdateien vergisst.
"""

import importlib.util
import json
import pathlib
import sys
from types import ModuleType
from typing import Any

import pytest

import application.license_manifest.use_cases as use_cases

_WURZEL = pathlib.Path(__file__).resolve().parents[2]
_I18N = _WURZEL / "frontend" / "src" / "i18n"
_SAMMLER_PFAD = _WURZEL / "scripts" / "gen_license_manifest.py"


def _lade_sammler() -> ModuleType:
    """Laedt den Sammler ueber seinen Pfad (``scripts/`` ist kein Paket)."""
    spezifikation = importlib.util.spec_from_file_location("gen_license_manifest", _SAMMLER_PFAD)
    assert spezifikation is not None and spezifikation.loader is not None
    modul = importlib.util.module_from_spec(spezifikation)
    sys.modules[spezifikation.name] = modul
    spezifikation.loader.exec_module(modul)
    return modul


_sammler = _lade_sammler()


def _sprachdatei(sprache: str) -> dict[str, Any]:
    with (_I18N / f"{sprache}.json").open(encoding="utf-8") as strom:
        daten: dict[str, Any] = json.load(strom)
    return daten


def _nachschlagen(daten: dict[str, Any], schluessel: str) -> Any:
    """Loest einen punktgetrennten i18n-Schluessel auf. ``None``, wenn er fehlt."""
    knoten: Any = daten
    for teil in schluessel.split("."):
        if not isinstance(knoten, dict) or teil not in knoten:
            return None
        knoten = knoten[teil]
    return knoten


#: Die Schluessel, die diese Etappe NEU eingefuehrt hat. Sie stehen hier
#: NAMENTLICH, weil genau ihr Fehlen der Befund waere -- eine aus den Dateien
#: abgeleitete Liste pruefte sich selbst und faende nichts.
NEUE_SCHLUESSEL: tuple[str, ...] = (
    "lizenzen.abschnitt.bestandteile.imBrowserZeigen",
    "lizenzen.filter.ohneLizenzId",
    "lizenzen.filter.mitgelieferteBestandteile",
    "lizenzen.vorhanden.nicht_ermittelbar",
    "lizenzen.bezugsart.aufgerufen",
    "lizenzen.bezugsart.vorausgesetzt",
    "lizenzen.bezugsart.aufgerufen_und_vorausgesetzt",
    "lizenzen.feld.bezugsart",
    "lizenzen.feld.binaries",
)


@pytest.mark.parametrize("sprache", ["de", "en"])
@pytest.mark.parametrize("schluessel", NEUE_SCHLUESSEL)
def test_jeder_neue_schluessel_liegt_in_beiden_sprachdateien(sprache: str, schluessel: str) -> None:
    """Teil 4, ausdruecklich: jeder neue Schluessel in de.json UND en.json."""
    wert = _nachschlagen(_sprachdatei(sprache), schluessel)
    assert isinstance(wert, str), f"{sprache}: {schluessel} fehlt"
    assert wert.strip() != "", f"{sprache}: {schluessel} ist leer"


def test_die_beiden_sprachdateien_bleiben_schluesselgleich() -> None:
    """Keine Sprache traegt einen Schluessel, den die andere nicht kennt.

    Der Einzelnachweis oben prueft die neuen Schluessel; dieser hier haelt die
    Zusage fuer den GANZEN Bestand -- sonst schuetzt der Test nur genau das, was
    beim Schreiben schon bedacht war.
    """

    def flach(knoten: Any, praefix: str = "") -> set[str]:
        if not isinstance(knoten, dict):
            return {praefix}
        gesammelt: set[str] = set()
        for name, wert in knoten.items():
            gesammelt |= flach(wert, f"{praefix}.{name}" if praefix else name)
        return gesammelt

    de = flach(_sprachdatei("de"))
    en = flach(_sprachdatei("en"))
    assert de - en == set(), f"nur in de.json: {sorted(de - en)}"
    assert en - de == set(), f"nur in en.json: {sorted(en - de)}"


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_jeder_vorhandenseins_zustand_des_use_case_hat_eine_beschriftung(
    sprache: str,
) -> None:
    """Die Anzeige baut ``lizenzen.vorhanden.<zustand>`` -- alle vier muessen da sein.

    Die Zustaende kommen aus dem Use-Case, nicht aus einer Liste hier: kaeme ein
    fuenfter hinzu, faellt dieser Test, statt dass die Anzeige still den rohen
    Zustandsnamen zeigte.
    """
    zustaende = (
        use_cases._VORHANDEN,
        use_cases._FEHLT,
        use_cases._NICHT_ZUTREFFEND,
        use_cases._NICHT_ERMITTELBAR,
    )
    daten = _sprachdatei(sprache)
    for zustand in zustaende:
        wert = _nachschlagen(daten, f"lizenzen.vorhanden.{zustand}")
        assert isinstance(wert, str) and wert.strip() != "", f"{sprache}: {zustand}"


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_jede_bezugsart_des_sammlers_hat_eine_beschriftung(sprache: str) -> None:
    """Die Anzeige baut ``lizenzen.bezugsart.<art>`` aus dem Wert der Aufstellung.

    Die Werte kommen aus dem Sammler. Eine vierte Abstufung ohne Beschriftung
    zeigte in der Oberflaeche den rohen Bezeichner -- deutsch, ohne Umlaute und
    mit Unterstrichen, also erkennbar Maschinentext.
    """
    daten = _sprachdatei(sprache)
    for art in sorted(_sammler.ZULAESSIGE_BEZUGSARTEN):
        wert = _nachschlagen(daten, f"lizenzen.bezugsart.{art}")
        assert isinstance(wert, str) and wert.strip() != "", f"{sprache}: {art}"


def test_die_schalterbeschriftung_steht_im_vorgegebenen_wortlaut() -> None:
    """Der Wortlaut war vorgegeben und ist keine freie Formulierung.

    Er selbst traegt keinen Umlaut; die uebrigen neuen deutschen Texte tun es und
    werden vom Test darunter geprueft.
    """
    de = _nachschlagen(_sprachdatei("de"), "lizenzen.abschnitt.bestandteile.imBrowserZeigen")
    en = _nachschlagen(_sprachdatei("en"), "lizenzen.abschnitt.bestandteile.imBrowserZeigen")
    assert de == "Im Lizenz-Browser anzeigen"
    assert en == "Show in the license browser"


def test_die_neuen_deutschen_texte_tragen_keine_ersatzschreibung() -> None:
    """Wo ein Umlaut hingehoert, steht einer -- keine ``ae``/``oe``/``ue``-Form.

    Die Umlaut-Vermeidung des Projekts gilt fuer QUELLTEXT (Bezeichner,
    Kommentare), nicht fuer das, was der Anwender liest. In den Sprachdateien
    waere sie ein Fehler.

    Geprueft werden die konkreten Woerter, die in diesen neun Texten vorkommen
    KOENNTEN und einen Umlaut tragen -- nicht die Buchstabenfolgen ``ae``/``oe``/
    ``ue`` als solche: die stehen voellig regulaer in Woertern wie "aktuell" oder
    "Auswertung" und ergaeben lauter Falschtreffer.
    """
    daten = _sprachdatei("de")
    ersatzformen = ("Fuer", "fuer", "Ueber", "ueber", "waehlt", "Loesung", "gehoert")
    for schluessel in NEUE_SCHLUESSEL:
        wert = _nachschlagen(daten, schluessel)
        assert isinstance(wert, str)
        for form in ersatzformen:
            assert form not in wert, f"{schluessel}: Ersatzschreibung {form!r} in {wert!r}"
