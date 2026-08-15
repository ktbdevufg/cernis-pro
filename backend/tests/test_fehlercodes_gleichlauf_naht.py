"""Naht-Test: laufen die vier Orte der Fehlercode-Tabelle gleich? (S85-A10, Befund 65)

DER ANLASS: Ein Fehlercode wird an VIER Orten gefuehrt, und keiner davon kennt die
anderen:

1. ``frontend/src/lib/fehlercodes.js``       -- die Codes selbst (``CODES``), Quelle
2. ``frontend/src/i18n/de.json``             -- Kurztext deutsch  (Zweig ``fehlercodes``)
3. ``frontend/src/i18n/en.json``             -- Kurztext englisch (Zweig ``fehlercodes``)
4. ``frontend/src/lib/help_content.json``    -- die Liste im Hilfe-Text
                                                ``help.allgemein.fehlercodes``, de + en

Ein neuer Code, der nur an drei Orten ankommt, faellt nirgends auf: die Anwendung
uebersetzt weiterhin, der Build laeuft durch -- der Anwender sieht lediglich einen
nackten Code ohne Text oder findet ihn im Handbuch nicht. Genau diese Luecke schliesst
dieser Test: er haelt die Gleichlaeufigkeit fest, nicht den einzelnen Wortlaut.

WARUM AUS pytest: Das Frontend hat kein eigenes Testframework (``frontend/package.json``
kennt nur dev/build/preview); die CI faehrt ``pytest``. Muster und Begruendung wie in
``backend/tests/test_werkzeug_fehler_texte_naht.py`` -- die Codes werden ueber ``node``
aus dem ECHTEN Modul gelesen, nicht in Python nachgebaut, sonst entstuende hier ein
zweiter Wahrheitsstand neben der Tabelle.

WAS DIESER TEST NICHT PRUEFT: ob ein Text gut formuliert ist, und ob ein Code auch
tatsaechlich irgendwo geworfen wird. Das Erste ist eine Entscheidung Karls, das Zweite
haengt am Backend, das die Codes als Text-Anhang ``(E-xxx)`` fuehrt (kein eigenes Feld).
"""

import json
import pathlib
import re
import subprocess

import pytest

from tests import naht_frontend

_FRONTEND = pathlib.Path(__file__).resolve().parents[2] / "frontend"
_FEHLERCODES_JS = _FRONTEND / "src" / "lib" / "fehlercodes.js"
_HELP_JSON = _FRONTEND / "src" / "lib" / "help_content.json"
_I18N = _FRONTEND / "src" / "i18n"

_HILFE_SCHLUESSEL = "help.allgemein.fehlercodes"

# Gemeinsame Bedingung (S89-A1): lokal ueberspringen, in der CI fallen -- siehe
# ``tests/naht_frontend.py``. Kein Buendeln hier, darum keine node_modules-Pakete.
_riegel = naht_frontend.riegel(dateien=(_FEHLERCODES_JS,))


def _codes_aus_dem_modul() -> list[str]:
    """Liest ``ALLE_CODES`` aus dem ECHTEN ``fehlercodes.js`` ueber node.

    Bewusst das Modul und keine Regex ueber die Datei: die Tabelle ist die Quelle, und
    nur so faellt auch ein Eintrag auf, der syntaktisch anders geschrieben ist.
    """
    modul = _FEHLERCODES_JS.resolve().as_uri()
    skript = (
        f"import {{ ALLE_CODES }} from {json.dumps(modul)};\n"
        "process.stdout.write(JSON.stringify(ALLE_CODES));\n"
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
    assert isinstance(geladen, list) and geladen, "ALLE_CODES ist leer oder keine Liste"
    return [str(c) for c in geladen]


def _i18n_codes(sprache: str) -> dict[str, str]:
    """Der Zweig ``fehlercodes`` aus einer Sprachdatei."""
    daten = json.loads((_I18N / f"{sprache}.json").read_text(encoding="utf-8"))
    zweig = daten["fehlercodes"]
    assert isinstance(zweig, dict), f"Zweig 'fehlercodes' fehlt in {sprache}.json"
    return {str(k): str(v) for k, v in zweig.items()}


def _hilfe_codes(sprache: str) -> dict[str, str]:
    """Die Codes aus der Liste im Hilfe-Text, als {Code: Zeilentext}.

    Die Liste steht als Fliesstext im Feld ``lang`` (Zeilen der Form ``E-xxx - Text``) --
    so fuehrt der Bestand sie; hier wird sie gelesen, nicht umgebaut.
    """
    daten = json.loads(_HELP_JSON.read_text(encoding="utf-8"))
    text = daten[_HILFE_SCHLUESSEL][sprache]["lang"]
    assert isinstance(text, str) and text.strip(), f"{_HILFE_SCHLUESSEL}/{sprache} ist leer"
    gefunden: dict[str, str] = {}
    for zeile in text.split("\n"):
        treffer = re.match(r"^(E-\d{3})\s+-\s+(.+)$", zeile.strip())
        if treffer:
            gefunden[treffer.group(1)] = treffer.group(2).strip()
    assert gefunden, f"In {_HILFE_SCHLUESSEL}/{sprache} steht keine Code-Liste"
    return gefunden


# ── Die Gleichlaeufigkeit selbst ──────────────────────────────────────────────


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_jeder_code_der_tabelle_hat_einen_kurztext_in_beiden_sprachen(sprache: str) -> None:
    """Jeder Code aus ``CODES`` steht im i18n-Zweig -- sonst bleibt die Anzeige leer."""
    fehlend = [c for c in _codes_aus_dem_modul() if c not in _i18n_codes(sprache)]

    assert not fehlend, f"Ohne Kurztext in {sprache}.json: {fehlend}"


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_der_i18n_zweig_fuehrt_keinen_code_den_die_tabelle_nicht_kennt(sprache: str) -> None:
    """Die Gegenrichtung: ein Text ohne Code in der Tabelle ist ein Ueberbleibsel.

    Er waere unerreichbar -- ``i18nKeyFuerCode`` wird nur mit Werten aus ``CODES``
    gerufen -- und stuende beim naechsten Leser als vermeintlich gepflegter Eintrag.
    """
    bekannt = set(_codes_aus_dem_modul())
    ueberzaehlig = [c for c in _i18n_codes(sprache) if c not in bekannt]

    assert not ueberzaehlig, f"In {sprache}.json, aber nicht in fehlercodes.js: {ueberzaehlig}"


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_jeder_code_der_tabelle_steht_in_der_hilfe_liste(sprache: str) -> None:
    """Der Hilfe-Text nennt sich "Die vollstaendige Liste" -- dann muss er das auch sein.

    Ein fehlender Code hiesse: der Anwender schlaegt genau den Code nach, den er gerade
    sieht, und findet ihn nicht.
    """
    fehlend = [c for c in _codes_aus_dem_modul() if c not in _hilfe_codes(sprache)]

    assert not fehlend, f"Nicht in der Hilfe-Liste ({sprache}): {fehlend}"


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_die_hilfe_liste_fuehrt_keinen_code_den_die_tabelle_nicht_kennt(sprache: str) -> None:
    """Auch hier die Gegenrichtung: kein Eintrag zu einem Code, den es nicht gibt."""
    bekannt = set(_codes_aus_dem_modul())
    ueberzaehlig = [c for c in _hilfe_codes(sprache) if c not in bekannt]

    assert not ueberzaehlig, (
        f"In der Hilfe-Liste ({sprache}), aber nicht in fehlercodes.js: {ueberzaehlig}"
    )


def test_beide_sprachen_fuehren_dieselben_codes() -> None:
    """de und en duerfen nicht auseinanderlaufen -- weder im i18n-Zweig noch in der Hilfe."""
    assert set(_i18n_codes("de")) == set(_i18n_codes("en")), "i18n-Zweige laufen auseinander"
    assert set(_hilfe_codes("de")) == set(_hilfe_codes("en")), "Hilfe-Listen laufen auseinander"


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_kein_kurztext_ist_leer(sprache: str) -> None:
    """Ein leerer Text ist so gut wie ein fehlender -- der Anwender sieht nur den Code."""
    leer = [c for c, t in _i18n_codes(sprache).items() if not t.strip()]

    assert not leer, f"Leerer Kurztext in {sprache}.json: {leer}"


# ── Der Anlass des Auftrags: E-507 ist an allen Orten angekommen ──────────────


def test_e507_steht_an_allen_vier_orten() -> None:
    """Der neu vergebene Code des Verlustfalls (Befund 65, Fassung B).

    Ausdruecklich neben den allgemeinen Regeln oben: die halten den Gleichlauf fuer JEDEN
    Code fest, dieser hier benennt den Fall, um den es in S85-A10 ging -- faellt er,
    steht im Fehlertext sofort, welcher Code gemeint ist.
    """
    assert "E-507" in _codes_aus_dem_modul(), "E-507 fehlt in fehlercodes.js"
    for sprache in ("de", "en"):
        assert "E-507" in _i18n_codes(sprache), f"E-507 fehlt in {sprache}.json"
        assert "E-507" in _hilfe_codes(sprache), f"E-507 fehlt in der Hilfe-Liste ({sprache})"


def test_e507_gehoert_zur_klasse_der_aktionen_und_daten() -> None:
    """Karls Entscheidung: E-5xx (Aktionen und Daten), KEINE neue Klasse.

    Die Klasse ist die erste Ziffer; ein E-6xx haette eine Klasse aufgemacht, die weder
    die Tabelle noch der Hilfe-Text kennt.
    """
    assert "E-507".startswith("E-5")
    klassen = {c[:3] for c in _codes_aus_dem_modul()}

    assert klassen == {"E-1", "E-2", "E-3", "E-4", "E-5"}, (
        f"Die Klassen der Tabelle haben sich geaendert: {sorted(klassen)}"
    )
