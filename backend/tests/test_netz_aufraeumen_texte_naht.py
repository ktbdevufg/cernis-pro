"""Naht-Test: die Texte des Aufraeumens + der Beweis des Dialog-Umbaus (S88-P3).

ZWEI NAEHTE werden hier geprueft, beide aus pytest heraus:

1. DIE TEXTE (Auftrag 4.6). Die neuen Bedientexte muessen in BEIDEN Sprachdateien
   stehen, zeichengenau nach Vorgabe, und die Platzhalter der Vorschau-Zeile
   muessen die sein, die die Komponente einsetzt. Ein Text ohne Platzhalter zeigte
   dem Anwender "Geraete im Netz  ()".

2. DER UMBAU (Auflage zu Entwurf A). ``ConfirmDeleteDialog.jsx`` wurde aus
   ``MaintenanceDialog.jsx`` HERAUSGEZOGEN; der Wartungsdialog muss danach exakt
   dasselbe zeigen wie vorher. Der Test rendert die ECHTE Komponente serverseitig
   und vergleicht ihr Markup gegen die eingefrorene Fassung des Bestandscodes
   (Stand 3fd12ea, ``_REFERENZ_*`` unten). Byte fuer Byte.

   WARUM DIESER BEWEIS UND NICHT "die bestehenden Tests bleiben gruen": Gemessen
   (S88-P3) hat der Wartungsdialog KEINE Tests -- weder Frontend-Tests (das
   Frontend hat kein Testframework, ``package.json`` kennt nur dev/build/preview)
   noch Naht-Tests auf ``settings.wartung.*``. Es gab also nichts, was gruen
   bleiben konnte. Statt die Auflage stillschweigend fallen zu lassen, steht hier
   ein schaerferer Beleg: nicht "kein Test ist gefallen", sondern "das Markup ist
   identisch".

WARUM AUS pytest: Wie ``test_netzgroesse_texte_naht.py`` -- die CI faehrt pytest,
und die ECHTEN Frontend-Dateien werden ueber ``node`` benutzt, statt ihre Logik in
Python nachzubauen (kein zweiter Wahrheitsstand).
"""

import json
import pathlib
import re
import subprocess

import pytest

from tests import naht_frontend

_FRONTEND = pathlib.Path(__file__).resolve().parents[2] / "frontend"
_I18N = _FRONTEND / "src" / "i18n"
_CONFIRM = _FRONTEND / "src" / "components" / "ConfirmDeleteDialog.jsx"

# Gemeinsame Bedingung (S89-A1/A5): siehe ``tests/naht_frontend.py``. Hier wird
# wirklich gerendert, darum ist die Paketliste die laengste: genannt ist JEDES Paket,
# das das Skript unten mit blossem Namen importiert und das dabei wirklich aufgeloest
# wird (``esbuild``, ``react-dom``, ``react``, ``i18next``, ``react-i18next``). Der
# Bestand nannte nur die ersten zwei -- fehlte eines der uebrigen, fiel der Test mit
# ERR_MODULE_NOT_FOUND, statt sich zu ueberspringen.
# ``dateien`` traegt nur den Einstieg ``ConfirmDeleteDialog.jsx``. ``lib/fehlercodes.js``,
# das ``bundle: true`` ueber dessen Import mitzieht, steht bewusst nicht hier:
# transitive Quellen gehoeren in keine Liste, ihr Fehlen ist der laute esbuild-Fehler
# (S89-A5).
_riegel = naht_frontend.riegel(
    dateien=(_CONFIRM,),
    pakete=("esbuild", "react-dom", "react", "i18next", "react-i18next"),
)

# Der i18n-Zweig der neuen Bedientexte.
_ZWEIG = "geraete.verwaltung.aufraeumen"


def _text(sprache: str, schluessel: str) -> str:
    """Loest einen punktierten Schluessel in der echten Sprachdatei auf.

    Fehlt ein Glied, faellt der Test -- ein Schluessel ohne Text ist eine leere
    Anzeige (Muster ``test_netzgroesse_texte_naht.py``).
    """
    daten: object = json.loads((_I18N / f"{sprache}.json").read_text(encoding="utf-8"))
    for glied in schluessel.split("."):
        assert isinstance(daten, dict), f"{schluessel}: '{glied}' ist kein Objekt"
        assert glied in daten, f"{schluessel}: '{glied}' fehlt in {sprache}.json"
        daten = daten[glied]
    assert isinstance(daten, str) and daten.strip(), f"{schluessel} ist leer in {sprache}.json"
    return daten


# ── 1. Die Texte, zeichengenau nach Vorgabe ──────────────────────────────────

# Karls Vorgaben aus dem Auftrag -- WOERTLICH, inklusive Umlauten. Steht hier als
# Erwartung im Test, damit eine spaetere Umformulierung eine bewusste Entscheidung
# ist und nicht unbemerkt passiert.
_VORGABEN = {
    "de": {
        "knopf": "Nach Netz aufräumen",
        "titelAuswahl": "Welche Geräte sollen entfernt werden?",
        "ohneIp": "Ohne bekannte IP",
        "hinweis": (
            "Die Zuordnung stammt aus der zuletzt bekannten IP eines Geräts. "
            "Wurde ein Gerät inzwischen in einem anderen Netz gesehen, erscheint es dort."
        ),
        "vorschauPosten": "Geräte im Netz {{netz}} ({{anzahl}})",
    },
    "en": {
        "knopf": "Clean up by network",
        "titelAuswahl": "Which devices should be removed?",
        "ohneIp": "Without known IP",
        "hinweis": (
            "The assignment comes from a device's last known IP. If a device has "
            "since been seen in a different network, it appears there."
        ),
        "vorschauPosten": "Devices in network {{netz}} ({{anzahl}})",
    },
}


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_die_vorgegebenen_texte_stehen_zeichengenau_in_der_sprachdatei(sprache: str) -> None:
    """Jeder vorgegebene Text steht WOERTLICH in seiner Sprachdatei."""
    for schluessel, erwartet in _VORGABEN[sprache].items():
        assert _text(sprache, f"{_ZWEIG}.{schluessel}") == erwartet, (
            f"{sprache}.json: {schluessel} weicht von der Vorgabe ab"
        )


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_die_vorschau_zeile_traegt_beide_platzhalter(sprache: str) -> None:
    """Ohne die Platzhalter saehe der Anwender "Geraete im Netz  ()".

    Die Namen muessen genau die sein, die ``NetzAufraeumenDialog.jsx`` einsetzt
    (``netz`` und ``anzahl``) -- ein umbenannter Platzhalter bliebe im Text stehen.
    """
    text = _text(sprache, f"{_ZWEIG}.vorschauPosten")
    assert "{{netz}}" in text, f"{sprache}.json: der Platzhalter netz fehlt"
    assert "{{anzahl}}" in text, f"{sprache}.json: der Platzhalter anzahl fehlt"


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_alle_bedientexte_des_zweiges_sind_in_beiden_sprachen_da(sprache: str) -> None:
    """Kein Schluessel darf in einer der beiden Sprachen fehlen.

    Ein fehlender Schluessel faellt im Betrieb nicht auf -- i18next zeigt dann den
    Schluesselnamen selbst an, und der Anwender liest "geraete.verwaltung...".
    """
    for schluessel in (
        "knopf",
        "titelAuswahl",
        "ohneIp",
        "hinweis",
        "vorschauPosten",
        "weiter",
        "nichtsGewaehlt",
        "leer",
        "ladeFehler",
    ):
        _text(sprache, f"{_ZWEIG}.{schluessel}")


def test_beide_sprachdateien_fuehren_denselben_satz_schluessel() -> None:
    """Gleichlauf der beiden Dateien -- kein einseitig nachgepflegter Zweig."""
    zweige = {}
    for sprache in ("de", "en"):
        daten = json.loads((_I18N / f"{sprache}.json").read_text(encoding="utf-8"))
        zweige[sprache] = set(daten["geraete"]["verwaltung"]["aufraeumen"])
    assert zweige["de"] == zweige["en"], (
        f"Nur in de: {zweige['de'] - zweige['en']}; nur in en: {zweige['en'] - zweige['de']}"
    )


def test_der_backend_wert_fuer_geraete_ohne_ip_wird_im_frontend_uebersetzt() -> None:
    """Die Naht zwischen Backend-Kennung und Anzeige-Text.

    Das Backend schickt fuer Geraete ohne brauchbare IP die Kennung ``ohne-ip``
    (``application/maintenance/netz_aufraeumen.py``); ``NetzAufraeumenDialog.jsx``
    loest genau diese Kennung in den uebersetzten Namen auf. Weichen beide
    voneinander ab, stuende in der Liste die rohe Kennung statt "Ohne bekannte IP".
    """
    from application.maintenance import OHNE_IP

    quelle = (_FRONTEND / "src" / "components" / "NetzAufraeumenDialog.jsx").read_text(
        encoding="utf-8"
    )
    assert f'const OHNE_IP = "{OHNE_IP}"' in quelle, (
        f"Das Frontend kennt die Backend-Kennung {OHNE_IP!r} nicht (mehr)"
    )


# ── 2. Der Umbau-Beweis: identisches Markup vor und nach der Extraktion ──────

# Das Markup, das der BESTANDSCODE (Stand 3fd12ea) an dieser Stelle erzeugt hat --
# aufgenommen, bevor Fenster 2 aus MaintenanceDialog.jsx herausgezogen wurde, mit
# den echten Texten aus de.json. Aendert sich die extrahierte Komponente, faellt
# der Vergleich auf.
#
# Zwei Lagen, weil der Wartungsdialog genau zwei kennt: Werkszustand (mit dem
# Secrets-Kaestchen) und Baukasten-Auswahl (ohne Kaestchen, hier mit Fehlerzeile).
_REFERENZ_FACTORY = (
    '<div class="maint-dialog__body">'
    '<p class="maint-confirm__lead">Folgendes wird unwiderruflich gelöscht:</p>'
    '<ul class="maint-confirm__list">'
    '<li class="maint-confirm__item">Alle Scan-Daten</li>'
    '<li class="maint-confirm__item">Geräte-Gedächtnis und Notizen</li>'
    '<li class="maint-confirm__item">Monitoring-Aufzeichnungen</li>'
    '<li class="maint-confirm__item">Einstellungen</li>'
    "</ul>"
    '<label class="maint-confirm__secrets">'
    '<input type="checkbox" class="maint-confirm__checkbox"/>'
    "<span>Auch gespeicherte Zugangsdaten entfernen "
    "(cpnetcheck-Token im Schlüsselbund)</span></label>"
    '<div class="maint-confirm__warn" role="alert">'
    "Kann nicht rückgängig gemacht werden. Sind Sie sicher?</div>"
    '<div class="maint-dialog__actions">'
    '<button type="button" class="maint-button">Zurück</button>'
    '<button type="button" class="maint-button maint-button--danger">'
    "Endgültig löschen</button></div></div>"
)

_REFERENZ_SELECTED = (
    '<div class="maint-dialog__body">'
    '<p class="maint-confirm__lead">Folgendes wird unwiderruflich gelöscht:</p>'
    '<ul class="maint-confirm__list">'
    '<li class="maint-confirm__item">Scan-Historie</li>'
    '<li class="maint-confirm__item">CVE-Befunde und Quittierungen</li>'
    "</ul>"
    '<div class="maint-confirm__warn" role="alert">'
    "Kann nicht rückgängig gemacht werden. Sind Sie sicher?</div>"
    '<span class="maint-dialog__error">Löschen fehlgeschlagen. '
    "Bitte erneut versuchen. (E-502)</span>"
    '<div class="maint-dialog__actions">'
    '<button type="button" class="maint-button">Zurück</button>'
    '<button type="button" class="maint-button maint-button--danger">'
    "Endgültig löschen</button></div></div>"
)

# Rendert ConfirmDeleteDialog serverseitig mit den Props, die MaintenanceDialog.jsx
# ihr in seinen zwei Lagen uebergibt. esbuild uebersetzt das JSX (das Frontend hat
# keinen eigenen Test-Runner), react-dom/server rendert.
_RENDER_SKRIPT = r"""
import { build } from "esbuild";
import { renderToStaticMarkup } from "react-dom/server";
import React from "react";
import { writeFileSync, unlinkSync, readFileSync } from "fs";
import i18n from "i18next";
import { initReactI18next } from "react-i18next";

const de = JSON.parse(readFileSync("./src/i18n/de.json", "utf8"));
await i18n.use(initReactI18next).init({
  lng: "de", resources: { de: { translation: de } },
  interpolation: { escapeValue: false },
});

const out = await build({
  entryPoints: ["./src/components/ConfirmDeleteDialog.jsx"],
  bundle: true, write: false, format: "esm", jsx: "automatic",
  external: ["react", "react-dom", "react-i18next", "lucide-react"],
  loader: { ".css": "empty" },
});
const tmp = "./.naht-confirm-" + process.pid + ".mjs";
writeFileSync(tmp, out.outputFiles[0].text);
let mod;
try { mod = await import(tmp); } finally { unlinkSync(tmp); }

const c = de.settings.wartung.confirm;
const ergebnis = {
  factory: renderToStaticMarkup(React.createElement(mod.default, {
    posten: [c.factory.item1, c.factory.item2, c.factory.item3, c.factory.item4],
    kaestchen: { text: c.includeSecrets, checked: false, onChange: () => {} },
    fehler: false, laeuft: false, onZurueck: () => {}, onBestaetigen: () => {},
  })),
  selected: renderToStaticMarkup(React.createElement(mod.default, {
    posten: ["Scan-Historie", "CVE-Befunde und Quittierungen"],
    kaestchen: null,
    fehler: true, laeuft: false, onZurueck: () => {}, onBestaetigen: () => {},
  })),
};
process.stdout.write(JSON.stringify(ergebnis));
"""


def _gerendert() -> dict[str, str]:
    """Rendert die ECHTE ConfirmDeleteDialog-Komponente ueber node."""
    ergebnis = subprocess.run(
        ["node", "--input-type=module", "-e", _RENDER_SKRIPT],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=_FRONTEND,
    )
    assert ergebnis.returncode == 0, f"node scheiterte: {ergebnis.stderr}"
    geladen: object = json.loads(ergebnis.stdout)
    assert isinstance(geladen, dict)
    return {str(k): str(v) for k, v in geladen.items()}


def test_der_werkszustand_sieht_aus_wie_vor_dem_umbau() -> None:
    """Die Werkszustands-Bestaetigung: identisches Markup, inkl. Secrets-Kaestchen."""
    assert _gerendert()["factory"] == _REFERENZ_FACTORY


def test_die_baukasten_bestaetigung_sieht_aus_wie_vor_dem_umbau() -> None:
    """Die Baukasten-Bestaetigung: identisches Markup, inkl. Fehlerzeile mit E-502.

    Deckt zugleich 3.6 ab: der Fehlercode dieses Weges ist E-502, und die
    Geraeteverwaltung fuehrt ueber DIESELBE Komponente denselben.
    """
    assert _gerendert()["selected"] == _REFERENZ_SELECTED


def test_der_bestaetigungsweg_existiert_genau_einmal() -> None:
    """Kein Nachbau: das Markup steht NUR in der geteilten Komponente.

    Faende sich ``maint-confirm__lead`` ein zweites Mal in einer Komponente, waere
    der Weg doppelt ausgelegt -- genau das, was der Umbau verhindern sollte.
    """
    komponenten = (_FRONTEND / "src" / "components").glob("*.jsx")
    traeger = [
        pfad.name
        for pfad in komponenten
        if "maint-confirm__lead" in pfad.read_text(encoding="utf-8")
    ]
    assert traeger == ["ConfirmDeleteDialog.jsx"], (
        f"Der Bestaetigungsweg steht in mehr als einer Komponente: {traeger}"
    )


def test_beide_aufrufer_benutzen_die_geteilte_komponente() -> None:
    """Wartungsdialog UND Geraeteverwaltung fuehren denselben Bestaetigungsweg."""
    for name in ("MaintenanceDialog.jsx", "NetzAufraeumenDialog.jsx"):
        quelle = (_FRONTEND / "src" / "components" / name).read_text(encoding="utf-8")
        assert "ConfirmDeleteDialog" in quelle, f"{name} benutzt die geteilte Komponente nicht"


def test_die_geteilte_komponente_kennt_ihre_aufrufer_nicht() -> None:
    """Auflage: kein Schalter der Bauart "wenn Geraeteaufraeumung, dann anders".

    Der CODE darf weder seine Aufrufer noch deren Fachbegriffe nennen -- alles reist
    als Prop herein. Sonst waere die Trennung nur nominell.

    Geprueft wird der Code OHNE Kommentare: der Kopf-Kommentar der Komponente nennt
    ``MaintenanceDialog.jsx`` bewusst, weil er die Herkunft des Markups festhaelt
    (es wurde von dort herausgezogen, nicht neu erfunden). Eine Erklaerung ist keine
    Fallunterscheidung -- verboten ist die Kenntnis im VERHALTEN, nicht im Text.
    """
    quelle = _CONFIRM.read_text(encoding="utf-8")
    # Zeilen-Kommentare (//) und Block-Kommentare im JSX ({/* ... */}) entfernen.
    ohne_zeilenkommentare = "\n".join(
        zeile for zeile in quelle.splitlines() if not zeile.lstrip().startswith("//")
    )
    code = re.sub(r"\{/\*.*?\*/\}", "", ohne_zeilenkommentare, flags=re.DOTALL)

    for verboten in ("factory", "STUFE_", "aufraeumen", "netz", "MaintenanceDialog"):
        assert verboten not in code, (
            f"ConfirmDeleteDialog.jsx nennt {verboten!r} im CODE -- sie kennt damit einen Aufrufer"
        )
