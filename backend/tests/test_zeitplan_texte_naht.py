"""Naht-Test: sind die Zeitplan-Wortlaute vollstaendig hinterlegt? (S88-P5)

DER ANLASS: Der Zeitplan-Ausgang reist bereits ueber ``GET /api/schedules`` in den
Spalten ``last_result`` ('ok'/'failed'/NULL) und ``last_error``. Eine
Zeitplan-Ansicht gibt es im Frontend NICHT -- ``/api/schedules`` wird dort nirgends
gerufen. Karls Entscheidung (Fassung C, S88-P5): die Wortlaute werden trotzdem
schon HINTERLEGT, damit sie da sind, wenn die Ansicht kommt.

WAS DIESER TEST HAELT: dass die drei Faelle in BEIDEN Sprachen und
SCHLUESSELGLEICH vorliegen -- ein Wortlaut, den nur ``de.json`` kennt, ist die
haelftige Version des Problems, das der Anschluss spaeter loesen soll.

WAS DIESER TEST AUSDRUECKLICH NICHT HAELT: dass die Schluessel irgendwo GERUFEN
werden. Sie werden es heute nicht, und das ist so gewollt (2.2/2.3). Genau diese
Lage -- ein Wortlaut ohne Aufrufer -- war in Sitzung 85 der Befund E-507. Sie ist
hier BENANNT statt entdeckt: der ``_hinweis``-Schluessel in beiden Katalogen sagt
es im Katalog selbst, dieser Test sagt es im Test.
"""

import json
import pathlib

_FRONTEND = pathlib.Path(__file__).resolve().parents[2] / "frontend"
_I18N = _FRONTEND / "src" / "i18n"

# Die drei Ausgaenge, die ``last_result`` kennt: 'ok', 'failed', NULL.
_SCHLUESSEL = ("letzterLaufOk", "letzterLaufFehlgeschlagen", "letzterLaufNie")

# Der echte Halbgeviertstrich (U+2014), nicht der Bindestrich (U+002D).
_GEDANKENSTRICH = "—"

# Karls Wortlaut, zeichengenau (Fassung C, S88-P5). Die Platzhalter sind
# i18next-Interpolation und je Sprache benannt.
_WORTLAUTE = {
    "de": {
        "letzterLaufOk": "{{zeit}} — erfolgreich",
        "letzterLaufFehlgeschlagen": "{{zeit}} — fehlgeschlagen ({{grund}})",
        "letzterLaufNie": "noch nicht gelaufen",
    },
    "en": {
        "letzterLaufOk": "{{time}} — succeeded",
        "letzterLaufFehlgeschlagen": "{{time}} — failed ({{reason}})",
        "letzterLaufNie": "not run yet",
    },
}


def _zweig(sprache: str) -> dict[str, str]:
    """Der ``zeitplan``-Zweig der echten Sprachdatei."""
    daten = json.loads((_I18N / f"{sprache}.json").read_text(encoding="utf-8"))
    assert "zeitplan" in daten, f"Der Zweig 'zeitplan' fehlt in {sprache}.json"
    zweig = daten["zeitplan"]
    assert isinstance(zweig, dict), f"'zeitplan' ist kein Objekt in {sprache}.json"
    return zweig


def test_die_vier_zeitplan_texte_liegen_in_beiden_sprachen_vor() -> None:
    """Aufgabe 3.3, erste Haelfte: vorhanden und nicht leer, de wie en.

    Vier Texte: die drei Ausgaenge plus der ``_hinweis``, der festhaelt, dass sie
    auf ihre Ansicht warten. Der Hinweis ist ausdruecklich Teil des Bestands -- er
    ist das, was den fehlenden Aufrufer erklaert.
    """
    for sprache in ("de", "en"):
        zweig = _zweig(sprache)
        for schluessel in (*_SCHLUESSEL, "_hinweis"):
            assert schluessel in zweig, f"zeitplan.{schluessel} fehlt in {sprache}.json"
            assert isinstance(zweig[schluessel], str) and zweig[schluessel].strip(), (
                f"zeitplan.{schluessel} ist leer in {sprache}.json"
            )


def test_die_zeitplan_texte_sind_schluesselgleich() -> None:
    """Aufgabe 3.3, zweite Haelfte: exakt dieselbe Schluesselmenge in beiden Katalogen."""
    de = set(_zweig("de"))
    en = set(_zweig("en"))

    assert de - en == set(), f"nur in de.json: {sorted(de - en)}"
    assert en - de == set(), f"nur in en.json: {sorted(en - de)}"


def test_die_zeitplan_texte_lauten_zeichengenau_wie_entschieden() -> None:
    """Der Wortlaut selbst, Zeichen fuer Zeichen -- inklusive der Platzhalternamen."""
    for sprache in ("de", "en"):
        zweig = _zweig(sprache)
        for schluessel, erwartet in _WORTLAUTE[sprache].items():
            assert zweig[schluessel] == erwartet, (
                f"zeitplan.{schluessel} ({sprache}): {zweig[schluessel]!r} != {erwartet!r}"
            )


def test_die_zeitplan_texte_tragen_den_echten_gedankenstrich() -> None:
    """Aufgabe 3.4: Halbgeviertstrich, kein Bindestrich -- in beiden Sprachen.

    Nur die beiden Texte mit Zeitangabe tragen ihn; ``letzterLaufNie`` hat keinen.
    """
    for sprache in ("de", "en"):
        zweig = _zweig(sprache)
        for schluessel in ("letzterLaufOk", "letzterLaufFehlgeschlagen"):
            text = zweig[schluessel]
            assert _GEDANKENSTRICH in text, (
                f"zeitplan.{schluessel} ({sprache}) traegt keinen Halbgeviertstrich: {text!r}"
            )
            assert " - " not in text, (
                f"zeitplan.{schluessel} ({sprache}) traegt einen Bindestrich: {text!r}"
            )


def test_die_zeitplan_texte_stehen_unescaped_in_der_datei() -> None:
    """Echte Zeichen in beiden Dateien, keine ``\\uXXXX``-Ersatzschreibung.

    Geprueft am ROHEN Dateiinhalt: nach ``json.loads`` ist ein Escape nicht mehr von
    einem echten Zeichen zu unterscheiden.
    """
    for sprache in ("de", "en"):
        roh = (_I18N / f"{sprache}.json").read_text(encoding="utf-8")
        for schluessel in _SCHLUESSEL:
            zeilen = [z for z in roh.splitlines() if f'"{schluessel}"' in z]
            assert len(zeilen) == 1, (
                f"zeitplan.{schluessel} steht {len(zeilen)}x roh in {sprache}.json (erwartet: 1)"
            )
            assert "\\u" not in zeilen[0], (
                f"zeitplan.{schluessel} ({sprache}) traegt eine Escape-Schreibung: {zeilen[0]!r}"
            )


def test_der_hinweis_benennt_den_fehlenden_aufrufer() -> None:
    """Der ``_hinweis`` sagt im Katalog selbst, dass diese Texte auf ihre Ansicht warten.

    Ohne ihn ist ein Schluessel ohne Aufrufer von einer Leiche nicht zu
    unterscheiden -- genau die Lage von E-507. Geprueft wird, dass der Hinweis den
    Anschlusspunkt nennt, damit er beim Bau der Ansicht auch gefunden wird.
    """
    for sprache in ("de", "en"):
        hinweis = _zweig(sprache)["_hinweis"]
        assert "/api/schedules" in hinweis, (
            f"Der Hinweis nennt den Anschlusspunkt nicht ({sprache}): {hinweis!r}"
        )
        assert "last_result" in hinweis, (
            f"Der Hinweis nennt die tragende Spalte nicht ({sprache}): {hinweis!r}"
        )


def test_das_frontend_ruft_die_zeitplan_texte_heute_nicht_auf() -> None:
    """Der gemessene Ist-Zustand, festgehalten: KEIN Aufrufer, und das ist gewollt.

    Dieser Test ist bewusst herum gedreht: er faellt, sobald jemand die Texte
    anschliesst. Das ist kein Verbot, sondern ein Wecker -- wer sie anschliesst,
    baut die Zeitplan-Ansicht, und dann gehoert dieser Test geloescht und durch
    einen richtigen Auswahl-Naht-Test ersetzt (Muster:
    ``test_sni_stopped_texte_naht.py``). Ohne ihn liefe die Hinterlegung still mit
    und niemand wuesste, ob sie noch stimmt.
    """
    quellen = [
        pfad
        for pfad in (_FRONTEND / "src").rglob("*")
        if pfad.suffix in (".js", ".jsx") and pfad.is_file()
    ]
    assert quellen, "Keine Frontend-Quellen gefunden -- die Messung waere wertlos"

    treffer = [
        f"{pfad.relative_to(_FRONTEND)}"
        for pfad in quellen
        if any(s in pfad.read_text(encoding="utf-8") for s in _SCHLUESSEL)
    ]

    assert not treffer, (
        "Die Zeitplan-Texte haben jetzt einen Aufrufer: "
        f"{treffer}. Die Hinterlegung ist damit erledigt -- diesen Test loeschen und "
        "durch einen Auswahl-Naht-Test der neuen Zeitplan-Ansicht ersetzen."
    )
