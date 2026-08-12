"""Tests der Use-Cases ``GetLicenseManifest`` / ``GetLicenseText``.

Sichern das VERHALTEN (Aufgabe 4b-4f): die Liste traegt keine Lizenztexte, aber alle
vier Abschnitte; die Normalisierung fuehrt die gemessen gleichbedeutenden
Schreibweisen zusammen und laesst ``lizenz_id`` unveraendert; ``null`` bleibt
``null``; Programme werden nur fuer die passende Plattform erhoben; ein bekannter
Schluessel liefert zeichengleich, ein unbekannter faellt.

Der Port wird durch einen Fake ersetzt -- kein Dateizugriff, keine echte Aufstellung.
Die verwendeten Lizenz-Ausdruecke sind AUSSCHLIESSLICH real in der Aufstellung
vorkommende Schreibweisen (Aufgabe 4c).
"""

import shutil
from typing import Any

import pytest

from application.license_manifest import (
    GetLicenseManifest,
    GetLicenseText,
    LicenseManifestUnavailable,
    LicenseTextUnknown,
)
from ports.license_manifest import (
    LicenseManifestUnavailableError,
    LicenseTextNotFoundError,
)


class FakeManifestPort:
    """Fake des ``LicenseManifestPort`` -- liefert eine vorgegebene Aufstellung."""

    def __init__(self, aufstellung: dict[str, Any]) -> None:
        self._aufstellung = aufstellung

    def load(self) -> dict[str, Any]:
        return self._aufstellung

    def get_text(self, schluessel: str) -> str:
        eintraege = self._aufstellung.get("lizenztexte", {})
        if schluessel not in eintraege:
            raise LicenseTextNotFoundError(f"Kein Lizenztext zum Schluessel '{schluessel}'.")
        text: str = eintraege[schluessel]["text"]
        return text


class KaputterManifestPort:
    """Fake, der wie ein fehlender/unlesbarer Bestand faellt."""

    def load(self) -> dict[str, Any]:
        raise LicenseManifestUnavailableError("Keine Lizenzaufstellung gefunden. Geprueft: /a, /b")

    def get_text(self, schluessel: str) -> str:
        raise LicenseManifestUnavailableError("Keine Lizenzaufstellung gefunden. Geprueft: /a, /b")


def _aufstellung(bestandteile: list[dict[str, Any]]) -> dict[str, Any]:
    """Aufstellung mit dem gemessenen Kopf und den vier Abschnitten."""
    return {
        "schema_version": "2",
        "erzeugt_am": "2026-08-03T11:47:38+00:00",
        "produktversion": "2.0.6",
        "plattform": "macos-aarch64",
        "werk": {
            "name": "CERNIS PRO",
            "urheber": "Karl Bach",
            "lizenz_id": "proprietaer",
            "lizenz_text": "Werk-Text",
            "lizenz_text_quelle": "LICENSE",
        },
        "bestandteile": bestandteile,
        "lizenztexte": {"spdx:MIT": {"text": "MIT License\n\nCopyright (c) ...\n"}},
        "luecken": [{"name": "irgendwas", "grund": "kein Lizenztext auffindbar"}],
        "ebene_nativ": {"erhoben": False, "zustand": "kein_paketverzeichnis"},
    }


# ── 4b: Liste ohne Texte, aber mit allen vier Abschnitten ────────────────────


def test_liste_traegt_keine_lizenztexte_aber_alle_vier_abschnitte() -> None:
    """Aufgabe 4b: ``lizenztexte`` fehlt; Kopf + werk/bestandteile/luecken/ebene_nativ da."""
    uc = GetLicenseManifest(
        FakeManifestPort(_aufstellung([{"name": "anyio", "ebene": "python", "lizenz_id": "MIT"}]))
    )

    erg = uc(plattform="macOS")

    # Die Texte sind NICHT dabei -- sie sind der Grund fuer den zweiten Endpunkt.
    assert "lizenztexte" not in erg
    # Die vier Abschnitte der Aufstellung.
    for abschnitt in ("werk", "bestandteile", "luecken", "ebene_nativ"):
        assert abschnitt in erg, abschnitt
    # Der Kopf.
    assert erg["schema_version"] == "2"
    assert erg["erzeugt_am"] == "2026-08-03T11:47:38+00:00"
    assert erg["produktversion"] == "2.0.6"
    assert erg["plattform"] == "macos-aarch64"
    # werk/luecken/ebene_nativ gehen unveraendert durch.
    assert erg["werk"]["name"] == "CERNIS PRO"
    assert erg["luecken"] == [{"name": "irgendwas", "grund": "kein Lizenztext auffindbar"}]
    assert erg["ebene_nativ"]["zustand"] == "kein_paketverzeichnis"


def test_fehlende_aufstellung_ist_ein_lauter_fehler() -> None:
    """Finding S3: keine leere Aufstellung als Rueckfall."""
    uc = GetLicenseManifest(KaputterManifestPort())

    with pytest.raises(LicenseManifestUnavailable) as fehler:
        uc(plattform="macOS")

    # Die geprueften Pfade werden weitergereicht.
    assert "/a, /b" in str(fehler.value)


# ── 4c: Normalisierung fuehrt zusammen, laesst lizenz_id unveraendert ────────


@pytest.mark.parametrize(
    ("rohe_schreibweisen", "erwartet"),
    [
        # Die MIT/Apache-2.0-Familie: sechs real vorkommende Schreibweisen.
        (
            [
                "MIT OR Apache-2.0",
                "Apache-2.0 OR MIT",
                "MIT/Apache-2.0",
                "Apache-2.0/MIT",
                "MIT / Apache-2.0",
                "Apache-2.0 / MIT",
            ],
            "Apache-2.0 OR MIT",
        ),
        # Drei Reihenfolgen derselben Dreier-Wahl.
        (
            [
                "MIT OR Apache-2.0 OR Zlib",
                "MIT OR Zlib OR Apache-2.0",
                "Zlib OR Apache-2.0 OR MIT",
            ],
            "Apache-2.0 OR MIT OR Zlib",
        ),
        # Namensvariante EINES Bezeichners.
        (["MIT", "MIT License"], "MIT"),
        # Schraegstrich vs. OR bei Unlicense.
        (["Unlicense OR MIT", "Unlicense/MIT"], "MIT OR Unlicense"),
    ],
)
def test_normalisierung_fuehrt_gleichbedeutende_schreibweisen_zusammen(
    rohe_schreibweisen: list[str], erwartet: str
) -> None:
    """Aufgabe 4c: real vorkommende Varianten landen auf EINEM Filterwert."""
    bestandteile = [
        {"name": f"paket-{i}", "ebene": "rust", "lizenz_id": roh}
        for i, roh in enumerate(rohe_schreibweisen)
    ]
    uc = GetLicenseManifest(FakeManifestPort(_aufstellung(bestandteile)))

    erg = uc(plattform="macOS")

    assert {teil["lizenz_id_normalisiert"] for teil in erg["bestandteile"]} == {erwartet}


def test_normalisierung_laesst_lizenz_id_unveraendert() -> None:
    """Aufgabe 4c: der rohe Wert bleibt roh -- die Normalisierung ist ADDITIV."""
    rohe = ["MIT/Apache-2.0", "MIT License", "Zlib OR Apache-2.0 OR MIT"]
    bestandteile = [
        {"name": f"paket-{i}", "ebene": "rust", "lizenz_id": roh} for i, roh in enumerate(rohe)
    ]
    uc = GetLicenseManifest(FakeManifestPort(_aufstellung(bestandteile)))

    erg = uc(plattform="macOS")

    assert [teil["lizenz_id"] for teil in erg["bestandteile"]] == rohe


@pytest.mark.parametrize(
    "roh",
    [
        # Klammern binden -- eine flache Sortierung wuerde die Bindung zerreissen.
        "(MIT OR Apache-2.0) AND Unicode-3.0",
        # AND ist eine Verpflichtung auf BEIDE, keine Wahl.
        "Apache-2.0 AND MIT",
        "BSD-3-Clause AND MIT",
        # WITH bindet die Ausnahme an genau einen Bezeichner.
        "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
    ],
)
def test_klammern_und_and_with_bleiben_unangetastet(roh: str) -> None:
    """Reihenfolge traegt hier Bedeutung -- ein Umstellen waere eine Verfaelschung."""
    uc = GetLicenseManifest(
        FakeManifestPort(_aufstellung([{"name": "p", "ebene": "rust", "lizenz_id": roh}]))
    )

    erg = uc(plattform="macOS")

    assert erg["bestandteile"][0]["lizenz_id_normalisiert"] == roh
    assert erg["bestandteile"][0]["lizenz_id"] == roh


# ── 4d: null bleibt null ─────────────────────────────────────────────────────


def test_lizenz_id_null_bleibt_auch_im_zusatzfeld_null() -> None:
    """Aufgabe 4d: wo die Aufstellung nichts ausweist, wird nichts erraten."""
    uc = GetLicenseManifest(
        FakeManifestPort(_aufstellung([{"name": "ip", "ebene": "programme", "lizenz_id": None}]))
    )

    erg = uc(plattform="macOS")

    assert erg["bestandteile"][0]["lizenz_id"] is None
    assert erg["bestandteile"][0]["lizenz_id_normalisiert"] is None


# ── 4e: Programme nur fuer die passende Plattform ────────────────────────────


def test_programme_fremder_plattform_stehen_auf_nicht_zutreffend() -> None:
    """Aufgabe 4e: ein Windows-Werkzeug FEHLT auf macOS nicht -- es ist nicht gemeint."""
    bestandteile = [
        {"name": "netsh", "ebene": "programme", "lizenz_id": None, "plattform": "Windows"},
        {"name": "ip", "ebene": "programme", "lizenz_id": None, "plattform": "Linux"},
    ]
    uc = GetLicenseManifest(FakeManifestPort(_aufstellung(bestandteile)))

    erg = uc(plattform="macOS")

    assert [teil["vorhanden"] for teil in erg["bestandteile"]] == [
        "nicht_zutreffend",
        "nicht_zutreffend",
    ]


def test_programm_der_laufenden_plattform_wird_erhoben() -> None:
    """Aufgabe 4e: fuer die passende Plattform wird ueber den PATH erhoben.

    ``sh`` ist auf jedem POSIX-System im PATH; ein frei erfundener Name ist es nie.
    Beide Eintraege nennen dieselbe Plattform -- das Ergebnis unterscheidet sich also
    allein an der Erhebung, nicht am Plattform-Abgleich.
    """
    bestandteile = [
        {"name": "sh", "ebene": "programme", "lizenz_id": None, "plattform": "Linux/macOS"},
        {
            "name": "gibt-es-ganz-sicher-nicht-xyz",
            "ebene": "programme",
            "lizenz_id": None,
            "plattform": "Linux/macOS",
        },
    ]
    uc = GetLicenseManifest(FakeManifestPort(_aufstellung(bestandteile)))

    erg = uc(plattform="macOS")

    assert erg["bestandteile"][0]["vorhanden"] == "vorhanden"
    assert erg["bestandteile"][1]["vorhanden"] == "fehlt"


def test_plattform_alle_schliesst_jede_plattform_ein() -> None:
    """``alle`` (gemessen bei ``nmap``) wird auf jeder Plattform erhoben."""
    uc = GetLicenseManifest(
        FakeManifestPort(
            _aufstellung(
                [{"name": "sh", "ebene": "programme", "lizenz_id": None, "plattform": "alle"}]
            )
        )
    )

    assert uc(plattform="Windows")["bestandteile"][0]["vorhanden"] == "vorhanden"


def test_sammel_eintrag_gilt_als_vorhanden_sobald_eines_da_ist() -> None:
    """Der gemessene Eintrag ``apt, dnf, yum, zypper, pacman`` meint austauschbare Programme."""
    uc = GetLicenseManifest(
        FakeManifestPort(
            _aufstellung(
                [
                    {
                        "name": "gibt-es-nicht-a, sh, gibt-es-nicht-b",
                        "ebene": "programme",
                        "lizenz_id": None,
                        "plattform": "macOS",
                    }
                ]
            )
        )
    )

    assert uc(plattform="macOS")["bestandteile"][0]["vorhanden"] == "vorhanden"


def test_nur_programme_tragen_das_vorhandensein_feld() -> None:
    """Ein Rust-Crate ist keine Datei im PATH -- die Frage waere dort sinnlos."""
    bestandteile: list[dict[str, Any]] = [
        {"name": "serde", "ebene": "rust", "lizenz_id": "MIT OR Apache-2.0"},
        {"name": "sh", "ebene": "programme", "lizenz_id": None, "plattform": "macOS"},
    ]
    uc = GetLicenseManifest(FakeManifestPort(_aufstellung(bestandteile)))

    erg = uc(plattform="macOS")

    assert "vorhanden" not in erg["bestandteile"][0]
    assert "vorhanden" in erg["bestandteile"][1]


def test_die_plattform_kommt_von_aussen_nicht_aus_sys_platform() -> None:
    """Aufgabe 2b: derselbe Use-Case, zwei uebergebene Plattformen, zwei Ergebnisse."""
    bestandteile = [
        {"name": "netsh", "ebene": "programme", "lizenz_id": None, "plattform": "Windows"}
    ]
    uc = GetLicenseManifest(FakeManifestPort(_aufstellung(bestandteile)))

    # Auf macOS: nicht gemeint. Mit uebergebenem "Windows": erhoben (und hier nicht da).
    assert uc(plattform="macOS")["bestandteile"][0]["vorhanden"] == "nicht_zutreffend"
    assert uc(plattform="Windows")["bestandteile"][0]["vorhanden"] == "fehlt"


# ── 4f: Volltext zeichengleich, unbekannter Schluessel faellt ────────────────


def test_bekannter_schluessel_liefert_zeichengleich() -> None:
    """Aufgabe 4f/2c: der Text kommt unveraendert -- Zeichen fuer Zeichen."""
    text = "MIT License\n\n  Eingerueckte Zeile\n\tTabulator\n\nEnde ohne Umbruch"
    aufstellung = _aufstellung([])
    aufstellung["lizenztexte"] = {"paket:python/anyio": {"text": text}}
    uc = GetLicenseText(FakeManifestPort(aufstellung))

    assert uc("paket:python/anyio") == text


def test_unbekannter_schluessel_ergibt_einen_fehler_keinen_leeren_text() -> None:
    """Aufgabe 4f: ein leerer Lizenztext waere eine Falschaussage (S3)."""
    uc = GetLicenseText(FakeManifestPort(_aufstellung([])))

    with pytest.raises(LicenseTextUnknown) as fehler:
        uc("spdx:GibtsNicht")

    assert "spdx:GibtsNicht" in str(fehler.value)


def test_fehlende_aufstellung_beim_text_ist_kein_404_fall() -> None:
    """Fehlende Datei und unbekannter Schluessel sind GETRENNTE Fehler."""
    uc = GetLicenseText(KaputterManifestPort())

    with pytest.raises(LicenseManifestUnavailable):
        uc("spdx:MIT")


def test_die_gehaltene_aufstellung_wird_nicht_mutiert() -> None:
    """Die Anreicherung arbeitet auf einer Kopie -- der Adapter haelt die Datei ja."""
    bestandteile: list[dict[str, Any]] = [
        {"name": "serde", "ebene": "rust", "lizenz_id": "MIT/Apache-2.0"}
    ]
    aufstellung = _aufstellung(bestandteile)
    uc = GetLicenseManifest(FakeManifestPort(aufstellung))

    uc(plattform="macOS")

    assert "lizenz_id_normalisiert" not in aufstellung["bestandteile"][0]
    assert aufstellung["bestandteile"][0]["lizenz_id"] == "MIT/Apache-2.0"


# ── S73-P5b: Der Bezugsort des Quelltextes wird durchgereicht ────────────────
# Der werk-Eintrag geht als GANZES durch, nicht Feld fuer Feld aufgezaehlt. Diese
# Tests sichern genau das ab: ein neues Feld der Quelle darf nicht still
# verschwinden, weder wenn es belegt ist noch wenn es fehlt.


def test_quelltext_bezug_erscheint_in_der_antwort() -> None:
    """Traegt der werk-Eintrag das Feld, steht es unveraendert in der Antwort."""
    aufstellung = _aufstellung([])
    aufstellung["werk"]["quelltext_bezug"] = (
        "Der vollstaendige Quelltext dieses Werks liegt dem jeweiligen Release als Archiv bei."
    )
    aufstellung["werk"]["quelltext_bezug_quelle"] = "projektkonfiguration"
    uc = GetLicenseManifest(FakeManifestPort(aufstellung))

    erg = uc(plattform="macOS")

    assert erg["werk"]["quelltext_bezug"] == (
        "Der vollstaendige Quelltext dieses Werks liegt dem jeweiligen Release als Archiv bei."
    )
    assert erg["werk"]["quelltext_bezug_quelle"] == "projektkonfiguration"


def test_fehlender_quelltext_bezug_ist_nicht_belegt_und_kein_leerer_text() -> None:
    """Fehlt die Angabe, ist der Wert ``None`` und die Quelle ``nicht_belegt``.

    Ausdruecklich KEIN leerer Text: ein "" laese sich in der Anzeige nicht von
    einer vorhandenen, aber inhaltsleeren Angabe unterscheiden (Finding S3).
    """
    aufstellung = _aufstellung([])
    aufstellung["werk"]["quelltext_bezug"] = None
    aufstellung["werk"]["quelltext_bezug_quelle"] = "nicht_belegt"
    uc = GetLicenseManifest(FakeManifestPort(aufstellung))

    erg = uc(plattform="macOS")

    assert erg["werk"]["quelltext_bezug"] is None
    assert erg["werk"]["quelltext_bezug"] != ""
    assert erg["werk"]["quelltext_bezug_quelle"] == "nicht_belegt"


def test_werk_eintrag_geht_als_ganzes_durch() -> None:
    """Der Ring zaehlt die Felder des Werks NICHT einzeln auf.

    Der eigentliche Schutz: ein Feld, das dieser Test gar nicht kennt, muss
    trotzdem ankommen. Sonst verschwindet jede kuenftige Ergaenzung der Quelle
    still zwischen Sammler und Anzeige.

    Der Werk-Text der Vorlage traegt hier KEINE aufloesbare Referenz -- die
    Aufloesung aus Befund 54b greift also nicht und der Eintrag geht wirklich
    unveraendert durch. Der Fall MIT Referenz steht weiter unten.
    """
    aufstellung = _aufstellung([])
    aufstellung["werk"]["ein_kuenftiges_feld"] = "beliebiger Wert"
    uc = GetLicenseManifest(FakeManifestPort(aufstellung))

    erg = uc(plattform="macOS")

    assert erg["werk"] == aufstellung["werk"]


# ── Befund 54b, Teil 1: bezugsart und der Vorhandenseins-Befund ohne Suchpfad ─


def _programm(name: str, **felder: Any) -> dict[str, Any]:
    """Ein Eintrag der Ebene ``programme`` mit den gemessenen Pflichtfeldern."""
    eintrag: dict[str, Any] = {
        "name": name,
        "ebene": "programme",
        "lizenz_id": None,
        "plattform": "Windows",
        "bezugsart": "vorausgesetzt",
    }
    eintrag.update(felder)
    return eintrag


def test_ohne_naht_steht_nicht_ermittelbar_und_nicht_fehlt() -> None:
    """Befund 54b: der Zustand ist EIGEN -- kein Rueckfall auf ``fehlt`` (S3).

    Ohne verdrahtete Naht gibt es keine Pruefung, die den Eintrag beantworten
    koennte. ``fehlt`` waere hier eine Aussage ueber Abwesenheit, die niemand
    erhoben hat.
    """
    uc = GetLicenseManifest(FakeManifestPort(_aufstellung([_programm("Npcap")])))

    erg = uc(plattform="Windows")

    assert erg["bestandteile"][0]["vorhanden"] == "nicht_ermittelbar"
    assert erg["bestandteile"][0]["vorhanden"] != "fehlt"
    assert erg["bestandteile"][0]["vorhanden"] != "vorhanden"


def test_naht_ohne_aussage_faellt_nicht_auf_fehlt_zurueck() -> None:
    """Liefert die Naht ``None``, bleibt es ``nicht_ermittelbar``.

    Der Unterschied zu ``False`` ist der ganze Punkt: ``None`` heisst "keine
    Auskunft", ``False`` heisst "geprueft und nicht da".
    """
    uc = GetLicenseManifest(
        FakeManifestPort(_aufstellung([_programm("Npcap")])),
        lambda _name: None,
    )

    assert uc(plattform="Windows")["bestandteile"][0]["vorhanden"] == "nicht_ermittelbar"


@pytest.mark.parametrize(("befund", "erwartet"), [(True, "vorhanden"), (False, "fehlt")])
def test_naht_entscheidet_statt_des_suchpfads(befund: bool, erwartet: str) -> None:
    """Der Befund kommt AUS DER NAHT, nicht aus ``shutil.which``.

    Der Name ist mit Absicht einer, den ``shutil.which`` garantiert nicht findet:
    kaeme das Ergebnis von dort, stuende bei ``befund=True`` trotzdem ``fehlt``.
    """
    uc = GetLicenseManifest(
        FakeManifestPort(_aufstellung([_programm("Npcap")])),
        lambda _name: befund,
    )

    assert uc(plattform="Windows")["bestandteile"][0]["vorhanden"] == erwartet


def test_npcap_wird_nicht_ueber_shutil_which_entschieden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ausdruecklich (Teil 4): fuer diesen Eintrag wird ``shutil.which`` NIE gerufen.

    Ein ``shutil.which``, das hier liefe, faende den Kerneltreiber nie und
    meldete auf Windows dauerhaft "fehlt" -- genau Befund 54b. Der Test faengt
    das nicht am Ergebnis, sondern an der Ausfuehrung: die Funktion wird durch
    eine ersetzt, die beim Aufruf faellt.
    """

    def _verboten(_name: str) -> str | None:
        raise AssertionError("shutil.which darf fuer diesen Eintrag nicht laufen")

    # Der Use-Case ruft ``shutil.which`` ueber das Modul (``import shutil``), nicht
    # ueber einen eigenen Namen -- ersetzt wird darum die Funktion im stdlib-Modul.
    monkeypatch.setattr(shutil, "which", _verboten)
    uc = GetLicenseManifest(
        FakeManifestPort(_aufstellung([_programm("Npcap")])),
        lambda _name: True,
    )

    assert uc(plattform="Windows")["bestandteile"][0]["vorhanden"] == "vorhanden"


def test_die_naht_bekommt_den_namen_des_eintrags() -> None:
    """Die Naht ist namensbasiert -- der Composition Root ordnet daran zu."""
    gesehen: list[str] = []

    def _pruefung(name: str) -> bool | None:
        gesehen.append(name)
        return True

    uc = GetLicenseManifest(FakeManifestPort(_aufstellung([_programm("Npcap")])), _pruefung)
    uc(plattform="Windows")

    assert gesehen == ["Npcap"]


def test_die_naht_gilt_nur_fuer_eintraege_ohne_suchpfad_bezug() -> None:
    """Ein aufgerufenes Programm laeuft weiter ueber den Suchpfad.

    Die Naht wuerde hier ``True`` sagen -- der Eintrag ist aber ``aufgerufen``
    und damit eine Datei im PATH. Der frei erfundene Name muss trotzdem ``fehlt``
    ergeben, sonst haette die Naht die falsche Menge uebernommen.
    """
    uc = GetLicenseManifest(
        FakeManifestPort(
            _aufstellung(
                [
                    _programm(
                        "gibt-es-ganz-sicher-nicht-xyz",
                        plattform="Linux",
                        bezugsart="aufgerufen",
                    )
                ]
            )
        ),
        lambda _name: True,
    )

    assert uc(plattform="Linux")["bestandteile"][0]["vorhanden"] == "fehlt"


def test_fremde_plattform_schlaegt_die_naht_gar_nicht_erst_auf() -> None:
    """Der Plattform-Abgleich steht VOR der Erhebung -- fuer beide Wege gleich."""
    gesehen: list[str] = []

    def _pruefung(name: str) -> bool | None:
        gesehen.append(name)
        return True

    uc = GetLicenseManifest(FakeManifestPort(_aufstellung([_programm("Npcap")])), _pruefung)

    assert uc(plattform="Linux")["bestandteile"][0]["vorhanden"] == "nicht_zutreffend"
    assert gesehen == []


# ── Befund 54b, Teil 2: der Werk-Lizenztext wird aufgeloest ──────────────────


def test_werk_lizenztext_traegt_kein_werk_praefix_mehr() -> None:
    """Teil 4, ausdruecklich: aus der Referenz wird der Volltext.

    Die Aufstellung schreibt in ``werk.lizenz_text`` den SCHLUESSEL
    ``werk:GPL-2.0-only``; die Ansicht zeigte diese Zeichenkette woertlich im
    Aufklappblock.
    """
    aufstellung = _aufstellung([])
    aufstellung["werk"]["lizenz_text"] = "werk:GPL-2.0-only"
    aufstellung["lizenztexte"]["werk:GPL-2.0-only"] = {
        "text": "GNU GENERAL PUBLIC LICENSE\n                       Version 2, June 1991\n"
    }
    uc = GetLicenseManifest(FakeManifestPort(aufstellung))

    erg = uc(plattform="macOS")

    assert not erg["werk"]["lizenz_text"].startswith("werk:")
    assert erg["werk"]["lizenz_text"].startswith("GNU GENERAL PUBLIC LICENSE")


def test_der_aufgeloeste_werk_text_ist_zeichengleich() -> None:
    """Aufgeloest heisst nachgeschlagen, nicht umgeschrieben (Aufgabe 2c)."""
    text = "Zeile eins\n\n  eingerueckt\n\tTabulator\nEnde ohne Umbruch"
    aufstellung = _aufstellung([])
    aufstellung["werk"]["lizenz_text"] = "werk:GPL-2.0-only"
    aufstellung["lizenztexte"]["werk:GPL-2.0-only"] = {"text": text}
    uc = GetLicenseManifest(FakeManifestPort(aufstellung))

    assert uc(plattform="macOS")["werk"]["lizenz_text"] == text


def test_die_ebene_lizenztexte_geht_trotz_aufloesung_nicht_hinaus() -> None:
    """Nur EIN Eintrag wird nachgeschlagen -- die grosse Ebene bleibt drinnen."""
    aufstellung = _aufstellung([])
    aufstellung["werk"]["lizenz_text"] = "werk:GPL-2.0-only"
    aufstellung["lizenztexte"]["werk:GPL-2.0-only"] = {"text": "Werk-Volltext"}
    uc = GetLicenseManifest(FakeManifestPort(aufstellung))

    erg = uc(plattform="macOS")

    assert "lizenztexte" not in erg
    assert erg["werk"]["lizenz_text"] == "Werk-Volltext"


def test_unaufloesbare_referenz_bleibt_stehen_und_wird_nicht_geleert() -> None:
    """Kein erfundener Text, keine leere Zeichenkette (Finding S3).

    Bleibt die Referenz unaufloesbar, kommt sie unveraendert an -- die Ansicht
    erkennt sie am Praefix und zeigt ihren vorhandenen Ersatzhinweis.
    """
    aufstellung = _aufstellung([])
    aufstellung["werk"]["lizenz_text"] = "werk:GPL-2.0-only"
    uc = GetLicenseManifest(FakeManifestPort(aufstellung))

    erg = uc(plattform="macOS")

    assert erg["werk"]["lizenz_text"] == "werk:GPL-2.0-only"
    assert erg["werk"]["lizenz_text"] != ""


def test_die_aufloesung_mutiert_die_gehaltene_aufstellung_nicht() -> None:
    """Wie bei den Bestandteilen: der Adapter haelt die Datei, wir kopieren."""
    aufstellung = _aufstellung([])
    aufstellung["werk"]["lizenz_text"] = "werk:GPL-2.0-only"
    aufstellung["lizenztexte"]["werk:GPL-2.0-only"] = {"text": "Werk-Volltext"}
    uc = GetLicenseManifest(FakeManifestPort(aufstellung))

    uc(plattform="macOS")

    assert aufstellung["werk"]["lizenz_text"] == "werk:GPL-2.0-only"
