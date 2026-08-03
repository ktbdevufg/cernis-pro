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
