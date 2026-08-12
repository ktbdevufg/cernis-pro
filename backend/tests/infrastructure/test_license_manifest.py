"""Tests des Ressourcen-Auflösers ``infrastructure.license_manifest``.

Sichern das VERHALTEN, nicht die Umsetzung (Aufgabe 4): dass eine Datei an einem der
Kandidatenpfade gefunden wird, dass das Ausbleiben ein BENANNTER Fehler mit der
vollstaendigen Liste der geprueften Pfade ist, und dass genau einmal von der Platte
gelesen wird.

Die Kandidatenpfade leiten sich aus ``sys.executable`` und aus dem Repo-Verzeichnis
ab. Die Tests setzen ``sys.executable`` per ``monkeypatch`` auf ein ``tmp_path``-
Verzeichnis und legen die Datei dort ab -- so laeuft der Fund ueber den ECHTEN
Auflösungsweg, ohne das Repo anzufassen und ohne eine Plattform vorauszusetzen.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from infrastructure.license_manifest import (
    LicenseManifestAdapter,
    LicenseManifestNotFound,
    LicenseManifestUnreadable,
    LicenseTextNotFound,
    _kandidaten,
)

_MINIMALE_AUFSTELLUNG: dict[str, Any] = {
    "schema_version": "2",
    "erzeugt_am": "2026-08-03T11:47:38+00:00",
    "produktversion": "2.0.6",
    "plattform": "macos-aarch64",
    "werk": {"name": "CERNIS PRO", "lizenz_id": "proprietaer"},
    "bestandteile": [{"name": "anyio", "ebene": "python", "lizenz_id": "MIT"}],
    "lizenztexte": {"spdx:MIT": {"text": "MIT License\n\nCopyright...", "zeichen": 26}},
    "luecken": [],
    "ebene_nativ": {"erhoben": False},
}


def _lege_aufstellung_ab(verzeichnis: Path, daten: dict[str, Any] | None = None) -> Path:
    """Schreibt eine Aufstellung in ``verzeichnis`` und liefert den Pfad."""
    ziel = verzeichnis / "lizenzaufstellung.json"
    ziel.write_text(
        json.dumps(daten if daten is not None else _MINIMALE_AUFSTELLUNG),
        encoding="utf-8",
    )
    return ziel


@pytest.fixture
def leeres_exe_verzeichnis(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Setzt ALLE Kandidatenquellen auf leere tmp-Verzeichnisse.

    ``sys.executable`` deckt die drei Bundle-Kandidaten ab, ``_repo_wurzel`` den
    Entwicklungs-Kandidaten. Letzterer MUSS mit umgebogen werden: im Entwicklungsbaum
    liegt die echte ``src-tauri/lizenzaufstellung.json``, und ohne die Umbiegung
    faenge jeder Test sie als stillen Rueckfall -- ein Nichtfund waere dann nie
    beobachtbar und die Belege waeren wertlos.

    Was der Test danach im gelieferten Verzeichnis ablegt, entscheidet ueber Fund
    oder Nichtfund.
    """
    exe_verzeichnis = tmp_path / "bin"
    exe_verzeichnis.mkdir()
    monkeypatch.setattr(sys, "executable", str(exe_verzeichnis / "cernis-backend"))
    monkeypatch.setattr(
        "infrastructure.license_manifest._repo_wurzel", lambda: str(tmp_path / "kein-repo")
    )
    return exe_verzeichnis


def test_kandidaten_decken_die_bundle_formen_und_die_entwicklung_ab(
    leeres_exe_verzeichnis: Path,
) -> None:
    """Vier Kandidaten: macOS-Resources, neben der exe, Linux-lib, Repo -- alle absolut."""
    kandidaten = _kandidaten()

    assert len(kandidaten) == 4
    assert all(os.path.isabs(pfad) for pfad in kandidaten)
    assert all(pfad.endswith("lizenzaufstellung.json") for pfad in kandidaten)
    # macOS-.app: eine Ebene ueber dem exe-Verzeichnis unter Resources/.
    assert kandidaten[0] == str(
        leeres_exe_verzeichnis.parent / "Resources" / "lizenzaufstellung.json"
    )
    # Windows (Ressourcen neben der exe).
    assert kandidaten[1] == str(leeres_exe_verzeichnis / "lizenzaufstellung.json")
    # Linux-Paket: eine Ebene ueber dem exe-Verzeichnis unter lib/CernisPro/ --
    # relativ gebildet, ohne festgeschriebenes /usr-Praefix (Befund 34b).
    assert kandidaten[2] == str(
        leeres_exe_verzeichnis.parent / "lib" / "CernisPro" / "lizenzaufstellung.json"
    )
    # Entwicklung: das Repo-Verzeichnis src-tauri/ -- unabhaengig von sys.executable.
    assert kandidaten[3].endswith(os.path.join("src-tauri", "lizenzaufstellung.json"))
    # KEIN _up_-Segment: der Eintrag in tauri.conf.json traegt kein fuehrendes "..".
    assert not any("_up_" in pfad for pfad in kandidaten)


def test_findet_die_aufstellung_neben_der_exe(leeres_exe_verzeichnis: Path) -> None:
    """Aufgabe 4a, Fall 1: eine Datei an einem Kandidatenpfad wird gefunden."""
    _lege_aufstellung_ab(leeres_exe_verzeichnis)

    aufstellung = LicenseManifestAdapter().load()

    assert aufstellung["schema_version"] == "2"
    assert aufstellung["produktversion"] == "2.0.6"
    assert "lizenztexte" in aufstellung


def test_findet_die_aufstellung_im_macos_resources_verzeichnis(
    leeres_exe_verzeichnis: Path,
) -> None:
    """Aufgabe 4a, Fall 1 (zweite Bundle-Form): ``<exe>/../Resources``."""
    resources = leeres_exe_verzeichnis.parent / "Resources"
    resources.mkdir()
    _lege_aufstellung_ab(resources)

    aufstellung = LicenseManifestAdapter().load()

    assert aufstellung["produktversion"] == "2.0.6"


def test_findet_die_aufstellung_im_linux_paket(leeres_exe_verzeichnis: Path) -> None:
    """Befund 34b: der IN DIESER SITZUNG AM PAKET GEMESSENE Linux-Fall.

    Das Backend liegt in einem ``bin``-Verzeichnis (im Paket ``/usr/bin``), die
    Aufstellung im DANEBEN liegenden ``lib/CernisPro`` (im Paket
    ``/usr/lib/CernisPro``). Neben der exe liegt sie ausdruecklich NICHT -- vor
    diesem Kandidaten fand die Anwendung sie im Linux-Paket ueberhaupt nicht.
    """
    lib_verzeichnis = leeres_exe_verzeichnis.parent / "lib" / "CernisPro"
    lib_verzeichnis.mkdir(parents=True)
    _lege_aufstellung_ab(lib_verzeichnis)
    assert not (leeres_exe_verzeichnis / "lizenzaufstellung.json").exists()

    aufstellung = LicenseManifestAdapter().load()

    assert aufstellung["produktversion"] == "2.0.6"


def test_neben_der_exe_geht_dem_linux_kandidaten_vor(leeres_exe_verzeichnis: Path) -> None:
    """Die REIHENFOLGE ist verbindlich: der neue Kandidat steht an dritter Stelle.

    Liegen beide Dateien, muss die neben der exe gewinnen -- der Linux-Kandidat ist
    hinter ihr eingehaengt und darf sie nicht verdraengen. Unterschiedliche
    ``produktversion`` macht sichtbar, welche gelesen wurde.
    """
    lib_verzeichnis = leeres_exe_verzeichnis.parent / "lib" / "CernisPro"
    lib_verzeichnis.mkdir(parents=True)
    _lege_aufstellung_ab(
        leeres_exe_verzeichnis, {**_MINIMALE_AUFSTELLUNG, "produktversion": "neben-exe"}
    )
    _lege_aufstellung_ab(
        lib_verzeichnis, {**_MINIMALE_AUFSTELLUNG, "produktversion": "lib-CernisPro"}
    )

    assert LicenseManifestAdapter().load()["produktversion"] == "neben-exe"


def test_linux_kandidat_geht_der_entwicklung_vor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, leeres_exe_verzeichnis: Path
) -> None:
    """Die andere Seite der Reihenfolge: der neue Kandidat steht VOR dem Repo-Pfad.

    Im ausgelieferten Paket soll die MITGELIEFERTE Datei gewinnen, nicht eine im
    Entwicklungsbaum gefundene.
    """
    lib_verzeichnis = leeres_exe_verzeichnis.parent / "lib" / "CernisPro"
    lib_verzeichnis.mkdir(parents=True)
    _lege_aufstellung_ab(
        lib_verzeichnis, {**_MINIMALE_AUFSTELLUNG, "produktversion": "lib-CernisPro"}
    )
    repo = tmp_path / "repo" / "src-tauri"
    repo.mkdir(parents=True)
    _lege_aufstellung_ab(repo, {**_MINIMALE_AUFSTELLUNG, "produktversion": "entwicklung"})
    monkeypatch.setattr(
        "infrastructure.license_manifest._repo_wurzel", lambda: str(tmp_path / "repo")
    )

    assert LicenseManifestAdapter().load()["produktversion"] == "lib-CernisPro"


def test_ohne_datei_benannter_fehler_mit_allen_geprueften_pfaden(
    leeres_exe_verzeichnis: Path,
) -> None:
    """Aufgabe 4a, Fall 2: kein Fund -> benannter Fehler, kein stiller Rueckfall."""
    with pytest.raises(LicenseManifestNotFound) as fehler:
        LicenseManifestAdapter().load()

    meldung = str(fehler.value)
    # Die vollstaendige Liste der geprueften Pfade gehoert in die Meldung.
    for pfad in _kandidaten():
        assert pfad in meldung
    assert "Keine Lizenzaufstellung gefunden" in meldung


def test_liest_genau_einmal_von_der_platte(leeres_exe_verzeichnis: Path) -> None:
    """Aufgabe 1d: ein erneuter Abruf liest nicht erneut -- Zustand im Adapter.

    Beleg ohne Blick in die Umsetzung: nach dem ersten Abruf wird die Datei GELOESCHT.
    Ein zweiter Abruf, der noch liest, muesste jetzt scheitern; er liefert aber
    weiterhin das Gehaltene.
    """
    pfad = _lege_aufstellung_ab(leeres_exe_verzeichnis)
    adapter = LicenseManifestAdapter()

    erst = adapter.load()
    pfad.unlink()
    zweit = adapter.load()

    assert zweit == erst
    assert zweit["produktversion"] == "2.0.6"


def test_zustand_gehoert_der_instanz_nicht_dem_modul(leeres_exe_verzeichnis: Path) -> None:
    """Aufgabe 1d: der Zustand ist INSTANZ-Zustand, kein Modul-Global.

    Zwei Adapter teilen nichts: der zweite, nach dem Loeschen der Datei erzeugte,
    findet nichts mehr -- ein Modul-Global haette ihm die Aufstellung durchgereicht.
    """
    pfad = _lege_aufstellung_ab(leeres_exe_verzeichnis)
    erster = LicenseManifestAdapter()
    erster.load()
    pfad.unlink()

    with pytest.raises(LicenseManifestNotFound):
        LicenseManifestAdapter().load()


def test_kaputte_datei_ist_ein_lauter_fehler(leeres_exe_verzeichnis: Path) -> None:
    """Eine vorhandene, aber unlesbare Aufstellung faellt laut -- kein Leerfall (S3)."""
    (leeres_exe_verzeichnis / "lizenzaufstellung.json").write_text("{kein json", encoding="utf-8")

    with pytest.raises(LicenseManifestUnreadable):
        LicenseManifestAdapter().load()


def test_get_text_liefert_zeichengleich(leeres_exe_verzeichnis: Path) -> None:
    """Aufgabe 2c/4f: der Text kommt unveraendert -- nicht gekuerzt, nicht umbrochen."""
    text = "MIT License\n\n  Zeile mit Einzug\n\tund Tabulator\n\n"
    _lege_aufstellung_ab(
        leeres_exe_verzeichnis,
        {**_MINIMALE_AUFSTELLUNG, "lizenztexte": {"spdx:MIT": {"text": text}}},
    )

    assert LicenseManifestAdapter().get_text("spdx:MIT") == text


def test_get_text_unbekannter_schluessel_ist_ein_fehler(leeres_exe_verzeichnis: Path) -> None:
    """Aufgabe 4f: unbekannter Schluessel -> Fehler, KEIN leerer Text."""
    _lege_aufstellung_ab(leeres_exe_verzeichnis)

    with pytest.raises(LicenseTextNotFound) as fehler:
        LicenseManifestAdapter().get_text("spdx:GibtsNicht")

    assert "spdx:GibtsNicht" in str(fehler.value)
