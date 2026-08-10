"""Tests der drei Waechter im Sammler ``scripts/gen_license_manifest.py``.

Geprueft werden die drei stillen Luecken, die der Auftrag S73-P7a schliesst:

WERK-LIZENZ (Regel L)
    Die Lizenzangabe des eigenen Werks steht an sieben Orten. Weicht einer ab,
    fiel das frueher niemandem auf. Der Waechter prueft ueber die ADRESSIERUNG:
    er faellt auch dann, wenn ein Ort fehlt oder an der erwarteten Stelle keinen
    Kandidaten fuehrt -- ein stillschweigend uebersprungener Ort waere wertlos.

EBENE rust
    Eine leere Zielmenge ging als Erfolg durch -- dieselbe Fehlerform, die fuer
    npm, python und daten bereits behoben ist. Die Meldung TRENNT die Ursachen:
    gar nicht gelaufen (keine Fremdpakete in den Metadaten) gegen ergebnislos
    gelaufen (Metadaten nennen welche, der Baum loest keine auf).

ZENTRALE LEERE-PRUEFUNG
    Die abschliessende Ergebnispruefung sah KEINE Ebene auf Leere durch. Sie
    prueft jetzt jede Pflichtebene und nennt die betroffene NAMENTLICH.

Dazu kommt seit S82-F1 die ZIELPLATTFORM als vierter Waechter: ``--zielplattform``
hat keinen Vorgabewert mehr. Ein fehlendes Argument ist ein Abbruch statt einer
Aufstellung, die sich als eine andere Plattform ausweist als die gebaute.

Bauart der Tests: der Sammler ist ein eigenstaendiges Skript unter ``scripts/``
und kein Paket unterhalb von ``backend/`` -- er wird deshalb ueber seinen Pfad
geladen, nicht ueber einen Paketimport. Geprueft wird gegen ``tmp_path``; das Repo
und ``src-tauri/lizenzaufstellung.json`` werden nie angefasst.
"""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_SAMMLER_PFAD = Path(__file__).resolve().parents[2] / "scripts" / "gen_license_manifest.py"


def _lade_sammler() -> ModuleType:
    """Laedt den Sammler ueber seinen Pfad, ohne ``scripts/`` zu einem Paket zu machen."""
    spezifikation = importlib.util.spec_from_file_location("gen_license_manifest", _SAMMLER_PFAD)
    assert spezifikation is not None and spezifikation.loader is not None
    modul = importlib.util.module_from_spec(spezifikation)
    sys.modules[spezifikation.name] = modul
    spezifikation.loader.exec_module(modul)
    return modul


sammler_modul = _lade_sammler()


# ────────────────────────────────────────────────────────────────────────────────
# Waechter 1 — Werk-Lizenz (Regel L)
# ────────────────────────────────────────────────────────────────────────────────


def _lege_werk_orte_an(wurzel: Path, werte: dict[str, str] | None = None) -> None:
    """Legt alle sieben Orte der Regel L unter ``wurzel`` an.

    ``werte`` ueberschreibt einzelne Orte; alle uebrigen fuehren ``GPL-2.0-only``.
    """
    abweichend = werte or {}

    def wert(datei: str) -> str:
        return abweichend.get(datei, "GPL-2.0-only")

    (wurzel / "frontend").mkdir(parents=True, exist_ok=True)
    (wurzel / "src-tauri").mkdir(parents=True, exist_ok=True)

    (wurzel / "pyproject.toml").write_text(
        f'[project]\nname = "cernis-pro"\nlicense = "{wert("pyproject.toml")}"\n',
        encoding="utf-8",
    )
    (wurzel / "src-tauri" / "Cargo.toml").write_text(
        f'[package]\nname = "cernis-pro"\nlicense = "{wert("src-tauri/Cargo.toml")}"\n',
        encoding="utf-8",
    )
    for datei in ("package.json", "frontend/package.json"):
        (wurzel / datei).write_text(json.dumps({"license": wert(datei)}), encoding="utf-8")
    for datei in ("package-lock.json", "frontend/package-lock.json"):
        (wurzel / datei).write_text(
            json.dumps({"packages": {"": {"license": wert(datei)}}}), encoding="utf-8"
        )
    (wurzel / "src-tauri" / "tauri.conf.json").write_text(
        json.dumps({"bundle": {"license": wert("src-tauri/tauri.conf.json")}}), encoding="utf-8"
    )


def test_werk_lizenz_guter_fall_faellt_nicht(tmp_path: Path) -> None:
    """Fuehren alle sieben Orte denselben Wert, laeuft der Waechter durch.

    Er liefert die uebereinstimmende Angabe zurueck -- sie ist der Bezeichner, den
    ``baue_werk`` in den werk-Eintrag schreibt.
    """
    _lege_werk_orte_an(tmp_path)
    assert sammler_modul.pruefe_werk_lizenz(tmp_path) == "GPL-2.0-only"


def test_werk_lizenz_deckt_die_gemessenen_sieben_orte_ab() -> None:
    """Die Liste fuehrt genau die sieben gemessenen Orte -- keinen weniger.

    Faellt ein Ort aus ``WERK_LIZENZ_ORTE`` heraus, bliebe seine Abweichung
    ungeprueft: der Waechter liefe still an ihr vorbei. Deshalb steht der Bestand
    hier fest und nicht bloss als Zahl.
    """
    orte = {datei for datei, _ in sammler_modul.WERK_LIZENZ_ORTE}
    assert orte == {
        "pyproject.toml",
        "package.json",
        "frontend/package.json",
        "package-lock.json",
        "frontend/package-lock.json",
        "src-tauri/Cargo.toml",
        "src-tauri/tauri.conf.json",
    }


def test_werk_lizenz_schlechter_fall_abweichung_bricht_ab(tmp_path: Path) -> None:
    """Weicht EIN Ort ab, ist das ein Abbruch -- und die Meldung nennt jeden Ort."""
    _lege_werk_orte_an(tmp_path, {"src-tauri/Cargo.toml": "MIT"})
    with pytest.raises(SystemExit) as fehler:
        sammler_modul.pruefe_werk_lizenz(tmp_path)
    meldung = str(fehler.value)
    # Sie sagt, WAS auseinandergeht ...
    assert "Werk-Lizenz" in meldung
    assert "'GPL-2.0-only'" in meldung and "'MIT'" in meldung
    # ... und WO: jeder Ort mit seinem Wert, nicht bloss der abweichende.
    for datei, _ in sammler_modul.WERK_LIZENZ_ORTE:
        assert datei in meldung
    assert "Regel L" in meldung


def test_werk_lizenz_fehlender_ort_bricht_ab_statt_ihn_zu_uebergehen(tmp_path: Path) -> None:
    """Ein GELOESCHTER Ort ist ein Abbruch, kein uebergangener Eintrag.

    Das ist der Kern des Waechters: wuerde er die fehlende Datei still
    ueberspringen, liesse sich Regel L durch Loeschen aushebeln.
    """
    _lege_werk_orte_an(tmp_path)
    (tmp_path / "frontend" / "package.json").unlink()
    with pytest.raises(SystemExit) as fehler:
        sammler_modul.pruefe_werk_lizenz(tmp_path)
    meldung = str(fehler.value)
    assert "frontend/package.json" in meldung
    assert "nicht vorhanden" in meldung


def test_werk_lizenz_adressierung_ohne_kandidat_bricht_ab(tmp_path: Path) -> None:
    """Der Ort ist da, fuehrt an der Adresse aber keinen Kandidaten -> Abbruch.

    Geprueft wird die ADRESSIERUNG, nicht das blosse Vorkommen der Zeichenkette:
    die Datei bleibt bestehen und nennt sogar eine Lizenz -- nur eben nicht unter
    ``packages."".license``.
    """
    _lege_werk_orte_an(tmp_path)
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"license": "GPL-2.0-only", "packages": {}}), encoding="utf-8"
    )
    with pytest.raises(SystemExit) as fehler:
        sammler_modul.pruefe_werk_lizenz(tmp_path)
    meldung = str(fehler.value)
    assert "package-lock.json" in meldung
    assert "kein Kandidat" in meldung


def test_werk_lizenz_adressierung_mit_falscher_art_bricht_ab(tmp_path: Path) -> None:
    """An der Adresse steht kein einzelner Bezeichner -> Abbruch, kein Raten."""
    _lege_werk_orte_an(tmp_path)
    (tmp_path / "package.json").write_text(
        json.dumps({"license": ["GPL-2.0-only", "MIT"]}), encoding="utf-8"
    )
    with pytest.raises(SystemExit) as fehler:
        sammler_modul.pruefe_werk_lizenz(tmp_path)
    assert "kein einzelner Lizenzbezeichner" in str(fehler.value)


def test_werk_lizenz_gilt_fuer_das_echte_repo() -> None:
    """Der Waechter laeuft gegen den ECHTEN Arbeitsbaum durch -- rein lesend.

    Kein Mock: schlaegt dieser Test fehl, gehen die sieben Orte im Repo
    tatsaechlich auseinander, und genau das soll er melden.
    """
    wurzel = _SAMMLER_PFAD.parent.parent
    assert sammler_modul.pruefe_werk_lizenz(wurzel) == "GPL-2.0-only"


# ────────────────────────────────────────────────────────────────────────────────
# Waechter 2 — Ebene rust
# ────────────────────────────────────────────────────────────────────────────────


def _cargo_antworten(
    monkeypatch: pytest.MonkeyPatch,
    metadaten: dict[str, Any],
    baum: str,
) -> None:
    """Legt die Antworten von ``cargo metadata`` und ``cargo tree`` fest.

    Ersetzt wird ``subprocess.run`` im Modul -- die Erhebung laeuft dadurch ueber
    ihren ECHTEN Weg (Zerlegung der Metadaten, Muster auf den Baum), nur die
    beiden Werkzeugausgaben sind gesetzt. ``cargo`` selbst wird nicht gebraucht.
    """

    class _Ergebnis:
        def __init__(self, stdout: str) -> None:
            self.stdout = stdout
            self.returncode = 0

    def _run(befehl: list[str], **kwargs: Any) -> _Ergebnis:
        if "metadata" in befehl:
            return _Ergebnis(json.dumps(metadaten))
        return _Ergebnis(baum)

    monkeypatch.setattr(sammler_modul, "werkzeugpfad", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sammler_modul.subprocess, "run", _run)


_EIGENES = {"name": "cernis-pro", "version": "2.0.6", "source": None}


def _fremdes(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "version": "1.0.0",
        "source": "registry+https://github.com/rust-lang/crates.io-index",
        "license": "MIT",
        "manifest_path": f"/nicht/vorhanden/{name}/Cargo.toml",
        "authors": ["Jemand <jemand@example.org>"],
    }


def test_rust_guter_fall_faellt_nicht(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Nennen Metadaten und Baum Crates, laeuft die Erhebung durch."""
    _cargo_antworten(
        monkeypatch,
        {"packages": [_EIGENES, _fremdes("serde")]},
        "cernis-pro v2.0.6\nserde v1.0.0\n",
    )
    sammler = sammler_modul.Sammler(tmp_path)
    sammler_modul.sammle_rust(sammler, tmp_path, "aarch64-apple-darwin")
    assert [e["name"] for e in sammler.bestandteile] == ["serde"]


def test_rust_schlechter_fall_nicht_gelaufen_bricht_ab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keine Fremdpakete in den Metadaten: die Erhebung ist NICHT GELAUFEN.

    Die Meldung muss diesen Fall vom ergebnislosen Lauf unterscheiden koennen --
    er fuehrt zu einer anderen Abhilfe (Lock/Manifest statt Rust-Ziel).
    """
    _cargo_antworten(monkeypatch, {"packages": [_EIGENES]}, "cernis-pro v2.0.6\n")
    sammler = sammler_modul.Sammler(tmp_path)
    with pytest.raises(SystemExit) as fehler:
        sammler_modul.sammle_rust(sammler, tmp_path, "aarch64-apple-darwin")
    meldung = str(fehler.value)
    assert "Ebene rust" in meldung
    assert "kein einziges FREMDES Paket" in meldung
    assert "nicht gelaufen" in meldung
    assert "Cargo.lock" in meldung
    # Der andere Fall darf hier NICHT gemeldet werden -- sonst traennte die
    # Meldung die beiden Ursachen nicht.
    assert "cargo tree --target" not in meldung


def test_rust_schlechter_fall_leeres_ziel_bricht_ab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Metadaten nennen Crates, der Baum loest keine auf: ERGEBNISLOS GELAUFEN.

    Die Meldung sagt, was leer war (die Zielmenge) und woran es lag (das
    Rust-Ziel), und nennt das Ziel im Wortlaut.
    """
    _cargo_antworten(
        monkeypatch,
        {"packages": [_EIGENES, _fremdes("serde")]},
        "cernis-pro v2.0.6\n",
    )
    sammler = sammler_modul.Sammler(tmp_path)
    with pytest.raises(SystemExit) as fehler:
        sammler_modul.sammle_rust(sammler, tmp_path, "aarch64-apple-darwin")
    meldung = str(fehler.value)
    assert "Ebene rust" in meldung
    assert "aarch64-apple-darwin" in meldung
    assert "keines zu einer Fassung auf" in meldung
    # Trennung zur anderen Ursache: hier lief das Werkzeug sehr wohl.
    assert "nicht gelaufen" not in meldung


def test_rust_schlechter_fall_baum_und_metadaten_passen_nicht(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Der Baum nennt Crates, die Metadaten kennen sie nicht -> kein Eintrag."""
    _cargo_antworten(
        monkeypatch,
        {"packages": [_EIGENES, _fremdes("serde")]},
        "cernis-pro v2.0.6\nserde v9.9.9\n",
    )
    sammler = sammler_modul.Sammler(tmp_path)
    with pytest.raises(SystemExit) as fehler:
        sammler_modul.sammle_rust(sammler, tmp_path, "aarch64-apple-darwin")
    meldung = str(fehler.value)
    assert "es entstand kein Eintrag" in meldung
    assert sammler.bestandteile == []


# ────────────────────────────────────────────────────────────────────────────────
# Waechter 3 — zentrale Leere-Pruefung
# ────────────────────────────────────────────────────────────────────────────────


def _bestandteile(**je_ebene: int) -> list[dict[str, Any]]:
    """Baut je Ebene die angegebene Zahl von Eintraegen."""
    eintraege: list[dict[str, Any]] = []
    for ebene, anzahl in je_ebene.items():
        for lauf in range(anzahl):
            eintraege.append({"name": f"{ebene}-{lauf}", "ebene": ebene})
    return eintraege


def _volle_ebenen() -> dict[str, int]:
    return dict.fromkeys(sammler_modul.PFLICHTEBENEN, 1)


def test_leere_pruefung_guter_fall_faellt_nicht() -> None:
    """Fuehrt jede Pflichtebene Eintraege, laeuft die Pruefung durch."""
    sammler_modul.pruefe_ebene_leere(_bestandteile(**_volle_ebenen()))


def test_leere_pruefung_deckt_alle_fuenf_ebenen_ab() -> None:
    """Geprueft werden alle fuenf Ebenen -- keine bleibt ungeprueft.

    Die Ebene ``nativ`` gehoert NICHT dazu: sie darf leer sein und erklaert das
    ueber ihr Feld ``zustand``.
    """
    assert set(sammler_modul.PFLICHTEBENEN) == {"daten", "npm", "programme", "python", "rust"}


@pytest.mark.parametrize("ausgefallen", ["daten", "npm", "programme", "python", "rust"])
def test_leere_pruefung_schlechter_fall_nennt_die_ebene_namentlich(ausgefallen: str) -> None:
    """JEDE Pflichtebene wird geprueft, und die Meldung nennt sie NAMENTLICH.

    Der Durchlauf ueber alle fuenf ist der Beleg dafuer, dass keine von ihnen
    ungeprueft durchgeht -- eine Pruefung, die nur eine Ebene kennt, faenge die
    anderen vier nicht.
    """
    ebenen = _volle_ebenen()
    ebenen[ausgefallen] = 0
    with pytest.raises(SystemExit) as fehler:
        sammler_modul.pruefe_ebene_leere(_bestandteile(**ebenen))
    meldung = str(fehler.value)
    assert f"Leere Ebene(n) in der Aufstellung: {ausgefallen}" in meldung
    # Nicht bloss eine Zahl: der Bestand JEDER Pflichtebene steht in der Meldung.
    for ebene in sammler_modul.PFLICHTEBENEN:
        assert ebene in meldung
    assert "zustand" in meldung


def test_leere_pruefung_haengt_in_der_ergebnispruefung(tmp_path: Path) -> None:
    """Die Pruefung laeuft in ``pruefe_ergebnis`` mit, nicht nur fuer sich.

    Ohne diese Verdrahtung waere der Waechter geschrieben, aber nie aufgerufen --
    die Ergebnispruefung meldete weiterhin Erfolg.
    """
    ergebnis: dict[str, Any] = {
        "bestandteile": [
            {
                "name": "serde",
                "ebene": "rust",
                "lizenz_id": "MIT",
                "lizenz_id_quelle": sammler_modul.QUELLE_PAKETMETADATEN,
                "urhebervermerk": "Copyright 2026 Jemand",
                "urhebervermerk_quelle": sammler_modul.QUELLE_PAKETDATEI,
                "lizenz_text_ref": None,
            }
        ],
        "lizenztexte": {},
        "werk": {"lizenz_text": None},
        "ebene_nativ": {"eintraege": []},
    }
    with pytest.raises(SystemExit) as fehler:
        sammler_modul.pruefe_ergebnis(ergebnis)
    meldung = str(fehler.value)
    assert "Leere Ebene(n) in der Aufstellung" in meldung
    # Vier der fuenf fehlen; rust ist besetzt und darf nicht gemeldet werden.
    assert "daten" in meldung and "npm" in meldung
    assert "Aufstellung: daten, npm, programme, python" in meldung


# ────────────────────────────────────────────────────────────────────────────────
# Waechter 4 — Zielplattform ohne Vorgabewert
# ────────────────────────────────────────────────────────────────────────────────


def test_zielplattform_kennt_linux_aarch64() -> None:
    """``linux-aarch64`` ist ein zulaessiger Wert -- und feldgleich zu x86_64.

    Ohne diesen Eintrag liesse sich der ARM64-Linux-Bau ueberhaupt nicht benennen;
    er fiele auf eine andere Plattform zurueck oder braeche ab. Geprueft wird
    nicht nur das Vorkommen, sondern der FELDBESTAND: fehlte eines der drei
    Merkmale, liefe die Erhebung an ihm auf einen KeyError statt auf eine Aussage.
    """
    merkmale = sammler_modul.ZIELPLATTFORMEN["linux-aarch64"]
    assert merkmale["rust_ziel"] == "aarch64-unknown-linux-gnu"
    assert merkmale["bibliotheksendungen"] == (".so",)
    assert merkmale["paketverzeichnis"] == "dpkg-query"
    # Feldgleich zum x86_64-Eintrag: kein Feld erfunden, keines weggelassen.
    assert set(merkmale) == set(sammler_modul.ZIELPLATTFORMEN["linux-x86_64"])


def test_zielplattform_ist_pflicht(tmp_path: Path) -> None:
    """Ohne ``--zielplattform`` bricht der Aufruf ab, statt eine Vorgabe zu nehmen.

    Das ist der Kern des Waechters: ein Vorgabewert lieferte beim vergessenen
    Schalter ein falsches, aber plausibles Ergebnis -- die Aufstellung eines
    anderen Ziels, die sich nicht als solche zu erkennen gibt (Finding S3).
    """
    with pytest.raises(SystemExit) as fehler:
        sammler_modul.main([str(tmp_path / "aufstellung.json")])
    # argparse beendet einen fehlenden Pflichtschalter mit Code 2, nicht mit 0.
    assert fehler.value.code == 2


def test_zielplattform_hat_keinen_vorgabewert_im_modul() -> None:
    """Es gibt keine Konstante mehr, aus der still eine Vorgabe kaeme.

    Der Schalter allein reicht nicht: bliebe die alte ``ZIELPLATTFORM_VORGABE``
    stehen, koennte sie in ``erzeuge`` oder einem spaeteren Aufrufer wieder zum
    stillen Rueckfall werden.
    """
    assert not hasattr(sammler_modul, "ZIELPLATTFORM_VORGABE")
