"""End-to-end-Tests des Lizenzaufstellungs-Routers gegen app.py via TestClient.

Belegt die Wire-Form beider Endpunkte und das Fehlerbild (Aufgabe 3c): unbekannter
Schluessel -> 404, fehlende Aufstellung -> 503, in keinem Fall eine leere Antwort mit
200. Die Use-Cases werden via ``dependency_overrides`` durch Fakes ersetzt -- keine
echte Aufstellung, kein Dateizugriff.

Ein Test laeuft bewusst gegen die ECHTE Verdrahtung (ohne Override): er belegt, dass
der Composition Root Router, Adapter und Plattform tatsaechlich zusammengesteckt hat.
"""

import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.license_manifest import (
    provide_get_license_manifest,
    provide_get_license_text,
    provide_laufende_plattform,
)
from app import create_app
from application.license_manifest import LicenseManifestUnavailable, LicenseTextUnknown
from infrastructure.config import AppConfig


@pytest.fixture
def app() -> Iterator[FastAPI]:
    yield create_app(AppConfig())


def test_liste_liefert_kopf_und_abschnitte_ohne_texte(app: FastAPI) -> None:
    """``GET /api/lizenzen`` traegt die vier Abschnitte, aber keine Lizenztexte."""

    def _fake(*, plattform: str) -> dict[str, Any]:
        return {
            "schema_version": "2",
            "erzeugt_am": "2026-08-03T11:47:38+00:00",
            "produktversion": "2.0.6",
            "plattform": "macos-aarch64",
            "werk": {"name": "CERNIS PRO"},
            "bestandteile": [
                {
                    "name": "serde",
                    "ebene": "rust",
                    "lizenz_id": "MIT/Apache-2.0",
                    "lizenz_id_normalisiert": "Apache-2.0 OR MIT",
                },
                {
                    "name": "netsh",
                    "ebene": "programme",
                    "lizenz_id": None,
                    "lizenz_id_normalisiert": None,
                    "plattform": "Windows",
                    "vorhanden": "nicht_zutreffend",
                },
            ],
            "luecken": [],
            "ebene_nativ": {"erhoben": False},
        }

    app.dependency_overrides[provide_get_license_manifest] = lambda: _fake
    app.dependency_overrides[provide_laufende_plattform] = lambda: "macOS"

    with TestClient(app) as client:
        antwort = client.get("/api/lizenzen")

    assert antwort.status_code == 200
    rumpf = antwort.json()
    assert "lizenztexte" not in rumpf
    for abschnitt in ("werk", "bestandteile", "luecken", "ebene_nativ"):
        assert abschnitt in rumpf
    assert rumpf["schema_version"] == "2"
    # Der rohe Bezeichner bleibt roh, die Normalisierung kommt zusaetzlich.
    assert rumpf["bestandteile"][0]["lizenz_id"] == "MIT/Apache-2.0"
    assert rumpf["bestandteile"][0]["lizenz_id_normalisiert"] == "Apache-2.0 OR MIT"
    assert rumpf["bestandteile"][1]["vorhanden"] == "nicht_zutreffend"


def test_fehlende_aufstellung_ergibt_503_nicht_200_mit_leerem_rumpf(app: FastAPI) -> None:
    """Aufgabe 3c: kein stiller Leerfall -- die geprueften Pfade stehen in der Meldung."""

    def _fake(*, plattform: str) -> dict[str, Any]:
        raise LicenseManifestUnavailable(
            "Keine Lizenzaufstellung gefunden. Geprueft wurden: /a/lizenzaufstellung.json"
        )

    app.dependency_overrides[provide_get_license_manifest] = lambda: _fake
    app.dependency_overrides[provide_laufende_plattform] = lambda: "macOS"

    with TestClient(app) as client:
        antwort = client.get("/api/lizenzen")

    assert antwort.status_code == 503
    assert "/a/lizenzaufstellung.json" in antwort.json()["detail"]


def test_text_endpunkt_nimmt_den_schluessel_als_abfrageparameter(app: FastAPI) -> None:
    """Aufgabe 3a: Doppelpunkt UND Schraegstrich kommen als Ganzes an."""
    text = "MIT License\n\n  Eingerueckt\n\tTabulator\n"
    gesehen: list[str] = []

    def _fake(schluessel: str) -> str:
        gesehen.append(schluessel)
        return text

    app.dependency_overrides[provide_get_license_text] = lambda: _fake

    with TestClient(app) as client:
        antwort = client.get("/api/lizenzen/text", params={"schluessel": "paket:python/anyio"})

    assert antwort.status_code == 200
    # Der Schluessel wurde NICHT am Trennzeichen zerlegt.
    assert gesehen == ["paket:python/anyio"]
    rumpf = antwort.json()
    assert rumpf["schluessel"] == "paket:python/anyio"
    # Zeichengleich -- nicht gekuerzt, nicht umbrochen (Aufgabe 2c).
    assert rumpf["text"] == text


def test_unbekannter_schluessel_ergibt_404_mit_verstaendlicher_meldung(app: FastAPI) -> None:
    """Aufgabe 3c: 404, kein leerer Text mit 200."""

    def _fake(schluessel: str) -> str:
        raise LicenseTextUnknown(
            f"Kein Lizenztext zum Schluessel '{schluessel}' in der Aufstellung."
        )

    app.dependency_overrides[provide_get_license_text] = lambda: _fake

    with TestClient(app) as client:
        antwort = client.get("/api/lizenzen/text", params={"schluessel": "spdx:GibtsNicht"})

    assert antwort.status_code == 404
    assert "spdx:GibtsNicht" in antwort.json()["detail"]


def test_fehlender_schluessel_wird_abgewiesen(app: FastAPI) -> None:
    """Ohne Abfrageparameter gibt es keine Auskunft -- 422 statt Raten."""
    with TestClient(app) as client:
        antwort = client.get("/api/lizenzen/text")

    assert antwort.status_code == 422


def test_echte_verdrahtung_liefert_die_aufstellung(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Ohne Override: Router, Adapter und Plattform sind im Composition Root gesteckt.

    Laeuft gegen den ECHTEN Adapter -- kein Fake, kein Override. Die Aufstellung ist
    ein Bau-Artefakt und per ``.gitignore`` ausgeschlossen (in der CI existiert sie
    also nicht); der Test legt sich darum eine eigene an und biegt den
    Entwicklungs-Kandidaten des Auflösers auf dieses Verzeichnis um. So faellt das
    Ergebnis ueberall gleich aus -- mit oder ohne lokalen Bau.
    """
    wurzel = tmp_path / "repo"
    (wurzel / "src-tauri").mkdir(parents=True)
    (wurzel / "src-tauri" / "lizenzaufstellung.json").write_text(
        json.dumps(
            {
                "schema_version": "2",
                "erzeugt_am": "2026-08-03T11:47:38+00:00",
                "produktversion": "2.0.6",
                "plattform": "macos-aarch64",
                "werk": {"name": "CERNIS PRO"},
                "bestandteile": [
                    {"name": "serde", "ebene": "rust", "lizenz_id": "MIT/Apache-2.0"},
                    {"name": "sh", "ebene": "programme", "lizenz_id": None, "plattform": "alle"},
                ],
                "lizenztexte": {"spdx:MIT": {"text": "MIT License\n"}},
                "luecken": [],
                "ebene_nativ": {"erhoben": False},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("infrastructure.license_manifest._repo_wurzel", lambda: str(wurzel))

    with TestClient(create_app(AppConfig())) as client:
        antwort = client.get("/api/lizenzen")
        text_antwort = client.get("/api/lizenzen/text", params={"schluessel": "spdx:MIT"})

    assert antwort.status_code == 200
    rumpf = antwort.json()
    assert "lizenztexte" not in rumpf
    # Jeder Bestandteil traegt das additive Filterfeld; der rohe Wert bleibt roh.
    assert rumpf["bestandteile"][0]["lizenz_id"] == "MIT/Apache-2.0"
    assert rumpf["bestandteile"][0]["lizenz_id_normalisiert"] == "Apache-2.0 OR MIT"
    # Die Plattform kommt aus dem Composition Root: ``alle`` wird ueberall erhoben.
    assert rumpf["bestandteile"][1]["vorhanden"] == "vorhanden"
    # Der zweite Endpunkt laeuft ueber DENSELBEN Adapter-Singleton.
    assert text_antwort.status_code == 200
    assert text_antwort.json()["text"] == "MIT License\n"


def test_echte_verdrahtung_ohne_aufstellung_ergibt_503(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Aufgabe 3c am echten Adapter: fehlende Datei -> 503, nie 200 mit leerem Rumpf."""
    leer = tmp_path / "kein-repo"
    monkeypatch.setattr("infrastructure.license_manifest._repo_wurzel", lambda: str(leer))
    # Auch die aus sys.executable abgeleiteten Kandidaten muessen ins Leere zeigen.
    bin_verzeichnis = tmp_path / "bin"
    bin_verzeichnis.mkdir()
    monkeypatch.setattr(sys, "executable", str(bin_verzeichnis / "cernis-backend"))

    with TestClient(create_app(AppConfig())) as client:
        antwort = client.get("/api/lizenzen")

    assert antwort.status_code == 503
    assert "Keine Lizenzaufstellung gefunden" in antwort.json()["detail"]
