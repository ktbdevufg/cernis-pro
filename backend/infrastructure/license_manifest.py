"""Adapter fuer ``LicenseManifestPort``: findet und liest ``lizenzaufstellung.json``.

Die Aufstellung entsteht im Bauvorgang (``scripts/gen_license_manifest.py``) und geht
ueber ``bundle.resources`` von ``src-tauri/tauri.conf.json`` ins Paket. Bis hierher war
sie eine BEILAGE ohne Lesepfad -- keine Zeile Anwendungscode hat sie je geoeffnet.
Dieser Adapter ist der erste Lesepfad.

AUFLOESUNG OHNE PLATTFORM-WEICHE (S73-P5a, Aufgabe 1a). Das Modul kennt KEIN
``sys.platform``. Statt einer Weiche prueft ``_kandidaten`` eine GEORDNETE Liste von
Pfaden auf Existenz und nimmt den ersten vorhandenen. Die Kandidaten leiten sich aus
``sys.executable`` und aus dem Repo-Verzeichnis ab, nicht aus geratenen Konstanten --
dieselbe Liste laeuft auf jeder Plattform durch, und auf jeder trifft genau der
Kandidat zu, der dort existiert. Das ist absichtlich robuster als eine Weiche: ein
Bundle, das die Datei an einem der ANDEREN Orte fuehrt, wird trotzdem gefunden, statt
an einer falsch geratenen Plattform-Annahme zu scheitern.

Abgedeckt sind die drei Bundle-Formen (an den gebauten Paketen abgelesen) und der
Entwicklungsbetrieb:

* macOS ``.app``: ``sys.executable`` liegt in ``Contents/MacOS/``, die Ressource unter
  ``Contents/Resources/`` -- also ``<exe-Verzeichnis>/../Resources``. AM GEBAUTEN
  BUNDLE VERIFIZIERT::

      .../bundle/macos/CernisPro.app/Contents/MacOS/cernis-backend
      .../bundle/macos/CernisPro.app/Contents/Resources/lizenzaufstellung.json

* Windows: Tauri legt die Ressourcen NEBEN die exe -- ``<exe-Verzeichnis>``.
* Linux-Paket: ``/usr/lib/CernisPro`` (dort landet ``bundle.resources``; die
  deb-/rpm-Beilagen unter ``/usr/share/...`` entstehen getrennt aus DERSELBEN Quelle
  und sind hier nicht gemeint). Der Kandidat leitet sich ebenfalls aus dem
  exe-Verzeichnis ab, weil die exe dort daneben liegt.
* Entwicklung: ``src-tauri/lizenzaufstellung.json`` im Repo -- relativ zu DIESER
  Datei (``backend/infrastructure/``), zwei Ebenen hoch zum Repo-Wurzelverzeichnis.

Der Eintrag in ``tauri.conf.json`` lautet schlicht ``lizenzaufstellung.json``, ohne
fuehrendes ``..`` -- Tauri erzeugt darum KEIN ``_up_``-Segment (anders als bei
``capture_access_macos._resolve_script_path``, wo der Eintrag ``../scripts/<name>``
lautet). Die Kandidaten fuehren deshalb bewusst kein ``_up_``.

BEWUSST OHNE ``bundle_paths.resolve_bundle_path`` (Aufgabe 1a: kein ``_MEIPASS``).
Jener Helfer loest gegen den PyInstaller-Temp-Root auf; die Aufstellung liegt aber
NICHT im PyInstaller-Bundle -- sie entsteht erst NACH den PyInstaller-Laeufen und geht
ueber Tauris ``bundle.resources`` ins Paket. ``_MEIPASS`` erreicht sie also nie.

KEIN STILLER RUECKFALL (Aufgabe 1b, Finding S3): findet kein Kandidat eine Datei, ist
das ``LicenseManifestNotFound`` MIT der vollstaendigen Liste der geprueften Pfade in
der Meldung -- nie eine leere oder erfundene Aufstellung. Dasselbe gilt fuer eine
vorhandene, aber unlesbare oder kaputte Datei (``LicenseManifestUnreadable``).

ZUSTAND IM ADAPTER, NICHT IM MODUL (Aufgabe 1d): die Datei wird genau einmal gelesen
und in der INSTANZ gehalten (``self._manifest``). Ein Modul-Global waere ueber Tests
und ueber mehrere App-Instanzen hinweg geteilt und damit nicht kontrollierbar; die
Instanz gehoert dem Composition Root, der sie als Singleton verdrahtet.
"""

import json
import os
import sys
from typing import Any

import structlog

from ports.license_manifest import (
    LicenseManifestPortError,
    LicenseManifestUnavailableError,
    LicenseTextNotFoundError,
)

_logger = structlog.get_logger(__name__)

# Dateiname der Aufstellung. Identisch in build.sh / build-linux.sh / build.ps1 und in
# src-tauri/tauri.conf.json (bundle.resources) -- eine Konstante, kein Parameter: es
# gibt genau diese eine Datei, und der Name kommt NIE aus einer Nutzereingabe.
_DATEINAME = "lizenzaufstellung.json"

# Unterverzeichnis der Ressourcen im macOS-.app, relativ zum exe-Verzeichnis
# (Contents/MacOS -> Contents/Resources).
_MACOS_RESOURCES = os.path.join("..", "Resources")


# Die Adapter-Fehler leiten von den PORT-Fehlern ab (``ports.license_manifest``): der
# Fehler-Vertrag gehoert zum Port, damit der application-Ring die Faelle unterscheiden
# kann, ohne infrastructure zu importieren (import-linter verbietet das). Die eigenen
# Klassen bleiben trotzdem: sie benennen den KONKRETEN Ausgang praeziser als der
# Vertrag es muss (Nichtfund vs. kaputte Datei fallen beide unter "unavailable").


class LicenseManifestError(LicenseManifestPortError):
    """Basis der Adapter-Fehler beim Auflösen/Lesen der Aufstellung."""


class LicenseManifestNotFound(LicenseManifestUnavailableError):
    """Keiner der geprueften Kandidatenpfade traegt eine Aufstellung.

    Die Meldung fuehrt ALLE geprueften Pfade auf -- ohne sie waere im Betrieb nicht
    nachvollziehbar, wo gesucht wurde.
    """


class LicenseManifestUnreadable(LicenseManifestUnavailableError):
    """Eine Aufstellung wurde gefunden, ist aber nicht lesbar oder kein JSON-Objekt."""


class LicenseTextNotFound(LicenseTextNotFoundError):
    """Der angefragte Lizenztext-Schluessel steht nicht in der Aufstellung.

    Bewusst ein Fehler statt eines leeren Textes (Finding S3): ein leerer Lizenztext
    waere eine Falschaussage ueber die Lizenzlage.
    """


def _repo_wurzel() -> str:
    """Repo-Wurzelverzeichnis, abgeleitet aus dem Ort DIESER Datei.

    Diese Datei liegt in ``backend/infrastructure/`` -- zwei Ebenen hoch ist die
    Wurzel. Abgeleitet, nicht geraten: ein verschobenes Repo bleibt aufloesbar.
    """
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def _kandidaten() -> list[str]:
    """Geordnete Kandidatenpfade der Aufstellung -- ohne ``sys.platform``-Weiche.

    Reihenfolge: erst die Bundle-Formen (im ausgelieferten Paket soll die
    MITGELIEFERTE Datei gewinnen), dann der Entwicklungspfad. Alle Eintraege sind
    normalisiert und absolut, damit die Fehlermeldung im Nichtfundfall eindeutig ist.
    """
    exe_verzeichnis = os.path.dirname(os.path.abspath(sys.executable))
    return [
        # macOS .app: Contents/MacOS/<exe> -> Contents/Resources/<datei>
        os.path.normpath(os.path.join(exe_verzeichnis, _MACOS_RESOURCES, _DATEINAME)),
        # Windows (Ressourcen neben der exe) UND Linux-Paket (/usr/lib/CernisPro,
        # wo die exe daneben liegt) -- derselbe abgeleitete Pfad deckt beide ab.
        os.path.normpath(os.path.join(exe_verzeichnis, _DATEINAME)),
        # Entwicklung: das Repo-Verzeichnis src-tauri/.
        os.path.normpath(os.path.join(_repo_wurzel(), "src-tauri", _DATEINAME)),
    ]


class LicenseManifestAdapter:
    """Liest die Lizenzaufstellung genau einmal und haelt sie in der Instanz.

    Erfuellt ``ports.license_manifest.LicenseManifestPort`` strukturell (Protocol,
    kein ``runtime_checkable`` -- die Vertragspruefung laeuft statisch ueber mypy und
    ueber die Verdrahtung in ``app.py``).

    Der Zustand (``self._manifest``) ist bewusst INSTANZ-Zustand: ein erneuter Abruf
    liest nicht wieder von der Platte, aber zwei Instanzen teilen nichts. Der
    Composition Root verdrahtet genau eine Instanz.
    """

    def __init__(self) -> None:
        self._manifest: dict[str, Any] | None = None

    def load(self) -> dict[str, Any]:
        """Die vollstaendige Aufstellung als ``dict`` -- inklusive ``lizenztexte``.

        Erster Aufruf: Kandidaten der Reihe nach auf Existenz pruefen, den ersten
        vorhandenen lesen, den gefundenen Pfad protokollieren (Aufgabe 1c) und das
        Ergebnis in der Instanz halten. Jeder weitere Aufruf liefert das Gehaltene,
        ohne die Platte anzufassen (Aufgabe 1d).

        Kein Fund -> ``LicenseManifestNotFound`` mit allen geprueften Pfaden. Gefunden,
        aber unlesbar/kein JSON-Objekt -> ``LicenseManifestUnreadable``. NIEMALS eine
        leere Aufstellung (Finding S3).
        """
        if self._manifest is not None:
            return self._manifest

        geprueft = _kandidaten()
        for pfad in geprueft:
            if not os.path.isfile(pfad):
                continue
            try:
                with open(pfad, encoding="utf-8") as datei:
                    daten = json.load(datei)
            except (OSError, json.JSONDecodeError) as exc:
                raise LicenseManifestUnreadable(
                    f"Lizenzaufstellung '{pfad}' ist vorhanden, aber nicht lesbar: {exc}"
                ) from exc
            if not isinstance(daten, dict):
                raise LicenseManifestUnreadable(
                    f"Lizenzaufstellung '{pfad}' enthaelt kein JSON-Objekt, "
                    f"sondern {type(daten).__name__}."
                )
            # Aufgabe 1c: der gelesene Pfad gehoert ins Protokoll -- im Betrieb muss
            # nachvollziehbar sein, WELCHE Datei die Auskunft getragen hat.
            _logger.info("lizenzaufstellung.gelesen", pfad=pfad)
            manifest: dict[str, Any] = daten
            self._manifest = manifest
            return manifest

        raise LicenseManifestNotFound(
            "Keine Lizenzaufstellung gefunden. Geprueft wurden: " + ", ".join(geprueft)
        )

    def get_text(self, schluessel: str) -> str:
        """Ein einzelner Lizenztext, ZEICHENGLEICH aus ``lizenztexte``.

        Der Text wird UNVERAENDERT durchgereicht -- nicht gekuerzt, nicht umbrochen,
        nicht uebersetzt (Aufgabe 2c). Unbekannter Schluessel -> ``LicenseTextNotFound``,
        NIE ein leerer String.

        Ein Eintrag ohne ``text``-Feld bzw. mit nicht-textuellem ``text`` ist ein
        kaputter Eintrag und damit ``LicenseManifestUnreadable`` -- auch das ist ein
        lauter Fehler, kein leiser Leerfall.
        """
        eintraege = self.load().get("lizenztexte")
        if not isinstance(eintraege, dict):
            raise LicenseManifestUnreadable(
                "Die Lizenzaufstellung fuehrt keine Ebene 'lizenztexte' als Objekt."
            )
        eintrag = eintraege.get(schluessel)
        if eintrag is None:
            raise LicenseTextNotFound(
                f"Kein Lizenztext zum Schluessel '{schluessel}' in der Aufstellung."
            )
        text = eintrag.get("text") if isinstance(eintrag, dict) else None
        if not isinstance(text, str):
            raise LicenseManifestUnreadable(
                f"Der Eintrag zum Schluessel '{schluessel}' fuehrt kein Textfeld."
            )
        return text
