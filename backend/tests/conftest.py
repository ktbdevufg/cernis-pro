"""Gemeinsame pytest-Fixtures — und der RIEGEL gegen die produktive Datenbank.

RIEGEL (muss ganz oben stehen, vor jedem Projekt-Import)
--------------------------------------------------------
``modules/db_path.py`` wertet ``DATA_DIR``/``DB_PATH`` auf MODULEBENE aus (Zeile 74/75)
und ruft dabei ``mkdir(parents=True, exist_ok=True)``. Der blosse Import legt das
Verzeichnis also an und friert den Pfad als Modulkonstante ein; ``modules/alerting.py``,
``modules/monitor.py``, ``modules/storage.py`` und ``modules/devices_db.py`` binden
diese Konstante per ``from modules.db_path import DB_PATH`` fest an sich.

Diese conftest importiert ``app``, und ``app.py`` importiert auf Modulebene
``modules.alerting``/``storage``/``devices_db`` — der Import DIESER Datei zieht also
bereits die Pfad-Aufloesung nach sich. Gemessen (Sitzung 69, L18):

    import app  ->  modules.db_path importiert, DATA_DIR = ~/.local/share/cernis-pro

Daraus folgt die Bauart. Ein ``pytest_configure``-Hook waere ZU SPAET: pytest importiert
die conftest als Modul, BEVOR es deren Hooks ruft — gemessen mit einer Sonde
(``-p plugin``): beim Laden eines externen Plugins ist ``modules.db_path`` noch nicht in
``sys.modules``, bei ``pytest_configure`` schon. Zum Hook-Zeitpunkt stehen die
Konstanten also bereits auf dem Produktivpfad. Eine Fixture waere noch spaeter und
damit erst recht wirkungslos.

Darum setzt der Riegel die Variable als ERSTE ausfuehrbare Anweisung dieser Datei --
vor ``from app import create_app`` -- und wirkt damit fuer den GESAMTEN Lauf, ohne
Zutun einer einzelnen Testdatei.

Das Verzeichnis liegt unter dem Temp-Verzeichnis des Betriebssystems (``mkdtemp``), das
das System selbst aufraeumt; zusaetzlich raeumt ``pytest_unconfigure`` unten es am
Laufende ab. Im Repo bleibt nichts zurueck.

Eine BEREITS GESETZTE ``CERNIS_DATA_DIR`` wird respektiert und NICHT ueberschrieben --
sonst braeche das bewusste Setzen in einem Einzeltest oder in der CI.
"""

import atexit
import os
import shutil
import tempfile

# ── RIEGEL: vor allen Projekt-Importen, sonst wirkungslos (siehe Modul-Docstring) ──
_riegel_verzeichnis: str | None = None

if not os.environ.get("CERNIS_DATA_DIR"):
    _riegel_verzeichnis = tempfile.mkdtemp(prefix="cernis-tests-")
    os.environ["CERNIS_DATA_DIR"] = _riegel_verzeichnis
    # Doppelte Absicherung: greift auch, wenn pytest ohne ``pytest_unconfigure``
    # endet (harter Abbruch der Sammelphase).
    atexit.register(shutil.rmtree, _riegel_verzeichnis, True)

# ruff: noqa: E402 -- die Importe MUESSEN nach dem Riegel stehen, das ist sein Sinn.
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app import create_app
from infrastructure.config import AppConfig


def pytest_unconfigure(config: pytest.Config) -> None:
    """Raeumt das laufeigene Riegel-Verzeichnis am Laufende ab."""
    if _riegel_verzeichnis is not None:
        shutil.rmtree(_riegel_verzeichnis, ignore_errors=True)


@pytest.fixture
def client() -> Iterator[TestClient]:
    """TestClient gegen eine frisch gebaute App-Instanz.

    Der Kontextmanager triggert den Lifespan (startup/shutdown), sodass der
    Smoke-Test zugleich das Hochfahren der App abdeckt.
    """
    app = create_app(AppConfig())
    with TestClient(app) as test_client:
        yield test_client
