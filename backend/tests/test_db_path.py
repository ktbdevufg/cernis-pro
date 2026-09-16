"""Tests der Datenverzeichnis-Aufloesung (``modules/db_path.py``) -- PLATTFORMFREI.

Laeuft auf der Linux-CI: ``sys.executable``, ``platform.system`` und ``Path.home``
werden per ``monkeypatch`` ersetzt, es wird nie ein echtes Bundle gebraucht.

Hintergrund (Etappe 2c): am installierten Artefakt war gemessen worden, dass das
gebundelte Backend ``~/Library/Application Support/cernis-pro/cernis.db`` oeffnete
statt des vorgesehenen ``.../de.cernis.pro/``. Ursache war NICHT diese Datei, sondern
eine ZWEITE Aufloesung im Tauri-Wrapper (``src-tauri/src/main.rs``), die
``CERNIS_DATA_DIR`` auf ``dirs::data_dir()/cernis-pro`` setzte und damit Prioritaet 1
ausloeste -- der Bundle-Zweig hier wurde nie erreicht. Der Wrapper setzt die Variable
nicht mehr; ``get_data_dir`` ist jetzt die EINZIGE wirksame Quelle. Diese Tests halten
das Verhalten fest, das dadurch wieder greift.

Die Tests legen bewusst KEINE echten Verzeichnisse im Home an: ``mkdir`` wird
mitgemockt, damit ein Testlauf nicht ``~/Library/...`` anlegt.
"""

import platform
import sys
from pathlib import Path

import pytest

from modules import db_path

# Pfad eines gebundelten Backends, wie er real gemessen wurde.
_BUNDLE_EXE = "/Applications/CernisPro.app/Contents/MacOS/cernis-backend"


@pytest.fixture(autouse=True)
def _kein_mkdir(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verhindert, dass die Tests echte Verzeichnisse anlegen.

    ``get_data_dir`` ruft auf jedem Zweig ``mkdir(parents=True, exist_ok=True)``.
    Ohne diesen Schutz wuerde ein Testlauf ``~/Library/Application Support/...`` bzw.
    ``~/.local/share/...`` anlegen -- ein Test darf das Benutzerprofil nicht veraendern.

    Gemockt wird NUR ``modules.db_path.Path`` (die Referenz im Modul unter Test), nicht
    ``pathlib.Path`` global: pytest selbst legt ueber ``Path.mkdir`` seine ``tmp_path``-
    Verzeichnisse an und wuerde von einem globalen Mock lahmgelegt.
    """

    class _PathOhneMkdir(Path):
        def mkdir(self, *_a: object, **_k: object) -> None:
            return None

    monkeypatch.setattr(db_path, "Path", _PathOhneMkdir)


@pytest.fixture(autouse=True)
def _ohne_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Entfernt ``CERNIS_DATA_DIR`` -- sonst greift Prioritaet 1 und verdeckt alles."""
    monkeypatch.delenv("CERNIS_DATA_DIR", raising=False)


# ── Prioritaet 1: expliziter Override ───────────────────────────────────────


def test_env_override_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """``CERNIS_DATA_DIR`` schlaegt jeden anderen Zweig -- auch den Bundle-Fall.

    Der Override BLEIBT bewusst erhalten (Tests, kuenftige Wrapper). Neu ist nur, dass
    der Tauri-Wrapper ihn nicht mehr selbst setzt.
    """
    monkeypatch.setenv("CERNIS_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "executable", _BUNDLE_EXE)

    assert db_path.get_data_dir() == tmp_path


# ── Prioritaet 2: macOS-.app-Bundle ─────────────────────────────────────────


def test_bundle_uses_de_cernis_pro(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Im ``.app``-Bundle gilt ``<home>/Library/Application Support/de.cernis.pro``.

    Das ist der Zweig, der am installierten Artefakt nie erreicht wurde (siehe
    Modul-Docstring). Der Verzeichnisname ist die Bundle-Identitaet ``de.cernis.pro``
    (vgl. ``identifier`` in ``tauri.conf.json``), NICHT ``cernis-pro``.
    """
    monkeypatch.setattr(sys, "executable", _BUNDLE_EXE)
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))

    ergebnis = db_path.get_data_dir()

    assert ergebnis == tmp_path / "Library" / "Application Support" / "de.cernis.pro"
    assert ergebnis.name == "de.cernis.pro"
    assert ergebnis.name != "cernis-pro"  # der gemessene Fehlzustand


def test_bundle_detected_from_any_parent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Die Erkennung greift ueber die Eltern-Pfade, nicht nur ueber den Dateinamen."""
    monkeypatch.setattr(
        sys, "executable", "/Applications/CernisPro.app/Contents/Resources/tief/cernis-backend"
    )
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))

    assert db_path.get_data_dir().name == "de.cernis.pro"


def test_db_path_is_cernis_db_in_data_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """``get_db_path`` haengt ``cernis.db`` an das aufgeloeste Verzeichnis."""
    monkeypatch.setattr(sys, "executable", _BUNDLE_EXE)
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))

    pfad = db_path.get_db_path()

    assert pfad.name == "cernis.db"
    assert pfad.parent.name == "de.cernis.pro"


# ── Prioritaeten 3-5: uebrige Plattformen + Dev ─────────────────────────────


def test_linux_uses_xdg_share(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Linux ohne Bundle -> ``$XDG_DATA_HOME/cernis-pro`` (unveraendert)."""
    monkeypatch.setattr(sys, "executable", "/usr/bin/cernis-backend")
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    assert db_path.get_data_dir() == tmp_path / "cernis-pro"


def test_windows_uses_appdata(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Windows ohne Bundle -> ``%APPDATA%/CernisPro`` (unveraendert)."""
    monkeypatch.setattr(sys, "executable", r"C:\Program Files\CernisPro\cernis-backend.exe")
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setenv("APPDATA", str(tmp_path))

    assert db_path.get_data_dir() == tmp_path / "CernisPro"


def test_dev_uses_backend_data_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dev-Betrieb (kein Bundle, kein Windows/Linux-Zweig) -> ``<backend>/data``.

    Der Dev-Pfad bleibt ausdruecklich unveraendert -- Etappe 2c korrigiert nur den
    Bundle-Fall.
    """
    monkeypatch.setattr(sys, "executable", "/opt/homebrew/bin/python3")
    monkeypatch.setattr(platform, "system", lambda: "Darwin")

    ergebnis = db_path.get_data_dir()

    assert ergebnis.name == "data"
    assert ergebnis.parent.name == "backend"
