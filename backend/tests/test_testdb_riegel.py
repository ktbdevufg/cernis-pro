"""WAECHTER ueber dem Riegel aus ``backend/tests/conftest.py``.

Der Riegel sorgt dafuer, dass kein Testlauf dieses Projekts eine Datenbank ausserhalb
eines temporaeren Verzeichnisses benutzt (Begruendung der Bauart: dortiger
Modul-Docstring). Ein Riegel ohne Waechter verrottet still: faellt er aus oder wird er
umgangen, merkt es niemand, und ein Lauf schreibt wieder in
``~/.local/share/cernis-pro/cernis.db``.

Darum diese zwei Tests:

* ``test_datenbank_liegt_nicht_unter_einem_plattform_standardpfad`` prueft die WIRKUNG --
  der im laufenden Prozess ermittelte DB-Pfad liegt unter keinem Plattform-Standardort.
* ``test_create_app_ohne_zutun_landet_im_temporaeren_verzeichnis`` prueft die URSACHE --
  genau der Aufruf ``create_app(AppConfig())`` ohne eigenes Verzeichnis, der den Befund
  erzeugt hat.

Die Standardpfade werden NICHT abgeschrieben, sondern ueber die echte Logik in
``modules/db_path.py`` ermittelt (``get_data_dir`` ohne ``CERNIS_DATA_DIR``, je Zweig).
Aendert sich dort ein Pfad, wandert der Waechter mit, statt still gruen zu laufen.

KEIN Zugriff auf die produktive Datenbank: die Tests VERGLEICHEN Pfade, sie oeffnen
nichts. ``mkdir`` ist auf allen Zweigen weggemockt (Vorbild ``test_db_path.py``), damit
das Ermitteln der Standardpfade selbst kein Verzeichnis im Benutzerprofil anlegt.
"""

import platform
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from modules import db_path


def _standardpfade_ohne_env(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Ermittelt die Plattform-Standardverzeichnisse ueber die ECHTE Code-Logik.

    Ruft ``db_path.get_data_dir()`` einmal pro Zweig (Bundle/Windows/Linux/Dev) auf,
    jeweils OHNE ``CERNIS_DATA_DIR`` — also genau das, was ein Testlauf ohne Riegel
    treffen wuerde. ``mkdir`` ist dabei ausgehebelt, es entsteht kein Verzeichnis.
    """

    class _PathOhneMkdir(Path):
        def mkdir(self, *_a: object, **_k: object) -> None:
            return None

    monkeypatch.setattr(db_path, "Path", _PathOhneMkdir)
    monkeypatch.delenv("CERNIS_DATA_DIR", raising=False)

    pfade: list[Path] = []

    # Zweig 2: macOS-.app-Bundle.
    monkeypatch.setattr(sys, "executable", "/Applications/CernisPro.app/Contents/MacOS/x")
    pfade.append(db_path.get_data_dir())

    # Zweige 3-5: kein Bundle, Plattform durchgespielt.
    monkeypatch.setattr(sys, "executable", "/usr/bin/python3")
    for system in ("Windows", "Linux", "Darwin"):
        monkeypatch.setattr(platform, "system", lambda system=system: system)
        pfade.append(db_path.get_data_dir())

    return pfade


def _liegt_unter(pfad: Path, verzeichnis: Path) -> bool:
    """True, wenn ``pfad`` gleich ``verzeichnis`` ist oder darunter liegt."""
    return pfad == verzeichnis or verzeichnis in pfad.parents


# ── Waechter 1: WIRKUNG — kein Standardpfad im laufenden Testprozess ──────────


def test_datenbank_liegt_nicht_unter_einem_plattform_standardpfad(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Der im Testprozess ermittelte DB-Pfad liegt unter KEINEM Standardort.

    Faellt dieser Test, ist der Riegel in ``backend/tests/conftest.py`` unwirksam oder
    umgangen — und der Lauf schreibt in eine echte Benutzerdatenbank.
    """
    # Erst den echten Pfad des LAUFENDEN Prozesses festhalten (mit Riegel-Env),
    # danach erst die Standardpfade ermitteln (die die Env wegnehmen).
    tatsaechlich = db_path.get_db_path()

    standardpfade = _standardpfade_ohne_env(monkeypatch)

    getroffen = [s for s in standardpfade if _liegt_unter(tatsaechlich, s)]

    assert not getroffen, (
        f"Der Testlauf benutzt die Datenbank {tatsaechlich} -- sie liegt unter dem "
        f"Plattform-Standardpfad {getroffen[0]} statt in einem temporaeren Verzeichnis. "
        "Der Riegel in backend/tests/conftest.py (CERNIS_DATA_DIR auf ein mkdtemp-"
        "Verzeichnis, gesetzt VOR allen Projekt-Importen) ist unwirksam oder umgangen. "
        f"Standardpfade laut modules/db_path.py: {[str(s) for s in standardpfade]}."
    )


# ── Waechter 2: URSACHE — create_app ohne eigenes Zutun ──────────────────────


def test_create_app_ohne_zutun_landet_im_temporaeren_verzeichnis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``create_app(AppConfig())`` OHNE eigenes Verzeichnis trifft ein Temp-Verzeichnis.

    Das ist genau der Fall, der den Befund erzeugt hat: eine Fixture, die die App baut,
    ohne den Datenort selbst festzulegen. Gebaut wird die App hier wirklich -- geprueft
    wird aber nur der PFAD, den sie ihren Repos mitgeben wuerde; es wird keine Datenbank
    geoeffnet.
    """
    from app import create_app
    from infrastructure.config import AppConfig

    create_app(AppConfig())

    ermittelt = db_path.get_db_path()
    temp_wurzel = Path(tempfile.gettempdir()).resolve()

    assert _liegt_unter(ermittelt.resolve(), temp_wurzel), (
        f"create_app(AppConfig()) wuerde die Datenbank {ermittelt} benutzen -- sie liegt "
        f"NICHT unter dem Temp-Verzeichnis {temp_wurzel}. Eine Fixture, die die App ohne "
        "eigenes Datenverzeichnis baut, wuerde damit eine echte Benutzerdatenbank "
        "beschreiben. Der Riegel in backend/tests/conftest.py ist unwirksam oder umgangen."
    )

    # Die Standardpfade sind zusaetzlich ausgeschlossen -- ein Temp-Verzeichnis, das
    # zufaellig unter einem Standardort laege, faellt hier auf.
    standardpfade = _standardpfade_ohne_env(monkeypatch)
    getroffen: list[Any] = [s for s in standardpfade if _liegt_unter(ermittelt, s)]
    assert not getroffen, (
        f"create_app(AppConfig()) wuerde {ermittelt} benutzen -- das liegt unter dem "
        f"Plattform-Standardpfad {getroffen[0]}."
    )
