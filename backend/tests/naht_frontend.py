"""Gemeinsamer Riegel der node-gestuetzten Naht-Tests (S89-A1).

WARUM AN EINER STELLE: neun Testdateien messen Frontend-Nahtstellen, indem sie die
ECHTEN Frontend-Quellen ueber ``node`` fahren -- teils uebersetzt und gebuendelt mit
``esbuild`` aus ``frontend/node_modules``. Jede Datei trug dieselbe Ueberspring-Bedingung
in eigener Fassung. Sie liefen darum auseinander: ``test_sni_status_autorefresh_naht.py``
fragte nach ``node`` und der Quelldatei, importierte im Skript aber ``esbuild`` -- in der
CI fiel der Test mit ``ERR_MODULE_NOT_FOUND``, statt sich zu ueberspringen (CI-Lauf
31816836761). Die Bedingung steht darum ab hier EINMAL.

DIE REGEL (Karls Vorgabe S89-A1, B3):

* Ohne gesetzte Umgebungsvariable ``CI`` -- also auf einer Entwicklermaschine -- darf
  sich der Test ueberspringen, wenn node oder die gebrauchten Frontend-Teile fehlen.
  Niemand muss ``npm ci`` fahren, nur um das Backend zu testen.
* MIT gesetzter ``CI`` ueberspringt sich nie etwas. Fehlt dort etwas, ist das ein
  Fehler des Ablaufs und faellt mit benannter Meldung auf. Ein stiller Uebersprung in
  der CI hiesse: die Naht gilt als geprueft, obwohl sie ungedeckt ist -- genau der
  Zustand, den dieser Riegel beendet.

Die CI installiert die Frontend-Abhaengigkeiten im quality-Job (``npm ci`` in
``frontend``, siehe ``.github/workflows/ci.yml``); der Riegel darf dort also fordern.

ZWEI FASSUNGEN, EINE BEDINGUNG: ``riegel()`` gilt fuer eine ganze Testdatei,
``nur_mit_frontend()`` fuer einzelne Tests einer Datei, die daneben auch reine
Backend-Tests traegt. Beide gehen durch dasselbe ``_pruefe``.
"""

import functools
import os
import pathlib
import shutil
from collections.abc import Callable
from typing import Any, Literal, TypeVar

import pytest

FRONTEND = pathlib.Path(__file__).resolve().parents[2] / "frontend"
NODE_MODULES = FRONTEND / "node_modules"

_F = TypeVar("_F", bound=Callable[..., Any])

# Die Scopes, die pytest kennt -- als Typ, damit ``riegel(scope=...)`` nicht auf einen
# Tippfehler hereinfaellt (mypy strict weist einen freien ``str`` hier ohnehin ab).
_Scope = Literal["session", "package", "module", "class", "function"]


def _fehlende_teile(dateien: tuple[pathlib.Path, ...], pakete: tuple[str, ...]) -> list[str]:
    """Nennt alles, was fuer die Messung fehlt -- als Liste, nicht als blosses Ja/Nein.

    Die Namen wandern in die Meldung: in der CI soll dort stehen, WAS fehlt, nicht
    nur, dass etwas fehlt.
    """
    fehlt: list[str] = []
    if shutil.which("node") is None:
        fehlt.append("node (Interpreter nicht im PATH)")
    fehlt += [str(datei) for datei in dateien if not datei.is_file()]
    fehlt += [
        f"frontend/node_modules/{paket}" for paket in pakete if not (NODE_MODULES / paket).is_dir()
    ]
    return fehlt


def _pruefe(dateien: tuple[pathlib.Path, ...], pakete: tuple[str, ...]) -> None:
    """DIE eine Entscheidung: laufen, ueberspringen (ohne CI) oder fallen (mit CI)."""
    fehlt = _fehlende_teile(dateien, pakete)
    if not fehlt:
        return

    aufzaehlung = ", ".join(fehlt)
    if os.environ.get("CI"):
        pytest.fail(
            "Die Frontend-Abhaengigkeiten fehlen in der CI -- die node-gestuetzte Naht ist "
            f"ungedeckt, nicht in Ordnung befunden. Fehlt: {aufzaehlung}. Erwartet wird der "
            "Schritt 'npm ci' im Verzeichnis frontend (quality-Job, .github/workflows/ci.yml).",
            pytrace=False,
        )
    pytest.skip(
        f"node-Messung faellt aus (lokal ohne CI), es fehlt: {aufzaehlung}. "
        "Sie laeuft mit installierten Frontend-Abhaengigkeiten (frontend: npm ci)."
    )


def riegel(
    *,
    dateien: tuple[pathlib.Path, ...] = (),
    pakete: tuple[str, ...] = (),
    scope: _Scope = "function",
) -> Any:
    """Baut den autouse-Riegel fuer eine GANZE Testdatei.

    ``dateien``: Frontend-Quellen, die die Messung braucht.
    ``pakete``: Namen unter ``frontend/node_modules``, die das node-Skript importiert
    (etwa ``esbuild``, ``react-dom``). Wer nichts buendelt, nennt hier nichts.
    ``scope``: normalerweise ``"function"``. Faehrt die Testdatei ihre node-Messung
    aber in einer eigenen Fixture mit weiterem Scope (etwa ``scope="module"``), MUSS
    der Riegel denselben Scope tragen -- sonst laeuft die Messung VOR ihm: pytest
    ordnet Fixtures nach Scope, weitere zuerst. Genau daran fiel
    ``test_helper_resource_syncstatus_naht.py`` in der Gegenprobe, obwohl der Riegel
    stand.

    Verwendung am Modulkopf der Testdatei::

        _riegel = naht_frontend.riegel(dateien=(_VIEW_JSX,), pakete=("esbuild",))

    Der Rueckgabewert ist eine autouse-Fixture; die Zuweisung an einen Modulnamen
    reicht, damit pytest sie fuer jeden Test der Datei fahrt. Der Rueckgabetyp ist
    ``Any``, weil ``pytest.fixture`` ein Marker-Objekt liefert, keine Funktion --
    ein engerer Typ waere hier eine Luege.
    """

    @pytest.fixture(autouse=True, scope=scope)
    def _frontend_naht_riegel() -> None:
        _pruefe(dateien, pakete)

    return _frontend_naht_riegel


def nur_mit_frontend(
    *,
    dateien: tuple[pathlib.Path, ...] = (),
    pakete: tuple[str, ...] = (),
) -> Callable[[_F], _F]:
    """Derselbe Riegel, aber je Test -- fuer Dateien mit gemischtem Inhalt.

    ``test_dns_bypass_npcap_naht.py`` prueft auch reine Backend-Nahtstellen; die
    duerfen ohne node laufen. Darum dort der Dekorator statt des Modul-Riegels.
    """

    def _dekorator(test: _F) -> _F:
        @functools.wraps(test)
        def _huelle(*args: Any, **kwargs: Any) -> Any:
            _pruefe(dateien, pakete)
            return test(*args, **kwargs)

        return _huelle  # type: ignore[return-value]

    return _dekorator
