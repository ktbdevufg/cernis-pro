"""Gemeinsamer Riegel der node-gestuetzten Naht-Tests (S89-A1/A5).

WARUM AN EINER STELLE: neun Testdateien messen Frontend-Nahtstellen, indem sie die
ECHTEN Frontend-Quellen ueber ``node`` fahren -- teils uebersetzt und gebuendelt mit
``esbuild`` aus ``frontend/node_modules``. Jede Datei trug dieselbe Ueberspring-Bedingung
in eigener Fassung. Sie liefen darum auseinander: ``test_sni_status_autorefresh_naht.py``
fragte nach ``node`` und der Quelldatei, importierte im Skript aber ``esbuild`` -- in der
CI fiel der Test mit ``ERR_MODULE_NOT_FOUND``, statt sich zu ueberspringen (CI-Lauf
31816836761). Die Bedingung steht darum ab hier EINMAL.

ZWEI URSACHEN, ZWEI ANTWORTEN (Karls Vorgabe S89-A5). Frueher behandelte der Riegel
alles Fehlende gleich. Das vermengte zwei Lagen, die verschieden gehoeren:

* KATEGORIE UMGEBUNG -- ``node`` im PATH und die Pakete aus ``frontend/node_modules``.
  Sie fehlen genau dann, wenn ``npm ci`` nicht gelaufen ist. Ohne gesetzte ``CI``
  -- also auf einer Entwicklermaschine -- darf sich der Test darum ueberspringen;
  niemand muss ``npm ci`` fahren, nur um das Backend zu testen. MIT gesetzter ``CI``
  ueberspringt sich nichts: dort ist es ein Fehler des Ablaufs und faellt mit
  benannter Meldung auf. Ein stiller Uebersprung in der CI hiesse: die Naht gilt als
  geprueft, obwohl sie ungedeckt ist -- genau der Zustand, den dieser Riegel beendet.
  Die CI installiert die Abhaengigkeiten im quality-Job (``npm ci`` in ``frontend``,
  siehe ``.github/workflows/ci.yml``); der Riegel darf dort also fordern.
* KATEGORIE QUELLE -- die Einstiegsquellen unter ``frontend/src``, die der Test selbst
  faehrt oder als Text liest. Fehlt eine, ist nicht die Umgebung unvollstaendig,
  sondern das Repo beschaedigt oder die Naht verschoben. Das FAELLT IMMER, in beiden
  Modi, mit eigener Meldung ohne ``npm ci``-Bezug: ein Waechter, der seinen Gegenstand
  nicht findet, faellt mit benannter Meldung und laeuft nie still durch (Regel S69-C).
  Ein Uebersprung waere der Rueckfall auf die schwaechere Pruefung (S73-D).

REIHENFOLGE: die Quelldateien werden ZUERST geprueft. Fehlen Quelle und Umgebung
zugleich, gewinnt der Quellen-Fehlschlag -- er darf nicht von einem
Umgebungs-Uebersprung maskiert werden.

DEKLARATIONS-TRENNLINIE, verbindlich fuer jeden kuenftigen Naht-Test:

* ``pakete``: nur Namen unter ``frontend/node_modules``, die WIRKLICH aufgeloest
  werden. Als ``external`` gefuehrte, nie aufgeloeste Pakete gehoeren NICHT hinein.
* ``dateien``: nur Einstiegsquellen, die der Test selbst faehrt oder liest.
* Transitive Quelldateien, die ``esbuild`` oder ``node`` ueber den Importgraphen
  ziehen, gehoeren in KEINE der beiden Listen. Dort ist der laute node- oder
  esbuild-Fehler die richtige Antwort; eine Liste bildete den Importgraphen ein
  zweites Mal ab und veraltete.

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


def _fehlende_quellen(dateien: tuple[pathlib.Path, ...]) -> list[str]:
    """Die Einstiegsquellen, die der Test fahren oder lesen will und die nicht da sind.

    Kategorie QUELLE: ihr Fehlen ist kein Umgebungsmangel, sondern ein beschaedigtes
    Repo oder eine verschobene Naht.
    """
    return [str(datei) for datei in dateien if not datei.is_file()]


def _fehlende_umgebung(pakete: tuple[str, ...]) -> list[str]:
    """Nennt alles, was an der UMGEBUNG fehlt -- als Liste, nicht als blosses Ja/Nein.

    Die Namen wandern in die Meldung: in der CI soll dort stehen, WAS fehlt, nicht
    nur, dass etwas fehlt.
    """
    fehlt: list[str] = []
    if shutil.which("node") is None:
        fehlt.append("node (Interpreter nicht im PATH)")
    fehlt += [
        f"frontend/node_modules/{paket}" for paket in pakete if not (NODE_MODULES / paket).is_dir()
    ]
    return fehlt


def _pruefe(dateien: tuple[pathlib.Path, ...], pakete: tuple[str, ...]) -> None:
    """DIE eine Entscheidung, zweigeteilt nach Ursache (S89-A5).

    Erst die Quellen: fehlt eine, faellt der Test in BEIDEN Modi -- ein Waechter ohne
    Gegenstand laeuft nie still durch (S69-C). Das steht bewusst VOR der
    Umgebungs-Pruefung: fehlen beide zugleich, darf der Quellen-Fehlschlag nicht von
    einem Umgebungs-Uebersprung maskiert werden.

    Dann die Umgebung: ohne ``CI`` ueberspringen, mit ``CI`` fallen -- unveraendert.
    """
    fehlende_quellen = _fehlende_quellen(dateien)
    if fehlende_quellen:
        pytest.fail(
            "Die Naht-Quelldatei fehlt -- das Ziel dieser Naht wurde geloescht, verschoben "
            "oder umbenannt. Der Test muss der Naht folgen. Fehlt: "
            f"{', '.join(fehlende_quellen)}.",
            pytrace=False,
        )

    fehlt = _fehlende_umgebung(pakete)
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

    ``dateien``: NUR die Einstiegsquellen, die dieser Test selbst faehrt oder als Text
    liest. Fehlt eine, faellt der Test in beiden Modi (Kategorie QUELLE, siehe
    Modulkopf). Transitive Importe gehoeren NICHT hierher -- dort ist der laute
    node-/esbuild-Fehler die richtige Antwort.
    ``pakete``: Namen unter ``frontend/node_modules``, die das node-Skript wirklich
    aufloest (etwa ``esbuild``, ``react-dom``). Als ``external`` gefuehrte Pakete
    gehoeren nicht hinein, sie werden nie aufgeloest. Wer nichts buendelt, nennt hier
    nichts.
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
