"""Naht-Test: reist der SNI-Status am bestehenden Auto-Refresh mit? (S88-P6)

DER ANLASS: ``fetchSniStatus`` stand in genau EINEM ``useEffect`` mit leerem
Dependency-Array und lief einmal beim Betreten der Ansicht; der Auto-Refresh rief
nur ``ladeTraffic``. Brach die Aufzeichnung waehrend des Zuschauens ab, blieb der
Schalter auf "aktiv" stehen, obwohl nichts mehr lief. Karls Entscheidung (Weg 2):
der Status reist am VORHANDENEN Auto-Refresh mit -- kein eigener Timer.

WAS HIER GEPRUEFT WIRD -- UND WAS AUSDRUECKLICH NICHT:

Geprueft wird die NAHT am echten Quelltext von ``TrafficView.jsx``: dass beide
Aufrufer (Betreten der Ansicht + Auto-Refresh-Intervall) DIESELBE Status-Funktion
rufen, dass diese Funktion genau einmal existiert, und dass kein zweiter
``setInterval``/``setTimeout`` entstanden ist. Dazu kommt eine echte
node-Messung: das Modul wird mit ``esbuild`` uebersetzt und gebuendelt, was
Syntaxfehler und die Reihenfolge-Falle der Umstellung ausschliesst (die Funktion
muss VOR dem Auto-Refresh-Effekt stehen, sonst liest dessen Dependency-Array
waehrend des Renders eine noch nicht initialisierte ``const`` -- ReferenceError).

NICHT geprueft wird das LAUFZEIT-Verhalten: dass das Intervall real feuert und der
Callback real ``fetchSniStatus`` ruft. Dafuer muesste die Komponente gemountet und
die Uhr vorgestellt werden. Gemessen (S88-P6): ``frontend/package.json`` kennt nur
dev/build/preview, und in ``frontend/node_modules`` fehlen jsdom, happy-dom,
linkedom, react-test-renderer, @testing-library/react, vitest und jest; node 20
bringt kein DOM mit (``globalThis.document === undefined``). Vorhanden sind nur
``esbuild`` und ``react-dom`` -- und ``react-dom/server`` fuehrt ``useEffect``
grundsaetzlich nicht aus, dort entsteht also nie ein Intervall. Ein Mount-Test
brauchte damit eine neue Abhaengigkeit, also ein Frontend-Testframework -- das ist
ein eigener Zuschnitt und hier ausdruecklich nicht gebaut worden.

Der Quelltext wird OHNE Kommentare geprueft. Die Kommentare an der Aenderung nennen
den Sachverhalt absichtlich im Wortlaut (u. a. den benannten Restfall); ein Test,
der auf sie hereinfaellt, wuerde eine Erklaerung fuer ein Verhalten halten.
Muster und Begruendung wie ``backend/tests/test_netz_aufraeumen_texte_naht.py``.
"""

import json
import pathlib
import re
import subprocess

from tests import naht_frontend

_FRONTEND = pathlib.Path(__file__).resolve().parents[2] / "frontend"
_VIEW_JSX = _FRONTEND / "src" / "components" / "TrafficView.jsx"

# Gemeinsame Bedingung (S89-A1): lokal ueberspringen, in der CI fallen -- siehe
# ``tests/naht_frontend.py``. HIER SASS DIE FEHLSTELLE: die alte Bedingung fragte nur
# nach node und der Quelldatei, das Buendel-Skript unten importiert aber ``esbuild``.
# In der CI fiel der Test darum mit ERR_MODULE_NOT_FOUND (Lauf 31816836761). ``react``
# und ``react-dom`` stehen nicht in der Liste: der Buendel-Lauf fuehrt sie als
# ``external``, sie werden nie aufgeloest.
_riegel = naht_frontend.riegel(dateien=(_VIEW_JSX,), pakete=("esbuild",))

# Der Name der EINEN Status-Funktion, die beide Aufrufer teilen.
_STATUS_FUNKTION = "uebernehmeSniStatus"


def _code_ohne_kommentare() -> str:
    """Liest ``TrafficView.jsx`` und entfernt Zeilen- und JSX-Block-Kommentare.

    Verboten ist die Bauart im VERHALTEN, nicht im erklaerenden Text -- und die
    Kommentare dieser Aenderung nennen ``setInterval`` und den Restfall bewusst
    im Klartext.
    """
    quelle = _VIEW_JSX.read_text(encoding="utf-8")
    ohne_zeilenkommentare = "\n".join(
        zeile for zeile in quelle.splitlines() if not zeile.lstrip().startswith("//")
    )
    return re.sub(r"\{/\*.*?\*/\}", "", ohne_zeilenkommentare, flags=re.DOTALL)


def _auto_refresh_effekt(code: str) -> str:
    """Schneidet den Rumpf des Auto-Refresh-Effekts aus dem kommentarfreien Code.

    Anker ist der einzige ``setInterval``-Aufruf der Datei (vom Test darunter
    abgesichert): vom ``useEffect``, das ihn traegt, bis zu dessen
    Dependency-Array. Findet sich der Anker nicht, faellt der Test -- dann ist die
    Stelle umgebaut worden und der Test muss neu vermessen werden, statt still
    durchzulaufen.
    """
    start = code.find("const id = setInterval(")
    assert start != -1, "Kein setInterval in TrafficView.jsx -- der Auto-Refresh ist weg?"

    kopf = code.rfind("useEffect(() => {", 0, start)
    assert kopf != -1, "Zum setInterval gehoert kein useEffect -- Stelle umgebaut?"

    ende = code.find("clearInterval", start)
    assert ende != -1, "Das Intervall wird nicht mehr geraeumt"
    schluss = code.find(");", ende)
    assert schluss != -1

    return code[kopf : schluss + 2]


def test_der_auto_refresh_holt_den_sni_status_mit() -> None:
    """Aufgabe 1.1: der Auto-Refresh-Pfad ruft die Status-Funktion.

    Das ist der Kern der Aenderung: im selben Intervall-Callback, in dem heute
    ``ladeTraffic`` steht, steht auch die Status-Uebernahme.
    """
    effekt = _auto_refresh_effekt(_code_ohne_kommentare())

    assert "ladeTraffic(false)" in effekt, "Der Auto-Refresh laedt den Traffic nicht mehr"
    assert f"{_STATUS_FUNKTION}()" in effekt, (
        f"Der Auto-Refresh-Callback ruft {_STATUS_FUNKTION} nicht -- der SNI-Status reist nicht mit"
    )


def test_beide_aufrufer_fahren_dieselbe_bauart() -> None:
    """Aufgabe 1.1: keine zweite Bauart -- eine Funktion, zwei Aufrufer.

    ``fetchSniStatus`` darf im View nur an EINER Stelle gerufen werden: in der
    geteilten Funktion. Steht der Aufruf ein zweites Mal da, ist der Weg
    doppelt ausgelegt -- genau das, was der Auftrag verbietet.
    """
    code = _code_ohne_kommentare()

    assert code.count(f"const {_STATUS_FUNKTION} = ") == 1, (
        f"{_STATUS_FUNKTION} ist nicht genau einmal definiert"
    )
    assert code.count("fetchSniStatus(") == 1, (
        "fetchSniStatus wird an mehr als einer Stelle gerufen -- zweite Bauart"
    )
    # Zwei Aufrufer: der Betretens-Effekt und der Auto-Refresh-Callback.
    assert code.count(f"{_STATUS_FUNKTION}()") == 2, (
        f"Erwartet genau zwei Aufrufer von {_STATUS_FUNKTION} (Betreten der Ansicht + Auto-Refresh)"
    )


def test_es_gibt_keinen_zweiten_timer() -> None:
    """Aufgabe 1.2: kein neuer Timer, kein neues Intervall, keine eigene Frequenz.

    Der vorhandene Auto-Refresh traegt es mit. Ein zweiter ``setInterval`` oder ein
    ``setTimeout`` waere die eigene Frequenz, die Weg 2 ausdruecklich ausschliesst.
    """
    code = _code_ohne_kommentare()

    assert code.count("setInterval(") == 1, (
        "Mehr als ein setInterval in TrafficView.jsx -- eigene Frequenz eingebaut"
    )
    assert "setTimeout(" not in code, (
        "setTimeout in TrafficView.jsx -- eigener Takt fuer den Status?"
    )


def test_das_holen_des_status_ist_best_effort() -> None:
    """Aufgabe 1.3: ein Fehlschlag darf weder Auto-Refresh noch Anzeige reissen.

    Gemessen am Bestand: ``fetchSniStatus`` WIRFT (kein stiller Fallback, siehe
    ``frontend/src/api/sni.js``), und der Aufruf beim Betreten fing das mit einem
    leeren ``.catch`` ab und liess die Marker unveraendert. Die geteilte Funktion
    fuehrt genau das fort -- damit gilt es fuer BEIDE Aufrufer, ohne dass der
    Auto-Refresh-Callback selbst etwas absichern muesste.

    Zusaetzlich geprueft: der Callback ``await``-et den Status NICHT. Ein ``await``
    haette den Traffic-Takt an die Antwortzeit des Status-Aufrufs gehaengt.
    """
    code = _code_ohne_kommentare()

    start = code.find(f"const {_STATUS_FUNKTION} = ")
    assert start != -1
    rumpf = code[start : code.find("useEffect", start)]

    assert ".catch(() => {})" in rumpf, (
        f"{_STATUS_FUNKTION} faengt den Fehlschlag von fetchSniStatus nicht ab"
    )

    effekt = _auto_refresh_effekt(code)
    assert f"await {_STATUS_FUNKTION}" not in effekt, (
        "Der Auto-Refresh awaitet den Status -- er haengt dann an dessen Antwortzeit"
    )


def test_der_abbruchmarker_wird_uebernommen() -> None:
    """Aufgabe 1.1: geholt wird der Status MIT dem Abbruchmarker.

    Ohne ``stoppedReason`` waere der Auto-Refresh-Anschluss folgenlos: der Hinweis
    auf den Selbst-Abbruch ist genau das, was mitreisen soll.
    """
    code = _code_ohne_kommentare()
    start = code.find(f"const {_STATUS_FUNKTION} = ")
    rumpf = code[start : code.find("useEffect", start)]

    assert "stoppedReason" in rumpf, "Die Status-Uebernahme liest den Abbruchmarker nicht"
    assert "setSniStopMarker" in rumpf, "Der Abbruchmarker wird nicht uebernommen"


def test_die_geaenderte_datei_uebersetzt_und_buendelt() -> None:
    """Echte node-Messung: der Umbau ist syntaktisch heil und in gueltiger Reihenfolge.

    ``esbuild`` uebersetzt das JSX und buendelt die Datei mitsamt ihrer lokalen
    Importe (das Frontend hat keinen Test-Runner; ``build`` ist der vorhandene
    echte Weg). Das faengt insbesondere die Reihenfolge-Falle: die geteilte
    Funktion muss VOR dem Auto-Refresh-Effekt stehen, weil dessen Dependency-Array
    schon waehrend des Renders ausgewertet wird.
    """
    skript = r"""
import { build } from "esbuild";
const out = await build({
  entryPoints: ["./src/components/TrafficView.jsx"],
  bundle: true, write: false, format: "esm", jsx: "automatic",
  external: ["react", "react-dom", "react-i18next", "lucide-react"],
  loader: { ".css": "empty" },
});
process.stdout.write(JSON.stringify({ bytes: out.outputFiles[0].text.length }));
"""
    ergebnis = subprocess.run(
        ["node", "--input-type=module", "-e", skript],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=_FRONTEND,
    )

    assert ergebnis.returncode == 0, f"esbuild scheiterte: {ergebnis.stderr}"
    geladen: object = json.loads(ergebnis.stdout)
    assert isinstance(geladen, dict)
    assert isinstance(geladen.get("bytes"), int) and geladen["bytes"] > 0


def test_die_status_funktion_steht_vor_dem_auto_refresh_effekt() -> None:
    """Die Reihenfolge ausdruecklich festgehalten -- sie ist kein Zufall.

    ``const`` in der Temporal Dead Zone: stuende die Definition unter dem
    Auto-Refresh-Effekt, faellt die Komponente beim ersten Render mit einem
    ReferenceError, weil das Dependency-Array die Funktion dann schon nennt.
    Der Buendel-Test darueber faengt das NICHT (esbuild uebersetzt es klaglos).
    """
    code = _code_ohne_kommentare()
    definition = code.find(f"const {_STATUS_FUNKTION} = ")
    verwendung = code.find("const id = setInterval(")

    assert definition != -1 and verwendung != -1
    assert definition < verwendung, (
        f"{_STATUS_FUNKTION} steht unter dem Auto-Refresh-Effekt -- "
        "dessen Dependency-Array liest sie dann in der Temporal Dead Zone"
    )
