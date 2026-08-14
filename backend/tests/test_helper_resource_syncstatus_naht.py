"""Naht-Test: fuehrt ``syncStatus`` den Zustand zweiseitig? (S88-P7)

DER ANLASS: ``syncStatus`` (``frontend/src/hooks/useHelperResource.js``) uebernahm
nur ``running=true``. Beendete der Sniffer sich selbst, blieb das im Eintrag
unsichtbar -- der Schalter stand weiter auf "aktiv", und der Stop-Hinweis der
Ansicht war unter ``!running`` maskiert (S88-P5/P6, Befund 30). Die Aenderung
uebernimmt jetzt auch ``running=false`` und ruft dabei ``notify``, spiegelbildlich
zum vorhandenen true-Weg. Das Verhalten bei ABRUFSFEHLER bleibt unveraendert: es
wird nichts geschrieben, der letzte Wert bleibt stehen -- Linie der Vorlage
``DnsBypassView.ladeStatus``, damit ein Aussetzer der Abfrage keine laufende
Aufzeichnung als beendet ausgibt.

WARUM AUS pytest UND WIE: Das Frontend hat kein Testframework
(``frontend/package.json`` kennt nur dev/build/preview), und es soll hier keines
entstehen. Gemessen wird daher am ECHTEN Modul ueber ``node``, Muster wie
``backend/tests/test_sni_stopped_texte_naht.py`` -- nichts wird in Python
nachgebaut, sonst entstuende ein zweiter Wahrheitsstand.

``useHelperResource`` ist ein React-Hook; damit sein Rumpf ausserhalb eines
Renderers laeuft, ersetzt ``esbuild`` beim Buendeln das Modul ``react`` durch
einen winzigen Stub: ``useCallback`` gibt die Funktion durch, ``useEffect``
fuehrt sie sofort aus (so registriert sich der Subscriber), ``useState`` liefert
einen zaehlenden Setter. Der Stub ersetzt AUSSCHLIESSLICH React -- der gepruefte
Code, ``syncStatus`` samt Registry und ``notify``, ist der echte aus der Datei.
Der Zaehler des ``useState``-Setters ist zugleich der Beleg, dass ``notify``
gelaufen ist: der Re-Render-Notifier des Hooks ist genau dieser Setter.

Jeder Fall bekommt einen EIGENEN key. Die Registry ist modul-global; ein geteilter
key liesse die Faelle uebereinander laufen.

Der Zaehler zaehlt SETTER-Aufrufe, nicht notify-Durchlaeufe: ein ``notify`` ruft
jeden Subscriber des key, und jeder Hook-Aufruf legt ueber den ``useEffect``-Stub
einen weiteren an. Das Skript meldet daher die Zahl der Subscriber mit; die Tests
pruefen "genau ein notify" als ``setter == subscriber`` bzw. "kein notify" als
``setter == 0``. Ein Nachbau der Subscriber-Zahl im Test waere ein zweiter
Wahrheitsstand -- sie wird gemessen, nicht angenommen.

NICHT geprueft wird das Verhalten im echten React-Renderer (Mount, Re-Render,
Unmount) -- dafuer braeuchte es ein Frontend-Testframework, das hier ausdruecklich
nicht gebaut worden ist. Ebenso ungeprueft bleiben ``acquire``, ``release`` und der
benannte Restfall (``running=false`` heisst auch "nie gestartet" / "vom Anwender
gestoppt"); der ist absichtlich nur im Kommentar festgehalten, nicht behoben.
"""

import json
import pathlib
import shutil
import subprocess

import pytest

_FRONTEND = pathlib.Path(__file__).resolve().parents[2] / "frontend"
_HOOK_JS = _FRONTEND / "src" / "hooks" / "useHelperResource.js"
_NODE_MODULES = _FRONTEND / "node_modules"

# ``esbuild`` MITGEPRUEFT (Muster ``test_netz_aufraeumen_texte_naht.py``): das
# Skript unten importiert es, und der quality-Job der CI richtet zwar node ein,
# installiert aber die Frontend-Abhaengigkeiten nicht -- dort fiel der Test mit
# ERR_MODULE_NOT_FOUND, statt sich zu ueberspringen. ``react-dom`` steht hier
# nicht in der Bedingung: React wird gestubbt, nicht gerendert.
pytestmark = pytest.mark.skipif(
    shutil.which("node") is None
    or not _HOOK_JS.is_file()
    or not (_NODE_MODULES / "esbuild").is_dir(),
    reason=(
        "Die node-Messung an useHelperResource.js faellt aus: node, "
        "frontend/src/hooks/useHelperResource.js oder frontend/node_modules/esbuild "
        "fehlt. Sie laeuft lokal mit installierten Frontend-Abhaengigkeiten "
        "(frontend: npm ci); die Naht ist hier ungedeckt, nicht in Ordnung befunden."
    ),
)

# Buendelt das ECHTE Hook-Modul mit React-Stub und faehrt die drei Faelle durch.
# Ausgabe: ein JSON-Objekt je Fall mit dem Zustand vorher/nachher, der Zahl der
# Setter-Aufrufe und der Zahl der Subscriber des key.
_SKRIPT = r"""
import { build } from "esbuild";

// Der React-Stub. Ersetzt NUR React, nicht den geprueften Code.
// `useEffect` sofort auszufuehren ist noetig, damit sich der Re-Render-Notifier
// des Hooks als Subscriber eintraegt -- er IST der `useState`-Setter, und sein
// Zaehler ist der Beleg, dass `notify` gelaufen ist.
const reactStub = `
export const useState = (init) => [
  typeof init === "function" ? init() : init,
  () => { globalThis.__setter = (globalThis.__setter ?? 0) + 1; },
];
export const useCallback = (fn) => fn;
export const useEffect = (fn) => { fn(); };
`;

const gebaut = await build({
  entryPoints: ["./src/hooks/useHelperResource.js"],
  bundle: true,
  write: false,
  format: "esm",
  plugins: [
    {
      name: "react-stub",
      setup(b) {
        b.onResolve({ filter: /^react$/ }, () => ({ path: "react", namespace: "stub" }));
        b.onLoad({ filter: /.*/, namespace: "stub" }, () => ({
          contents: reactStub,
          loader: "js",
        }));
      },
    },
  ],
});

const quelltext = gebaut.outputFiles[0].text;
const modul = await import(
  "data:text/javascript;base64," + Buffer.from(quelltext).toString("base64")
);
const { useHelperResource } = modul;

// Jeder Hook-Aufruf traegt ueber den useEffect-Stub genau einen Subscriber in den
// Eintrag ein. Hier gezaehlt, damit die Tests "genau ein notify" gegen die ECHTE
// Subscriber-Zahl pruefen koennen statt gegen eine angenommene.
const subscriber = new Map();
function hook(key, callbacks) {
  subscriber.set(key, (subscriber.get(key) ?? 0) + 1);
  return useHelperResource(key, callbacks);
}

// Setzt den Eintrag eines frischen key auf running=true, OHNE syncStatus zu
// benutzen: ein acquire mit einem start-Callback, der Erfolg meldet.
async function laufendMachen(key) {
  await hook(key, { start: async () => ({ ok: true }) }).acquire();
}

const faelle = {};

// Fall 1: der true-Weg wirkt unveraendert. Eintrag steht auf false, Backend
// meldet running=true -> uebernehmen und notify.
{
  const key = "fall-true";
  const h = hook(key, { status: async () => ({ running: true }) });
  const vorher = h.running;
  globalThis.__setter = 0;
  await h.syncStatus();
  const setter = globalThis.__setter;
  faelle.true_weg = {
    vorher,
    nachher: hook(key, {}).running,
    setter,
    subscriber: subscriber.get(key) - 1, // der Ablese-Aufruf kam NACH dem notify
  };
}

// Fall 2: ein gemeldetes running=false schaltet ab. Eintrag steht auf true,
// Backend meldet running=false -> abschalten und notify.
{
  const key = "fall-false";
  await laufendMachen(key);
  const h = hook(key, { status: async () => ({ running: false }) });
  const vorher = h.running;
  globalThis.__setter = 0;
  await h.syncStatus();
  const setter = globalThis.__setter;
  faelle.false_weg = {
    vorher,
    nachher: hook(key, {}).running,
    setter,
    subscriber: subscriber.get(key) - 1,
  };
}

// Fall 3: ein Abrufsfehler schreibt nichts. Eintrag steht auf true, der
// status-Callback wirft -> der letzte Wert bleibt stehen, kein notify, und der
// Wurf kommt NICHT bei uns an.
{
  const key = "fall-fehler";
  await laufendMachen(key);
  const h = hook(key, {
    status: async () => {
      throw new Error("Abruf fehlgeschlagen");
    },
  });
  const vorher = h.running;
  globalThis.__setter = 0;
  let geworfen = false;
  try {
    await h.syncStatus();
  } catch {
    geworfen = true;
  }
  const setter = globalThis.__setter;
  faelle.abrufsfehler = {
    vorher,
    nachher: hook(key, {}).running,
    setter,
    subscriber: subscriber.get(key) - 1,
    geworfen,
  };
}

process.stdout.write(JSON.stringify(faelle));
"""


@pytest.fixture(scope="module")
def gemessen() -> dict[str, dict[str, object]]:
    """Faehrt die node-Messung EINMAL und gibt die drei Faelle zurueck.

    Ein Lauf je Test waere derselbe Buendel-Vorgang dreimal; die Faelle sind im
    Skript ueber getrennte keys ohnehin voneinander unabhaengig.
    """
    ergebnis = subprocess.run(
        ["node", "--input-type=module", "-e", _SKRIPT],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=_FRONTEND,
    )
    assert ergebnis.returncode == 0, f"node-Messung scheiterte: {ergebnis.stderr}"

    geladen: object = json.loads(ergebnis.stdout)
    assert isinstance(geladen, dict)
    return geladen


def _zahl(fall: dict[str, object], feld: str) -> int:
    """Liest ein Zaehlfeld der Messung als ``int``.

    Aus ``json.loads`` kommt ``object``; die Pruefung haelt fest, dass das Feld
    ueberhaupt eine Zahl ist -- fehlt es oder ist es etwas anderes, ist die
    Messung untauglich und das soll auffallen, nicht durchrutschen.
    """
    wert = fall[feld]
    assert isinstance(wert, int), f"Feld {feld} ist keine Zahl: {wert!r}"
    return wert


def test_der_true_weg_wirkt_unveraendert(gemessen: dict[str, dict[str, object]]) -> None:
    """Aufgabe 1.1: die vorhandene Richtung bleibt, wie sie war.

    Meldet das Backend ``running=true``, waehrend der Eintrag false haelt, wird
    uebernommen und ``notify`` gerufen. Das ist der Stand VOR der Aenderung und
    muss ihn ueberleben -- sonst waere die Zweiseitigkeit ein Tausch statt einer
    Ergaenzung.
    """
    fall = gemessen["true_weg"]

    assert fall["vorher"] is False, "Der Eintrag stand nicht auf false -- Messung untauglich"
    assert fall["nachher"] is True, "Ein gemeldetes running=true wird nicht mehr uebernommen"
    assert _zahl(fall, "subscriber") > 0, (
        "Kein Subscriber am Eintrag -- ein notify waere unsichtbar"
    )
    assert _zahl(fall, "setter") == _zahl(fall, "subscriber"), (
        "Der true-Weg benachrichtigt nicht genau einmal jeden Subscriber"
    )


def test_ein_gemeldetes_running_false_schaltet_ab(
    gemessen: dict[str, dict[str, object]],
) -> None:
    """Aufgabe 1.1: die NEUE Richtung -- der Kern der Aenderung.

    Meldet das Backend ``running=false``, waehrend der Eintrag true haelt, wird
    abgeschaltet und ``notify`` gerufen. Ohne das bleibt ein Selbst-Abbruch des
    Sniffers unsichtbar: der Schalter steht auf "aktiv", und der Stop-Hinweis der
    Ansicht ist unter ``!running`` maskiert (Befund 30).
    """
    fall = gemessen["false_weg"]

    assert fall["vorher"] is True, "Der Eintrag stand nicht auf true -- Messung untauglich"
    assert fall["nachher"] is False, (
        "Ein gemeldetes running=false schaltet den Eintrag nicht ab -- "
        "der Selbst-Abbruch bleibt unsichtbar"
    )
    assert _zahl(fall, "subscriber") > 0, (
        "Kein Subscriber am Eintrag -- ein notify waere unsichtbar"
    )
    assert _zahl(fall, "setter") == _zahl(fall, "subscriber"), (
        "Das Abschalten benachrichtigt die Subscriber nicht genau einmal -- "
        "die Ansicht erfaehrt es nie"
    )


def test_ein_abrufsfehler_schreibt_nichts(gemessen: dict[str, dict[str, object]]) -> None:
    """Aufgabe 1.2: das Verhalten bei Abrufsfehler bleibt unveraendert.

    Wirft der ``status``-Callback, wird NICHTS geschrieben und der letzte Wert
    bleibt stehen -- ein Aussetzer der Abfrage darf eine laufende Aufzeichnung
    nicht als beendet ausgeben. Das ist zugleich die Linie der Vorlage
    ``DnsBypassView.ladeStatus``; ``DnsBypassRecordingPill`` schaltet in dieser
    Lage ab, was hier ausdruecklich NICHT die Vorlage ist.

    Mitgeprueft: ``syncStatus`` wirft nicht nach aussen (Beiwerk, S3-Linie).
    """
    fall = gemessen["abrufsfehler"]

    assert fall["vorher"] is True, "Der Eintrag stand nicht auf true -- Messung untauglich"
    assert fall["nachher"] is True, (
        "Ein Abrufsfehler hat den Eintrag umgelegt -- ein Aussetzer gibt jetzt "
        "eine laufende Aufzeichnung als beendet aus"
    )
    assert _zahl(fall, "subscriber") > 0, (
        "Kein Subscriber am Eintrag -- ein notify waere unsichtbar"
    )
    assert _zahl(fall, "setter") == 0, (
        "Bei Abrufsfehler wurde benachrichtigt, obwohl nichts geschah"
    )
    assert fall["geworfen"] is False, "syncStatus wirft nach aussen -- es ist Beiwerk"
