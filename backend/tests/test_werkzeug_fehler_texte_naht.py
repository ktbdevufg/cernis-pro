"""Naht-Test: kommt die Meldung des Backends beim Anwender an? (S84-A7, Befund 61)

DER BEFUND: Zwei Ansichten zeigten bei einem HTTP 503 einen FESTEN Satz, der ein
bestimmtes Programm benannte. ``RouteView`` behauptete stets, ``traceroute`` fehle --
auch dann, wenn in Wahrheit ``dig`` fehlte (``ResolverToolMissing``) oder eine Geo/ASN-
Datendatei (``ResolverDataMissing``). ``LookupPanel`` wertete den Fehler ueberhaupt nicht
aus (``.catch(() => setStatus("fehler"))``) und verwarf damit beide 503er des Resolvers.

Dazu kam das Loch, durch das der echte Grund gar nicht erst ankam: ``apiGet`` in
``frontend/src/api/client.js`` uebergab den dritten Konstruktor-Parameter von ``ApiError``
nicht -- ``detail`` war auf JEDEM GET-Weg ``null``. Genau darum hatte sich
``api/licenses.js`` einen eigenen GET gebaut.

WAS HIER GEPRUEFT WIRD, UND WARUM AUS pytest: Die Auswahl ist eine Frontend-Funktion
(``frontend/src/lib/werkzeugFehler.js``), die Meldungen aber kommen aus dem Backend
(``infrastructure.resolver.errors``). Die Naht zwischen beiden ist die Stelle, an der
dieses Finding entstanden ist. Das Frontend hat kein eigenes Testframework
(``frontend/package.json`` kennt nur dev/build/preview); die CI faehrt ``pytest``. Darum
laeuft die Pruefung von hier aus und ruft die ECHTEN Frontend-Funktionen ueber ``node``
auf -- kein Nachbau der Logik in Python, kein zweiter Wahrheitsstand. Muster:
``backend/tests/test_traffic_permission_texte_naht.py``.
"""

import json
import pathlib
import shutil
import subprocess

import pytest

from infrastructure.resolver.errors import ResolverDataMissing, ResolverToolMissing

_FRONTEND = pathlib.Path(__file__).resolve().parents[2] / "frontend"
_WERKZEUG_JS = _FRONTEND / "src" / "lib" / "werkzeugFehler.js"
_CLIENT_JS = _FRONTEND / "src" / "api" / "client.js"
_I18N = _FRONTEND / "src" / "i18n"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not _WERKZEUG_JS.is_file(),
    reason="node oder frontend/src/lib/werkzeugFehler.js nicht vorhanden",
)

# Der ansichts-eigene Schluessel fuer "irgendein anderer Fehler". Er bleibt je Ansicht
# verschieden (die Handlung ist verschieden) -- nur der 503-Fall ist gemeinsam.
_ROUTE_FEHLER = "untersuchen.route.error"
_LOOKUP_FEHLER = "beobachten.lookup.error"

# Der gemeinsame Rueckfallschluessel, wenn das Backend keinen Grund mitliefert.
_RUECKFALL = "werkzeug.nichtVerfuegbar"


def _anzeige(status: object, detail: object, fehler_schluessel: str) -> dict[str, object]:
    """Ruft die ECHTE ``waehleWerkzeugFehlerAnzeige`` aus ``lib/werkzeugFehler.js`` ueber node.

    Das Modul wird als ES-Modul importiert (``package.json`` faehrt Vite/ESM). Die
    Funktion ist rein (Status + detail rein, Anzeige raus) und zieht nichts nach.
    """
    modul = _WERKZEUG_JS.resolve().as_uri()
    skript = (
        f"import {{ waehleWerkzeugFehlerAnzeige }} from {json.dumps(modul)};\n"
        f"const a = waehleWerkzeugFehlerAnzeige("
        f"{json.dumps(status)}, {json.dumps(detail)}, {json.dumps(fehler_schluessel)});\n"
        f"process.stdout.write(JSON.stringify(a));\n"
    )
    ergebnis = subprocess.run(
        ["node", "--input-type=module", "-e", skript],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=_FRONTEND,
    )
    assert ergebnis.returncode == 0, f"node scheiterte: {ergebnis.stderr}"
    geladen: object = json.loads(ergebnis.stdout)
    assert isinstance(geladen, dict)
    return geladen


def _text(sprache: str, schluessel: str) -> str:
    """Loest einen punktierten Schluessel in der echten Sprachdatei auf.

    Fehlt ein Glied, faellt der Test -- ein Schluessel ohne Text ist eine leere Anzeige.
    """
    daten: object = json.loads((_I18N / f"{sprache}.json").read_text(encoding="utf-8"))
    for glied in schluessel.split("."):
        assert isinstance(daten, dict), f"{schluessel}: '{glied}' ist kein Objekt"
        assert glied in daten, f"{schluessel}: '{glied}' fehlt in {sprache}.json"
        daten = daten[glied]
    assert isinstance(daten, str) and daten.strip(), f"{schluessel} ist leer in {sprache}.json"
    return daten


# ── Die Regression selbst: die Backend-Meldung kommt beim Anwender an ──────────


@pytest.mark.parametrize("fehler_schluessel", [_ROUTE_FEHLER, _LOOKUP_FEHLER])
def test_die_meldung_des_backends_erreicht_beide_ansichten_im_wortlaut(
    fehler_schluessel: str,
) -> None:
    """Ein 503 MIT detail zeigt genau diesen Text -- in BEIDEN Fundstellen.

    Die Meldung wird aus der ECHTEN Backend-Exception genommen, nicht abgeschrieben:
    aendert sich ihr Wortlaut, prueft dieser Test weiterhin den echten.
    """
    meldung = ResolverToolMissing("dig").message

    anzeige = _anzeige(503, meldung, fehler_schluessel)

    assert anzeige["text"] == meldung, (
        "Der Grund des Backends kommt nicht im Wortlaut an -- genau das war der Befund."
    )
    assert anzeige["textKey"] is None, "Bei vorhandenem Grund darf kein Schluessel gewaehlt werden"


def test_kein_fester_programmname_wenn_ein_anderes_programm_fehlt() -> None:
    """Fehlt ``dig`` (nicht ``traceroute``), steht ``traceroute`` NICHT in der Anzeige.

    Der Kern des Findings: der alte feste Satz behauptete an dieser Stelle immer
    ``traceroute``. Geprueft wird die Route-Fundstelle, weil dort der falsche Satz stand.
    """
    meldung = ResolverToolMissing("dig").message

    anzeige = _anzeige(503, meldung, _ROUTE_FEHLER)
    gezeigt = str(anzeige["text"])

    assert "dig" in gezeigt, f"Das tatsaechlich fehlende Programm wird nicht genannt: {gezeigt}"
    assert "traceroute" not in gezeigt.lower(), (
        f"Es wird weiterhin 'traceroute' behauptet, obwohl 'dig' fehlt: {gezeigt}"
    )


def test_auch_eine_fehlende_datendatei_kommt_im_wortlaut_an() -> None:
    """Der zweite echte 503 des Resolvers: eine Geo/ASN-CSV fehlt -- kein Programm.

    ``LookupPanel`` verwarf beide 503er; dieser hier benennt gar kein Programm, sondern
    eine Datei. Ein fester Programmname waere hier doppelt falsch.
    """
    meldung = ResolverDataMissing("/data/asn-country-ipv4.csv").message

    anzeige = _anzeige(503, meldung, _LOOKUP_FEHLER)
    gezeigt = str(anzeige["text"])

    assert gezeigt == meldung
    assert "traceroute" not in gezeigt.lower()
    assert "dig" not in gezeigt.lower()


@pytest.mark.parametrize("fehler_schluessel", [_ROUTE_FEHLER, _LOOKUP_FEHLER])
@pytest.mark.parametrize("leer", [None, "", "   "])
def test_ohne_grund_der_neutrale_rueckfalltext(fehler_schluessel: str, leer: object) -> None:
    """Liefert das Backend keinen (oder einen leeren) Grund, greift der Rueckfallschluessel.

    Er behauptet KEIN bestimmtes Programm -- an dieser Stelle ist keines bekannt.
    """
    anzeige = _anzeige(503, leer, fehler_schluessel)

    assert anzeige["textKey"] == _RUECKFALL
    assert anzeige["text"] is None


@pytest.mark.parametrize("fehler_schluessel", [_ROUTE_FEHLER, _LOOKUP_FEHLER])
@pytest.mark.parametrize("status", [None, 500, 502, 404])
def test_andere_fehler_bleiben_beim_ansichts_eigenen_text(
    fehler_schluessel: str, status: object
) -> None:
    """Nur der 503 ist der Werkzeug-/Daten-Fall. Alles andere bleibt, wie es war.

    Auch ein Netzfehler (``status`` null) darf nicht in den Werkzeug-Zweig laufen -- dort
    steht kein Werkzeug in Frage.
    """
    anzeige = _anzeige(status, "irgendein Grund", fehler_schluessel)

    assert anzeige["textKey"] == fehler_schluessel
    assert anzeige["text"] is None


# ── Der neue Schluessel liegt in BEIDEN Sprachdateien ─────────────────────────


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_der_rueckfallschluessel_hat_in_beiden_sprachen_einen_text(sprache: str) -> None:
    """Was die Auswahl waehlt, muss in de.json UND en.json stehen -- sonst bleibt es leer."""
    assert _text(sprache, _RUECKFALL)


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_der_rueckfalltext_nennt_kein_bestimmtes_programm(sprache: str) -> None:
    """Der Rueckfalltext behauptet nichts, was an dieser Stelle niemand geprueft hat.

    Er greift genau dann, wenn das Backend KEINEN Grund mitgeliefert hat. Ein
    Programmname waere dort frei erfunden.
    """
    klein = _text(sprache, _RUECKFALL).lower()

    for verboten in ("traceroute", "dig", "nmap", "npcap", "tcpdump"):
        assert verboten not in klein, f"Der Rueckfalltext nennt '{verboten}' ({sprache})"


@pytest.mark.parametrize("sprache", ["de", "en"])
def test_der_alte_falsche_schluessel_steht_nicht_mehr_da(sprache: str) -> None:
    """``untersuchen.route.toolMissing`` darf nicht mit falschem Inhalt stehenbleiben.

    Er behauptete unbedingt ``traceroute``. Er wurde ersetzt, nicht umgeschrieben -- ein
    umgeschriebener Schluessel unter altem Namen haette dieselbe Falle fuer den naechsten
    Leser gestellt.
    """
    daten = json.loads((_I18N / f"{sprache}.json").read_text(encoding="utf-8"))

    assert "toolMissing" not in daten["untersuchen"]["route"], (
        f"Der alte Schluessel steht weiterhin in {sprache}.json"
    )


# ── Das Loch im GET-Weg selbst ────────────────────────────────────────────────


def test_apiget_reicht_das_detail_des_backends_durch() -> None:
    """``apiGet`` traegt den Begruendungstext jetzt in ``ApiError.detail``.

    Ohne diesen Schritt kaeme die Anzeige-Auswahl oben nie an einen Grund heran: der
    dritte Konstruktor-Parameter blieb im GET-Weg leer, ``detail`` war stets ``null``.
    Geprueft wird gegen ein gestelltes ``fetch``, damit kein Backend laufen muss.
    """
    meldung = ResolverToolMissing("dig").message
    modul = _CLIENT_JS.resolve().as_uri()
    skript = (
        "globalThis.fetch = async () => ({\n"
        "  ok: false,\n"
        "  status: 503,\n"
        f"  json: async () => ({{ detail: {json.dumps(meldung)} }}),\n"
        "});\n"
        f"const {{ apiGet, ApiError }} = await import({json.dumps(modul)});\n"
        "try {\n"
        "  await apiGet('/api/resolve');\n"
        "  process.stdout.write(JSON.stringify({fehler: 'kein Wurf'}));\n"
        "} catch (e) {\n"
        "  process.stdout.write(JSON.stringify({\n"
        "    istApiError: e instanceof ApiError,\n"
        "    status: e.status,\n"
        "    detail: e.detail,\n"
        "  }));\n"
        "}\n"
    )
    ergebnis = subprocess.run(
        ["node", "--input-type=module", "-e", skript],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=_FRONTEND,
    )
    assert ergebnis.returncode == 0, f"node scheiterte: {ergebnis.stderr}"
    geworfen = json.loads(ergebnis.stdout)

    assert geworfen == {"istApiError": True, "status": 503, "detail": meldung}


def test_apiget_erfindet_kein_detail_wenn_der_body_keines_traegt() -> None:
    """Kein JSON-Body / kein ``detail`` -> ``detail`` bleibt ``null``, nichts wird gedeutet."""
    modul = _CLIENT_JS.resolve().as_uri()
    skript = (
        "globalThis.fetch = async () => ({\n"
        "  ok: false,\n"
        "  status: 503,\n"
        "  json: async () => { throw new Error('kein JSON'); },\n"
        "});\n"
        f"const {{ apiGet }} = await import({json.dumps(modul)});\n"
        "try {\n"
        "  await apiGet('/api/resolve');\n"
        "  process.stdout.write('kein Wurf');\n"
        "} catch (e) {\n"
        "  process.stdout.write(JSON.stringify({status: e.status, detail: e.detail}));\n"
        "}\n"
    )
    ergebnis = subprocess.run(
        ["node", "--input-type=module", "-e", skript],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=_FRONTEND,
    )
    assert ergebnis.returncode == 0, f"node scheiterte: {ergebnis.stderr}"

    assert json.loads(ergebnis.stdout) == {"status": 503, "detail": None}
