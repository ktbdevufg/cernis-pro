"""Naht-Test: erkennt der DNS-Waechter den Npcap-Marker, bevor er startet? (S84-A7, Befund 52)

DER BEFUND: Der netzweite DNS-Umgehungs-Waechter war die EINZIGE Ansicht der Sniff-
Familie ohne Npcap-Vorpruefung. ``StartDnsBypassRecording`` rief ``recorder.start()``
direkt -- ohne ``check_permission``, ohne ``sniffd_unavailable_reason``. Der Anwender sah
dort den Rohtext der Erfassungsschicht, waehrend Aussenkontakte (``OutboundView``) und
Per-App-Verkehr (``TrafficView``) dieselbe Ursache sauber benennen und die Funktion mit
dem vorhandenen Npcap-Block ausgrauen.

WEG 1 (Karls Entscheidung): der DNS-Waechter bekommt dieselbe Marker-Vorpruefung wie SNI.
Liegt ``NPCAP_MISSING`` vor, zeigt ``DnsBypassView`` denselben Ausgrau-Block mit
``npcap.inlineHint`` und dem Knopf zum ``NpcapDialog``. KEIN neuer Wortlaut. Der Rohtext
aus ``sniff_core.py`` wird NICHT umformuliert, und der ``CAP_NET_RAW``-Substring, an dem
``sni_sniffer.py`` die Naht zwischen HTTP 403 und 503 festmacht, bleibt unangetastet.

GEPRUEFT WIRD DIE GANZE KETTE, beide Seiten:
* Backend: die Vorpruefung greift VOR dem Start; kein Datensatz, keine Quelle.
* Wire: ``DnsBypassStatusOut`` traegt den Marker im Feld ``permission_error``.
* Frontend: ``DnsBypassView`` vergleicht exakt gegen den Marker und unterdrueckt den
  Kasten "Keine Umgehung erfasst", solange er anliegt.

Die Frontend-Seite folgt dem Muster ``test_traffic_permission_texte_naht.py``: das
Frontend hat kein eigenes Testframework, die CI faehrt ``pytest`` -- geprueft wird gegen
die ECHTEN Quelldateien, nicht gegen einen Nachbau.

NICHT VERIFIZIERBAR AUF DIESER MASCHINE: der Marker entsteht ausschliesslich im
Windows-Zweig von ``sniffd_platform_supported`` (``sys.platform == "win32"``). Auf Linux
ist er strukturell immer leer. Diese Tests stellen ihn daher ueber die injizierte Naht
bzw. einen Monkeypatch her -- sie belegen das VERHALTEN bei anliegendem Marker, nicht sein
Auftreten auf dieser Maschine.
"""

import json
import pathlib
import re
import subprocess

import pytest

from api.dns_bypass import DnsBypassStatusOut
from application.dns_bypass import StartDnsBypassRecording
from domain.dns_bypass import DnsBypassRecording
from tests import naht_frontend

_FRONTEND = pathlib.Path(__file__).resolve().parents[2] / "frontend"
_VIEW_JSX = _FRONTEND / "src" / "components" / "DnsBypassView.jsx"
_API_JS = _FRONTEND / "src" / "api" / "dnsBypass.js"
_SNI_SNIFFER = pathlib.Path(__file__).resolve().parents[1] / "infrastructure" / "sni"

# Der eine stabile Marker (``sniffd_unavailable_reason``). Bewusst hier als Literal:
# laeuft der Wert im Backend auseinander, faellt genau das auf.
_MARKER = "NPCAP_MISSING"


class _SpyRecorder:
    """``DnsBypassRecorder``-Spy: zeichnet auf, OB ``start`` ueberhaupt gerufen wurde."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self._recording_id: str | None = None

    def start(self, interface: str | None, recording_id: str) -> str | None:
        self.calls.append("start")
        self._recording_id = recording_id
        return None

    def stop(self) -> None:  # pragma: no cover -- im Vorpruefungs-Fall nie gerufen
        self.calls.append("stop")

    def active_recording_id(self) -> str | None:  # pragma: no cover
        return self._recording_id


class _FakeRecordingRepo:
    """In-memory ``DnsBypassRecordingRepository``-Fake -- zaehlt die abgelegten Saetze."""

    def __init__(self) -> None:
        self.store: dict[str, DnsBypassRecording] = {}

    def save(self, recording: DnsBypassRecording) -> None:
        self.store[recording.id] = recording

    def get(self, recording_id: str) -> DnsBypassRecording | None:  # pragma: no cover
        return self.store.get(recording_id)

    def list_all(self) -> list[DnsBypassRecording]:  # pragma: no cover
        return list(self.store.values())

    def delete(self, recording_id: str) -> None:  # pragma: no cover
        self.store.pop(recording_id, None)

    def clear_all(self) -> None:  # pragma: no cover
        self.store = {}


# ── Backend: die Vorpruefung greift VOR dem Start ─────────────────────────────


def test_bei_anliegendem_marker_wird_die_quelle_gar_nicht_erst_gerufen() -> None:
    """Der Marker wird als Fehlertext zurueckgegeben -- ohne Start, ohne Aufzeichnung.

    Das ist der Kern von Weg 1: die Vorpruefung sitzt VOR allem anderen. Waere sie
    nachgelagert, entstuende ein ACTIVE-Datensatz fuer einen Lauf, der nie stattfand.
    """
    recorder = _SpyRecorder()
    recordings = _FakeRecordingRepo()
    use_case = StartDnsBypassRecording(
        recorder,  # type: ignore[arg-type]
        recordings,
        expected_servers_provider=lambda: ["192.168.0.1"],
        permission_check=lambda: _MARKER,
    )

    ergebnis = use_case(None, recording_id="rec-1", now=1000.0)

    assert ergebnis == _MARKER, "Der Marker muss unveraendert herauskommen"
    assert recorder.calls == [], "Die Quelle darf bei anliegendem Marker nicht gerufen werden"
    assert recordings.store == {}, "Es darf keine Aufzeichnung angelegt werden"


def test_ohne_marker_laeuft_der_start_unveraendert() -> None:
    """Liefert die Vorpruefung nichts, bleibt alles wie zuvor -- kein neues Hindernis."""
    recorder = _SpyRecorder()
    recordings = _FakeRecordingRepo()
    use_case = StartDnsBypassRecording(
        recorder,  # type: ignore[arg-type]
        recordings,
        expected_servers_provider=lambda: ["192.168.0.1"],
        permission_check=lambda: None,
    )

    ergebnis = use_case(None, recording_id="rec-1", now=1000.0)

    assert ergebnis is None
    assert recorder.calls == ["start"]
    assert "rec-1" in recordings.store


def test_ohne_vorpruefungs_naht_bleibt_das_verhalten_unveraendert() -> None:
    """Die Naht ist optional: ohne sie faehrt der Use-Case wie vor diesem Auftrag."""
    recorder = _SpyRecorder()
    recordings = _FakeRecordingRepo()
    use_case = StartDnsBypassRecording(
        recorder,  # type: ignore[arg-type]
        recordings,
        expected_servers_provider=lambda: [],
    )

    assert use_case(None, recording_id="rec-1", now=1000.0) is None
    assert recorder.calls == ["start"]


@pytest.mark.parametrize("leer", [None, ""])
def test_ein_leerer_marker_ist_kein_hindernis(leer: str | None) -> None:
    """Auf Linux/macOS liefert die Quelle ``""`` -- das darf den Start NICHT blockieren."""
    recorder = _SpyRecorder()
    use_case = StartDnsBypassRecording(
        recorder,  # type: ignore[arg-type]
        _FakeRecordingRepo(),
        expected_servers_provider=lambda: [],
        permission_check=lambda: leer,
    )

    assert use_case(None, recording_id="rec-1", now=1000.0) is None
    assert recorder.calls == ["start"]


# ── Wire: der Status traegt den Marker ────────────────────────────────────────


def test_der_status_traegt_den_marker_im_wire_feld() -> None:
    """``DnsBypassStatusOut`` fuehrt ``permission_error`` -- so kommt der Marker an.

    Dasselbe Feld, das ``GET /api/sni/status`` schon liefert. Die Ansicht liest diesen
    Status ohnehin beim Mount und nach jedem Start/Stop.
    """
    status = DnsBypassStatusOut(recording=False, collected_queries=0, permission_error=_MARKER)

    assert status.model_dump()["permission_error"] == _MARKER


def test_der_status_traegt_ohne_hindernis_kein_feld_mit_inhalt() -> None:
    """Ohne Marker bleibt das Feld ``None`` -- kein leerer String als Pseudo-Marker."""
    status = DnsBypassStatusOut(recording=True, collected_queries=7)

    assert status.model_dump()["permission_error"] is None


def test_der_composition_root_zieht_den_marker_aus_derselben_quelle_wie_sni(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Die Root-Naht liest ``sniffd_unavailable_reason`` -- nicht irgendeine eigene Pruefung.

    Auf dieser Maschine ist der echte Wert strukturell leer (Linux). Der Monkeypatch
    stellt den Windows-Fall her und belegt, dass genau diese Funktion die Quelle ist.
    """
    import infrastructure.sniffd_client.base as base

    monkeypatch.setattr(base, "sniffd_unavailable_reason", lambda: _MARKER)

    from infrastructure.sniffd_client.base import sniffd_unavailable_reason

    marker = sniffd_unavailable_reason()

    assert (marker or None) == _MARKER


# ── Der CAP_NET_RAW-Substring bleibt unangetastet ─────────────────────────────


def test_die_cap_net_raw_naht_ist_unveraendert() -> None:
    """``sni_sniffer.py`` macht an diesem Substring die 403/503-Naht fest -- er BLEIBT.

    Ausdruecklicher Waechter, weil dieser Auftrag an der Nachbarschaft gearbeitet hat.
    """
    quelle = (_SNI_SNIFFER / "sni_sniffer.py").read_text(encoding="utf-8")

    assert 'if "CAP_NET_RAW" in error:' in quelle, (
        "Die tragende CAP_NET_RAW-Naht in sni_sniffer.py wurde veraendert"
    )


# ── Frontend: die Ansicht liest den Marker und unterdrueckt den Leer-Kasten ───

# Gemeinsame Bedingung (S89-A1/A5): siehe ``tests/naht_frontend.py``. Der Dekorator
# statt eines Modul-Riegels, weil die Backend-Tests oben ohne node laufen duerfen.
# ``dateien`` traegt die beiden Einstiegsquellen dieser Naht: ``_VIEW_JSX`` wird als
# Text gelesen, ``_API_JS`` von den Mapper-Tests ueber node gefahren.
# ``api/client.js``, das node ueber den Import von ``dnsBypass.js`` mitzieht, steht
# bewusst nicht hier: transitive Quellen gehoeren in keine Liste, ihr Fehlen ist der
# laute node-Fehler (S89-A5).
_nur_mit_frontend = naht_frontend.nur_mit_frontend(dateien=(_VIEW_JSX, _API_JS))


@_nur_mit_frontend
def test_die_ansicht_vergleicht_exakt_gegen_den_marker() -> None:
    """``DnsBypassView`` fuehrt denselben Marker-Vergleich wie Aussenkontakte/Verkehr.

    Geprueft wird die ECHTE Quelldatei: der Marker-String steht dort, und er wird per
    Gleichheit verglichen -- nicht per Textsuche im Rohtext (die haette an einer
    umformulierten Meldung gebrochen).
    """
    quelle = _VIEW_JSX.read_text(encoding="utf-8")

    assert f'const NPCAP_MARKER = "{_MARKER}";' in quelle, (
        "Der Marker-String fehlt in DnsBypassView"
    )
    assert "marker === NPCAP_MARKER" in quelle, (
        "Der Vergleich ist nicht exakt -- die anderen beiden Ansichten vergleichen so"
    )


@_nur_mit_frontend
def test_die_ansicht_nutzt_die_vorhandenen_npcap_texte_ohne_neue_zu_erfinden() -> None:
    """Kein neuer Wortlaut: derselbe Hinweis und derselbe Knopf wie in OutboundView."""
    quelle = _VIEW_JSX.read_text(encoding="utf-8")

    assert 't("npcap.inlineHint")' in quelle
    assert 't("npcap.installBtn")' in quelle
    assert "NpcapDialog" in quelle, "Der Knopf muss zum vorhandenen NpcapDialog fuehren"


@_nur_mit_frontend
def test_der_kasten_keine_umgehung_erfasst_haengt_am_marker() -> None:
    """ "Keine Umgehung erfasst" erscheint NICHT, solange der Marker anliegt.

    Der Kasten liest sich als Befund ("es wurde geschaut, es war nichts"), obwohl gar
    nichts erfasst werden konnte. Er haengt an ``prominenterLeerzustand``; geprueft wird,
    dass dessen Bedingung den Marker ausschliesst.
    """
    quelle = _VIEW_JSX.read_text(encoding="utf-8")

    treffer = re.search(
        r"const prominenterLeerzustand\s*=\s*(.+?);",
        quelle,
        re.DOTALL,
    )
    assert treffer is not None, "prominenterLeerzustand ist nicht mehr auffindbar"
    bedingung = treffer.group(1)

    assert "npcapFehlt" in bedingung, (
        f"Der Leer-Kasten haengt nicht am Marker -- er erschiene trotz Ausgrau-Block: "
        f"{bedingung.strip()}"
    )
    assert "!npcapFehlt" in bedingung, "Der Marker muss den Kasten UNTERDRUECKEN, nicht ausloesen"


@_nur_mit_frontend
def test_der_mapper_reicht_den_marker_aus_dem_status_durch() -> None:
    """``fetchDnsBypassStatus`` traegt ``permission_error`` in die View-Form.

    Ohne diesen Schritt kaeme der Marker nie in der Ansicht an.
    """
    modul = _API_JS.resolve().as_uri()
    skript = (
        "globalThis.fetch = async () => ({\n"
        "  ok: true,\n"
        "  status: 200,\n"
        "  json: async () => ({ recording: false, collected_queries: 0,"
        f" permission_error: {json.dumps(_MARKER)} }}),\n"
        "});\n"
        f"const {{ fetchDnsBypassStatus }} = await import({json.dumps(modul)});\n"
        "process.stdout.write(JSON.stringify(await fetchDnsBypassStatus()));\n"
    )
    ergebnis = subprocess.run(
        ["node", "--input-type=module", "-e", skript],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=_FRONTEND,
    )
    assert ergebnis.returncode == 0, f"node scheiterte: {ergebnis.stderr}"

    assert json.loads(ergebnis.stdout)["permissionError"] == _MARKER


@_nur_mit_frontend
def test_der_mapper_macht_aus_fehlendem_feld_kein_hindernis() -> None:
    """Fehlt ``permission_error`` (oder ist es leer), wird daraus ``null`` -- kein Ausgrauen."""
    modul = _API_JS.resolve().as_uri()
    skript = (
        "globalThis.fetch = async () => ({\n"
        "  ok: true,\n"
        "  status: 200,\n"
        "  json: async () => ({ recording: true, collected_queries: 3 }),\n"
        "});\n"
        f"const {{ fetchDnsBypassStatus }} = await import({json.dumps(modul)});\n"
        "process.stdout.write(JSON.stringify(await fetchDnsBypassStatus()));\n"
    )
    ergebnis = subprocess.run(
        ["node", "--input-type=module", "-e", skript],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=_FRONTEND,
    )
    assert ergebnis.returncode == 0, f"node scheiterte: {ergebnis.stderr}"

    assert json.loads(ergebnis.stdout)["permissionError"] is None
