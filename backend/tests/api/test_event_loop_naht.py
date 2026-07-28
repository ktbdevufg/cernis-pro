"""Naht-Pruefung: Endpunkte, die einen Hintergrund-Task einplanen, MUESSEN ``async`` sein.

Hintergrund (S65 W-g). Ein Composition-Root-Callable, das ``asyncio.create_task``
ruft, braucht eine LAUFENDE Ereignisschleife. FastAPI/Starlette fuehrt einen
SYNCHRON deklarierten Endpunkt (``def``) in einem eigenen Threadpool-Faden aus --
dort laeuft KEINE Schleife, und ``create_task`` scheitert mit ``RuntimeError: no
running event loop`` (der Nutzer sieht einen 500er). Ein ``async``-Endpunkt laeuft
im Loop; der Callable selbst bleibt synchron.

Warum die bisherigen Tests das NICHT sahen: ``tests/api/test_capture_api.py``
ersetzt ``provide_start_capture`` per ``dependency_overrides`` durch ein Lambda,
das nur ein ``{ok, error}``-dict zurueckgibt -- also genau den Teil, der
``create_task`` ruft. Gefaelscht ist damit die Naht selbst; der Endpunkt konnte
synchron bleiben, ohne dass ein Test es merkte.

Dieses Modul faelscht die Naht NICHT. Es ruft den Endpunkt ueber den ECHTEN Weg des
Rahmenwerks auf (``TestClient`` gegen die ECHTE Composition Root ``create_app``) und
laesst den taskplanenden Callable UNANGETASTET. Gefaelscht wird nur, was DAHINTER
liegt -- der Helfer-Client, der sonst einen echten Subprozess spawnen wuerde. Es geht
um die Naht, nicht um echte Pakete.

Zwei Ebenen, bewusst getrennt:

1. LAUFZEIT (``test_pcap_start_*``, ``test_traffic_poll_start_*``,
   ``test_dns_bypass_start_*``): der Endpunkt wird echt aufgerufen; ein 500er mit
   ``no running event loop`` faellt hier auf. Deckt die drei HEUTE bekannten
   Stellen ab -- auch die beiden bereits geheilten (traffic/dns_bypass), die bis
   jetzt nur durch einen Docstring-Kommentar geschuetzt waren.
2. STATISCH (``test_kein_synchroner_endpunkt_plant_einen_task_ein``): ein Waechter,
   der den Baum per AST absucht und JEDE kuenftige Neuauflage des Fehlers faengt --
   auch in Domaenen, die es heute noch nicht gibt. Das ist der eigentliche
   Nachhaltigkeits-Anteil: die Laufzeit-Tests decken das Bekannte, der Waechter das
   Unbekannte.
"""

import ast
import asyncio
import pathlib
import queue
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import app as app_module
from app import create_app
from infrastructure.config import AppConfig

# ── Fake-Helfer-Client (kein Subprozess, keine Pipe, kein scapy) ─────────────


class _FakePcapClient:
    """In-Memory-``PcapClient`` (Muster ``tests/infrastructure/capture``).

    ``start`` meldet Erfolg OHNE Subprozess; ``next_packet`` blockiert bis ``stop``.
    So laeuft der ``RunCapture``-Task nach dem Start echt weiter (wie in Produktion),
    ohne dass ein Paket noetig waere -- geprueft wird die Naht, nicht der Mitschnitt.
    """

    def __init__(self) -> None:
        self._queue: queue.Queue[Any] = queue.Queue()
        self._running = False
        self.start_calls: list[tuple[str | None, str, int]] = []

    def start(self, interface: str | None, bpf_filter: str, max_packets: int) -> str | None:
        self.start_calls.append((interface, bpf_filter, max_packets))
        self._running = True
        return None

    def next_packet(self, timeout: float | None = None) -> Any:
        raise queue.Empty

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def export_pcap(self, path: str) -> bool:
        return False


@pytest.fixture
def app_mit_fake_helfer(monkeypatch: pytest.MonkeyPatch) -> Iterator[FastAPI]:
    """ECHTE Composition Root; nur der Helfer-Spawn ist gefaelscht.

    ``provide_start_capture`` (der Callable mit dem ``create_task``) wird NICHT
    ueberschrieben -- genau darum geht es. Ersetzt wird die Sniffer-KLASSE, die
    ``create_app`` instanziiert, durch dieselbe Klasse mit Fake-Client.
    """
    from infrastructure.capture import ScapyPacketSniffer

    monkeypatch.setattr(
        app_module,
        "ScapyPacketSniffer",
        lambda: ScapyPacketSniffer(client_factory=_FakePcapClient),
    )
    yield create_app(AppConfig())


# ── 1. Laufzeit: die drei bekannten Stellen ueber den echten Rahmenwerks-Weg ──


def test_pcap_start_plant_den_task_ohne_500er_ein(app_mit_fake_helfer: FastAPI) -> None:
    """``POST /api/pcap/start`` darf nicht am fehlenden Event-Loop scheitern.

    OHNE die Behebung (``def pcap_start``) laeuft der Endpunkt im Starlette-Threadpool,
    ``asyncio.create_task`` findet keine Schleife und der Client sieht einen 500er.
    """
    with TestClient(app_mit_fake_helfer) as client:
        response = client.post("/api/pcap/start", json={})

    assert response.status_code == 200, (
        f"pcap/start scheiterte mit {response.status_code}: {response.text}. "
        "Vermutlich ist der Endpunkt synchron (``def``) deklariert -- dann laeuft er "
        "im Threadpool OHNE Ereignisschleife und ``create_task`` wirft "
        "``RuntimeError: no running event loop``."
    )
    assert response.json()["ok"] is True


def test_pcap_start_haengt_den_task_an_app_state(app_mit_fake_helfer: FastAPI) -> None:
    """Der Task ist wirklich eingeplant -- nicht nur der Antwortcode stimmt.

    Belegt, dass der Endpunkt die Naht ECHT durchlaufen hat (``app.state.capture_task``
    existiert und lief an), statt nur ein huebsches dict zurueckzugeben.
    """
    with TestClient(app_mit_fake_helfer) as client:
        assert client.post("/api/pcap/start", json={}).status_code == 200
        task = getattr(app_mit_fake_helfer.state, "capture_task", None)
        assert task is not None, "kein capture_task eingeplant"
        assert isinstance(task, asyncio.Task)


def test_traffic_poll_start_plant_den_task_ohne_500er_ein(app_mit_fake_helfer: FastAPI) -> None:
    """Regressionsschutz fuer das bereits geheilte Vorbild (``async`` seit T.4b-2).

    Bis jetzt war diese Stelle nur durch einen Docstring-Kommentar geschuetzt: ein
    Rueckfall auf ``def`` waere unbemerkt geblieben.
    """
    with TestClient(app_mit_fake_helfer) as client:
        response = client.post("/api/traffic/poll/start")

    assert response.status_code == 200, (
        f"traffic/poll/start scheiterte mit {response.status_code}: {response.text}"
    )
    assert response.json() == {"ok": True}


def test_dns_bypass_start_scheitert_nicht_am_event_loop(app_mit_fake_helfer: FastAPI) -> None:
    """Regressionsschutz fuer die zweite bereits geheilte Stelle (``async``).

    Der DNS-Umgehungs-Recorder darf hier legitim mit ``{ok: false, error: ...}``
    antworten (kein Helfer/keine Rechte in der Testumgebung) -- das ist die ehrliche
    Fehler-Naht (S3). Ein 500er dagegen waere der Event-Loop-Fehler.
    """
    with TestClient(app_mit_fake_helfer) as client:
        response = client.post("/api/dns-bypass/start", json={})

    assert response.status_code != 500, (
        f"dns-bypass/start lieferte 500: {response.text}. "
        "Bei ``no running event loop`` ist der Endpunkt synchron deklariert."
    )


# ── 2. Statischer Waechter: faengt kuenftige Neuauflagen im ganzen Baum ───────

_BACKEND = pathlib.Path(__file__).resolve().parents[2]
_LOOP_RUFE = {"create_task", "ensure_future", "get_running_loop"}


def _callables_mit_schleifenbedarf(baum: ast.Module) -> set[str]:
    """Namen aller Funktionen in ``app.py``, die selbst eine laufende Schleife brauchen.

    ``lifespan``/``create_app`` sind ausgenommen: der lifespan LAEUFT bereits im Loop
    (Startup-Kontext), und ``create_app`` erbt die Treffer seiner inneren Funktionen.
    """
    treffer: set[str] = set()
    for knoten in ast.walk(baum):
        if not isinstance(knoten, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if knoten.name in {"lifespan", "create_app"}:
            continue
        for inner in ast.walk(knoten):
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and inner.func.attr in _LOOP_RUFE
            ):
                treffer.add(knoten.name)
                break
    return treffer


def _provider_je_callable(quelle: str, callables: set[str]) -> dict[str, str]:
    """``provide_*`` -> Callable-Name, gelesen aus den ``dependency_overrides``-Zeilen."""
    zuordnung: dict[str, str] = {}
    for zeile in quelle.splitlines():
        s = zeile.strip()
        if not s.startswith("app.dependency_overrides[provide_"):
            continue
        provider = s.split("[", 1)[1].split("]", 1)[0]
        wert = s.split("=", 1)[1].strip()
        for name in callables:
            if wert == f"lambda: {name}":
                zuordnung[provider] = name
    return zuordnung


def test_kein_synchroner_endpunkt_plant_einen_task_ein() -> None:
    """Kein ``def``-Endpunkt haengt an einem Callable, das eine Schleife braucht.

    Der Waechter liest ``app.py`` und den gesamten ``api``-Ring per AST:

    1. welche Composition-Callables rufen ``create_task``/``get_running_loop``?
    2. ueber welches ``provide_*`` sind sie verdrahtet?
    3. ist der Endpunkt, der dieses ``provide_*`` per ``Depends`` zieht, ``async``?

    Damit faellt auch eine kuenftige, heute noch nicht existierende Domaene auf --
    ohne dass jemand daran denken muss, hier einen Laufzeit-Test nachzutragen.
    """
    quelle = (_BACKEND / "app.py").read_text(encoding="utf-8")
    callables = _callables_mit_schleifenbedarf(ast.parse(quelle))
    zuordnung = _provider_je_callable(quelle, callables)

    assert zuordnung, (
        "Der Waechter fand keine einzige taskplanende Verdrahtung -- vermutlich hat "
        "sich das Muster in app.py geaendert und der Waechter ist blind geworden."
    )

    verstoesse: list[str] = []
    for datei in sorted((_BACKEND / "api").glob("*.py")):
        baum = ast.parse(datei.read_text(encoding="utf-8"))
        for knoten in ast.walk(baum):
            if not isinstance(knoten, ast.FunctionDef):  # nur SYNCHRONE Endpunkte
                continue
            benutzte = {n.id for n in ast.walk(knoten.args) if isinstance(n, ast.Name)} & set(
                zuordnung
            )
            for provider in sorted(benutzte):
                verstoesse.append(
                    f"api/{datei.name}:{knoten.lineno} {knoten.name} ist synchron (``def``), "
                    f"zieht aber ``{provider}`` -> ``{zuordnung[provider]}`` mit "
                    f"``asyncio.create_task``. Ein ``def``-Endpunkt laeuft im "
                    f"Starlette-Threadpool OHNE Ereignisschleife -> ``RuntimeError: no "
                    f"running event loop`` (500er beim Nutzer). Loesung: ``async def`` "
                    f"(Muster ``traffic.start_traffic_poll``); der Callable selbst bleibt "
                    f"synchron und wird weiterhin OHNE ``await`` gerufen."
                )

    assert not verstoesse, "Synchrone Endpunkte mit Event-Loop-Bedarf:\n" + "\n".join(verstoesse)
