"""Use-Cases der traffic-Domaene -- Per-App-Verbindungen, Rechte-Naht, Raten.

Orchestrieren die reine Domaene (``aggregate_by_app``/``match_samples``/
``compute_rate``) + die Ports (``PerProcessTrafficProvider``/``TrafficPermissionPort``).
Kennen ``domain/`` und ``ports/``, NIEMALS ``infrastructure/`` (maschinell per
import-linter erzwungen). Ports kommen per Constructor-Injection als Protocol-Typ
herein -- nie ein konkreter Adapter.

Drei Use-Cases, gestaffelt nach den Vision-Stufen:

* ``ListAppTraffic`` -- Stufe 1: Verbindungen holen, pro App buendeln (duenner
  Lese-Pass-Through ueber den Provider + ``aggregate_by_app``).
* ``CheckTrafficPermission`` -- die ``{ok, error}``-Rechte-Naht (Muster capture
  ``StartCapture``): ``is_available`` -> ``check_permission`` -> dict. Der api-Rand
  uebersetzt ``ok=False`` spaeter in 403.
* ``MeasureThroughput`` -- Stufe 2, bewusst ZUSTANDSFREI: bekommt zwei Messpunkte
  als Parameter und wendet ``match_samples``+``compute_rate`` an. Reine Anwendung der
  Domaenenlogik -- kein Port, kein State.
* ``PollThroughput`` -- der LEBENDE Stufe-2-Use-Case (T.4b, Muster ``RunMonitor``):
  haelt den Messpunkt-/Raten-State ueber die Zeit (``tick``/``run``/``stop`` +
  ``current_rates``), KEIN Modul-Global. Treibt ``MeasureThroughput`` pro tick. Den
  ``asyncio.Task``-Lebenszyklus (AUTO im lifespan ODER MANUELL on-demand) und die
  Verheiratung der Raten-Map mit ``ListAppTraffic`` macht der Composition Root
  (T.4b-2) -- der Use-Case selbst kennt keinen Task.
"""

import asyncio
from collections.abc import Sequence
from dataclasses import replace

from domain.traffic import (
    AppTraffic,
    Connection,
    ConnSample,
    aggregate_by_app,
    compute_rate,
    make_socket_key,
    match_samples,
)
from ports.traffic import PerProcessTrafficProvider, TrafficPermissionPort


class ListAppTraffic:
    """Stufe 1: Verbindungen holen, pro App buendeln (App-Uebersicht + Verbindungen).

    Duenn (Muster ``ListInterfaces``): rohe Verbindungen ueber den Provider holen ->
    ueber ``aggregate_by_app`` pro App buendeln. Nicht zuordenbare Verbindungen
    (``app_name=None`` -- rootless) landen in der ehrlichen None-Gruppe, nichts wird
    verworfen. Leere Verbindungssicht -> ``[]`` (kein Fehler).
    """

    def __init__(self, provider: PerProcessTrafficProvider) -> None:
        self._provider = provider

    async def __call__(
        self, rates: dict[str, tuple[float, float]] | None = None
    ) -> list[AppTraffic]:
        """Verbindungen pro App buendeln; optional mit Durchsatz-Raten angereichert.

        ``rates`` ist die ``key -> (send_bps, recv_bps)``-Map des ``PollThroughput``-
        State (vom Composition Root hereingereicht, T.4b-2). OHNE ``rates`` (bzw. leere
        Map) bleibt das Stufe-1-Verhalten unveraendert -- die Raten-Felder bleiben
        ``None`` (ehrlich "nicht gemessen"), sodass ``/api/traffic`` auch ohne
        laufenden Poller funktioniert. Die Summierung pro App macht
        ``aggregate_by_app`` (None-sicher via ``_sum_known_rates``).
        """
        conns = await self._provider.list_connections()
        if rates:
            conns = [self._enrich(conn, rates) for conn in conns]
        return aggregate_by_app(conns)

    def _enrich(self, conn: Connection, rates: dict[str, tuple[float, float]]) -> Connection:
        """Setzt die Raten-Felder einer Verbindung, wenn ihr Socket-key gemessen wurde.

        Baut den kanonischen ``key`` ueber ``make_socket_key`` (deckungsgleich mit dem
        Stufe-2-key aus ``ss``, T.4a-fix) und schlaegt die Rate nach. Kein Treffer
        (Socket nicht im letzten Messpunkt-Paar) -> Verbindung unveraendert (Raten
        ``None``). ``Connection`` ist frozen -> ``replace``.
        """
        key = make_socket_key(
            conn.l4,
            conn.local.ip,
            conn.local.port,
            conn.remote.ip if conn.remote else None,
            conn.remote.port if conn.remote else None,
        )
        rate = rates.get(key)
        if rate is None:
            return conn
        return replace(conn, send_rate_bps=rate[0], recv_rate_bps=rate[1])


class CheckTrafficPermission:
    """Rechte-Naht wie capture ``StartCapture``: is_available -> check_permission -> {ok, error}.

    Duenn (Muster der monitoring-Pass-Throughs + capture ``StartCapture``): prueft
    Verfuegbarkeit (Tooling/Plattform da?) und dann die Sicht-Tiefe
    (``check_permission``) ueber den Rechte-Port und gibt die ``{ok, error}``-Form
    zurueck. Der api-Rand uebersetzt ``ok=False`` spaeter in 403.
    """

    def __init__(self, permission: TrafficPermissionPort) -> None:
        self._permission = permission

    def __call__(self) -> dict[str, object]:
        """``{"ok": True, "error": ""}`` bei voller Sicht, sonst ``ok=False`` + Grund.

        ``is_available`` False -> Quelle nicht nutzbar (Plattform/Tooling fehlt).
        Sonst ``check_permission``: ein nicht-leerer Text ist die Rechte-Begruendung
        (z. B. "als Root starten") -> ``ok=False`` (Router uebersetzt das in 403).
        ``None`` -> volle Sicht moeglich.
        """
        if not self._permission.is_available():
            return {
                "ok": False,
                "error": "Per-App-Traffic ist auf dieser Plattform nicht verfuegbar.",
            }
        text = self._permission.check_permission()
        return {"ok": text is None, "error": text or ""}

    def is_available(self) -> bool:
        """Reiner Verfuegbarkeits-Check (fuer einen spaeteren ``/available``-Pfad)."""
        return self._permission.is_available()

    def check_permission(self) -> str | None:
        """Rechte-Begruendung oder ``None`` (fuer einen spaeteren ``permission_error``)."""
        return self._permission.check_permission()


class MeasureThroughput:
    """Stufe 2: Raten aus ZWEI uebergebenen Messpunkten -- zustandsfrei, KEIN Port.

    Bekommt ``prev``+``curr`` als Parameter (wer sie sammelt/aufbewahrt =
    Polling-Zustand, ist T.4). Paart die Messpunkte ueber ``match_samples`` (nur
    Sockets in BEIDEN Punkten) und rechnet je Paar ueber ``compute_rate`` die grobe
    Rate. Reine Anwendung der Domaenenlogik -- kein I/O, kein State, keine Uhr.
    """

    def __call__(
        self, prev: Sequence[ConnSample], curr: Sequence[ConnSample]
    ) -> dict[str, tuple[float, float]]:
        """Rate je gepaartem Socket-``key`` als ``(send_bps, recv_bps)``.

        Rueckgabeform ``dict key -> (send_bps, recv_bps)``: der ``key`` ist die
        stabile Socket-Identitaet, an der T.4 die Rate an die Verbindung haengt
        (``Connection`` traegt denselben ``key``-Aufbau). Nur in BEIDEN Messpunkten
        vorhandene Sockets erscheinen (``match_samples``); neue/verschwundene fallen
        raus. Leere oder disjunkte Eingaben -> ``{}``.
        """
        pairs = match_samples(prev, curr)
        return {curr_s.key: compute_rate(prev_s, curr_s) for prev_s, curr_s in pairs}


class PollThroughput:
    """Lebender Stufe-2-Use-Case: pollt Byte-Zaehler und haelt die Raten ueber die Zeit.

    Muster ``RunMonitor`` (``tick``/``run``/``stop`` + interner State, KEIN
    Modul-Global, A3): pro ``tick`` einen Messpunkt ueber den Provider holen, mit dem
    vorigen die Raten rechnen (``MeasureThroughput`` -- zustandsfrei), die Raten-Map
    halten. ``current_rates`` gibt sie als DEFENSIVE Kopie heraus (Naht-Linie wie
    ``RunMonitor.current_status``) -- der Composition Root verheiratet sie mit
    ``ListAppTraffic`` (T.4b-2).

    KEIN ``asyncio.Task``-Management hier: der Use-Case bietet ``run()``/``stop()``,
    das ``create_task``/Teardown (AUTO im lifespan ODER MANUELL on-demand) treibt der
    Composition Root -- exakt wie ``RunMonitor``.
    """

    def __init__(self, provider: PerProcessTrafficProvider, *, interval: float = 1.0) -> None:
        self._provider = provider
        self._interval = interval
        # Letzter Messpunkt (prev der naechsten tick-Runde) + aktuelle Raten-Map.
        # State ueber die tick-Aufrufe gehalten -- kein Modul-Global (RunMonitor-Stil).
        self._prev: list[ConnSample] = []
        self._rates: dict[str, tuple[float, float]] = {}
        self._running = False
        self._measure = MeasureThroughput()

    async def tick(self) -> None:
        """Eine Mess-Runde: neuen Messpunkt holen, Raten gegen den vorigen rechnen.

        Erster ``tick`` (noch kein ``_prev``) -> nur den Messpunkt merken, KEINE Raten
        (ein einzelner Messpunkt ergibt keine Rate -- ehrlich leer statt 0). Ab dem
        zweiten ``tick`` rechnet ``MeasureThroughput`` (``match_samples`` +
        ``compute_rate``) die Raten der in BEIDEN Punkten vorhandenen Sockets.
        """
        curr = await self._provider.sample_throughput()
        if self._prev:
            self._rates = self._measure(self._prev, curr)
        self._prev = curr

    async def run(self) -> None:
        """Endlos-Rahmen (AUTO): tickt bis ``stop()``. Trivial -- Logik sitzt in ``tick``."""
        self._running = True
        while self._running:
            await self.tick()
            await asyncio.sleep(self._interval)

    def stop(self) -> None:
        """Beendet den ``run``-Loop nach der laufenden Iteration (Flag, kein Cancel)."""
        self._running = False

    def current_rates(self) -> dict[str, tuple[float, float]]:
        """Aktuelle ``key -> (send_bps, recv_bps)``-Map (DEFENSIVE Kopie, kein Live-Ref).

        Muster ``RunMonitor.current_status``: der Aufrufer (Composition Root) darf das
        Ergebnis nicht in den internen State zurueckwirken -- darum eine flache Kopie
        (die Tupel-Werte sind unveraenderlich, eine flache ``dict``-Kopie genuegt).
        """
        return dict(self._rates)
