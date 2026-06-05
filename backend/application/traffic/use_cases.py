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
  als Parameter und wendet ``match_samples``+``compute_rate`` an. WER die Messpunkte
  sammelt und ueber die Zeit aufbewahrt (Polling-Zustand, AUTO/MANUELL), ist T.4 --
  hier KEIN Port, KEIN State, nur reine Anwendung der Domaenenlogik.
"""

from collections.abc import Sequence

from domain.traffic import (
    AppTraffic,
    ConnSample,
    aggregate_by_app,
    compute_rate,
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

    async def __call__(self) -> list[AppTraffic]:
        conns = await self._provider.list_connections()
        return aggregate_by_app(conns)


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
