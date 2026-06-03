"""Use-Cases der monitoring-Domaene -- der Live-Connectivity-Loop ``RunMonitor``.

Fuehrt den Altcode-``run_monitor`` (``modules/monitor.py``) als sauberen Use-Case
zusammen: die reine Domaenenlogik (``classify_transition`` + ``should_notify``,
M.2), die sechs Loop-Ports (M.3) und -- ueber die Ports -- die Adapter (M.4). Kennt
``domain/`` und ``ports/``, NIEMALS ``infrastructure/`` oder ``modules/``
(maschinell per import-linter erzwungen). Alle Ports kommen per Constructor-
Injection als Protocol-Typ herein. Kein Framework-Import, KEIN ``asyncio.Task``-
Management: der Use-Case bietet ``run()``/``stop()``, das ``create_task``/Teardown
treibt der Composition Root (``app.py``-Lifespan, M.9).

LOOP-FORM (testbar): ``tick()`` ist EINE Iteration ueber alle Targets -- voll mit
Fake-Ports deterministisch testbar (kein Loop-Takt). ``run()`` ist nur der triviale
Rahmen ``while self._running: await self.tick(); await sleep(interval)``. So sitzt
die GANZE Logik im getesteten ``tick``; ungetestet bleibt nur ``while``/``sleep``.

STATE: ``self._status`` haelt ``target_id -> letzter alive-bool`` -- exakt wie der
Altcode-``_status`` (nicht mehr: ``label``/``rtt`` sind KEIN Status-State). Er lebt
ueber die ``tick``-Iterationen und ist der ``prev``-Input fuer
``classify_transition``. ``current_status()`` gibt eine DEFENSIVE KOPIE der rohen
``dict[str, bool]``-Map heraus -- die ``label``-Anreicherung zur Altcode-Form
``{tid: {"alive", "label"}}`` macht der Rand (M.9: ``/api/monitor/status`` +
WS-Connect laden die Targets via ``MonitorTargetSource`` und loesen ``label`` mit
``tid``-Fallback auf). Naht-Linie wie der Broadcaster: der Use-Case gibt rohe
Domaenen-Daten, der Rand baut die Response-Shape.

TARGETS (Live-Reload): ``tick`` laedt die Targets PRO Iteration via
``MonitorTargetSource.load()``. Das gibt den Altcode-Live-Reload ohne
``configure()``-Kruecke: ein ueber ``/api/monitor/targets`` (M.9) geaendertes
Custom-Target wirkt bei der naechsten Iteration automatisch (die TargetSource liest
frisch aus den Settings).

Pro-Target-Sequenz (altcode-treu, ``run_monitor`` Z.236-285):
    target.enabled? sonst skip
    -> ping(target) -> rtt_repo.save(sample)
    -> prev = status.get(id); now = sample.alive
    -> event = classify_transition(prev, now, sample.loss_pct)
    -> status[id] = now            (IMMER -- auch ohne Event; prev der naechsten Runde)
    -> wenn event: event_repo.save(MonitorEvent)
                   + wenn should_notify(prev, event): notifier.notify(MonitorEvent)
    -> IMMER broadcaster.broadcast(target, sample, event)

BEWUSSTE, HARMLOSE REORDERING ggue. Altcode: Dort lief ``_notify_macos`` INLINE in
den classify-Zweigen, also VOR dem ``_status``-Update und VOR ``_save_event``. Hier
ist die Reihenfolge ``status-Update -> save_event -> notify``. Das aendert nichts
Beobachtbares: ``notify`` ist ein best-effort-Seiteneffekt, ``save_event`` reine
Persistenz -- es gibt keine Abhaengigkeit zwischen ihnen, und ``prev`` (der einzige
Wert, den das Status-Update beeinflusst) ist fuer ``should_notify`` bereits VOR dem
Update gelesen. Bewusst so geordnet (Klassifikation -> Status -> Konsequenzen),
nicht versehentlich abweichend.
"""

import asyncio

from domain.monitoring import (
    MonitorEvent,
    MonitorTarget,
    classify_transition,
    should_notify,
)
from ports.monitoring import (
    MonitorBroadcasterPort,
    MonitorEventRepository,
    MonitorNotifierPort,
    MonitorPingerPort,
    MonitorTargetSource,
    RttHistoryRepository,
)

# Sekunden zwischen den tick-Durchlaeufen (Altcode ``_interval``, Default 5).
_DEFAULT_INTERVAL = 5


class RunMonitor:
    """Orchestriert den Live-Connectivity-Loop (eine ``tick`` je Mess-Runde)."""

    def __init__(
        self,
        pinger: MonitorPingerPort,
        rtt_history: RttHistoryRepository,
        event_repo: MonitorEventRepository,
        notifier: MonitorNotifierPort,
        broadcaster: MonitorBroadcasterPort,
        target_source: MonitorTargetSource,
        interval: int = _DEFAULT_INTERVAL,
    ) -> None:
        self._pinger = pinger
        self._rtt_history = rtt_history
        self._event_repo = event_repo
        self._notifier = notifier
        self._broadcaster = broadcaster
        self._target_source = target_source
        self._interval = interval
        # target_id -> letzter bekannter alive-Zustand (None = noch nie gemessen).
        self._status: dict[str, bool] = {}
        self._running = False

    async def tick(self) -> None:
        """Eine Mess-Runde ueber alle (frisch geladenen) Targets."""
        for target in self._target_source.load():
            if not target.enabled:
                # Disabled Targets werden uebersprungen (kein Ping, kein
                # Status-Update) -- altcode-treu (``if not target.enabled: continue``).
                continue
            await self._tick_target(target)

    async def _tick_target(self, target: MonitorTarget) -> None:
        """Misst ein Target, klassifiziert den Uebergang und loest die Konsequenzen aus."""
        sample = await self._pinger.ping(target)
        self._rtt_history.save(sample)

        # prev VOR dem Status-Update lesen -- es ist der Eingang fuer Klassifikation
        # UND fuer die Notify-Flanken-Regel (should_notify braucht prev).
        prev = self._status.get(target.id)
        now = sample.alive

        event = classify_transition(prev, now, sample.loss_pct)
        self._status[target.id] = now  # IMMER (auch ohne Event): prev der naechsten Runde.

        if event is not None:
            monitor_event = MonitorEvent(
                target_id=target.id,
                label=target.label,
                event=event,
                rtt_ms=sample.rtt_ms,
                timestamp=sample.timestamp,
            )
            self._event_repo.save(monitor_event)
            if should_notify(prev, event):
                await self._notifier.notify(monitor_event)

        # IMMER broadcasten -- auch bei event=None (Altcode: monitor_update jede Runde).
        await self._broadcaster.broadcast(target, sample, event)

    async def run(self) -> None:
        """Endlos-Rahmen: tickt bis ``stop()``. Trivial -- die Logik sitzt in ``tick``."""
        self._running = True
        while self._running:
            await self.tick()
            await asyncio.sleep(self._interval)

    def stop(self) -> None:
        """Beendet den ``run``-Loop nach der laufenden Iteration (Flag, kein Cancel)."""
        self._running = False

    def current_status(self) -> dict[str, bool]:
        """Rohe ``target_id -> alive``-Map (DEFENSIVE Kopie, kein Live-Ref nach aussen).

        Die Altcode-Form ``{tid: {"alive", "label"}}`` baut der Rand (M.9) durch
        ``label``-Anreicherung aus den Targets -- siehe Modul-Docstring.
        """
        return dict(self._status)
