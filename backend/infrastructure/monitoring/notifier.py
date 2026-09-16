"""Adapter fuer ``MonitorNotifierPort`` -- Wrapper um ``modules.monitor._notify_macos``.

``_notify_macos`` ist im Altcode SYNCHRON und blockierend (``subprocess.run`` mit
``timeout=3``). Anders als der Pinger (dessen ``_ping_burst`` schon async ist) wird
es daher ueber ``run_in_executor`` ausgelagert, damit der Event-Loop des Monitors
nicht blockiert -- die Port-Methode bleibt ``async``. Der ``modules``-Import ist
durch die ADR-0007-Erweiterung ``infrastructure.monitoring.** -> modules`` gedeckt.

Plattform-Verhalten (port-treu): ``_notify_macos`` ruft ``osascript`` -- ein
macOS-only-Binary. Auf Linux existiert es nicht, ``subprocess.run`` wirft
``FileNotFoundError``, was der Altcode-interne ``except Exception: pass`` schluckt
-> faktisch ein NO-OP. Das ist genau der vom Port vorgesehene "kein
Notification-Backend"-Zustand (kein Fehler).

Best-effort (Port-Vertrag): Ein fehlgeschlagener Notification-Versuch ist KEIN
Loop-Fehler. ``_notify_macos`` faengt bereits intern; der Adapter umschliesst den
Executor-Aufruf ZUSAETZLICH defensiv und loggt einen unerwarteten Fehler (statt
ihn in den Loop zu werfen) -- kein stiller S3-Fang OHNE Log.

Mapping ``MonitorEvent`` -> die zwei ``_notify_macos``-Argumente
(``title``/``message``) reproduziert den Altcode-Wortlaut aus ``run_monitor``:
Titel ``"CERNIS PRO — Network Alert"``, Nachricht ``"<label> is DOWN"`` bzw.
``"<label> is back UP"`` je nach Event.
"""

import asyncio

import structlog

from domain.monitoring import MonitorEvent, MonitorEventType
from modules.monitor import _notify_macos

_logger = structlog.get_logger(__name__)

# Altcode-Wortlaut aus run_monitor (modules/monitor.py): der Titel ist konstant,
# die Nachricht haengt am Event-Typ.
_TITLE = "CERNIS PRO — Network Alert"
_MESSAGES = {
    MonitorEventType.DOWN: "{label} is DOWN",
    MonitorEventType.UP: "{label} is back UP",
}


class MonitorNotifierAdapter:
    """Erfuellt das ``MonitorNotifierPort``-Protocol strukturell (modules-Wrapper)."""

    async def notify(self, event: MonitorEvent) -> None:
        """Loest eine Desktop-Notification fuer ``event`` aus (best-effort).

        ``_notify_macos`` ist blockierend -> ``run_in_executor``. Auf Linux ist es
        ein no-op (kein ``osascript``); ein unerwarteter Fehler wird geloggt, nicht
        in den Loop geworfen.
        """
        template = _MESSAGES.get(event.event)
        if template is None:
            # Nur up/down loesen im Altcode eine Notification aus (degraded nicht).
            # should_notify (M.2) filtert das bereits; hier defensiv kein Versand.
            return
        message = template.format(label=event.label)
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, _notify_macos, _TITLE, message)
        except Exception:
            # Best-effort: nie ein Loop-Fehler. Mit Log (kein stiller S3-Fang).
            _logger.warning("monitor_notify_failed", target_id=event.target_id)
