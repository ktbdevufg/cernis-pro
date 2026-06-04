"""Tests fuer die monitoring->alerting-Trigger-Naht (app.py, A.7a).

Zwei Auflagen aus dem A.7a-Spec, beide am Composition-Root-Wrapper ``_MonitorAlertRaiser``:

* AUFLAGE 1 (Wortlaut-Konsistenz als Vertrag): Der Alert-Message-Wortlaut ist an ZWEI
  Stellen dupliziert -- ``MonitorNotifierAdapter._MESSAGES`` (infra) und ``app._ALERT_MESSAGES``.
  Ein Test nagelt fest, dass beide ZEICHENGLEICH sind, sonst liefen Notification-Text
  und alert_history-message kuenftig still auseinander. (Beide sind als Modul-Konstanten
  importierbar -> der Test bindet sie direkt -- die in der Bau-Vorab-Pruefung bestaetigte
  Annahme, dass Option (i) testbar ist.)

* AUFLAGE 3 (Mapping-Adapter): ``_MonitorAlertRaiser`` mappt ein ``MonitorEvent`` korrekt
  auf ``RaiseAlert(rule_type="host_down", target=event.target_id, message=...)`` -- fuer
  DOWN und UP -- und faengt einen werfenden RaiseAlert best-effort (wirft NICHT, Warn-Log).

Der ``RaiseAlert``-Use-Case wird durch ein aufzeichnendes Fake ersetzt (kein echtes
sqlite/SMTP/osascript). Async-Smokes via ``asyncio.run`` (kein pytest-asyncio, wie die
ganze Migration).
"""

import asyncio
from typing import Any

import pytest

import app as app_module
from app import _ALERT_MESSAGES, _MonitorAlertRaiser
from domain.monitoring import MonitorEvent, MonitorEventType
from infrastructure.monitoring.notifier import _MESSAGES as _NOTIFIER_MESSAGES

# ── AUFLAGE 1: Wortlaut-Konsistenz (gegen stille Divergenz der Duplikation) ──


def test_alert_message_wording_matches_notifier() -> None:
    """app._ALERT_MESSAGES MUSS zeichengleich mit MonitorNotifierAdapter._MESSAGES sein.

    Beide Quellen halten denselben up/down-Wortlaut. Lauefen sie auseinander, saehe der
    Nutzer in der Desktop-Notification einen anderen Text als in der alert_history --
    genau die stille Divergenz, die diese Duplikation (Option i) sonst riskiert. Der
    direkte Dict-Vergleich nagelt die Gleichheit fuer BEIDE Flanken (down + up) fest.
    """
    assert _ALERT_MESSAGES == _NOTIFIER_MESSAGES
    # Explizit auch die beiden Schluessel/Werte, falls die Dicts je um Eintraege wachsen.
    assert _ALERT_MESSAGES[MonitorEventType.DOWN] == _NOTIFIER_MESSAGES[MonitorEventType.DOWN]
    assert _ALERT_MESSAGES[MonitorEventType.UP] == _NOTIFIER_MESSAGES[MonitorEventType.UP]


# ── AUFLAGE 3: Mapping-Adapter (rule_type/target/message korrekt + best-effort) ──


class _RecordingRaiseAlert:
    """Fake-RaiseAlert: zeichnet (rule_type, target, message) je Aufruf auf."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(
        self,
        rule_type: str,
        target: str,
        message: str,
        now: float | None = None,
    ) -> None:
        self.calls.append({"rule_type": rule_type, "target": target, "message": message})


def _event(
    event_type: MonitorEventType, *, target_id: str = "wlan", label: str = "WLAN"
) -> MonitorEvent:
    return MonitorEvent(
        target_id=target_id, label=label, event=event_type, rtt_ms=1.0, timestamp=0.0
    )


def test_down_event_maps_to_host_down_with_down_message() -> None:
    fake = _RecordingRaiseAlert()
    raiser = _MonitorAlertRaiser(fake)  # type: ignore[arg-type]

    event = _event(MonitorEventType.DOWN, target_id="wlan", label="WLAN")
    asyncio.run(raiser.raise_alert(event))

    assert fake.calls == [{"rule_type": "host_down", "target": "wlan", "message": "WLAN is DOWN"}]


def test_up_event_maps_to_host_down_with_up_message() -> None:
    fake = _RecordingRaiseAlert()
    raiser = _MonitorAlertRaiser(fake)  # type: ignore[arg-type]

    event = _event(MonitorEventType.UP, target_id="internet", label="Internet")
    asyncio.run(raiser.raise_alert(event))

    # rule_type bleibt "host_down" AUCH fuer up (DF2: eine Regel faengt beide Flanken).
    assert fake.calls == [
        {"rule_type": "host_down", "target": "internet", "message": "Internet is back UP"}
    ]


def test_degraded_event_does_not_call_raise_alert() -> None:
    # degraded ist nicht in _ALERT_MESSAGES -> defensiver no-op (should_notify filtert es
    # ohnehin schon im Use-Case; der Adapter ruft RaiseAlert hier gar nicht erst).
    fake = _RecordingRaiseAlert()
    raiser = _MonitorAlertRaiser(fake)  # type: ignore[arg-type]

    asyncio.run(raiser.raise_alert(_event(MonitorEventType.DEGRADED)))

    assert fake.calls == []


def test_raise_alert_failure_is_caught_and_logged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Best-effort: wirft RaiseAlert, faengt der Adapter -> raise_alert wirft NICHT, Warn-Log."""

    class _ThrowingRaiseAlert:
        async def __call__(self, **kwargs: Any) -> None:
            raise RuntimeError("repo kaputt")

    warnings: list[tuple[str, dict[str, Any]]] = []

    def _spy_warning(event: str, **kwargs: Any) -> None:
        warnings.append((event, kwargs))

    monkeypatch.setattr(app_module.logger, "warning", _spy_warning)

    raiser = _MonitorAlertRaiser(_ThrowingRaiseAlert())  # type: ignore[arg-type]

    # Wirft NICHT (best-effort) -- der tick darf nie an einem Alert-Fehler sterben.
    asyncio.run(raiser.raise_alert(_event(MonitorEventType.DOWN, target_id="wlan")))

    assert warnings == [("monitor_alert_raise_failed", {"target_id": "wlan"})]
