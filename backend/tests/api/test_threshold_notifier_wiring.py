"""Tests fuer die Schwellwert-Alarm->alerting-Notifier-Naht (app.py, Schnitt 3b).

Der Composition-Root-Wrapper ``_ThresholdNotifierWiring`` erfuellt
``ThresholdNotifierPort`` und mappt eine frisch gefeuerte Schwellwert-Flanke auf den
vorhandenen alerting-Notifier (Desktop + E-Mail):

* ``notify_desktop=True`` -> ``notifier.macos`` mit erwartetem Titel/subtitle.
* ``notify_email=True`` + vorhandene ``SmtpConfig`` -> ``notifier.email`` mit Titel/Body.
* ``notify_email=True`` + ``load()`` ``None`` -> KEINE Mail, kein Fehler (sichtbar geloggt).
* beide Kanaele aus -> kein Notifier-Aufruf.
* best-effort: ein werfender ``notifier.macos`` faengt der Wrapper -> wirft NICHT.
* LATENCY_ABOVE vs UNREACHABLE -> die Nachricht enthaelt den jeweils erwarteten Text.

Notifier + SmtpConfig werden durch aufzeichnende Fakes ersetzt (kein echtes
osascript/SMTP/settings). Async-Smokes via ``asyncio.run`` (kein pytest-asyncio, wie die
ganze Migration -- Muster ``test_monitor_alert_raiser_wiring.py``).
"""

import asyncio
from typing import Any

import pytest

import app as app_module
from app import _ThresholdNotifierWiring
from domain.alerting import EmailResult, SmtpConfig
from domain.monitoring import (
    CaptureMode,
    LatencyThreshold,
    LoggingTask,
    OperationMode,
    PingSample,
    TaskState,
    ThresholdCondition,
)


class _RecordingNotifier:
    """Fake-``AlertNotifierPort``: zeichnet macos-/email-Aufrufe auf, kann werfen."""

    def __init__(self, *, macos_raises: bool = False) -> None:
        self.macos_calls: list[dict[str, Any]] = []
        self.email_calls: list[dict[str, Any]] = []
        self._macos_raises = macos_raises

    async def macos(self, title: str, message: str, subtitle: str = "") -> None:
        if self._macos_raises:
            raise RuntimeError("osascript kaputt")
        self.macos_calls.append({"title": title, "message": message, "subtitle": subtitle})

    async def email(self, subject: str, body: str, config: SmtpConfig) -> EmailResult:
        self.email_calls.append({"subject": subject, "body": body, "config": config})
        return EmailResult(success=True, log=[])


class _RecordingSmtpConfig:
    """Fake-``SmtpConfigPort``: gibt eine vorgegebene ``SmtpConfig | None`` aus ``load`` zurueck."""

    def __init__(self, config: SmtpConfig | None) -> None:
        self._config = config
        self.load_calls = 0

    def load(self) -> SmtpConfig | None:
        self.load_calls += 1
        return self._config

    def load_raw(self) -> dict[str, Any] | None:  # pragma: no cover - vom Wrapper ungenutzt
        return None

    def save(self, config: dict[str, Any]) -> None:  # pragma: no cover - vom Wrapper ungenutzt
        raise NotImplementedError


def _smtp_config() -> SmtpConfig:
    return SmtpConfig(
        host="mail.example.org",
        port=587,
        user="u@example.org",
        password="geheim",
        from_addr="u@example.org",
        to="ops@example.org",
    )


def _task(*, label: str = "WLAN-Latenz") -> LoggingTask:
    return LoggingTask(
        id="t1",
        target_id="wlan",
        label=label,
        purpose="",
        capture_mode=CaptureMode.REACHABILITY_LATENCY,
        operation_mode=OperationMode.IMMEDIATE,
        state=TaskState.ACTIVE,
        planned_start=None,
        planned_end=None,
        max_duration_s=None,
        created_at=0.0,
    )


def _threshold(
    condition: ThresholdCondition = ThresholdCondition.LATENCY_ABOVE,
    *,
    limit_ms: float = 50.0,
    notify_desktop: bool = True,
    notify_email: bool = False,
) -> LatencyThreshold:
    return LatencyThreshold(
        condition=condition,
        limit_ms=limit_ms,
        notify_desktop=notify_desktop,
        notify_email=notify_email,
    )


def _sample(*, rtt_ms: float = 120.0, alive: bool = True) -> PingSample:
    return PingSample(target_id="wlan", host="wlan", alive=alive, rtt_ms=rtt_ms)


# ── Desktop-Kanal ─────────────────────────────────────────────────────────────


def test_notify_desktop_calls_macos_with_title_and_subtitle() -> None:
    notifier = _RecordingNotifier()
    smtp = _RecordingSmtpConfig(None)
    wiring = _ThresholdNotifierWiring(notifier, smtp)

    task = _task(label="WLAN-Latenz")
    asyncio.run(wiring.notify_threshold(task, _threshold(notify_desktop=True), _sample(), now=0.0))

    assert len(notifier.macos_calls) == 1
    call = notifier.macos_calls[0]
    assert call["title"] == "CERNIS PRO — WLAN-Latenz"
    assert call["subtitle"] == "WLAN-Latenz"
    assert not notifier.email_calls
    assert smtp.load_calls == 0  # E-Mail aus -> load() gar nicht erst gerufen


# ── E-Mail-Kanal ──────────────────────────────────────────────────────────────


def test_notify_email_with_config_calls_email() -> None:
    notifier = _RecordingNotifier()
    cfg = _smtp_config()
    smtp = _RecordingSmtpConfig(cfg)
    wiring = _ThresholdNotifierWiring(notifier, smtp)

    asyncio.run(
        wiring.notify_threshold(
            _task(),
            _threshold(notify_desktop=False, notify_email=True),
            _sample(),
            now=0.0,
        )
    )

    assert smtp.load_calls == 1
    assert len(notifier.email_calls) == 1
    call = notifier.email_calls[0]
    assert call["subject"] == "CERNIS PRO — WLAN-Latenz"
    assert call["config"] is cfg
    assert not notifier.macos_calls  # Desktop aus


def test_notify_email_without_config_skips_email(monkeypatch: pytest.MonkeyPatch) -> None:
    """load() == None -> KEINE Mail, kein Fehler, aber sichtbar per info-Log."""
    notifier = _RecordingNotifier()
    smtp = _RecordingSmtpConfig(None)
    wiring = _ThresholdNotifierWiring(notifier, smtp)

    infos: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(app_module.logger, "info", lambda event, **kw: infos.append((event, kw)))

    asyncio.run(
        wiring.notify_threshold(
            _task(),
            _threshold(notify_desktop=False, notify_email=True),
            _sample(),
            now=0.0,
        )
    )

    assert smtp.load_calls == 1
    assert not notifier.email_calls  # keine Mail versucht
    assert infos == [("threshold_email_skipped_no_smtp", {"task_id": "t1"})]


# ── Beide Kanaele aus ─────────────────────────────────────────────────────────


def test_both_channels_off_calls_nothing() -> None:
    notifier = _RecordingNotifier()
    smtp = _RecordingSmtpConfig(_smtp_config())
    wiring = _ThresholdNotifierWiring(notifier, smtp)

    asyncio.run(
        wiring.notify_threshold(
            _task(),
            _threshold(notify_desktop=False, notify_email=False),
            _sample(),
            now=0.0,
        )
    )

    assert not notifier.macos_calls
    assert not notifier.email_calls
    assert smtp.load_calls == 0


# ── Best-effort ───────────────────────────────────────────────────────────────


def test_notifier_failure_is_caught_and_logged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wirft notifier.macos, faengt der Wrapper -> notify_threshold wirft NICHT, Warn-Log."""
    notifier = _RecordingNotifier(macos_raises=True)
    smtp = _RecordingSmtpConfig(None)
    wiring = _ThresholdNotifierWiring(notifier, smtp)

    warnings: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(
        app_module.logger, "warning", lambda event, **kw: warnings.append((event, kw))
    )

    # Wirft NICHT (best-effort) -- der Sink/Loop darf nie an einem Notify-Fehler sterben.
    asyncio.run(wiring.notify_threshold(_task(), _threshold(), _sample(), now=0.0))

    assert warnings == [("threshold_notify_failed", {"task_id": "t1"})]


# ── Nachrichten-Text je Bedingung ─────────────────────────────────────────────


def test_latency_above_message_mentions_limit_and_measured() -> None:
    notifier = _RecordingNotifier()
    wiring = _ThresholdNotifierWiring(notifier, _RecordingSmtpConfig(None))

    asyncio.run(
        wiring.notify_threshold(
            _task(),
            _threshold(ThresholdCondition.LATENCY_ABOVE, limit_ms=50.0),
            _sample(rtt_ms=120.0, alive=True),
            now=0.0,
        )
    )

    message = notifier.macos_calls[0]["message"]
    assert "Latenz" in message
    assert "50" in message  # limit_ms
    assert "120" in message  # gemessener rtt_ms


def test_unreachable_message_mentions_unreachable() -> None:
    notifier = _RecordingNotifier()
    wiring = _ThresholdNotifierWiring(notifier, _RecordingSmtpConfig(None))

    asyncio.run(
        wiring.notify_threshold(
            _task(),
            _threshold(ThresholdCondition.UNREACHABLE),
            _sample(rtt_ms=-1.0, alive=False),
            now=0.0,
        )
    )

    message = notifier.macos_calls[0]["message"]
    assert "nicht erreichbar" in message
