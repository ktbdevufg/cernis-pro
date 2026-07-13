"""Tests fuer ``AlertNotifierAdapter`` (A.4) -- macos (osascript) + email (SMTP-Wrapper).

Getestet: (1) Port-Konformitaet, (2) email mappt das Altcode-{success,log}-dict zu
EmailResult (success ist exakt der dict-Wert), (3) macos-Fehler wird geloggt statt
geschluckt (bewusste E.4-Abweichung) und NICHT geworfen, (4) email laeuft im Executor
(notify_email_with_log ist blockierend).
"""

import asyncio
import threading

import pytest

from domain.alerting import EmailResult, SmtpConfig
from infrastructure.alerting import notifier as notifier_mod
from infrastructure.alerting.notifier import AlertNotifierAdapter
from ports.alerting import AlertNotifierPort

_CONFIG = SmtpConfig(
    host="mail.bach.world",
    port=587,
    user="alerts@bach.world",
    password="secret",
    from_addr="cernis@bach.world",
    to="admin@bach.world",
)


def test_conforms_to_notifier_protocol() -> None:
    _: AlertNotifierPort = AlertNotifierAdapter()


# ── email: dict -> EmailResult ────────────────────────────────


def test_email_maps_success_dict_to_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        notifier_mod,
        "notify_email_with_log",
        lambda subject, body, smtp_config: {"success": True, "log": ["Email sent successfully!"]},
    )
    result = asyncio.run(AlertNotifierAdapter().email("Subj", "Body", _CONFIG))
    assert isinstance(result, EmailResult)
    assert result.success is True
    assert result.log == ["Email sent successfully!"]


def test_email_maps_failure_dict_to_result(monkeypatch: pytest.MonkeyPatch) -> None:
    # success aus dem dict ist exakt EmailResult.success (A.1-/test 503 haengt daran).
    monkeypatch.setattr(
        notifier_mod,
        "notify_email_with_log",
        lambda subject, body, smtp_config: {"success": False, "log": ["CONNECTION REFUSED"]},
    )
    result = asyncio.run(AlertNotifierAdapter().email("Subj", "Body", _CONFIG))
    assert result.success is False
    assert result.log == ["CONNECTION REFUSED"]


def test_email_passes_smtp_config_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    # SmtpConfig wird wieder zu den Altcode-Keys auseinandergenommen.
    seen: dict[str, object] = {}

    def fake_send(subject: str, body: str, smtp_config: dict[str, object]) -> dict[str, object]:
        seen.update(smtp_config)
        return {"success": True, "log": []}

    monkeypatch.setattr(notifier_mod, "notify_email_with_log", fake_send)
    asyncio.run(AlertNotifierAdapter().email("Subj", "Body", _CONFIG))
    assert seen["host"] == "mail.bach.world"
    assert seen["port"] == 587
    assert seen["user"] == "alerts@bach.world"
    assert seen["password"] == "secret"
    assert seen["from"] == "cernis@bach.world"
    assert seen["to"] == "admin@bach.world"


def test_email_runs_in_executor_not_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    call_thread: dict[str, int] = {}

    def fake_send(subject: str, body: str, smtp_config: dict[str, object]) -> dict[str, object]:
        call_thread["tid"] = threading.get_ident()
        return {"success": True, "log": []}

    monkeypatch.setattr(notifier_mod, "notify_email_with_log", fake_send)

    async def _run() -> None:
        loop_tid = threading.get_ident()
        await AlertNotifierAdapter().email("S", "B", _CONFIG)
        # notify_email_with_log lief in einem ANDEREN Thread (Executor), nicht im Loop.
        assert call_thread["tid"] != loop_tid

    asyncio.run(_run())


# ── macos: best-effort + Log (E.4-Abweichung) ─────────────────


def test_macos_logs_on_error_and_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    # osascript fehlt (Linux) -> notify_macos wirft -> Adapter loggt, wirft NICHT.
    def boom(title: str, message: str, subtitle: str = "") -> None:
        raise FileNotFoundError("osascript")

    monkeypatch.setattr(notifier_mod, "notify_macos", boom)
    warnings: list[str] = []
    monkeypatch.setattr(notifier_mod._logger, "warning", lambda event, **kw: warnings.append(event))
    # darf nicht werfen:
    asyncio.run(AlertNotifierAdapter().macos("Title", "Message"))
    # ... aber sichtbar geloggt (bewusste E.4-Abweichung: kein except: pass).
    assert "alert_macos_notify_failed" in warnings


def test_macos_success_no_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, str] = {}
    monkeypatch.setattr(
        notifier_mod,
        "notify_macos",
        lambda title, message, subtitle="": seen.update(title=title, message=message),
    )
    warnings: list[str] = []
    monkeypatch.setattr(notifier_mod._logger, "warning", lambda event, **kw: warnings.append(event))
    asyncio.run(AlertNotifierAdapter().macos("T", "M", subtitle="S"))
    assert seen == {"title": "T", "message": "M"}
    assert warnings == []


def test_macos_runs_in_executor_not_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    call_thread: dict[str, int] = {}
    monkeypatch.setattr(
        notifier_mod,
        "notify_macos",
        lambda title, message, subtitle="": call_thread.update(tid=threading.get_ident()),
    )

    async def _run() -> None:
        loop_tid = threading.get_ident()
        await AlertNotifierAdapter().macos("T", "M")
        assert call_thread["tid"] != loop_tid

    asyncio.run(_run())
