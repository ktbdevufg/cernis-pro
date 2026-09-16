"""Tests der alerting-Use-Cases (A.5) gegen Fake-Ports.

CRUD/History: Pass-Through-Durchreichung verifiziert. SendTestAlert: load()-Pfad +
None-Fall. RaiseAlert: der ORCHESTRIERUNGS-Vertrag (wer ruft wen in welcher
Reihenfolge, welche Kanaele bei welchen Flags, save_event je gefeuerter Regel) -- die
domain-Wahrheitstabelle (select_rules_to_fire) ist in A.2 getestet, hier NICHT erneut.
"""

import asyncio

import pytest

from application.alerting import (
    AddAlertRule,
    DeleteAlertRule,
    GetAlertHistory,
    GetAlertRules,
    GetSmtpConfigRaw,
    RaiseAlert,
    SaveSmtpConfig,
    SendTestAlert,
    UpdateAlertRule,
)
from domain.alerting import AlertEvent, AlertRule, EmailResult, SmtpConfig

_CONFIG = SmtpConfig(
    host="mail.bach.world",
    port=587,
    user="u@bach.world",
    password="secret",
    from_addr="cernis@bach.world",
    to="admin@bach.world",
)


def _rule(
    *,
    rule_id: int = 1,
    name: str = "R",
    rule_type: str = "host_down",
    target: str = "any",
    threshold: int = 60,
    notify_email: bool = False,
    notify_macos: bool = True,
    enabled: bool = True,
    last_triggered: float = 0.0,
) -> AlertRule:
    return AlertRule(
        id=rule_id,
        name=name,
        rule_type=rule_type,
        target=target,
        threshold=threshold,
        notify_email=notify_email,
        notify_macos=notify_macos,
        enabled=enabled,
        last_triggered=last_triggered,
    )


class FakeRepo:
    """In-Memory-AlertRuleRepository (erfuellt das Protocol strukturell).

    Optionales geteiltes ``seq``-Log (Reihenfolge-Vertrag): wird mit dem Notifier
    geteilt, sodass die GESAMTE Orchestrierungs-Sequenz (Kanal-Aufrufe UND save_event
    in der richtigen Reihenfolge) auf EINEM Band sichtbar ist.
    """

    def __init__(self, rules: list[AlertRule] | None = None, seq: list[str] | None = None) -> None:
        self.rules = list(rules or [])
        self.saved_events: list[AlertEvent] = []
        self.calls: list[str] = []
        self.seq = seq if seq is not None else []
        self._next_id = 1

    def get_rules(self) -> list[AlertRule]:
        self.calls.append("get_rules")
        self.seq.append("get_rules")
        return list(self.rules)

    def add(self, name, rule_type, target, threshold, notify_email, notify_macos):  # type: ignore[no-untyped-def]
        self.calls.append("add")
        rid = self._next_id
        self._next_id += 1
        self.rules.append(
            _rule(
                rule_id=rid,
                name=name,
                rule_type=rule_type,
                target=target,
                threshold=threshold,
                notify_email=notify_email,
                notify_macos=notify_macos,
            )
        )
        return rid

    def update(self, rule_id, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(f"update:{kwargs}")

    def delete(self, rule_id):  # type: ignore[no-untyped-def]
        self.calls.append(f"delete:{rule_id}")

    def save_event(self, event: AlertEvent) -> None:
        self.calls.append(f"save_event:{event.rule_id}")
        self.seq.append(f"save_event:{event.rule_id}")
        self.saved_events.append(event)

    def recent(self, limit: int) -> list[AlertEvent]:
        self.calls.append(f"recent:{limit}")
        return self.saved_events[:limit]

    def clear_all(self) -> None:
        """Leert Regeln und gespeicherte Events."""
        self.rules.clear()
        self.saved_events.clear()


class FakeNotifier:
    """In-Memory-AlertNotifierPort. Teilt optional das ``seq``-Log mit dem Repo."""

    def __init__(self, result: EmailResult | None = None, seq: list[str] | None = None) -> None:
        self.macos_calls: list[tuple[str, str, str]] = []
        self.email_calls: list[tuple[str, str, SmtpConfig]] = []
        self._result = result or EmailResult(success=True, log=["sent"])
        self.seq = seq if seq is not None else []

    async def macos(self, title: str, message: str, subtitle: str = "") -> None:
        self.macos_calls.append((title, message, subtitle))
        self.seq.append("macos")

    async def email(self, subject: str, body: str, config: SmtpConfig) -> EmailResult:
        self.email_calls.append((subject, body, config))
        self.seq.append("email")
        return self._result


class FakeSmtpConfig:
    """In-Memory-SmtpConfigPort."""

    def __init__(self, config: SmtpConfig | None, raw: dict[str, object] | None = None) -> None:
        self._config = config
        self._raw = raw
        self.load_count = 0
        self.saved: list[dict[str, object]] = []

    def load(self) -> SmtpConfig | None:
        self.load_count += 1
        return self._config

    def load_raw(self) -> dict[str, object] | None:
        return self._raw

    def save(self, config: dict[str, object]) -> None:
        self.saved.append(config)


# ── CRUD / History Pass-Throughs ──────────────────────────────


def test_get_alert_rules_passes_through() -> None:
    repo = FakeRepo([_rule(name="A"), _rule(rule_id=2, name="B")])
    assert [r.name for r in GetAlertRules(repo)()] == ["A", "B"]
    assert repo.calls == ["get_rules"]


def test_add_alert_rule_passes_through_and_returns_id() -> None:
    repo = FakeRepo()
    rid = AddAlertRule(repo)(
        name="R",
        rule_type="host_down",
        target="any",
        threshold=60,
        notify_email=True,
        notify_macos=False,
    )
    assert rid == 1
    assert repo.rules[0].notify_email is True
    assert repo.rules[0].notify_macos is False


def test_update_alert_rule_passes_only_given_fields() -> None:
    repo = FakeRepo([_rule()])
    UpdateAlertRule(repo)(1, name="X", enabled=False)
    # nur die uebergebenen Felder (Rest None) -> Repo bekommt name+enabled gesetzt.
    assert any("'name': 'X'" in c and "'enabled': False" in c for c in repo.calls)


def test_delete_alert_rule_passes_through() -> None:
    repo = FakeRepo([_rule()])
    DeleteAlertRule(repo)(1)
    assert repo.calls == ["delete:1"]


def test_get_alert_history_passes_through_with_limit() -> None:
    repo = FakeRepo()
    repo.saved_events = [
        AlertEvent(
            rule_id=1,
            rule_name="R",
            rule_type="host_down",
            target="any",
            message="m",
            timestamp=1.0,
        )
    ]
    result = GetAlertHistory(repo)(limit=10)
    assert len(result) == 1
    assert repo.calls == ["recent:10"]


def test_get_alert_history_default_limit_50() -> None:
    repo = FakeRepo()
    GetAlertHistory(repo)()
    assert repo.calls == ["recent:50"]


# ── SendTestAlert ─────────────────────────────────────────────


def test_send_test_alert_returns_email_result() -> None:
    notifier = FakeNotifier(EmailResult(success=True, log=["sent"]))
    uc = SendTestAlert(FakeSmtpConfig(_CONFIG), notifier)
    result = asyncio.run(uc())
    assert result == EmailResult(success=True, log=["sent"])
    assert len(notifier.email_calls) == 1
    # Subject wie Altcode-/test, Config durchgereicht.
    assert notifier.email_calls[0][0] == "Test Alert"
    assert notifier.email_calls[0][2] is _CONFIG


def test_send_test_alert_none_when_not_configured() -> None:
    notifier = FakeNotifier()
    uc = SendTestAlert(FakeSmtpConfig(None), notifier)
    result = asyncio.run(uc())
    assert result is None
    # KEIN email-Versuch, wenn nicht konfiguriert.
    assert notifier.email_calls == []


def test_send_test_alert_propagates_failure_result() -> None:
    # success=False muss 1:1 durchkommen (A.6 leitet 503 daraus ab).
    notifier = FakeNotifier(EmailResult(success=False, log=["CONNECTION REFUSED"]))
    uc = SendTestAlert(FakeSmtpConfig(_CONFIG), notifier)
    result = asyncio.run(uc())
    assert result is not None
    assert result.success is False


# ── SMTP-Config GET/PUT Pass-Throughs ─────────────────────────


def test_get_smtp_config_raw_passes_through() -> None:
    raw: dict[str, object] = {"host": "h", "to": "t", "password": "enc:secret"}
    uc = GetSmtpConfigRaw(FakeSmtpConfig(None, raw=raw))
    assert uc() == raw


def test_get_smtp_config_raw_none() -> None:
    assert GetSmtpConfigRaw(FakeSmtpConfig(None, raw=None))() is None


def test_save_smtp_config_passes_through() -> None:
    smtp = FakeSmtpConfig(None)
    payload = {"host": "h", "to": "t", "password": "neuesPW"}
    SaveSmtpConfig(smtp)(payload)
    assert smtp.saved == [payload]


# ── RaiseAlert: Orchestrierungs-Vertrag ───────────────────────


def test_raise_alert_fires_macos_and_saves_event() -> None:
    repo = FakeRepo([_rule(notify_macos=True, notify_email=False)])
    notifier = FakeNotifier()
    smtp = FakeSmtpConfig(_CONFIG)
    asyncio.run(RaiseAlert(repo, notifier, smtp)("host_down", "192.168.1.1", "down", now=1000.0))

    # macos gefeuert (Titel + subtitle=target), KEIN email.
    assert notifier.macos_calls == [("CERNIS PRO — R", "down", "192.168.1.1")]
    assert notifier.email_calls == []
    # save_event je gefeuerter Regel, mit now als timestamp.
    assert len(repo.saved_events) == 1
    assert repo.saved_events[0].timestamp == 1000.0
    assert repo.saved_events[0].rule_id == 1
    # SmtpConfig NICHT geladen, wenn keine email-Regel feuert.
    assert smtp.load_count == 0


def test_raise_alert_full_sequence_fire_before_save() -> None:
    # (a) SCHARFE Reihenfolge auf EINEM geteilten Band: get_rules -> Kanaele -> save_event.
    # save_event MUSS nach dem Feuern kommen (Altcode: erst _notify_*, dann
    # _save_alert_event). Beide Kanaele an, eine Regel.
    seq: list[str] = []
    repo = FakeRepo([_rule(notify_email=True, notify_macos=True)], seq=seq)
    notifier = FakeNotifier(seq=seq)
    asyncio.run(
        RaiseAlert(repo, notifier, FakeSmtpConfig(_CONFIG))(
            "host_down", "192.168.1.1", "down", now=1000.0
        )
    )
    # Exakte Sequenz: Auswahl, dann macos, dann email, dann save_event -- save_event
    # NACH beiden Kanaelen (kein History-Eintrag vor dem Feuern).
    assert seq == ["get_rules", "macos", "email", "save_event:1"]


def test_raise_alert_two_rules_interleave_fire_then_save_each() -> None:
    # (a)+(c): Pro Regel die Kette Kanal -> save_event, in Regel-Reihenfolge; save_event
    # GENAU 1x pro Regel, jeweils NACH deren Kanal.
    seq: list[str] = []
    repo = FakeRepo(
        [
            _rule(rule_id=1, name="A", notify_macos=True, notify_email=False),
            _rule(rule_id=2, name="B", notify_macos=True, notify_email=False),
        ],
        seq=seq,
    )
    notifier = FakeNotifier(seq=seq)
    asyncio.run(
        RaiseAlert(repo, notifier, FakeSmtpConfig(_CONFIG))(
            "host_down", "192.168.1.1", "down", now=1000.0
        )
    )
    assert seq == ["get_rules", "macos", "save_event:1", "macos", "save_event:2"]


def test_raise_alert_email_only_with_flag_and_config() -> None:
    repo = FakeRepo([_rule(notify_email=True, notify_macos=False)])
    notifier = FakeNotifier()
    smtp = FakeSmtpConfig(_CONFIG)
    asyncio.run(RaiseAlert(repo, notifier, smtp)("host_down", "192.168.1.1", "down", now=1000.0))

    # email gefeuert (Subject = rule.name, Config durchgereicht), KEIN macos.
    assert len(notifier.email_calls) == 1
    assert notifier.email_calls[0][0] == "R"
    assert notifier.email_calls[0][2] is _CONFIG
    assert notifier.macos_calls == []
    assert smtp.load_count == 1


def test_raise_alert_email_flag_but_no_config_does_not_email() -> None:
    # notify_email=True, aber load() == None -> KEIN email (Altcode-treu:
    # fire_alert mailt nur wenn smtp_config vorhanden). save_event trotzdem.
    repo = FakeRepo([_rule(notify_email=True, notify_macos=False)])
    notifier = FakeNotifier()
    asyncio.run(
        RaiseAlert(repo, notifier, FakeSmtpConfig(None))(
            "host_down", "192.168.1.1", "down", now=1000.0
        )
    )
    assert notifier.email_calls == []
    assert len(repo.saved_events) == 1


def test_raise_alert_no_channels_still_saves_event() -> None:
    # (b) SUBTILER FALL: beide Flags 0 -> KEIN Kanal, aber save_event JA. Altcode-treu:
    # fire_alert ruft _save_alert_event fuer JEDE selektierte Regel, unabhaengig von den
    # Kanal-Flags (Z.311, ausserhalb der if notify_*-Bloecke).
    repo = FakeRepo([_rule(notify_macos=False, notify_email=False)])
    notifier = FakeNotifier()
    smtp = FakeSmtpConfig(_CONFIG)
    asyncio.run(RaiseAlert(repo, notifier, smtp)("host_down", "192.168.1.1", "down", now=1000.0))
    assert notifier.macos_calls == []
    assert notifier.email_calls == []
    # save_event trotzdem -- History-Eintrag auch ohne Kanal.
    assert len(repo.saved_events) == 1
    assert repo.saved_events[0].rule_id == 1
    # Keine email-Regel -> Config NICHT geladen.
    assert smtp.load_count == 0


def test_raise_alert_no_match_does_nothing() -> None:
    # rule_type-Mismatch -> select gibt nichts -> kein Kanal, kein save_event.
    repo = FakeRepo([_rule(rule_type="host_down")])
    notifier = FakeNotifier()
    smtp = FakeSmtpConfig(_CONFIG)
    asyncio.run(RaiseAlert(repo, notifier, smtp)("new_device", "192.168.1.1", "new", now=1000.0))
    assert notifier.macos_calls == []
    assert notifier.email_calls == []
    assert repo.saved_events == []
    assert smtp.load_count == 0


def test_raise_alert_both_channels_when_both_flags() -> None:
    repo = FakeRepo([_rule(notify_email=True, notify_macos=True)])
    notifier = FakeNotifier()
    asyncio.run(
        RaiseAlert(repo, notifier, FakeSmtpConfig(_CONFIG))(
            "host_down", "192.168.1.1", "down", now=1000.0
        )
    )
    assert len(notifier.macos_calls) == 1
    assert len(notifier.email_calls) == 1
    assert len(repo.saved_events) == 1


def test_raise_alert_multiple_rules_each_fire_and_save() -> None:
    repo = FakeRepo(
        [
            _rule(rule_id=1, name="A", target="any", notify_macos=True),
            _rule(rule_id=2, name="B", target="192.168.1.1", notify_macos=True),
            _rule(rule_id=3, name="C", target="10.0.0.9", notify_macos=True),  # falsches Ziel
        ]
    )
    notifier = FakeNotifier()
    asyncio.run(
        RaiseAlert(repo, notifier, FakeSmtpConfig(_CONFIG))(
            "host_down", "192.168.1.1", "down", now=1000.0
        )
    )
    # A (any) + B (exaktes Ziel) feuern, C nicht.
    assert len(notifier.macos_calls) == 2
    assert [e.rule_id for e in repo.saved_events] == [1, 2]


def test_raise_alert_uses_time_when_now_omitted(monkeypatch: pytest.MonkeyPatch) -> None:
    # now weggelassen -> time.time() im Use-Case (Muster GetSlaStats). Am time-Modul
    # selbst gepatcht (use_cases nutzt `import time`, ruft `time.time()`).
    import time as time_mod

    monkeypatch.setattr(time_mod, "time", lambda: 4242.0)
    repo = FakeRepo([_rule(notify_macos=True)])
    asyncio.run(
        RaiseAlert(repo, FakeNotifier(), FakeSmtpConfig(_CONFIG))(
            "host_down", "192.168.1.1", "down"
        )
    )
    assert repo.saved_events[0].timestamp == 4242.0


def _unused_typecheck() -> None:
    # Statische Protocol-Konformitaet der Fakes (mypy prueft die Zuweisung).
    from ports.alerting import AlertNotifierPort, AlertRuleRepository, SmtpConfigPort

    _r: AlertRuleRepository = FakeRepo()
    _n: AlertNotifierPort = FakeNotifier()
    _s: SmtpConfigPort = FakeSmtpConfig(None)
    _ = (_r, _n, _s)
