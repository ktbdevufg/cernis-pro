"""Tests der maintenance-Use-Cases gegen In-Memory-Spy-Fakes der Ports.

Kein echtes SQLite/keyring noetig -- die Use-Cases orchestrieren nur ``clear_all``
(bzw. ARP-/Scheduler-Methoden) auf den Ports, also reichen Spies, die ihren
Methodennamen in eine GEMEINSAME Aufruf-Liste schreiben. So pruefen die Tests die
exakte Reihenfolge und die An-/Abwesenheit einzelner Schritte.

Kern der Behauptungen:
* Stufe 1 ruft genau die 8 Schritte und KEINEN Stufe-2-Schritt.
* Stufe 2 ruft Stufe-1 UND Stufe-2-Schritte.
* ``include_secrets`` steuert ``SecretStore.delete`` (False -> nie; True -> die
  cpnetcheck-Keys).
* Der Scheduler wird fuer JEDE gelistete id abgemeldet, BEVOR die Schedule-Tabelle
  geleert wird.
"""

from typing import Any

from application.maintenance import FactoryReset, ResetScanData
from application.maintenance.use_cases import _CPNETCHECK_SECRET_KEYS


class _Spy:
    """Generischer Port-Spy: protokolliert jeden Methodenaufruf in ``calls``.

    ``calls`` ist eine GETEILTE Liste ueber alle Spies eines Tests -- so ergibt sich
    die globale Reihenfolge. Jeder Eintrag ist ``"<label>.<methode>"``. Beliebige
    ``clear_all``/``clear_baseline``/``clear_alerts``-Aufrufe werden generisch
    bedient (die Use-Cases brauchen keine Rueckgabewerte).
    """

    def __init__(self, calls: list[str], label: str) -> None:
        self._calls = calls
        self._label = label

    def __getattr__(self, name: str) -> Any:
        def _record(*_args: Any, **_kwargs: Any) -> None:
            self._calls.append(f"{self._label}.{name}")

        return _record


class _SpyBase:
    """Basis fuer die speziellen Spies: ``__getattr__`` bedient ungenutzte Methoden.

    Die explizit definierten Methoden (``list``/``unregister``/``delete`` ...) bleiben
    echte Methoden mit Logik; alle UEBRIGEN Vertragsmethoden des jeweiligen Ports
    werden generisch (no-op, in ``_calls`` protokolliert) ueber ``__getattr__``
    bereitgestellt. Der Rueckgabetyp ``Any`` macht den Spy fuer mypy zu einer
    gueltigen Protocol-Implementierung, ohne den ganzen Vertrag nachzubauen (gleiche
    Technik wie ``_Spy``).
    """

    _calls: list[str]
    _label: str

    def __getattr__(self, name: str) -> Any:
        def _record(*_args: Any, **_kwargs: Any) -> None:
            self._calls.append(f"{self._label}.{name}")

        return _record


class _ScheduleRepoSpy(_SpyBase):
    """Schedule-Repo-Spy mit konfigurierbarer ``list()``-Ausgabe (Zeilen-dicts)."""

    def __init__(self, calls: list[str], rows: list[dict[str, Any]]) -> None:
        self._calls = calls
        self._label = "schedules"
        self._rows = rows

    def list(self) -> list[dict[str, Any]]:
        self._calls.append("schedules.list")
        return self._rows

    def clear_all(self) -> None:
        self._calls.append("schedules.clear_all")


class _SchedulerSpy(_SpyBase):
    """Scheduler-Spy: protokolliert ``unregister`` MIT der id (Reihenfolge-Beweis)."""

    def __init__(self, calls: list[str]) -> None:
        self._calls = calls
        self._label = "scheduler"
        self.unregistered: list[int] = []

    def unregister(self, schedule_id: int) -> None:
        self.unregistered.append(schedule_id)
        self._calls.append(f"scheduler.unregister({schedule_id})")


class _SecretStoreSpy(_SpyBase):
    """SecretStore-Spy: protokolliert NUR ``delete`` (die uebrigen Methoden ungenutzt)."""

    def __init__(self, calls: list[str]) -> None:
        self._calls = calls
        self._label = "secret"
        self.deleted: list[str] = []

    def delete(self, key: str) -> None:
        self.deleted.append(key)
        self._calls.append(f"secret.delete({key})")


def _make_reset_scan_data(calls: list[str]) -> ResetScanData:
    """Baut eine ``ResetScanData`` aus reinen Spies, die in ``calls`` protokollieren."""
    return ResetScanData(
        scan_history=_Spy(calls, "scan_history"),
        cve_findings=_Spy(calls, "cve_findings"),
        cve_checkstate=_Spy(calls, "cve_checkstate"),
        cve_acknowledgements=_Spy(calls, "cve_acknowledgements"),
        known_hosts=_Spy(calls, "known_hosts"),
        analysis_acknowledgements=_Spy(calls, "analysis_acknowledgements"),
        arp_guard=_Spy(calls, "arp_guard"),
    )


# Die erwartete Stufe-1-Reihenfolge (8 Schritte), s. use_cases.ResetScanData.run.
_STAGE1_CALLS = [
    "scan_history.clear_all",
    "cve_findings.clear_all",
    "cve_checkstate.clear_all",
    "cve_acknowledgements.clear_all",
    "known_hosts.clear_all",
    "analysis_acknowledgements.clear_all",
    "arp_guard.clear_baseline",
    "arp_guard.clear_alerts",
]


def _make_factory_reset(
    calls: list[str],
    *,
    reset_scan_data: ResetScanData,
    schedules: _ScheduleRepoSpy,
    scheduler: _SchedulerSpy,
    secret_store: _SecretStoreSpy,
) -> FactoryReset:
    """Baut eine ``FactoryReset`` aus Spies (Stufe 1 wird injiziert)."""
    return FactoryReset(
        reset_scan_data=reset_scan_data,
        devices=_Spy(calls, "devices"),
        settings=_Spy(calls, "settings"),
        user_rules=_Spy(calls, "user_rules"),
        schedules=schedules,
        scheduler=scheduler,
        rtt_history=_Spy(calls, "rtt_history"),
        monitor_events=_Spy(calls, "monitor_events"),
        sla_samples=_Spy(calls, "sla_samples"),
        logging_tasks=_Spy(calls, "logging_tasks"),
        logging_rtt=_Spy(calls, "logging_rtt"),
        logging_events=_Spy(calls, "logging_events"),
        alert_rules=_Spy(calls, "alert_rules"),
        agents=_Spy(calls, "agents"),
        dns_watch_acknowledgements=_Spy(calls, "dns_watch_acknowledgements"),
        scheduled_jobs=_Spy(calls, "scheduled_jobs"),
        secret_store=secret_store,
    )


# ── (1) Stufe 1: genau die 8 Schritte, KEIN Stufe-2-Schritt ────────────────────


def test_reset_scan_data_ruft_genau_die_acht_schritte() -> None:
    calls: list[str] = []
    _make_reset_scan_data(calls).run()
    assert calls == _STAGE1_CALLS


def test_reset_scan_data_fasst_keine_stufe2_tabellen_an() -> None:
    calls: list[str] = []
    _make_reset_scan_data(calls).run()
    # Keine Geraete/Settings/Regeln/Monitoring/Alert/Agent-Aufrufe in Stufe 1.
    verbotene_label = (
        "devices.",
        "settings.",
        "user_rules.",
        "schedules.",
        "scheduler.",
        "rtt_history.",
        "monitor_events.",
        "sla_samples.",
        "logging_tasks.",
        "logging_rtt.",
        "logging_events.",
        "alert_rules.",
        "agents.",
        "secret.",
    )
    assert not [c for c in calls if c.startswith(verbotene_label)]


# ── (2) Stufe 2: Stufe-1 UND Stufe-2-Schritte ──────────────────────────────────


def test_factory_reset_ruft_stufe1_und_stufe2() -> None:
    calls: list[str] = []
    reset = _make_reset_scan_data(calls)
    schedules = _ScheduleRepoSpy(calls, rows=[{"id": 1}, {"id": 2}])
    scheduler = _SchedulerSpy(calls)
    secret_store = _SecretStoreSpy(calls)
    factory = _make_factory_reset(
        calls,
        reset_scan_data=reset,
        schedules=schedules,
        scheduler=scheduler,
        secret_store=secret_store,
    )

    factory.run()

    expected = [
        *_STAGE1_CALLS,
        "devices.clear_all",
        "settings.clear_all",
        "user_rules.clear_all",
        "schedules.list",
        "scheduler.unregister(1)",
        "scheduler.unregister(2)",
        "schedules.clear_all",
        "rtt_history.clear_all",
        "monitor_events.clear_all",
        "sla_samples.clear_all",
        "logging_tasks.clear_all",
        "logging_rtt.clear_all",
        "logging_events.clear_all",
        "scheduled_jobs.clear_all",
        "alert_rules.clear_all",
        "agents.clear_all",
        "dns_watch_acknowledgements.clear_all",
    ]
    assert calls == expected


def test_factory_reset_loescht_dns_watch_quittierungen() -> None:
    calls: list[str] = []
    factory = _make_factory_reset(
        calls,
        reset_scan_data=_make_reset_scan_data(calls),
        schedules=_ScheduleRepoSpy(calls, rows=[]),
        scheduler=_SchedulerSpy(calls),
        secret_store=_SecretStoreSpy(calls),
    )

    factory.run()

    assert "dns_watch_acknowledgements.clear_all" in calls


# ── (3) include_secrets steuert SecretStore.delete ─────────────────────────────


def test_factory_reset_ohne_secrets_loescht_keine_secrets() -> None:
    calls: list[str] = []
    secret_store = _SecretStoreSpy(calls)
    factory = _make_factory_reset(
        calls,
        reset_scan_data=_make_reset_scan_data(calls),
        schedules=_ScheduleRepoSpy(calls, rows=[]),
        scheduler=_SchedulerSpy(calls),
        secret_store=secret_store,
    )

    factory.run(include_secrets=False)

    assert secret_store.deleted == []
    assert not [c for c in calls if c.startswith("secret.")]


def test_factory_reset_mit_secrets_loescht_die_cpnetcheck_keys() -> None:
    calls: list[str] = []
    secret_store = _SecretStoreSpy(calls)
    factory = _make_factory_reset(
        calls,
        reset_scan_data=_make_reset_scan_data(calls),
        schedules=_ScheduleRepoSpy(calls, rows=[]),
        scheduler=_SchedulerSpy(calls),
        secret_store=secret_store,
    )

    factory.run(include_secrets=True)

    assert secret_store.deleted == list(_CPNETCHECK_SECRET_KEYS)
    assert "cpnetcheck_token" in secret_store.deleted


# ── (4) Scheduler vor Schedule-Tabelle, fuer jede gelistete id ─────────────────


def test_factory_reset_meldet_jede_id_vor_clear_all_ab() -> None:
    calls: list[str] = []
    scheduler = _SchedulerSpy(calls)
    schedules = _ScheduleRepoSpy(calls, rows=[{"id": 7}, {"id": 8}, {"id": 9}])
    factory = _make_factory_reset(
        calls,
        reset_scan_data=_make_reset_scan_data(calls),
        schedules=schedules,
        scheduler=scheduler,
        secret_store=_SecretStoreSpy(calls),
    )

    factory.run()

    # Jede gelistete id wurde abgemeldet ...
    assert scheduler.unregistered == [7, 8, 9]
    # ... und das ZULETZT abgemeldete kam noch VOR dem Leeren der Schedule-Tabelle.
    letztes_unregister = max(
        i for i, c in enumerate(calls) if c.startswith("scheduler.unregister(")
    )
    schedules_clear = calls.index("schedules.clear_all")
    assert letztes_unregister < schedules_clear
