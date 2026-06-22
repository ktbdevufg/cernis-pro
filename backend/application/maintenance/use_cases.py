"""Use-Cases der maintenance-Domaene: die zwei Stufen der Daten-Loeschung.

Kennt ausschliesslich ``ports/`` (Protocols) -- NIE ``infrastructure/``, NIE
``modules/``, NIE Domaenen-Interna anderer Domaenen (import-linter). Alle Ports
kommen per Constructor-Injection herein (Hausstil wie ``application/cve``).

Zwei Adapter haben (bewusst) KEINEN eigenen Port: ``analysis_host_history_db``
(``analysis_known_hosts``) und ``analysis_acknowledgements_db``
(``analysis_acknowledgements``). Damit der Use-Case trotzdem port-/protocol-sauber
bleibt, definieren wir hier je ein schmales lokales Protocol mit genau einer
Methode ``clear_all`` (``KnownHostsCleaner`` / ``AnalysisAckCleaner``) und
injizieren diese ebenso.

ZWEI STUFEN (ADR Wartungs-Funktion):
* ``ResetScanData`` (Stufe 1) -- leert NUR Scan-/CVE-/ARP-/Analyse-Befunde. KEINE
  Settings, KEIN Geraete-Gedaechtnis, KEINE Monitoring-Daten, KEINE Regeln.
* ``FactoryReset`` (Stufe 2, "Werkszustand") -- fuehrt erst die ganze Stufe 1 aus
  (komponiert: ``ResetScanData`` wird injiziert, sein ``run()`` laeuft zuerst) und
  raeumt DANACH Geraete, Settings, Regeln, Monitoring (Scheduler-Jobs ZUERST,
  dann Tabellen), Alert-Regeln und Agenten ab -- optional auch die Secrets.
"""

from typing import Protocol

import structlog

from ports.agent import AgentRepository
from ports.alerting import AlertRuleRepository
from ports.analysis import UserRuleStore
from ports.cve import (
    CveAcknowledgementRepository,
    CveCheckStateRepository,
    CveFindingRepository,
)
from ports.devices import DeviceRepository
from ports.monitoring import (
    LoggingEventRepository,
    LoggingRttRepository,
    LoggingTaskRepository,
    MonitorEventRepository,
    RttHistoryRepository,
    ScanJobScheduler,
    ScheduleRepository,
    SlaSampleRepository,
)
from ports.scanning import ScanHistoryRepository
from ports.security import ArpGuardRepository
from ports.settings import SecretStore, SettingsRepository

__all__ = [
    "AnalysisAckCleaner",
    "DnsWatchAckCleaner",
    "FactoryReset",
    "KnownHostsCleaner",
    "ResetScanData",
    "ScheduledJobCleaner",
]

_logger = structlog.get_logger(__name__)

# Die fuer cpnetcheck bekannten Secret-Keys (domain/settings.py SECRET_KEYS:
# ``cpnetcheck_token``; ``cpnetcheck_url`` ist KEIN Secret). NUR diese loeschen.
_CPNETCHECK_SECRET_KEYS: tuple[str, ...] = ("cpnetcheck_token",)


# ── Lokale Protocols fuer die port-losen Cleaner ───────────────────────────────


class KnownHostsCleaner(Protocol):
    """Schmaler Vertrag fuer ``analysis_known_hosts`` (Adapter ohne eigenen Port)."""

    def clear_all(self) -> None:
        """Leert die bekannten Hosts (``analysis_known_hosts``) vollstaendig."""
        ...


class AnalysisAckCleaner(Protocol):
    """Schmaler Vertrag fuer ``analysis_acknowledgements`` (Adapter ohne eigenen Port)."""

    def clear_all(self) -> None:
        """Leert die Analyse-Quittierungen (``analysis_acknowledgements``) vollstaendig."""
        ...


class DnsWatchAckCleaner(Protocol):
    """Schmaler Vertrag fuer dns_watch_acknowledgements (Adapter ohne eigenen Port)."""

    def clear_all(self) -> None:
        """Leert die DNS-Waechter-Quittierungen (``dns_watch_acknowledgements``) vollstaendig."""
        ...


class ScheduledJobCleaner(Protocol):
    """Schmaler Vertrag fuer die v2-Scheduler-Jobs (``scheduler_jobs``-Tabelle).

    Der ``ScheduledJobRepository``-Adapter (``SqliteScheduledJobRepository``) erfuellt
    diesen Vertrag via seiner ``clear_all``-Methode; der Werkszustand braucht hier nur
    das Leeren. Getrennt vom alten ``ApschedulerJobScheduler``/``schedules`` (eigene Tabelle).
    """

    def clear_all(self) -> None:
        """Leert die v2-Scheduler-Jobs (``scheduler_jobs``) vollstaendig."""
        ...


# ── Stufe 1: Scan-Daten zuruecksetzen ──────────────────────────────────────────


class ResetScanData:
    """Stufe 1 ("Scan-Daten zuruecksetzen"): leert die Befund-/Verlaufstabellen.

    Beruehrt ausschliesslich Scan-Historie, CVE (Befunde + Pruefstand +
    Quittierungen), die beiden Analyse-Tabellen und die ARP-Wache (Baseline +
    Alerts). KEINE Settings, KEIN Geraete-Gedaechtnis, KEINE Monitoring-Daten,
    KEINE eigenen Regeln. Jeder Schritt wird ausgefuehrt; am Ende EIN Info-Log.
    """

    def __init__(
        self,
        scan_history: ScanHistoryRepository,
        cve_findings: CveFindingRepository,
        cve_checkstate: CveCheckStateRepository,
        cve_acknowledgements: CveAcknowledgementRepository,
        known_hosts: KnownHostsCleaner,
        analysis_acknowledgements: AnalysisAckCleaner,
        arp_guard: ArpGuardRepository,
    ) -> None:
        self._scan_history = scan_history
        self._cve_findings = cve_findings
        self._cve_checkstate = cve_checkstate
        self._cve_acknowledgements = cve_acknowledgements
        self._known_hosts = known_hosts
        self._analysis_acknowledgements = analysis_acknowledgements
        self._arp_guard = arp_guard

    def run(self) -> None:
        """Leert die Stufe-1-Tabellen in fester Reihenfolge (s. Klassen-Docstring)."""
        self._scan_history.clear_all()
        self._cve_findings.clear_all()
        self._cve_checkstate.clear_all()
        self._cve_acknowledgements.clear_all()
        self._known_hosts.clear_all()
        self._analysis_acknowledgements.clear_all()
        self._arp_guard.clear_baseline()
        self._arp_guard.clear_alerts()
        _logger.info("scan_data_reset")


# ── Stufe 2: Werkszustand ──────────────────────────────────────────────────────


class FactoryReset:
    """Stufe 2 ("Werkszustand"): die ganze Stufe 1 plus alles Uebrige.

    Komponiert sauber ueber ``ResetScanData`` (injiziert, dessen ``run()`` laeuft
    ZUERST). Danach: Geraete, Settings, User-Regeln, Monitoring (Scheduler-Jobs
    ZUERST sauber abraeumen, dann Tabellen), Alert-Regeln, Agenten. Bei
    ``include_secrets=True`` zusaetzlich die bekannten cpnetcheck-Secrets ueber den
    ``SecretStore`` (idempotent -- ein fehlender Key ist KEIN Fehler).
    """

    def __init__(
        self,
        reset_scan_data: ResetScanData,
        devices: DeviceRepository,
        settings: SettingsRepository,
        user_rules: UserRuleStore,
        schedules: ScheduleRepository,
        scheduler: ScanJobScheduler,
        rtt_history: RttHistoryRepository,
        monitor_events: MonitorEventRepository,
        sla_samples: SlaSampleRepository,
        logging_tasks: LoggingTaskRepository,
        logging_rtt: LoggingRttRepository,
        logging_events: LoggingEventRepository,
        alert_rules: AlertRuleRepository,
        agents: AgentRepository,
        dns_watch_acknowledgements: DnsWatchAckCleaner,
        scheduled_jobs: ScheduledJobCleaner,
        secret_store: SecretStore,
    ) -> None:
        self._reset_scan_data = reset_scan_data
        self._devices = devices
        self._settings = settings
        self._user_rules = user_rules
        self._schedules = schedules
        self._scheduler = scheduler
        self._rtt_history = rtt_history
        self._monitor_events = monitor_events
        self._sla_samples = sla_samples
        self._logging_tasks = logging_tasks
        self._logging_rtt = logging_rtt
        self._logging_events = logging_events
        self._alert_rules = alert_rules
        self._agents = agents
        self._dns_watch_acknowledgements = dns_watch_acknowledgements
        self._scheduled_jobs = scheduled_jobs
        self._secret_store = secret_store

    def run(self, *, include_secrets: bool = False) -> None:
        """Setzt alles auf Werkszustand zurueck (s. Klassen-Docstring)."""
        # Stufe 1 zuerst (komponiert, keine Duplikation der 8 Schritte).
        self._reset_scan_data.run()

        # a/b/c: Geraete, Settings, User-Regeln.
        self._devices.clear_all()
        self._settings.clear_all()
        self._user_rules.clear_all()

        # d: Monitoring -- erst die Scheduler-Jobs sauber abmelden, DANN die Tabellen.
        # Das Abmelden ist idempotent/best-effort (ein nicht (mehr) registrierter Job
        # ist kein Fehler), und es muss VOR dem Leeren der Schedule-Tabelle laufen,
        # damit kein verwaister Job auf eine geloeschte Zeile feuert.
        schedule_ids = [zeile["id"] for zeile in self._schedules.list()]
        for schedule_id in schedule_ids:
            self._scheduler.unregister(schedule_id)
        self._schedules.clear_all()
        self._rtt_history.clear_all()
        self._monitor_events.clear_all()
        self._sla_samples.clear_all()
        self._logging_tasks.clear_all()
        self._logging_rtt.clear_all()
        self._logging_events.clear_all()
        # v2-Scheduler-Jobs (eigene Tabelle, getrennt vom alten ApschedulerJobScheduler/
        # schedules). Eigener Schritt im Monitoring-Block; raeumt nur die scheduler_jobs.
        self._scheduled_jobs.clear_all()

        # e/f: Alert-Regeln, Agenten.
        self._alert_rules.clear_all()
        self._agents.clear_all()
        # DNS-Waechter-Quittierungen (nutzergesetzte ack-Liste).
        self._dns_watch_acknowledgements.clear_all()

        # Optional: die bekannten cpnetcheck-Secrets (idempotent).
        if include_secrets:
            for key in _CPNETCHECK_SECRET_KEYS:
                self._secret_store.delete(key)

        _logger.info("factory_reset", include_secrets=include_secrets)
