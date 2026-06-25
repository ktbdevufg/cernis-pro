"""Composition Root von CERNIS PRO 2.0.

Einziger Ort, an dem alle Ringe zusammenkommen: konfiguriert Logging und
Middleware, baut die FastAPI-App und verdrahtet (ab Schritt 6) ``ports/`` <->
``infrastructure/`` per Dependency Injection. Bewusst von den import-linter-
Vertraegen ausgenommen (Composition-Root-Ausnahme, Regel 5).

Lifespan-Kontext statt ``@app.on_event`` (siehe docs/migration_notes.md,
fastapi/starlette).
"""

import asyncio
import json
import os
import sys
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, replace
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response
from starlette.types import Scope

from api.agent import (
    provide_delete_agent,
    provide_list_agents,
    provide_ping_agent,
    provide_save_agent,
    provide_scan_via_agent,
)
from api.agent import router as agent_router
from api.alerting import (
    provide_add_alert_rule,
    provide_delete_alert_rule,
    provide_get_alert_history,
    provide_get_alert_rules,
    provide_get_smtp_config_raw,
    provide_save_smtp_config,
    provide_send_test_alert,
    provide_update_alert_rule,
)
from api.alerting import router as alerting_router
from api.analysis import (
    UserRuleBody,
    provide_acknowledge,
    provide_add_user_rules,
    provide_analyze,
    provide_delete_user_rule,
    provide_list_all_rules,
    provide_list_user_rules,
    provide_service_lookup,
)
from api.analysis import router as analysis_router
from api.capture import (
    TopologySource,
    provide_build_topology,
    provide_capture_lldp,
    provide_capture_status,
    provide_get_lldp_neighbors,
    provide_pcap_path,
    provide_recent_packets,
    provide_save_dir,
    provide_start_capture,
    provide_start_capture_uc,
    provide_stop_capture,
)
from api.capture import router as capture_router
from api.cve import (
    provide_cve_acknowledge,
    provide_get_acknowledged_findings,
    provide_get_active_findings,
    provide_get_cve_status,
)
from api.cve import router as cve_router
from api.devices import (
    provide_answer_archive_prompt,
    provide_archive_device,
    provide_create_device,
    provide_delete_device,
    provide_dismiss_device_from_watch,
    provide_get_archive_candidates,
    provide_get_archived_devices,
    provide_get_device,
    provide_get_device_stats,
    provide_get_devices,
    provide_get_unclassified_devices,
    provide_record_scanned_host,
    provide_restore_device,
    provide_update_device_meta,
)
from api.devices import router as devices_router
from api.diagnostics import (
    provide_build_route_geo,
    provide_check_dhcp_permission,
    provide_check_external,
    provide_check_tools,
    provide_check_traceroute_permission,
    provide_detect_rogue_dhcp,
    provide_enrich_route_orgs,
    provide_grab_banner,
    provide_resolve_dns,
    provide_run_traceroute,
)
from api.diagnostics import router as diagnostics_router
from api.dns_watch import (
    DNS_DOH_PROVIDERS_KEY,
    DNS_EXPECTED_SERVERS_KEY,
    DnsContactOut,
    DnsWatchOverviewOut,
    provide_dns_watch,
    provide_dns_watch_acknowledge,
)
from api.dns_watch import router as dns_watch_router
from api.export import provide_export_analysis, provide_export_logging, provide_export_scan
from api.export import router as export_router
from api.fritz import provide_get_fritz_detail
from api.fritz import router as fritz_router
from api.interfaces import provide_list_interfaces
from api.interfaces import router as interfaces_router
from api.maintenance import (
    provide_delete_selected,
    provide_factory_reset,
    provide_reset_scan_data,
)
from api.maintenance import router as maintenance_router
from api.metrics import provide_export_metrics
from api.metrics import router as metrics_router
from api.monitoring import (
    provide_add_monitor_target,
    provide_check_log_volume,
    provide_create_logging_task,
    provide_delete_logging_task,
    provide_delete_monitor_target,
    provide_get_all_sla_stats,
    provide_get_logging_task_detail,
    provide_get_logging_task_events,
    provide_get_logging_task_rtt,
    provide_get_logging_task_sla,
    provide_get_monitor_events,
    provide_get_rtt_history,
    provide_get_schedules,
    provide_get_sla_stats,
    provide_list_logging_tasks,
    provide_manage_schedules,
    provide_monitor_status,
    provide_pause_logging_task,
    provide_resume_logging_task,
    provide_start_logging_task,
    provide_stop_logging_task,
    provide_update_schedule,
)
from api.monitoring import router as monitoring_router
from api.outbound import OutboundContactOut, OutboundOverviewOut, provide_outbound_contacts
from api.outbound import router as outbound_router
from api.outbound_log import (
    provide_create_outbound_recording,
    provide_delete_outbound_recording,
    provide_get_outbound_aggregate,
    provide_get_outbound_detail_range,
    provide_get_outbound_recording,
    provide_list_outbound_recordings,
    provide_pause_outbound_recording,
    provide_resume_outbound_recording,
    provide_start_outbound_recording,
    provide_stop_outbound_recording,
)
from api.outbound_log import router as outbound_log_router
from api.process import provide_check_process_permission, provide_list_processes
from api.process import router as process_router
from api.report import (
    CveFindingOut,
    NetFindingOut,
    PortFindingOut,
    ScoreContributionOut,
    ScoreOut,
    SecurityReportOut,
    provide_manual_pdf,
    provide_security_report,
    provide_security_report_pdf,
)
from api.report import router as report_router
from api.resolver import provide_resolve_endpoint, provide_resolve_ptr_batch
from api.resolver import router as resolver_router
from api.scanning import (
    provide_get_arp_table,
    provide_get_scan_detail,
    provide_get_scan_history,
    provide_lookup_vendor,
)
from api.scanning import router as scanning_router
from api.scheduler import (
    CreateJobBody,
    ScheduledJobOut,
    provide_scheduler_create,
    provide_scheduler_delete,
    provide_scheduler_list,
    provide_scheduler_pause,
    provide_scheduler_resume,
)
from api.scheduler import router as scheduler_router
from api.security import (
    provide_check_default_creds,
    provide_clear_arp_baseline,
    provide_get_arp_alerts,
    provide_get_arp_baseline,
    provide_inspect_tls,
    provide_lookup_cves,
    provide_run_arp_scan,
)
from api.security import router as security_router
from api.settings import (
    provide_get_settings,
    provide_update_secret,
    provide_update_setting,
)
from api.settings import router as settings_router
from api.sni import (
    provide_get_observed_sni,
    provide_sni_running,
    provide_start_sni,
    provide_start_sni_uc,
    provide_stop_sni,
)
from api.sni import router as sni_router
from api.system import (
    provide_system_info,
    provide_url_opener,
    provide_version,
)
from api.system import router as system_router
from api.traffic import (
    provide_check_traffic_permission,
    provide_list_app_traffic,
    provide_start_poll,
    provide_stop_poll,
)
from api.traffic import router as traffic_router
from application.agent import (
    DeleteAgent,
    ListAgents,
    PingAgent,
    SaveAgent,
    ScanViaAgent,
)
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
from application.analysis import AddUserRules, AnalyzeSnapshot, ListUserRules
from application.capture import (
    BuildTopology,
    CaptureLldp,
    GetLldpNeighbors,
    RunCapture,
    StartCapture,
)
from application.cve import (
    ActiveFinding,
    GetAcknowledgedFindings,
    GetActiveFindings,
    GetCveMonitorStatus,
    RunCveMonitor,
)
from application.devices import (
    AnswerArchivePrompt,
    ArchiveDevice,
    CreateDevice,
    DeleteDevice,
    DismissDeviceFromWatch,
    GetArchiveCandidates,
    GetArchivedDevices,
    GetDevice,
    GetDevices,
    GetDeviceStats,
    GetUnclassifiedDevices,
    RecordScannedHost,
    RestoreDevice,
    UpdateDeviceMeta,
)
from application.diagnostics import (
    BuildRouteGeo,
    CheckDhcpPermission,
    CheckDiagnosticsTools,
    CheckExternalReachability,
    CheckTraceroutePermission,
    DetectRogueDhcp,
    EnrichRouteOrgs,
    GetLatestRogueDhcp,
    GrabBanner,
    ResolveDns,
    RogueDhcpPermissionError,
    RunTraceroute,
)
from application.dns_watch import BuildDnsWatch, RawDnsConnection
from application.export import (
    ExportAnalysis,
    ExportLoggingReport,
    ExportScan,
    LoggingReportNotFound,
    ScanNotFoundError,
)
from application.fritz_detail import FritzDetailAuthError, GetFritzDetail
from application.interfaces import ListInterfaces
from application.maintenance import DeleteSelectedData, FactoryReset, ResetScanData
from application.metrics import ExportMetrics
from application.monitoring import (
    AddMonitorTarget,
    CheckLogVolume,
    CreateLoggingTask,
    DeleteLoggingTask,
    DeleteMonitorTarget,
    EnforceLoggingRetention,
    GetAllSlaStats,
    GetLoggingTaskDetail,
    GetLoggingTaskEvents,
    GetLoggingTaskRtt,
    GetLoggingTaskSla,
    GetMonitorEvents,
    GetRttHistory,
    GetSchedules,
    GetSlaStats,
    ListLoggingTasks,
    ManageSchedules,
    PauseLoggingTask,
    ResumeActiveLoggingTasks,
    ResumeLoggingTask,
    RunLoggingRetention,
    RunMonitor,
    StartLoggingTask,
    StopLoggingTask,
    UpdateSchedule,
)
from application.monitoring.scheduler_handler import MonitoringWindowHandler
from application.outbound import BuildOutboundContacts, RawConnection
from application.outbound_log import (
    CreateOutboundRecording,
    DeleteOutboundRecording,
    GetOutboundAggregate,
    GetOutboundDetailRange,
    GetOutboundRecording,
    ListOutboundRecordings,
    PauseOutboundRecording,
    ResumeOutboundRecording,
    RunOutboundRecorder,
    StartOutboundRecording,
    StopOutboundRecording,
)
from application.process import CheckProcessPermission, ListProcesses
from application.reporting import (
    BuildSecurityReport,
    ManualPdfModel,
    ManualPdfSection,
    SecurityPdfModel,
    SecurityReport,
)
from application.reporting import (
    CveFinding as ReportCveFinding,
)
from application.reporting import (
    NetFinding as ReportNetFinding,
)
from application.reporting import (
    PortFinding as ReportPortFinding,
)
from application.resolver import ResolveEndpoint, ResolvePtrBatch
from application.scanning import (
    GetArpTable,
    GetScanDetail,
    GetScanHistory,
    LookupVendor,
    RunNetworkScan,
)
from application.scheduler import (
    CreateScheduledJob,
    DeleteScheduledJob,
    ListScheduledJobs,
    PauseScheduledJob,
    ResumeScheduledJob,
    RunScheduler,
)
from application.security import (
    CheckDefaultCreds,
    ClearArpBaseline,
    GetArpAlerts,
    GetArpBaseline,
    InspectTls,
    LookupCves,
    RunArpScan,
)
from application.settings import GetSettings, UpdateSecret, UpdateSetting
from application.sni import GetObservedSni, RunSniCapture, StartSniCapture
from application.traffic import CheckTrafficPermission, ListAppTraffic, PollThroughput
from domain.analysis import (
    ObservedConnection,
    ObservedHost,
    ObservedProcess,
    Rule,
    Severity,
    Snapshot,
    service_for_port,
)
from domain.analysis.engine import _SEVERITY_RANK
from domain.dns_watch import doh_providers_or_default, expected_servers_or_default
from domain.export import (
    ExportableAnalysis,
    ExportableFinding,
    ExportableHost,
    ExportableLoggingEvent,
    ExportableLoggingReport,
    ExportableLoggingRtt,
    ExportablePort,
    ExportableScan,
)
from domain.monitoring import (
    LatencyThreshold,
    LoggingTask,
    MonitorEvent,
    MonitorEventType,
    OperationMode,
    PingSample,
    ThresholdCondition,
    compute_sla_stats,
)
from domain.outbound_log import ContactDelta
from domain.process import classify_kind
from domain.scanning import EnrichedHost
from domain.scheduler.models import DailyWindow
from infrastructure.agent import (
    SqliteAgentRepository,
    UrllibAgentPinger,
    WebsocketsAgentScanClient,
)
from infrastructure.alerting import (
    AlertNotifierAdapter,
    SettingsSmtpConfigAdapter,
    SqliteAlertRuleRepository,
)
from infrastructure.analysis import BuiltinRuleProvider, StaticHelpLinkResolver
from infrastructure.analysis_acknowledgements_db import SqliteAcknowledgementRepository
from infrastructure.analysis_host_history_db import SqliteHostHistoryRepository
from infrastructure.analysis_rules_db import SqliteUserRuleRepository
from infrastructure.capture import (
    ScapyLldpSniffer,
    ScapyPacketSniffer,
    WebSocketCaptureBroadcaster,
)
from infrastructure.clock import SystemClock
from infrastructure.config import APP_NAME, APP_VERSION, AppConfig
from infrastructure.cve_acknowledgements_db import SqliteCveAcknowledgementRepository
from infrastructure.cve_checkstate_db import SqliteCveCheckStateRepository
from infrastructure.cve_findings_db import SqliteCveFindingRepository
from infrastructure.device_repository import SqliteDeviceRepository
from infrastructure.diagnostics_linux import (
    DiagnosticsToolMissing,
    DigDnsResolver,
    ExternalCheckFailed,
    HttpxReachabilityProvider,
    LinuxDhcpPermission,
    LinuxPackageManagerDetector,
    LinuxTraceroutePermission,
    NmapDhcpProbe,
    ShutilToolDetector,
    SocketBannerGrabber,
    SystemTracerouteRunner,
)
from infrastructure.dns_watch_acknowledgements_db import (
    SqliteDnsWatchAcknowledgementRepository,
)
from infrastructure.export_pdf import ReportlabRenderer
from infrastructure.interfaces_linux import InterfaceDiscoveryAdapter
from infrastructure.logging import configure_logging
from infrastructure.metrics import SqliteMetricsReader
from infrastructure.monitoring import (
    ApschedulerJobScheduler,
    CompositeTargetSource,
    MonitorLoggingSink,
    MonitorNotifierAdapter,
    MonitorPingerAdapter,
    SqliteLoggingEventRepository,
    SqliteLoggingRttRepository,
    SqliteLoggingTaskRepository,
    SqliteMonitorEventRepository,
    SqliteRttHistoryRepository,
    SqliteScheduleRepository,
    SqliteSlaSampleRepository,
    WebSocketMonitorBroadcaster,
)
from infrastructure.outbound_log_aggregate import SqliteOutboundAggregateRepository
from infrastructure.outbound_log_detail import SqliteOutboundDetailRepository
from infrastructure.outbound_log_recordings import SqliteOutboundRecordingRepository
from infrastructure.process_linux import PsutilProcessAdapter
from infrastructure.process_permission import ProcessPermissionAdapter
from infrastructure.resolver import (
    CsvGeoAsnDb,
    DigDnsPtrResolver,
    RdapClient,
    ResolverDataMissing,
    ResolverToolMissing,
    TlsCertReader,
)
from infrastructure.rogue_dhcp_repository import SqliteRogueDhcpRepository
from infrastructure.scanning.arp_table import ArpTableAdapter
from infrastructure.scanning.fritz_detail import FritzDetailAdapter
from infrastructure.scanning.fritz_hosts import FritzAuthError, FritzHostsAdapter
from infrastructure.scanning.host_discovery import HostDiscoveryAdapter
from infrastructure.scanning.hostname_resolver import HostnameResolverAdapter
from infrastructure.scanning.ipv6_enrichment import Ipv6EnrichmentAdapter
from infrastructure.scanning.mdns import MdnsAdapter
from infrastructure.scanning.port_scanner import PortScannerAdapter
from infrastructure.scanning.scan_history import CorruptScanError, SqliteScanHistoryRepository
from infrastructure.scanning.ssdp import SsdpAdapter
from infrastructure.scanning.vendor_lookup import VendorLookupAdapter
from infrastructure.scheduler_jobs_db import SqliteScheduledJobRepository
from infrastructure.secret_store import KeyringSecretStore, SecretStoreUnavailableError
from infrastructure.security import (
    CveLookupAdapter,
    DefaultCredsCheckerAdapter,
    SqliteArpGuardRepository,
    TlsInspectorAdapter,
)
from infrastructure.settings_repository import CorruptSettingError, SqliteSettingsRepository
from infrastructure.sni.errors import SniError
from infrastructure.sni.sni_sniffer import ScapySniSniffer
from infrastructure.traffic_linux import PsutilTrafficAdapter
from infrastructure.traffic_permission import TrafficPermissionAdapter

# ── ÜBERGANGS-KRÜCKE P2.1b: Bootstrap-Init aus dem Altcode (modules/) ──────────
# app.py ist Bootstrap-Owner und ruft die Init-/Teardown-Funktionen der noch
# nicht migrierten Domaenen (monitoring, scheduler, sla, alerting, agent,
# devices) UEBERGANGSWEISE direkt aus modules/ auf. Diese Importe sind bewusst
# nur hier erlaubt (Composition Root, nicht vom import-linter analysiert); ein
# Guardrail-Contract verbietet den Ringen jeden modules/-Import. Jede Gruppe
# faellt weg, sobald die jeweilige Domaene migriert ist.
from modules.alerting import init_alerts_db
from modules.devices_db import init_devices_db
from modules.storage import init_db
from ports.alerting import AlertNotifierPort, SmtpConfigPort
from ports.cve import InventoryHost, InventoryPort, LookupCve
from ports.scheduler import JobHandler
from ports.security import PortQuery
from ports.settings import SettingsRepository
from ws_monitor import make_ws_monitor
from ws_pcap import make_ws_pcap
from ws_scan import make_ws_scan

logger = structlog.get_logger()


# ── Lokale Bootstrap-Helfer (aus main.py hochgezogen, NICHT aus main importiert) ──


def _check_version_upgrade() -> None:
    """Schreibt die Version-Markierung; Settings bleiben ueber Upgrades erhalten (wie main.py)."""
    from modules.db_path import DATA_DIR

    version_file = Path(DATA_DIR) / ".version"
    try:
        old_version = version_file.read_text().strip() if version_file.exists() else ""
    except OSError:
        old_version = ""
    if old_version != APP_VERSION:
        if old_version:
            logger.info("version_upgrade", old=old_version, new=APP_VERSION)
        version_file.write_text(APP_VERSION)


async def _scheduled_scan(cidr: str, profile_id: str, schedule_id: int) -> None:
    # Bewusste Abweichung von main.py: die dortige Profil-/`config`-Maschinerie war
    # toter Code (das berechnete `config` wurde nie genutzt -- discover_subnet nimmt
    # nur `cidr`) und barg einen latenten KeyError bei fehlendem "standard"-Profil.
    # Hier nur das beobachtbare Verhalten: Subnetz scannen, Ergebnis speichern.
    from modules.discovery import discover_subnet
    from modules.storage import save_scan

    logger.info("scheduled_scan", cidr=cidr, profile=profile_id)
    discovered = await discover_subnet(cidr, max_concurrent=64, timeout=1.0)
    save_scan(cidr, [{"ip": h.ip, "mac": h.mac, "rtt_ms": h.rtt_ms} for h in discovered])


# ── FritzBox-Hosts: Verdrahtungs-Wrapper (best-effort, S.7c) ──────────────────


class _FritzHostsWiring:
    """Verdrahtungs-Wrapper um den ``FritzHostsAdapter`` -- erfuellt ``FritzHostsPort``.

    Buendelt zwei Verdrahtungs-Entscheidungen (S.7c) an EINER Stelle, damit der
    ``RunNetworkScan``-Use-Case immer mit einem 10. Port baubar bleibt und Fritz
    sauber best-effort ist:

    * **Nicht konfiguriert** (kein ``fritz_host`` / kein ``fritz_password``): gar
      keinen echten Adapter bauen -> ``[]`` ohne TR-064-Verbindungsversuch
      (Entscheidung 2A, expliziter Null-Pfad statt Adapter mit leerem host, der
      in einen Verbindungs-Timeout liefe).
    * **Auth-Fehler** (falsche Credentials): ``FritzAuthError`` des echten Adapters
      wird HIER zu ``[]`` gefangen UND geloggt (Entscheidung 3C). Fritz ist
      optional -- ein Credential-Tippfehler darf NICHT den ganzen Scan abbrechen
      (anders als nmap, ein angeforderter Scan-Modus). Das Logging ist PFLICHT:
      ein verschluckter Auth-Fehler ohne Spur waere ein stiller Fallback (S3); mit
      Warn-Log ist es dokumentierte best-effort-Semantik.

    Der Use-Case sieht so nie eine ``FritzAuthError`` -- der Schichtungs-Vertrag
    (application kennt nicht infrastructure) bleibt unberuehrt: der Fang sitzt im
    Composition Root (app.py ist von den import-linter-Contracts ausgenommen).
    """

    def __init__(self, host: str, user: str, password: str) -> None:
        # Echter Adapter nur, wenn host UND password gesetzt sind (wie der Altcode:
        # Merge nur bei ``fritz_host AND fritz_pass``). Sonst Null-Pfad.
        self._adapter = (
            FritzHostsAdapter(host=host, user=user, password=password)
            if host and password
            else None
        )

    async def get_hosts(self) -> list[Any]:
        if self._adapter is None:
            return []  # nicht konfiguriert -> leerer Merge, kein Verbindungsversuch
        try:
            return await self._adapter.get_hosts()
        except FritzAuthError as exc:
            # best-effort: Auth-Fehler killt den Scan nicht -- aber GELOGGT (kein S3).
            logger.warning("fritz_auth_failed", host=exc.host)
            return []


class _FritzDetailWiring:
    """Verdrahtungs-Wrapper um den ``FritzDetailAdapter`` -- erfuellt ``FritzDetailPort``.

    Uebersetzt die ``infrastructure``-``FritzAuthError`` des echten Adapters in den
    application-eigenen ``FritzDetailAuthError`` (Muster wie ``_FritzHostsWiring``:
    eine kleine Verdrahtungs-Klasse, die einen Port strukturell erfuellt). Diese
    Uebersetzung MUSS im Composition Root passieren -- er ist von den import-linter-
    Contracts ausgenommen und darf beide Typen kennen; so kann der api-Ring den
    Auth-Fehler als reinen application-Typ fangen, ohne ``infrastructure`` zu
    importieren.

    Anders als ``_FritzHostsWiring`` wird der Auth-Fehler hier NICHT verschluckt:
    der Detail-Endpunkt ist ein expliziter Lese-Pfad (REST), kein best-effort-Merge
    -- der Fehler propagiert (als application-Typ) bis in den Router (502).
    """

    def __init__(self, host: str, user: str, password: str) -> None:
        self._adapter = FritzDetailAdapter(host=host, user=user, password=password)

    async def get_detail(self) -> Any:
        try:
            return await self._adapter.get_detail()
        except FritzAuthError as exc:
            raise FritzDetailAuthError(exc.host) from exc


class _CompositeRuleProvider:
    """Kombiniert mehrere ``RuleProvider`` ADDITIV -- erfuellt selbst den RuleProvider-Port.

    A.2-Verdrahtung: die analysis-Engine soll die eingebauten ``DEFAULT_RULES`` UND die
    benutzer-eigenen, gespeicherten Regeln sehen. Diese additive Kombination lebt HIER im
    Composition Root (nicht im DB-Adapter -- jeder Adapter bleibt sortenrein) als kleiner
    Wrapper-Provider, Muster wie ``_FritzHostsWiring``/``_MonitorAlertRaiser``: eine kleine
    Verdrahtungs-Klasse, die einen Port (``ports.analysis.RuleProvider``) strukturell
    erfuellt.

    ``get_rules`` konkateniert die Regeln der gehaltenen Provider IN REIHENFOLGE (Defaults
    zuerst, dann DB). Es kombiniert die PROVIDER, nicht rohe Listen -- der
    ``BuiltinRuleProvider`` liefert die Defaults schon, der ``SqliteUserRuleRepository`` die
    gespeicherten. Ohne gespeicherte Regeln liefert er exakt die Defaults (additiv: ein
    leerer User-Store aendert das Verhalten nicht).
    """

    def __init__(self, *providers: BuiltinRuleProvider | SqliteUserRuleRepository) -> None:
        self._providers = providers

    def get_rules(self) -> tuple[Rule, ...]:
        return tuple(rule for provider in self._providers for rule in provider.get_rules())


# Settings-Key fuer die Deaktivierungs-Liste (JSON-Array von rule_id-Strings).
_DISABLED_RULES_KEY = "analysis_disabled_rules"


def _read_disabled_rule_ids(settings: SettingsRepository) -> frozenset[str]:
    """Liest die Menge deaktivierter rule_ids defensiv aus den Settings.

    Eine freie Funktion, weil zwei Stellen im Composition Root die EXAKT gleiche
    disabled-Semantik brauchen: der ``_FilteredRuleProvider`` (filtert die Regeln fuer
    die Engine heraus) und der ``/api/analysis/rules/all``-Runner (ADR 0028, der die
    deaktivierten Regeln gerade NICHT filtert, sondern sie mit ``disabled: true``
    markiert, damit die UI sie wieder einschalten kann). Eine gemeinsame Quelle
    garantiert, dass beide dieselbe Menge sehen.

    Defensiver Leer-Zustand (S3-konform): fehlender Key ODER Nicht-Listen-Wert ->
    ``frozenset()`` ("nichts deaktiviert"). Kaputtes JSON (``CorruptSettingError``) ->
    GELOGGTE Warnung + derselbe fail-safe-Rueckfall "nichts deaktiviert" -- eine kaputte
    Komfort-Einstellung darf NICHT den Scan faellen und niemanden heimlich abschalten;
    der Fehler wird benannt/geloggt, nicht still verschluckt. Nicht-String-Eintraege
    werden uebersprungen.
    """
    try:
        setting = settings.get(_DISABLED_RULES_KEY)
    except CorruptSettingError:
        # Kaputter JSON-Wert: GELOGGT (kein stiller Fallback, S3) und fail-safe
        # auf "nichts deaktiviert" zurueck -- der Filter darf den Scan nicht faellen.
        logger.warning("analysis_disabled_rules_corrupt", key=_DISABLED_RULES_KEY)
        return frozenset()
    if setting is None or not isinstance(setting.value, list):
        # Fehlender Key (frische DB ist normal -> kein Log) oder Nicht-Listen-Wert:
        # gueltiger Leer-Zustand "nichts deaktiviert".
        return frozenset()
    # Nur String-Eintraege als rule_id; kaputte Nicht-String-Eintraege ueberspringen.
    return frozenset(x for x in setting.value if isinstance(x, str))


# Defaults der cve-Domaene (ADR 0037): Auffrisch-Intervall 24h (Fall 3; 0 = aus), Scan-
# Intervall 20s (Drosselung; der NVD-sleep(0.6) kommt obendrauf). Im Composition Root, weil
# die Settings-Auswertung hier lebt -- die Domaene/Application tragen ihre eigenen Defaults
# (DEFAULT_REFRESH_INTERVAL_HOURS / DEFAULT_SCAN_INTERVAL_SECONDS) fuer den direkten Gebrauch.
_CVE_DEFAULT_REFRESH_HOURS = 24
_CVE_DEFAULT_SCAN_SECONDS = 20

# Default-Schwelle (Tage) fuer die Archivierungs-Nachfrage: lange nicht gesehene
# Geraete werden ab hier als Kandidaten vorgeschlagen. Vom Setting
# ``device_archive_prompt_days`` ueberschreibbar (s. _read_device_int_setting).
_DEVICE_ARCHIVE_PROMPT_DEFAULT_DAYS = 30


def _read_cve_int_setting(settings: SettingsRepository, key: str, default: int) -> int:
    """Liest einen ganzzahligen cve-Setting-Wert defensiv (S3-konform).

    Fehlender Key (frische DB ist normal -> kein Log) ODER Nicht-Zahl-Wert -> ``default``.
    Kaputtes JSON (``CorruptSettingError``) -> GELOGGTE Warnung + ``default`` (eine kaputte
    Komfort-Einstellung darf den Worker nicht faellen; der Fehler wird benannt, nicht still
    verschluckt). Bools werden ausgeschlossen (``True`` ist in Python ein int-Subtyp, aber
    als Intervall-Wert sinnlos). Negative Werte werden auf 0 geklemmt (0 = Fall 3 aus bzw.
    minimal-Intervall) -- kein negativer sleep/Intervall.
    """
    try:
        setting = settings.get(key)
    except CorruptSettingError:
        logger.warning("cve_setting_corrupt", key=key)
        return default
    if setting is None:
        return default
    value = setting.value
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(0, value)


def _read_device_int_setting(settings: SettingsRepository, key: str, default: int) -> int:
    """Liest einen ganzzahligen devices-Setting-Wert defensiv (S3-konform).

    Eigener Helfer statt ``_read_cve_int_setting`` wiederzuverwenden: der cve-Helfer
    loggt mit dem festen Marker ``cve_setting_corrupt`` und gehoert fachlich zur
    cve-Domaene -- hier wird mit ``device_setting_corrupt`` geloggt. Verhalten sonst
    identisch: fehlender Key (frische DB ist normal -> kein Log) ODER Nicht-Zahl-Wert
    -> ``default``; kaputtes JSON (``CorruptSettingError``) -> GELOGGTE Warnung +
    ``default`` (eine kaputte Komfort-Einstellung darf nicht faellen); Bools
    ausgeschlossen (``True`` ist int-Subtyp, als Schwelle sinnlos); negative Werte auf
    0 geklemmt.
    """
    try:
        setting = settings.get(key)
    except CorruptSettingError:
        logger.warning("device_setting_corrupt", key=key)
        return default
    if setting is None:
        return default
    value = setting.value
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(0, value)


class _FilteredRuleProvider:
    """Filtert deaktivierte Regel-IDs aus einem inneren ``RuleProvider`` heraus.

    ADR 0023: Built-in- und User-Regeln sollen per Settings abschaltbar sein, OHNE die
    Regeln im Code anzufassen (Konfiguration = reine Daten). Die Deaktivierungs-Liste
    liegt als Settings-Wert (``analysis_disabled_rules``, JSON-Array von ``rule_id``-
    Strings) und wird ueber den ``SettingsRepository``-Port gelesen. Dieser Wrapper lebt
    -- wie ``_CompositeRuleProvider`` -- HIER im Composition Root und erfuellt selbst
    strukturell ``ports.analysis.RuleProvider`` (``get_rules() -> tuple[Rule, ...]``).

    Defensiver Leer-Zustand: fehlender Key ODER Nicht-Listen-Wert -> ``frozenset()``
    ("nichts deaktiviert, alle Regeln an"). Kaputtes JSON (``CorruptSettingError``)
    -> geloggte Warnung + derselbe fail-safe-Rueckfall "alle Regeln an" -- der Filter
    ist ein Nebenpfad in der Analyse, eine kaputte Komfort-Einstellung darf NICHT den
    ganzen Scan faellen. Die fail-safe-Richtung ist "mehr zeigen, nichts heimlich
    unterdruecken"; der Fehler wird benannt/geloggt, nicht still verschluckt (S3-konform).
    """

    def __init__(
        self,
        inner: "_CompositeRuleProvider | _ConfiguredRuleProvider",
        settings: SqliteSettingsRepository,
    ) -> None:
        self._inner = inner
        self._settings = settings

    def get_rules(self) -> tuple[Rule, ...]:
        # Gemeinsame defensive Lese-Quelle mit dem /rules/all-Runner (ADR 0028).
        disabled = _read_disabled_rule_ids(self._settings)
        return tuple(rule for rule in self._inner.get_rules() if rule.id not in disabled)


# Settings-Keys fuer die per-Setting konfigurierbaren Regel-Parameter (ADR 0027).
# Schwelle (Integer) + zwei Portlisten (JSON-Array von Integern). Die Built-in-Defaults
# leben unveraendert in ``domain.analysis.rules``; ein gesetzter, wohlgeformter Wert
# UEBERSCHREIBT den jeweiligen Regel-Parameter (dataclasses.replace), sonst greift der
# Built-in-Default.
_PORT_COUNT_THRESHOLD_KEY = "analysis_port_count_threshold"
_SUSPICIOUS_PORTS_KEY = "analysis_suspicious_ports"
_CRITICAL_PORTS_KEY = "analysis_critical_ports"

# Default-Schwelle der ``host_many_high_ports``-Regel (gespiegelt aus rules.py als
# fail-safe-Rueckfall, wenn das Setting fehlt/kaputt ist). Bewusst hier als benannte
# Konstante: der Composition Root liest defensiv, die Domaene bleibt die Quelle der
# eigentlichen Built-in-Regel.
_PORT_COUNT_THRESHOLD_DEFAULT = 10

# Built-in-Regel-IDs, deren Parameter konfigurierbar sind (ADR 0027). Stabil -- der
# Deaktivierungs-Filter und spaetere Acknowledge-Historie referenzieren diese IDs.
_PORT_COUNT_RULE_ID = "host_many_high_ports"
_SUSPICIOUS_RULE_ID = "host_remote_access_port"
_CRITICAL_RULE_ID = "host_backdoor_port"


class _ConfiguredRuleProvider:
    """Ueberschreibt konfigurierbare Built-in-Regel-Parameter aus den Settings (ADR 0027).

    Drei Parameter sind per Setting aenderbar, OHNE die Built-in-Regeln im Code anzufassen
    (Konfiguration = reine Daten, gleiche Linie wie ADR 0023):

    * ``analysis_port_count_threshold`` (Integer) -> ``threshold`` der Regel
      ``host_many_high_ports``.
    * ``analysis_suspicious_ports`` (JSON-Array von Integern) -> ``ports`` der Regel
      ``host_remote_access_port`` (datengetriebene auffaellig-Regel).
    * ``analysis_critical_ports`` (JSON-Array von Integern) -> ``ports`` der Regel
      ``host_backdoor_port`` (kritisch).

    Wie ``_CompositeRuleProvider``/``_FilteredRuleProvider`` ein kleiner Wrapper-Provider
    HIER im Composition Root, der strukturell ``ports.analysis.RuleProvider`` erfuellt
    (``get_rules() -> tuple[Rule, ...]``). Er aendert KEINE Domaene und KEINE Engine: er
    erzeugt per ``dataclasses.replace`` eine Kopie der betroffenen Default-Regel mit
    ueberschriebenem Parameter und reicht alle anderen Regeln unveraendert durch -- ein
    leeres Override-Set laesst jede Regel exakt wie gebaut.

    Defensiver Leer-Zustand (S3-konform, gleiche Linie wie ``_disabled_rule_ids``):
    fehlender Key / falscher Typ -> Built-in-Default (kein Log, frische DB ist normal);
    kaputtes JSON (``CorruptSettingError``) -> GELOGGTE Warnung + Built-in-Default. Eine
    kaputte Komfort-Einstellung darf den Scan NICHT faellen. Ein leeres Array ist ein
    GUELTIGER Wert (= "diese Regel trifft nichts"), kein Rueckfall auf den Default.
    """

    def __init__(
        self,
        inner: _CompositeRuleProvider,
        settings: SettingsRepository,
    ) -> None:
        self._inner = inner
        self._settings = settings

    def _port_count_threshold(self) -> int:
        """Liest die Schwelle defensiv (fehlt/falscher Typ -> Default; kaputt -> Log+Default)."""
        try:
            setting = self._settings.get(_PORT_COUNT_THRESHOLD_KEY)
        except CorruptSettingError:
            logger.warning("analysis_port_count_threshold_corrupt", key=_PORT_COUNT_THRESHOLD_KEY)
            return _PORT_COUNT_THRESHOLD_DEFAULT
        # bool ist Subtyp von int -- ``True``/``False`` waeren ein versehentlicher
        # Schwellenwert; explizit ausschliessen (nur echte Integer zaehlen).
        if setting is None or not isinstance(setting.value, int) or isinstance(setting.value, bool):
            return _PORT_COUNT_THRESHOLD_DEFAULT
        return setting.value

    def _ports_override(self, key: str) -> frozenset[int] | None:
        """Liest eine Portliste defensiv. ``None`` = kein Override (Built-in-Default greift).

        Vorhanden + Liste (auch leer) -> ``frozenset`` der Integer-Eintraege (ein leeres
        Array ergibt ``frozenset()`` = gueltiger "trifft nichts"-Zustand). Fehlt / falscher
        Typ -> ``None`` (Built-in-Default). Kaputtes JSON -> geloggte Warnung + ``None``.
        Nicht-Integer-Eintraege (inkl. ``bool``) werden uebersprungen, wie der
        Deaktivierungs-Filter kaputte rule_id-Eintraege ueberspringt.
        """
        try:
            setting = self._settings.get(key)
        except CorruptSettingError:
            logger.warning("analysis_ports_setting_corrupt", key=key)
            return None
        if setting is None or not isinstance(setting.value, list):
            return None
        return frozenset(x for x in setting.value if isinstance(x, int) and not isinstance(x, bool))

    def get_rules(self) -> tuple[Rule, ...]:
        threshold = self._port_count_threshold()
        suspicious = self._ports_override(_SUSPICIOUS_PORTS_KEY)
        critical = self._ports_override(_CRITICAL_PORTS_KEY)
        configured: list[Rule] = []
        for rule in self._inner.get_rules():
            if rule.id == _PORT_COUNT_RULE_ID:
                configured.append(replace(rule, threshold=threshold))
            elif rule.id == _SUSPICIOUS_RULE_ID and suspicious is not None:
                configured.append(replace(rule, ports=suspicious))
            elif rule.id == _CRITICAL_RULE_ID and critical is not None:
                configured.append(replace(rule, ports=critical))
            else:
                configured.append(rule)
        return tuple(configured)


def _build_configured_provider(
    rules: SqliteUserRuleRepository,
    settings: SettingsRepository,
) -> _ConfiguredRuleProvider:
    """Baut den Provider-Stack Composite -> Configured (ADR 0029, Single Source).

    Die Kette ``_CompositeRuleProvider(BuiltinRuleProvider(), <User-Regeln>)`` umschlossen
    vom ``_ConfiguredRuleProvider`` (5a-Injektion von Schwelle/Portlisten, ADR 0027) lag
    HEUTE zweimal inline im Composition Root (im ``_analyze_snapshot`` MIT zusaetzlichem
    Filter, im ``/rules/all``-Runner OHNE Filter). Diese freie Funktion ist nun die EINE
    Quelle dieser Kette -- semantisch identisch zu den beiden alten Inline-Stellen, kein
    Verhaltenswechsel. ``rules`` ist der User-Regel-Store, ``settings`` die Settings-Quelle
    fuer die konfigurierbaren Parameter (beide werden vom Aufrufer als frische Repo-Instanz
    hereingereicht -- die Verdrahtung bleibt im Composition Root).
    """
    composite = _CompositeRuleProvider(BuiltinRuleProvider(), rules)
    return _ConfiguredRuleProvider(composite, settings)


def _build_filtered_provider(
    rules: SqliteUserRuleRepository,
    settings: SqliteSettingsRepository,
) -> _FilteredRuleProvider:
    """Baut den vollen Provider-Stack Composite -> Configured -> Filtered (ADR 0029).

    Die gefilterte Variante (zusaetzlich der ``_FilteredRuleProvider``, der per Setting
    abgeschaltete Regel-IDs herausnimmt, ADR 0023) -- der Stack, den die ENGINE sieht. Baut
    auf ``_build_configured_provider`` auf, damit die gemeinsame Composite->Configured-Kette
    Single Source bleibt. Genutzt von ``_analyze_snapshot`` (Engine-Pfad) und der WS-
    Severity-Verdrahtung; der ``/rules/all``-Runner nutzt bewusst die UNGEFILTERTE Variante
    (er muss deaktivierte Regeln weiter sehen, um sie wieder einschaltbar zu machen).
    """
    return _FilteredRuleProvider(_build_configured_provider(rules, settings), settings)


def _observed_host(host: EnrichedHost, is_known: bool) -> ObservedHost:
    """Projiziert einen scanning-``EnrichedHost`` auf analysis' ``ObservedHost`` (ADR 0029).

    Die frueher im ``_analyze_snapshot`` inline gebaute Projektion -- jetzt EINE Quelle, von
    der DB-Historie-Schleife (Bulk, GET /api/analysis) UND der Live-Host-Severity (WS-Loop)
    genutzt. ``open_ports`` sind die Portnummern mit ``state == "open"`` (BEWUSST nur die
    Nummern, kein ``PortInfo`` -- independence-Contract). ``is_known`` wird vom Aufrufer
    bestimmt und hereingereicht (Bulk: aus dem ``known_macs``-Bulk-Read; WS: der schon vor
    ``record_seen`` gelesene ``baseline_known``) -- die Projektion liest KEINE Historie.
    """
    return ObservedHost(
        ip=host.ip,
        hostname=host.hostname,
        vendor=host.vendor,
        open_ports=frozenset(p.port for p in host.ports if p.state == "open"),
        is_known=is_known,
    )


def _severity_for_host(
    host: EnrichedHost,
    is_known: bool,
    analyze: AnalyzeSnapshot,
    acked: frozenset[int] = frozenset(),
) -> Severity | None:
    """Hoechste Achse-B-Severity EINES Live-Hosts gegen die konfigurierten Regeln (ADR 0029).

    Baut einen Ein-Host-``Snapshot`` (nur ``hosts`` belegt, ``connections``/``processes``
    leer, ``full_process_visibility`` auf dem Snapshot-Default ``False`` -- der Host-Pfad
    haengt nicht an der Prozess-Sicht), laesst die injizierte ``AnalyzeSnapshot`` (mit dem
    GEFILTERTEN Provider) darueber laufen und nimmt die hoechste Severity der
    HOST-Beobachtungen (``kind`` beginnt mit ``host_`` -- die Host-RuleKinds aus
    ``domain.analysis.rules.RuleKind``: host_remote_port/host_new/host_port_count).

    ``"info"`` ist KEINE Auffaelligkeit (Achse B kennt nur ``"critical"``/``"notable"``):
    bei nur info-/keinen Host-Befunden -> ``None``. Die Rangfolge kommt aus
    ``_SEVERITY_RANK`` (``"critical"`` < ``"notable"`` < ``"info"``) -- kleinster Rang
    gewinnt. Hosts ohne ``ip`` werden uebersprungen (kein bewertbares Subjekt) -> ``None``.

    ``acked`` (ADR 0031): die QUITTIERTEN Ports dieses Hosts werden VOR dem Engine-Lauf
    aus dem bewerteten Portstand entfernt -- ein quittierter Port traegt nicht mehr zur
    Severity bei. Die "offen"-Projektion bleibt ansonsten identisch (``_observed_host``
    selbst unveraendert); nur die fuer die BEWERTUNG sichtbare Portmenge wird reduziert.
    Default leer -> kein Verhaltenswechsel fuer Bestandsaufrufer.
    """
    if not host.ip:
        return None
    observed = _observed_host(host, is_known)
    if acked:
        observed = replace(observed, open_ports=observed.open_ports - acked)
    snapshot = Snapshot(hosts=(observed,))
    resolved = analyze(snapshot)
    host_severities = [
        r.observation.severity
        for r in resolved
        if r.observation.kind.startswith("host_") and r.observation.severity != "info"
    ]
    if not host_severities:
        return None
    return min(host_severities, key=lambda sev: _SEVERITY_RANK[sev])


# Achse-B-Severity-Stufen, in denen flagged_ports gruppiert werden (ADR 0030). NUR
# "critical"/"notable" -- "info" ist KEINE Auffaelligkeit (gleiche Linie wie
# _severity_for_host, das info ausfiltert). Stabile, leere Default-Form des Felds: jede
# Stufe ist IMMER vorhanden, leere Stufe = []. Diese Liste ist die EINE Quelle dafuer,
# welche Stufen das Feld kennt -- der Frame-Default in ws_scan spiegelt sie.
_FLAGGED_SEVERITIES: tuple[Severity, ...] = ("critical", "notable")

# RuleKind der portbasierten Achse-B-Regeln (ADR 0030). NUR diese tragen zu flagged_ports
# bei: sie halten eine konkrete ``ports``-Menge, deren Schnitt mit den offenen Host-Ports
# die "schuldigen" Ports liefert. host_port_count (anzahlbasiert) + host_new (kein Port)
# faerben bewusst KEINEN einzelnen Port -- sie bleiben Teil von analysis_severity, tragen
# aber nicht zu flagged_ports bei (siehe ADR 0030).
_PORT_BASED_KIND = "host_remote_port"


def _empty_flagged_ports() -> dict[str, list[int]]:
    """Leere flagged_ports-Form (ADR 0030): jede Achse-B-Stufe vorhanden, leere Liste.

    EINE Quelle der Default-Form -- genutzt vom Hosts-ohne-ip-Pfad in
    ``_flagged_ports_for_host`` UND (gespiegelt) vom Frame-Default in ws_scan. So bleibt das
    Feld-Schema konsistent: ``{"critical": [], "notable": []}``.
    """
    return {sev: [] for sev in _FLAGGED_SEVERITIES}


def _flagged_ports_for_host(
    host: EnrichedHost, provider: Any, acked: frozenset[int] = frozenset()
) -> dict[str, list[int]]:
    """Die konkret getroffenen offenen Ports EINES Live-Hosts je Achse-B-Stufe (ADR 0030).

    Zweites Achse-B-Feld neben ``analysis_severity`` (0029, Host-Maximum). Waehrend die
    Severity das Host-MAXIMUM traegt, traegt dieses Feld die MENGE der "schuldigen" Ports
    pro Stufe -- damit das Frontend (Schnitt 6b) die betroffenen Port-Boeppel einfaerben
    kann. Form: ``{"critical": [...], "notable": [...]}`` (sortierte Integer-Listen, leere
    Stufe = ``[]``).

    Die getroffene Portmenge ist der MENGENSCHNITT ``open & rule.ports`` -- NICHT das Parsen
    des Observation-detail-Strings (Format-Kopplung waere fragil). ``open`` wird mit DEMSELBEN
    Ausdruck wie ``_observed_host`` gebildet (Ports mit ``state == "open"``), keine zweite
    Definition von "offen". Iteriert wird ueber ``provider.get_rules()`` -- den GEFILTERTEN
    Provider, denselben, den ``_severity_for_host`` ueber die Engine sieht (Single Source);
    nur ``kind == "host_remote_port"``-Regeln tragen bei, nach ``rule.severity`` (Union ueber
    mehrere Regeln gleicher Stufe) gesammelt. ``host_port_count``/``host_new`` faerben keinen
    Port und tragen bewusst NICHT bei (siehe ADR 0030).

    ``acked`` (ADR 0031): die QUITTIERTEN Ports werden VOR der Schnittbildung aus ``open``
    entfernt -- ein quittierter Port wird nicht mehr geflaggt. SELBE Reduktion wie in
    ``_severity_for_host`` (beide ziehen ``acked`` vom selben "offen"-Stand ab), damit die
    KONSISTENZ-Invariante zu ``analysis_severity`` haelt. Default leer -> kein
    Verhaltenswechsel fuer Bestandsaufrufer.

    Host ohne ``ip`` -> leere Form (kein bewertbares Subjekt, gleiche Linie wie
    ``_severity_for_host``). Das haelt die KONSISTENZ-Invariante zu ``analysis_severity``:
    beide kommen aus demselben Provider und derselben "offen"-Projektion, duerfen nicht
    auseinanderlaufen.
    """
    if not host.ip:
        return _empty_flagged_ports()
    open_ports = {p.port for p in host.ports if p.state == "open"} - acked
    flagged: dict[str, set[int]] = {sev: set() for sev in _FLAGGED_SEVERITIES}
    for rule in provider.get_rules():
        if rule.kind != _PORT_BASED_KIND or rule.severity not in flagged:
            continue
        flagged[rule.severity] |= open_ports & rule.ports
    return {sev: sorted(ports) for sev, ports in flagged.items()}


# ── monitoring -> alerting-Trigger-Naht (A.7a) ────────────────────────────────
# Der erste echte VERHALTENS-Change der alerting-Migration: ab hier feuert RaiseAlert
# real, wenn der monitor-Loop eine up/down-Flanke erkennt (alert_history wird
# beschrieben, Alerts gehen je Nutzer-Regel raus). Die Naht lebt HIER im Composition
# Root -- nicht in infrastructure -- weil sie BEIDE Domaenen kennt: sie liest ein
# domain/monitoring.MonitorEvent UND ruft den application/alerting.RaiseAlert-Use-Case.
# Ein infrastructure-Adapter duerfte application NICHT importieren (Contract
# "infrastructure kennt nicht application"); app.py ist als Composition Root von den
# import-linter-Contracts ausgenommen und der einzige erlaubte Ort. Muster wie
# _scheduled_scan (M.6-ScanTriggerCallback) und _FritzHostsWiring: eine kleine
# Verdrahtungs-Klasse, die einen Port strukturell erfuellt.

# Der Alert-Message-Wortlaut, dupliziert aus MonitorNotifierAdapter._MESSAGES (infra).
# Bewusst Option (i): View-Vokabular ("{label} is DOWN"/"is back UP") gehoert nicht in
# die Domaene (models.py VIEW-Prinzip). Die Duplikation ist als VERTRAG abgesichert --
# ein Test (test_alert_message_wording_matches_notifier) nagelt fest, dass dieses Dict
# zeichengleich mit dem Notifier-Dict ist, sonst liefen Notification-Text und
# alert_history-message kuenftig still auseinander. GLEICHE FORM wie _MESSAGES
# (dict[MonitorEventType, str] mit {label}-Template), damit der Test schlicht == prueft.
_ALERT_MESSAGES: dict[MonitorEventType, str] = {
    MonitorEventType.DOWN: "{label} is DOWN",
    MonitorEventType.UP: "{label} is back UP",
}


class _MonitorAlertRaiser:
    """Verdrahtungs-Wrapper, der ``AlertRaiserPort`` erfuellt -- mappt MonitorEvent -> RaiseAlert.

    Haelt den ``RaiseAlert``-Use-Case und uebersetzt das durchgereichte
    ``MonitorEvent`` in den alerting-Aufruf (DF2-Mapping, A.7a):

    * ``rule_type = "host_down"`` fuer BEIDE Flanken (down UND up) -- eine
      Nutzer-Regel mit Typ ``host_down`` faengt beide Richtungen; ein eigener
      rule_type fuer ``up`` wuerde nie eine existierende Regel matchen (toter Strang).
    * ``target = event.target_id`` -- der stabile/semantische Target-Bezeichner
      (= Frontend-Target-Kennung), gegen den die Regel mit ``target`` exakt oder
      ``"any"`` matcht.
    * ``message`` aus ``_ALERT_MESSAGES`` -- exakt der Notifier-Wortlaut (Vertrag, s.o.).

    BEST-EFFORT (Port-Vertrag, EXAKT wie der MonitorNotifierAdapter): faengt JEDEN
    Fehler des Use-Cases und loggt ihn -- wirft NIE in den Loop. So bleibt die
    raise_alert-Konsequenz von der notify-Konsequenz isoliert (keine kann die andere
    verschlucken), ohne dass der RunMonitor-Use-Case ein try/except braucht.
    """

    def __init__(self, raise_alert: RaiseAlert) -> None:
        self._raise_alert = raise_alert

    async def raise_alert(self, event: MonitorEvent) -> None:
        template = _ALERT_MESSAGES.get(event.event)
        if template is None:
            # Nur up/down loesen einen Alert aus (should_notify filtert das im
            # Use-Case bereits auf genau diese zwei Flanken -- hier defensiv kein Ruf).
            return
        message = template.format(label=event.label)
        try:
            await self._raise_alert(
                rule_type="host_down",
                target=event.target_id,
                message=message,
            )
        except Exception:
            # Best-effort: nie ein Loop-Fehler. MIT Log (kein stiller S3-Fang).
            logger.warning("monitor_alert_raise_failed", target_id=event.target_id)


# ── Schwellwert-Alarm -> alerting-Notifier-Naht (Schnitt 3b) ──────────────────
# Die VIERTE Konsequenz-Naht des Monitorings, ganz analog zu _MonitorAlertRaiser:
# der Logging-Sink wertet pro Tick je aktiver Aufgabe ihren Schwellwert per
# evaluate_sample (Hysterese) aus und ruft bei einer Alarm-FLANKE den
# ThresholdNotifierPort. Dieser Wrapper mappt die rein monitoring-seitige Flanke
# (LoggingTask + LatencyThreshold + PingSample) auf den vorhandenen alerting-
# Notifier (Desktop + E-Mail). Die Naht lebt HIER im Composition Root -- nicht im
# Sink/infrastructure -- weil sie BEIDE Domaenen kennt: sie liest monitoring-Typen
# UND ruft den alerting-Notifier/SmtpConfig. Ein infrastructure-Adapter duerfte das
# nicht (Contract "monitoring kennt nicht alerting"); app.py ist als Composition
# Root von den import-linter-Contracts ausgenommen und der einzige erlaubte Ort.
# Muster wie _MonitorAlertRaiser: eine kleine Verdrahtungs-Klasse, die einen Port
# (ThresholdNotifierPort) strukturell erfuellt.


class _ThresholdNotifierWiring:
    """Verdrahtungs-Wrapper, der ``ThresholdNotifierPort`` erfuellt -- mappt Flanke -> Notifier.

    Haelt den vorhandenen alerting-``AlertNotifierAdapter`` (Desktop + E-Mail) und den
    ``SettingsSmtpConfigAdapter`` und uebersetzt eine frisch gefeuerte Schwellwert-Flanke
    in den/die gewuenschten Notification-Kanal/Kanaele (3b):

    * **Titel**: ``"CERNIS PRO — <label>"`` -- exakt der Stil des ``_MonitorAlertRaiser``-
      Umfelds bzw. der bestehenden Alert-Notifications (App-Name + Task-Label).
    * **Nachricht**: deutsch, nennt das Task-Label, die verletzte Bedingung
      (``LATENCY_ABOVE`` -> "Latenz ueber <limit_ms> ms"; ``UNREACHABLE`` -> "Ziel nicht
      erreichbar") und bei Latenz den Messwert (``sample.rtt_ms``). Reiner Notification-
      Text, KEINE i18n-Maschinerie.
    * **Desktop** (``threshold.notify_desktop``): ``notifier.macos(title, message,
      subtitle=task.label)`` -- ``subtitle`` aus dem Task-Label (wie der Notifier den
      target nutzt).
    * **E-Mail** (``threshold.notify_email``): ``smtp_config.load()``; NUR wenn das
      Ergebnis nicht ``None`` ist (konfiguriert), ``notifier.email(subject=title,
      body=message, config=cfg)``. Ist es ``None`` (keine SMTP-Config), wird KEINE Mail
      versucht -- kein Fehler, still uebersprungen, aber per ``structlog.info`` sichtbar.

    BEST-EFFORT (Port-Vertrag, EXAKT wie ``_MonitorAlertRaiser`` / der Sink): der GANZE
    Methodenkoerper steht in try/except -- jeder Fehler wird per ``structlog.warning``
    geloggt und NIE geworfen. Der Sink ruft uns best-effort, aber wir garantieren den
    Vertrag selbst (so kann ein Notify-Fehler weder den Sink-``record`` noch den
    Live-Loop killen).
    """

    def __init__(self, notifier: AlertNotifierPort, smtp_config: SmtpConfigPort) -> None:
        self._notifier = notifier
        self._smtp_config = smtp_config

    @staticmethod
    def _build_message(task: LoggingTask, threshold: LatencyThreshold, sample: PingSample) -> str:
        """Baut den deutschen Notification-Text aus Task/Threshold/Sample (reiner View-String)."""
        if threshold.condition is ThresholdCondition.UNREACHABLE:
            return f"{task.label}: Ziel nicht erreichbar."
        # LATENCY_ABOVE: verletzte Latenz-Bedingung + der ausloesende Messwert.
        return (
            f"{task.label}: Latenz ueber {threshold.limit_ms:g} ms (gemessen {sample.rtt_ms:g} ms)."
        )

    async def notify_threshold(
        self,
        task: LoggingTask,
        threshold: LatencyThreshold,
        sample: PingSample,
        now: float,
    ) -> None:
        title = f"CERNIS PRO — {task.label}"
        message = self._build_message(task, threshold, sample)
        try:
            if threshold.notify_desktop:
                await self._notifier.macos(title, message, subtitle=task.label)
            if threshold.notify_email:
                cfg = self._smtp_config.load()
                if cfg is None:
                    # Mail gewuenscht, aber keine SMTP-Config -> still uebersprungen,
                    # aber sichtbar (kein stiller S3-Fallback, kein Fehler).
                    logger.info("threshold_email_skipped_no_smtp", task_id=task.id)
                else:
                    await self._notifier.email(subject=title, body=message, config=cfg)
        except Exception:
            # Best-effort: nie ein Sink-/Loop-Fehler. MIT Log (kein stiller S3-Fang).
            logger.warning("threshold_notify_failed", task_id=task.id)


# ── RECURRING-Logging <-> Scheduler-Job-Naht (3b-3) ──────────────────────────
# Beim Anlegen eines RECURRING-Logging-Tasks soll automatisch der zugehoerige
# Scheduler-Job (job_type "monitoring_window") entstehen, beim Loeschen wieder
# verschwinden. Diese Naht lebt HIER im Composition Root -- nicht am
# provide_*-Override (ein loses Wrapper-Closure briche die ``Annotated[...,
# Depends]``-Signatur, mypy meckert), sondern als schmaler Erben-Wrapper, der den
# Use-Case-Vertrag STRUKTURELL durch Vererbung erfuellt (Muster wie die anderen
# Verdrahtungs-Wrapper, nur ueber Erbung statt Komposition, weil das Interface ein
# konkreter Use-Case-Typ ist). Beide Wrapper kennen monitoring UND scheduler --
# app.py ist als Composition Root von den import-linter-Contracts ausgenommen.


class _CreateLoggingTaskWithSchedule(CreateLoggingTask):
    """``CreateLoggingTask`` + Auto-Scheduler-Job fuer RECURRING-Tasks (3b-3).

    Erbt von ``CreateLoggingTask`` (erfuellt den Use-Case-Vertrag durch Vererbung) und
    haengt EINE Konsequenz an: legt der Nutzer einen RECURRING-Task an, entsteht der
    zugehoerige ScheduledJob (``job_type`` "monitoring_window") ueber ``CreateScheduledJob``.
    Der Job traegt in seinen ``params`` die ``task_id`` (damit der Handler den Task am Ende
    des Gesamtzeitraums beenden kann) und ``recur_until`` (als String, leer = unbegrenzt).
    Das ``DailyWindow`` baut sich aus den ``recur_*``-Feldern des frisch angelegten Tasks
    (None-Leerwerte auf die Domaenen-Leerform 0/0.0 gemappt -- der Task ist hier bereits
    RECURRING, also sind die Minuten gesetzt; die ``or``-Fallbacks sind nur mypy-Defensive).

    Bei jedem anderen Modus (IMMEDIATE/SCHEDULED) wird KEIN Job angelegt -- der Wrapper
    verhaelt sich dann exakt wie ``CreateLoggingTask``.
    """

    def __init__(self, repo: SqliteLoggingTaskRepository, create_job: CreateScheduledJob) -> None:
        super().__init__(repo)
        self._create_job = create_job

    def __call__(self, **kwargs: Any) -> LoggingTask:
        task = super().__call__(**kwargs)
        if task.operation_mode is OperationMode.RECURRING:
            window = DailyWindow(
                start_minute=task.recur_start_minute or 0,
                end_minute=task.recur_end_minute or 0,
                weekdays=task.recur_weekdays,
                from_epoch=task.recur_from or 0.0,
                until_epoch=task.recur_until or 0.0,
            )
            self._create_job(
                "monitoring_window",
                (
                    ("task_id", task.id),
                    ("recur_until", str(task.recur_until) if task.recur_until else ""),
                ),
                window,
            )
        return task


class _DeleteLoggingTaskWithUnschedule(DeleteLoggingTask):
    """``DeleteLoggingTask`` + Mitloeschen des zugehoerigen Scheduler-Jobs (3b-3).

    Gegenstueck zu ``_CreateLoggingTaskWithSchedule``: erbt von ``DeleteLoggingTask`` und
    raeumt nach dem Loeschen der Task-Definition den verwaisten ScheduledJob ab. Sucht ueber
    ``ListScheduledJobs`` den Job mit ``job_type == "monitoring_window"`` und ``task_id``-
    ``param`` gleich der geloeschten ``task_id`` und entfernt ihn via ``DeleteScheduledJob``.

    Idempotent wie der Basis-Use-Case: existiert kein passender Job (Task war nicht
    RECURRING oder schon abgeraeumt), passiert nichts -- kein Fehler.
    """

    def __init__(
        self,
        repo: SqliteLoggingTaskRepository,
        list_jobs: ListScheduledJobs,
        delete_job: DeleteScheduledJob,
    ) -> None:
        super().__init__(repo)
        self._list_jobs = list_jobs
        self._delete_job = delete_job

    def __call__(self, task_id: str) -> None:
        super().__call__(task_id)
        for job in self._list_jobs():
            if job.job_type == "monitoring_window" and dict(job.params).get("task_id") == task_id:
                self._delete_job(job.id)


# ── Frontend-Serving (traversal-sicher) ───────────────────────────────────────


def _resolve_frontend_dir(configured: str | None) -> Path | None:
    """Loest das frontend-dist-Verzeichnis auf.

    ``configured`` (CERNIS_FRONTEND_DIR / AppConfig.frontend_dir) hat Vorrang;
    fehlt es, dieselbe Suchreihenfolge wie main.py._find_frontend(). Erstes
    existierendes ``realpath`` gewinnt, sonst None (-> kein Frontend-Serving).
    """
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured))
    if hasattr(sys, "_MEIPASS"):  # PyInstaller-Bundle
        meipass = Path(sys._MEIPASS)
        exe_dir = Path(sys.executable).parent
        candidates += [
            meipass / "frontend-dist",
            exe_dir / "frontend-dist",
            exe_dir / ".." / "frontend-dist",
            meipass / ".." / "frontend-dist",
        ]
    here = Path(__file__).parent
    candidates += [
        here / ".." / "frontend-dist",
        here / "frontend-dist",
        here / ".." / "frontend" / "dist",
    ]
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.is_dir():
            return resolved
    return None


class _SpaStaticFiles(StaticFiles):
    """Traversal-sicheres SPA-Serving.

    Existierende Dateien liefert ``StaticFiles`` aus (containt von Haus aus gegen
    Path-Traversal); unbekannte Nicht-``api/``-/``ws/``-Pfade fallen auf
    ``index.html`` zurueck (fixer Pfad). KEINE Zeile konkateniert user-Input in
    einen Dateipfad -- genau das war die Altcode-Luecke (Finding S6).
    """

    async def get_response(self, path: str, scope: Scope) -> Response:
        # API/WS nicht auf index.html zurueckfallen lassen -> 404 (Sekundaer-
        # Absicherung; echte API-Routen matchen ohnehin vor diesem "/"-Mount).
        if path.lstrip("/").startswith(("api/", "ws/")):
            raise StarletteHTTPException(status_code=404)
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404:
                # SPA-Client-Route: index.html (fixer Pfad, sicherer StaticFiles-Lookup).
                return await super().get_response("index.html", scope)
            raise


# ── Sicherheitsbericht: PDF-Modell-Projektion (Etappe 4b, reine Funktion) ──────────────
# Projiziert den application-Typ ``SecurityReport`` (samt der zwei ehrlichen Statuswerte) auf
# das render-fertige ``SecurityPdfModel``. REIN und DETERMINISTISCH: KEINE Wanduhr -- das
# Erzeugungsdatum (``generated_at_text``) und das Rogue-Pruefdatum (``pruefdatum``) kommen als
# FERTIGE Strings herein (der Runner ``_security_report_pdf`` liest die Uhr GENAU EINMAL). Alle
# Texte werden HIER fertig formatiert (deutsche Sprache, Dezimalkomma); der reportlab-Adapter
# rendert sie nur. Modul-Ebene (nicht in ``create_app``), damit testbar ohne App-Bau.


def _format_burden_de(value: float) -> str:
    """Formatiert einen Lastwert deutsch (Dezimalkomma), schlicht und robust.

    Zwei Nachkommastellen, Punkt -> Komma; eine nachlaufende Null wird NUR entfernt, wenn die
    zweite Nachkommastelle 0 ist (1,00 -> "1,0"; 0,33 bleibt "0,33"). Mehr Kuerzung nicht --
    bewusst schlicht (Auftrag).
    """
    text = f"{value:.2f}".replace(".", ",")
    if text.endswith("0"):
        text = text[:-1]
    return text


def _pdf_severity_label(severity: str) -> str:
    """Mappt das rohe severity-Feld auf den Achse-B-Klartext ("kritisch"/"auffaellig").

    "critical" -> "kritisch", alles andere ("notable") -> "auffaellig". Der Adapter faerbt die
    Zelle/den Balken danach (Badge) -- KEIN Roh-Severity-String im Modell.
    """
    return "kritisch" if severity == "critical" else "auffällig"


def _project_security_pdf_model(
    report: SecurityReport,
    has_scan: bool,
    generated_at_text: str,
    rogue_checked_ts: float | None,
    pruefdatum: str = "",
) -> SecurityPdfModel:
    """Projiziert ``SecurityReport`` (+ Statuswerte) auf das render-fertige ``SecurityPdfModel``.

    REIN/DETERMINISTISCH (keine Uhr): ``generated_at_text`` (Erzeugungsdatum) und ``pruefdatum``
    (Rogue-Pruefdatum) kommen FERTIG formatiert herein. ``has_scan`` ist hier nicht
    text-relevant (die leere Basis traegt sich ueber Score 100 + leere Listen ehrlich selbst),
    wird aber -- analog ``_security_report`` -- mitgefuehrt, weil der Runner es ohnehin haelt.
    """
    score = report.score

    # Score-Einordnung: fertiger deutscher Satz aus den Zaehlern (Achse-B: beschreibt/ordnet
    # ein, KEINE Wertung angehaengt). Bei leerer Basis ehrlich der "keine Geraete"-Satz.
    if score.device_count == 0:
        score_einordnung = "Es wurden keine Geräte in die Bewertung einbezogen."
    else:
        score_einordnung = (
            f"Von {score.device_count} bewerteten Geräten sind {score.critical_devices} "
            f"kritisch und {score.notable_devices} auffällig belastet; "
            f"{score.clean_devices} ohne Befund."
        )

    # Rogue-Hinweis: noch nie geprueft (ts None) -> Rechte-Hinweis; sonst das Pruefdatum
    # (kommt als fertiger String ``pruefdatum`` herein -- HIER NICHT aus dem ts gerechnet).
    if rogue_checked_ts is None:
        rogue_hinweis = (
            "Hinweis: Auf unerwartete DHCP-Server wurde noch nie geprüft "
            "(erfordert erhöhte Rechte)."
        )
    else:
        rogue_hinweis = f"Zuletzt auf unerwartete DHCP-Server geprüft am {pruefdatum}."

    # Score-Beitragsliste: je belastetem Geraet ein fertiges Tripel (Label, Klartext-Schwere,
    # Lastwert-Text mit Dezimalkomma).
    contributions = tuple(
        (
            c.device_label,
            "kritisch" if c.worst_severity == "critical" else "auffällig",
            _format_burden_de(c.burden_value),
        )
        for c in score.contributions
    )

    # Geraete-Balken: je Geraet MIT Befund die Anzahl kritischer und auffaelliger OFFENER
    # Befunde -- ueber alle drei OFFENEN Quellen gezaehlt (CVE via cvss_score: >= 9.0 kritisch).
    # VOLLSTAENDIG (kein Top-N); nur Geraete mit crit+notable > 0. Sortiert (crit desc,
    # notable desc, Label asc) fuer eine stabile, sinnvolle Balken-Reihenfolge.
    crit_by_device: dict[str, int] = {}
    notable_by_device: dict[str, int] = {}

    def _bump(label: str, is_critical: bool) -> None:
        target = crit_by_device if is_critical else notable_by_device
        target[label] = target.get(label, 0) + 1
        # sicherstellen, dass beide Zaehler den Schluessel kennen (fuer das Auslesen unten)
        other = notable_by_device if is_critical else crit_by_device
        other.setdefault(label, 0)

    for p in report.port_findings:
        _bump(p.device_label, p.severity == "critical")
    for n in report.net_findings:
        _bump(n.device_label, n.severity == "critical")
    for c in report.cve_findings:
        _bump(c.device_label, c.cvss_score >= 9.0)

    geraete_balken = tuple(
        (label, crit_by_device[label], notable_by_device[label])
        for label in sorted(
            crit_by_device,
            key=lambda lbl: (-crit_by_device[lbl], -notable_by_device[lbl], lbl),
        )
        if crit_by_device[label] + notable_by_device[label] > 0
    )

    # port_rows (PORT_COLUMNS: Gerät, Ports, Schwere, Grund). Grund: IMMER der feste Klartext
    # (kein Achse-B-Jargon, das rohe reason-Feld bewusst ignoriert).
    port_rows = tuple(
        (
            p.device_label,
            p.ports,
            _pdf_severity_label(p.severity),
            "Offene Ports, die CERNIS als ungewöhnlich einstuft",
        )
        for p in report.port_findings
    )

    # cve_rows (CVE_COLUMNS: Gerät, CVE, CVSS, Dienst, Beschreibung), NACH GERAET GRUPPIERT:
    # stabil nach device_label gruppieren (gleiche Labels untereinander), innerhalb der Gruppe
    # nach cvss_score absteigend. CVSS als Text mit Dezimalkomma.
    cve_order: list[str] = []
    cve_groups: dict[str, list[ReportCveFinding]] = {}
    for c in report.cve_findings:
        if c.device_label not in cve_groups:
            cve_groups[c.device_label] = []
            cve_order.append(c.device_label)
        cve_groups[c.device_label].append(c)
    cve_rows = tuple(
        (
            c.device_label,
            c.cve_id,
            f"{c.cvss_score:.1f}".replace(".", ","),
            c.service,
            c.description,
        )
        for label in cve_order
        for c in sorted(cve_groups[label], key=lambda f: f.cvss_score, reverse=True)
    )

    # net_rows (NET_COLUMNS: Art, Gerät, Schwere, Beschreibung).
    net_rows = tuple(
        (n.kind, n.device_label, _pdf_severity_label(n.severity), n.description)
        for n in report.net_findings
    )

    # acknowledged_rows (ACK_COLUMNS: Art, Gerät, Detail) -- alle drei quittierten Listen
    # zusammengefuehrt, Reihenfolge: erst Ports, dann CVE, dann Netz. Leer -> leeres tuple
    # (der Adapter laesst die Rubrik dann weg).
    acknowledged_rows = (
        *(("Port", p.device_label, f"Ports: {p.ports}") for p in report.acknowledged_port_findings),
        *(
            ("CVE", c.device_label, f"{c.cve_id} ({c.service})")
            for c in report.acknowledged_cve_findings
        ),
        *((n.kind, n.device_label, n.description) for n in report.acknowledged_net_findings),
    )

    return SecurityPdfModel(
        title="Netzwerk-Sicherheitsbericht",
        generated_at_text=generated_at_text,
        footer_left="CERNIS PRO 2.0 - Netzwerk-Sicherheitsbericht",
        score_value=score.score,
        score_level=score.level,
        score_einordnung=score_einordnung,
        critical_devices=score.critical_devices,
        notable_devices=score.notable_devices,
        clean_devices=score.clean_devices,
        device_count=score.device_count,
        total_burden=score.total_burden,
        einleitung=(
            "Dieser Bericht fasst die über CERNIS verteilten Sicherheits-Beobachtungen zu "
            "einem Bild zusammen. Er beschreibt und ordnet ein - die Bewertung jeder "
            "Auffälligkeit bleibt bei Ihnen."
        ),
        rogue_hinweis=rogue_hinweis,
        contributions=contributions,
        geraete_balken=geraete_balken,
        port_rows=port_rows,
        cve_rows=cve_rows,
        net_rows=net_rows,
        acknowledged_rows=acknowledged_rows,
    )


# ── Benutzerhandbuch: PDF-Modell-Projektion + JSON-Lade-Helfer (reine Modul-Ebene) ───
# Muster _project_security_pdf_model: REINE, deterministische Projektion (KEINE Uhr, KEINE I/O)
# vom bereits geladenen help_content-dict auf das render-fertige ManualPdfModel. Der Runner
# _manual_pdf liest die Uhr GENAU EINMAL und uebergibt fertige Kopf-/Fusstexte.

# Pfad zur Hilfe-Quelle, relativ zu DIESEM Modul aufgeloest (app.py liegt in backend/, NICHT in
# backend/src): von backend/ ein Verzeichnis hoch zum Repo-Root, dann frontend/src/lib/.
# Wie _LOGO_PATH ueber os.path.normpath verifiziert. Existiert die Datei nicht (frozen-Build),
# liefert der Lade-Helfer ein leeres dict -> das PDF hat dann nur Kopf/Titel (ehrlicher Leerfall).
_HELP_CONTENT_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "frontend", "src", "lib", "help_content.json")
)


def _load_help_content() -> dict[str, object]:
    """Laedt die Hilfe-Inhalte aus ``help_content.json`` -- fehlt die Datei, leeres dict.

    Composition-Root-Bootstrap-Stil (synchroner Datei-Lesezugriff). Existiert die Datei nicht
    (z. B. im frozen-Build), wird ein leeres dict geliefert (das PDF traegt dann nur Kopf/Titel
    -- ehrlicher Leerfall, kein Absturz). Liest mit encoding utf-8.
    """
    if not os.path.exists(_HELP_CONTENT_PATH):
        return {}
    with open(_HELP_CONTENT_PATH, encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, dict) else {}


def _project_manual_pdf_model(
    help_data: dict[str, object],
    lang: str,
    generated_at_text: str,
    footer_left: str,
    title: str,
) -> ManualPdfModel:
    """Projiziert das geladene help_content-dict auf das render-fertige ``ManualPdfModel``.

    REIN/DETERMINISTISCH: KEINE Uhr, KEINE I/O (das dict ist bereits geladen). Iteriert die
    Eintraege in EINFUEGE-Reihenfolge (Python-dict ist insertion-ordered = JSON-Reihenfolge),
    ueberspringt den Schluessel ``_meta`` und nimmt sonst ALLE Eintraege (auch den einen mit
    status "vorlaeufig"). Pro Eintrag: Kategorie + Sprachblock[lang] (titel + an Leerzeilen
    getrennte, gestrippte, nicht-leere Stuecke von "lang"). ``lang`` wird normalisiert (alles
    ausser "en" -> "de").
    """
    normalized = "en" if lang == "en" else "de"

    # KATEGORIE-REINE GRUPPIERUNG (analog UI-Funktion ``baueKategorien`` in
    # frontend/src/views/ManualView.jsx): Die JSON-Reihenfolge ist NICHT
    # kategorierein, darum gruppieren wir hier. Kategorie-Reihenfolge folgt dem
    # ERSTEN Auftreten in der JSON (nicht alphabetisch); innerhalb einer Kategorie
    # bleiben die Eintraege in JSON-Reihenfolge. So steht jede Kategorie genau
    # einmal als zusammenhaengender Block -- der Renderer erkennt den Gruppen-
    # wechsel weiterhin am Wechsel des ``category_label``.
    kategorie_reihenfolge: list[str] = []
    gruppen: dict[str, list[ManualPdfSection]] = {}
    for key, entry in help_data.items():
        if key == "_meta" or not isinstance(entry, dict):
            continue
        kategorie = str(entry.get("kategorie", ""))
        sprachblock = entry.get(normalized)
        if not isinstance(sprachblock, dict):
            continue
        heading = str(sprachblock.get("titel", ""))
        lang_text = str(sprachblock.get("lang", ""))
        paragraphs = tuple(
            stripped for stueck in lang_text.split("\n\n") if (stripped := stueck.strip())
        )
        if kategorie not in gruppen:
            kategorie_reihenfolge.append(kategorie)
            gruppen[kategorie] = []
        gruppen[kategorie].append(
            ManualPdfSection(category_label=kategorie, heading=heading, paragraphs=paragraphs)
        )

    sections: list[ManualPdfSection] = []
    for kategorie in kategorie_reihenfolge:
        sections.extend(gruppen[kategorie])

    return ManualPdfModel(
        title=title,
        generated_at_text=generated_at_text,
        footer_left=footer_left,
        intro="",
        sections=tuple(sections),
    )


def create_app(config: AppConfig | None = None) -> FastAPI:
    """Baut die FastAPI-App. ``config=None`` liest die Konfiguration aus der Umgebung."""
    cfg = config or AppConfig()
    configure_logging(level=cfg.log_level, json_logs=cfg.log_json)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        logger.info("startup", service=APP_NAME, version=APP_VERSION)
        # Bootstrap nur, wenn app.py der produktive Owner ist (P2.3). Default aus
        # -> kein echter DB-/Monitor-/Scheduler-Start in Tests oder bei
        # versehentlichem Doppelstart.
        if cfg.bootstrap_on_startup:
            _check_version_upgrade()
            init_db()
            init_devices_db()
            # ── monitoring v2 (M.9): Altcode-Loop (configure_monitor + run_monitor)
            # und Altcode-Scheduler (start_scheduler) ERSETZT durch die v2-Use-Cases.
            # Der RunMonitor tickt bis stop(); der Task haengt an app.state (kein GC).
            # Die gespeicherten aktiven Schedules registriert die Verdrahtung HIER
            # (der ApschedulerJobScheduler.start() tut das bewusst nicht -- er kennt
            # das Repo nicht), exakt wie der Altcode-``start_scheduler``.
            run_monitor_uc = _build_run_monitor()
            _app.state.run_monitor = run_monitor_uc
            _app.state.monitor_task = asyncio.create_task(run_monitor_uc.run())
            # traffic-Durchsatz-Poller AUTO (T.4b-2): nur wenn explizit eingeschaltet.
            # Default aus -> der Durchsatz wird sparsam erst auf Anforderung erfasst
            # (MANUELL ueber POST /api/traffic/poll/start). Nutzt DENSELBEN Singleton +
            # app.state-Keys wie der MANUELL-Pfad (eine Instanz, ein State).
            if cfg.traffic_poll_auto:
                poll_throughput_uc = _poll_throughput()
                _app.state.poll_throughput = poll_throughput_uc
                _app.state.poll_task = asyncio.create_task(poll_throughput_uc.run())
            job_scheduler().start(_scheduled_scan)
            for row in schedule_repository().list():
                if row["enabled"]:
                    job_scheduler().register(row, _scheduled_scan)
            # ── Langzeit-Logging B-II: Resume + periodischer Cleanup ──────────
            # RESUME: aktive Aufgaben mit noch offenem Fenster nimmt der Sink ab dem
            # naechsten Tick automatisch wieder auf (er liest die aktiven Tasks frisch)
            # -- KEIN Extra-Schritt. Der Use-Case beendet nur die ABGELAUFENEN, die
            # sonst als ewig-aktiv haengenblieben (IMMEDIATE-Maximaldauer/SCHEDULED-Ende
            # waehrend der Auszeit verstrichen). Einmaliger Aufruf, time.time() als now.
            import time

            resume_result = ResumeActiveLoggingTasks(logging_task_repository())(time.time())
            logger.info(
                "logging_tasks_resumed",
                kept_active=resume_result.kept_active,
                finished=resume_result.finished,
            )
            # CLEANUP: periodischer Retention-Runner (Muster monitor_task/poll_task).
            # Setzt EnforceLoggingRetention stuendlich durch; haengt an app.state, der
            # Teardown stoppt+canceled+awaitet ihn (suppress CancelledError).
            logging_retention_uc = RunLoggingRetention(
                EnforceLoggingRetention(logging_rtt_repository(), logging_event_repository())
            )
            _app.state.logging_retention = logging_retention_uc
            _app.state.logging_cleanup_task = asyncio.create_task(logging_retention_uc.run())
            # ── CVE-Drip-Worker (ADR 0037) ────────────────────────────────────
            # Gedrosselter Hintergrund-Loop (Muster monitor_task): prueft pro Intervall
            # HOECHSTENS EINEN faelligen Host (Faelle 1-3) gegen den jüngsten Scan-Bestand.
            # KEIN stures Neu-Pruefen beim Start -- die tick-Logik entscheidet Faelligkeit
            # aus dem persistierten last_checked_ts je Host (dreimal Neustart am Tag
            # rattert NICHT dreimal alles durch; Fall 3 greift erst nach dem Intervall).
            # Leerer Bestand / kein faelliger Host -> der Loop schlaeft (kein NVD-Aufruf).
            # Haengt an app.state; der Teardown stoppt+cancelt+awaitet ihn.
            run_cve_monitor_uc = _build_run_cve_monitor()
            _app.state.run_cve_monitor = run_cve_monitor_uc
            _app.state.cve_monitor_task = asyncio.create_task(run_cve_monitor_uc.run())
            # ── Aussenkontakte-Recorder (E3b) ─────────────────────────────────
            # Snapshot-Worker (Muster cve_monitor_task): tickt bis stop(); schreibt aber
            # nur, wenn ueber den (in E4 kommenden) REST-Weg eine Aufzeichnung ACTIVE
            # gesetzt wurde. Bis dahin tickt er und macht nur DETAIL-Retention (harmlos,
            # leere DB -- ehrlicher Leerzustand, S3). Haengt an app.state; der Teardown
            # stoppt+cancelt+awaitet ihn.
            run_outbound_recorder_uc = _build_run_outbound_recorder()
            _app.state.run_outbound_recorder = run_outbound_recorder_uc
            _app.state.outbound_recorder_task = asyncio.create_task(run_outbound_recorder_uc.run())
            # ── v2-Scheduler-Worker (Block 3a, Etappe 3b) ─────────────────────
            # Lifespan-Worker (Muster cve_monitor_task): tickt bis stop(); der Task
            # haengt an app.state (kein GC). Die Handler-Registry ist in 3b LEER --
            # der Worker laeuft und tut nichts (ehrlicher Leerzustand, S3); der erste
            # Handler (monitoring_window) kommt in Block 3b. Getrennt vom alten
            # ApschedulerJobScheduler (job_scheduler().start oben), eigene Tabelle.
            run_scheduler_uc = _build_run_scheduler()
            _app.state.run_scheduler = run_scheduler_uc
            _app.state.scheduler_task = asyncio.create_task(run_scheduler_uc.run())
            init_alerts_db()
            # agent (A.4+5): KEIN init_agents_db mehr -- das v2-SqliteAgentRepository
            # legt die remote_agents-Tabelle beim Bau selbst an (_ensure_schema),
            # Muster wie die schedule/sla-Repos. Der letzte modules.agent-Bootstrap-
            # Faden faellt damit weg.
        yield
        if cfg.bootstrap_on_startup:
            # stop() setzt das Loop-Flag (Abbruch nach der laufenden Iteration);
            # cancel() bricht zusaetzlich ein laufendes sleep(interval) sofort ab.
            # Den CancelledError beim Awaiten unterdruecken -- erwarteter Abgang.
            run_monitor_uc.stop()
            _app.state.monitor_task.cancel()
            with suppress(asyncio.CancelledError):
                await _app.state.monitor_task
            # Langzeit-Logging-Cleanup (B-II): periodischer Retention-Runner -- selber
            # Teardown wie der monitor_task (stop-Flag + cancel + awaiten, CancelledError
            # unterdruecken). Laeuft immer (im bootstrap-Block gestartet).
            logging_retention_uc.stop()
            _app.state.logging_cleanup_task.cancel()
            with suppress(asyncio.CancelledError):
                await _app.state.logging_cleanup_task
            # CVE-Drip-Worker (ADR 0037): selber Teardown wie der monitor_task (stop-Flag
            # + cancel + awaiten, CancelledError unterdruecken). Laeuft immer (im bootstrap-
            # Block gestartet).
            run_cve_monitor_uc.stop()
            _app.state.cve_monitor_task.cancel()
            with suppress(asyncio.CancelledError):
                await _app.state.cve_monitor_task
            # Aussenkontakte-Recorder (E3b): selber Teardown wie der cve_monitor_task
            # (stop-Flag + cancel + awaiten, CancelledError unterdruecken). Laeuft immer
            # (im bootstrap-Block gestartet).
            run_outbound_recorder_uc.stop()
            _app.state.outbound_recorder_task.cancel()
            with suppress(asyncio.CancelledError):
                await _app.state.outbound_recorder_task
            # v2-Scheduler-Worker (Etappe 3b): selber Teardown wie der cve_monitor_task
            # (stop-Flag + cancel + awaiten, CancelledError unterdruecken). Laeuft immer
            # (im bootstrap-Block gestartet).
            run_scheduler_uc.stop()
            _app.state.scheduler_task.cancel()
            with suppress(asyncio.CancelledError):
                await _app.state.scheduler_task
            # capture-Loop (C.5): laeuft NUR, wenn ueber POST /api/pcap/start gestartet
            # (kein startup-Autostart). Beim Shutdown sauber stoppen + canceln, falls aktiv.
            capture_task = getattr(_app.state, "capture_task", None)
            if capture_task is not None and not capture_task.done():
                run_capture().stop()
                capture_task.cancel()
                with suppress(asyncio.CancelledError):
                    await capture_task
            # traffic-Poll-Loop (T.4b-2): laeuft per AUTO (oben) ODER MANUELL
            # (POST /api/traffic/poll/start). Beim Shutdown sauber stoppen + canceln,
            # falls aktiv -- selber Pfad fuer beide Modi (ein Singleton/Task).
            poll_task = getattr(_app.state, "poll_task", None)
            if poll_task is not None and not poll_task.done():
                poll_uc = getattr(_app.state, "poll_throughput", None)
                if poll_uc is not None:
                    poll_uc.stop()
                poll_task.cancel()
                with suppress(asyncio.CancelledError):
                    await poll_task
            # sni-Sniff (ADR 0017): laeuft NUR, wenn ueber POST /api/sni/start gestartet
            # (kein startup-Autostart, MANUELL). Anders als der capture-/poll-Loop gibt
            # es KEINE Coroutine/keinen asyncio.Task -- der Adapter haelt die beiden
            # Hintergrund-THREADS (scapy-AsyncSniffer + psutil-Poller). Daher kein
            # task.cancel(): der lifespan-Shutdown stoppt+joint die Threads ueber
            # RunSniCapture.stop() (idempotent), falls ein Sniff lief.
            run_sni_uc = getattr(_app.state, "run_sni", None)
            if run_sni_uc is not None:
                run_sni_uc.stop()
            job_scheduler().stop()
        logger.info("shutdown", service=APP_NAME)

    app = FastAPI(title="CERNIS PRO", version=APP_VERSION, lifespan=lifespan)

    # Restriktives CORS statt allow_origins=["*"] (Finding S1).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health", tags=["ops"])
    async def health() -> dict[str, str]:
        """Liveness-Check fuer Betrieb und Smoke-Tests."""
        return {"status": "ok", "service": APP_NAME, "version": APP_VERSION}

    # ── settings-Domaene v2 verdrahten (Regel 5: ports<->infrastructure nur hier) ──
    # Lazy + pro App-Instanz memoisiert: die Adapter-Konstruktion (DB-Datei,
    # Keystore-Pfad) passiert erst beim ersten settings-Request, nicht beim
    # App-Bau. Tests ueberschreiben die Provider via dependency_overrides.
    @lru_cache(maxsize=1)
    def repository() -> SqliteSettingsRepository:
        # Lokaler Import: die Pfad-Aufloesung aus db_path.py (und ihr
        # Verzeichnis-Seiteneffekt) bleibt aus dem App-Bau heraus. Pfad NICHT
        # hartkodiert.
        from modules.db_path import get_db_path

        return SqliteSettingsRepository(get_db_path())

    @lru_cache(maxsize=1)
    def secret_store() -> KeyringSecretStore:
        return KeyringSecretStore(service="cernis-pro")

    app.include_router(settings_router)
    app.dependency_overrides[provide_get_settings] = lambda: GetSettings(
        repository(), secret_store()
    )
    app.dependency_overrides[provide_update_setting] = lambda: UpdateSetting(repository())
    app.dependency_overrides[provide_update_secret] = lambda: UpdateSecret(secret_store())

    # ── devices-Domaene v2 verdrahten (Regel 5: ports<->infrastructure nur hier) ──
    # Lazy memoisiert wie das settings-Repository: die Adapter-/DB-Konstruktion
    # passiert erst beim ersten devices-Request, nicht beim App-Bau (Tests
    # ueberschreiben die Provider). Das v2-Repository nutzt NUR devices +
    # device_ip_history; known_devices bleibt unberuehrt (stirbt mit dem Altcode).
    @lru_cache(maxsize=1)
    def device_repository() -> SqliteDeviceRepository:
        from modules.db_path import get_db_path

        return SqliteDeviceRepository(get_db_path())

    device_clock = SystemClock()

    app.include_router(devices_router)
    app.dependency_overrides[provide_get_device_stats] = lambda: GetDeviceStats(
        device_repository(), device_clock
    )
    app.dependency_overrides[provide_get_devices] = lambda: GetDevices(device_repository())
    app.dependency_overrides[provide_get_unclassified_devices] = lambda: GetUnclassifiedDevices(
        device_repository()
    )
    app.dependency_overrides[provide_get_device] = lambda: GetDevice(device_repository())
    app.dependency_overrides[provide_update_device_meta] = lambda: UpdateDeviceMeta(
        device_repository()
    )
    app.dependency_overrides[provide_dismiss_device_from_watch] = lambda: DismissDeviceFromWatch(
        device_repository()
    )
    app.dependency_overrides[provide_delete_device] = lambda: DeleteDevice(device_repository())
    # RecordScannedHost hat (noch) keinen Endpunkt -- hier verdrahtet und bereit-
    # gestellt, damit die spaeter migrierte scanning-Domaene ihn konsumiert.
    app.dependency_overrides[provide_record_scanned_host] = lambda: RecordScannedHost(
        device_repository(), device_clock
    )
    # Geraete-Lebenszyklus (A3): Anlegen/Archivieren/Wiederherstellen + Nachfrage.
    app.dependency_overrides[provide_create_device] = lambda: CreateDevice(
        device_repository(), device_clock
    )
    app.dependency_overrides[provide_archive_device] = lambda: ArchiveDevice(device_repository())
    app.dependency_overrides[provide_restore_device] = lambda: RestoreDevice(device_repository())
    app.dependency_overrides[provide_get_archived_devices] = lambda: GetArchivedDevices(
        device_repository()
    )
    app.dependency_overrides[provide_answer_archive_prompt] = lambda: AnswerArchivePrompt(
        device_repository()
    )

    # Nachfrage-Kandidaten: die Tage-Schwelle wird LIVE aus dem Setting gelesen und
    # in den Use-Case eingesetzt, sodass der Endpunkt argumentlos aufrufen kann. Der
    # Provider liefert daher ein Callable[[], list], nicht die Use-Case-Instanz.
    def _build_get_archive_candidates() -> Callable[[], list[Any]]:
        days = _read_device_int_setting(
            repository(), "device_archive_prompt_days", _DEVICE_ARCHIVE_PROMPT_DEFAULT_DAYS
        )
        use_case = GetArchiveCandidates(device_repository(), device_clock)
        return lambda: use_case(days)

    app.dependency_overrides[provide_get_archive_candidates] = _build_get_archive_candidates

    # ── scanning-Domaene v2 verdrahten (Regel 5: ports<->infrastructure nur hier) ──
    # REST (history/vendor) ueber duenne Use-Cases im api-Ring; der WS-Handler
    # /ws/scan lebt im Composition Root (ws_scan.py), weil er domain-Event-Typen
    # + Adapter-Exceptions kennt (im api-Ring verboten). Das ScanHistory-Repository
    # teilt die DB mit settings/devices; die uebrigen Adapter sind zustandslos.
    @lru_cache(maxsize=1)
    def scan_history_repository() -> SqliteScanHistoryRepository:
        from modules.db_path import get_db_path

        return SqliteScanHistoryRepository(get_db_path())

    vendor_lookup = VendorLookupAdapter()
    arp_table = ArpTableAdapter()

    app.include_router(scanning_router)
    app.dependency_overrides[provide_get_scan_history] = lambda: GetScanHistory(
        scan_history_repository()
    )
    app.dependency_overrides[provide_get_scan_detail] = lambda: GetScanDetail(
        scan_history_repository()
    )
    app.dependency_overrides[provide_lookup_vendor] = lambda: LookupVendor(vendor_lookup)
    app.dependency_overrides[provide_get_arp_table] = lambda: GetArpTable(arp_table)

    # WS-Handler: pro Verbindung einen frischen RunNetworkScan mit den konkreten
    # Adaptern. ArpTableAdapter (S.7b) + FritzHosts-Wrapper (S.7c) sind dabei. Die
    # zustandslosen Adapter werden pro Scan neu gebaut; das ScanHistory-Repository
    # wird geteilt. Die Fritz-Credentials werden PRO SCAN frisch gelesen (Aenderung
    # in den Settings wirkt ohne App-Neustart).
    def _build_run_network_scan() -> RunNetworkScan:
        # Credentials zum Scan-Zeitpunkt lesen: host/user aus dem Settings-
        # Repository (Rohwerte), das Passwort als Klartext DIREKT aus dem
        # SecretStore (Composition Root darf Secret-Klartext lesen, um einen
        # Adapter zu bauen -- das ist sein Job; NIE ueber GetSettings, der maskiert).
        fritz_host_setting = repository().get("fritz_host")
        fritz_user_setting = repository().get("fritz_user")
        fritz_host = str(fritz_host_setting.value) if fritz_host_setting is not None else ""
        fritz_user = str(fritz_user_setting.value) if fritz_user_setting is not None else ""
        fritz_password = secret_store().get("fritz_password") or ""
        return RunNetworkScan(
            discovery=HostDiscoveryAdapter(),
            port_scanner=PortScannerAdapter(),
            vendor_lookup=vendor_lookup,
            resolver=HostnameResolverAdapter(),
            mdns=MdnsAdapter(),
            ssdp=SsdpAdapter(),
            ipv6=Ipv6EnrichmentAdapter(),
            fritz_hosts=_FritzHostsWiring(fritz_host, fritz_user, fritz_password),
            arp_table=arp_table,
            scan_history=scan_history_repository(),
        )

    # devices-Projektion (S.7d): der WS-Handler verbucht pro angereichertem Host
    # ueber RecordScannedHost in die devices-DB. Die Projektion EnrichedHost ->
    # ScannedHost + der Aufruf liegen im Composition Root (ws_scan.py), NICHT im
    # scanning-Use-Case (keine scanning->devices-Domaenenkopplung). Gleiche
    # Verdrahtung wie der api-Provider oben (DeviceRepository + Clock).
    def _build_record_scanned_host() -> RecordScannedHost:
        return RecordScannedHost(device_repository(), device_clock)

    # analysis-Host-Historie-Schreibnaht (C.2): die zweite, von der devices-Projektion
    # UNABHAENGIGE Schreib-Naht. Liefert das record_seen-Callable (mac) -> None aus dem
    # Host-Historie-Repo. Das Repo (host_history_repository) ist als lru_cache erst im
    # analysis-Block weiter unten definiert; diese Closure laeuft aber erst bei der
    # WS-Verbindung (spaete Namensaufloesung, Muster _build_run_monitor/_scheduled_scan).
    # Diese Naht pflegt die Historie, aus der die LESE-Naht (_analyze_snapshot) spaeter
    # ObservedHost.is_known fuellt -- die Baseline der new_host_seen-Regel (ADR 0013).
    def _build_record_seen() -> Any:
        return host_history_repository().record_seen

    # Baseline-Anreicherung des host_detail-Frames (ADR 0019): zwei zusaetzliche
    # Lese-Pfade, die der WS-Handler pro angereichertem Host konsultiert.
    # get_device liefert die kuratierten devices-Felder (label/tags/notes) -- gleicher
    # Use-Case wie der api-Provider provide_get_device, pro Verbindung frisch gebaut
    # (Muster _build_record_scanned_host). is_known liefert den VORZUSTAND der Host-
    # Historie (gelesen VOR record_seen) -- analog _build_record_seen, nur die Lese-
    # statt der Schreib-Methode desselben Repos (spaete Namensaufloesung von
    # host_history_repository, das erst im analysis-Block definiert ist).
    def _build_get_device() -> GetDevice:
        return GetDevice(device_repository())

    def _build_is_known() -> Any:
        # Baseline EINMAL beim WS-Aufbau lesen. Leere Historie (allererster Scan, kein
        # Vorzustand) -> JEDER Host bekannt: new_host_seen feuert nicht ("neu" ist gegen
        # eine leere Baseline bedeutungslos; gleiche Linie wie MAC-lose Hosts -> True).
        # Sonst der normale Vorzustand-Abgleich gegen die vor record_seen gelesene Menge.
        repo = host_history_repository()
        baseline = repo.known_macs()
        if not baseline:
            return lambda mac: True
        return lambda mac: True if not mac else (mac in baseline)

    # analysis-Achse-B-Bewertung (ADR 0029 + 0030): der WS-Handler bewertet pro
    # angereichertem Host den LIVE-Portstand gegen die KONFIGURIERTEN Regeln und traegt BEIDE
    # Achse-B-Felder ins host_detail-Frame -- analysis_severity (Host-Maximum, 0029) UND
    # flagged_ports (die getroffenen offenen Ports je Stufe, 0030).
    #
    # Single Source (ADR 0030): EIN gefilterter Provider wird pro Verbindung EINMAL gebaut
    # (DERSELBE _build_filtered_provider wie der REST-Pfad), daraus EINE AnalyzeSnapshot-
    # Instanz. Das zurueckgegebene Callable liefert beide Felder zusammen: die Severity aus
    # dem Engine-Lauf (_severity_for_host), die flagged_ports aus dem Mengenschnitt ueber
    # GENAU DENSELBEN Provider (_flagged_ports_for_host) -- so koennen die beiden Achse-B-
    # Felder nicht auseinanderlaufen (Konsistenz-Invariante). KEINE DB-Historie -- die WS-
    # Quelle bewertet den aktuellen Scan-Host, nicht den abgeschlossenen Scan aus der DB.
    def _build_axis_b() -> Any:
        provider = _build_filtered_provider(analysis_rule_repository(), repository())
        analyze = AnalyzeSnapshot(provider, StaticHelpLinkResolver())
        # acked-Lese-Naht (ADR 0031): das acknowledged_ports-Callable (mac) -> set[int] aus
        # dem Acknowledge-Repo, EINMAL pro Verbindung geholt (spaete Namensaufloesung von
        # acknowledgement_repository, das erst im analysis-Block weiter unten definiert ist
        # -- Muster wie _build_is_known/host_history_repository). Die acked-Logik lebt
        # KOMPLETT in dieser Closure (geringste Kopplung, Teil 3): ws_scan setzt nur ein
        # weiteres Frame-Feld und braucht keine zweite Factory.
        acknowledged_ports = acknowledgement_repository().acknowledged_ports

        # Das Callable liefert ein TRIPEL (severity, flagged, acked_list): die quittierten
        # Ports werden EINMAL je Host geholt und doppelt genutzt -- (a) die BEWERTUNG
        # (severity + flagged) auf dem um ``acked`` reduzierten Portstand bilden (Single
        # Source, beide aus demselben reduzierten Stand -> Konsistenz haelt), (b) als
        # sortierte Liste ins host_detail-Frame (das Panel in 8b braucht sie). Die normale
        # "offen"-Projektion (Frame-Feld ``ports``) bleibt UNberuehrt -- nur die Bewertung
        # reduziert. Die Signatur (host, known) bleibt; ``acked`` wird INNEN geholt.
        def axis_b(
            host: EnrichedHost, known: bool
        ) -> tuple[Severity | None, dict[str, list[int]], list[int]]:
            acked = frozenset(acknowledged_ports(host.mac)) if host.mac else frozenset()
            return (
                _severity_for_host(host, known, analyze, acked),
                _flagged_ports_for_host(host, provider, acked),
                sorted(acked),
            )

        return axis_b

    app.add_api_websocket_route(
        "/ws/scan",
        make_ws_scan(
            _build_run_network_scan,
            _build_record_scanned_host,
            _build_record_seen,
            _build_get_device,
            _build_is_known,
            _build_axis_b,
        ),
    )

    # ── fritz-Detailansicht verdrahten (read-only, Regel 5: ports<->infra nur hier) ──
    # GET /api/fritz/detail liefert den vollen TR-064-Schnappschuss (WAN/DSL/WLAN/
    # Clients/Log/Portfreigaben) ueber GetFritzDetail -> FritzDetailAdapter. Der
    # Adapter wird PRO REQUEST frisch mit den aktuellen Credentials gebaut (Aenderung
    # in den Settings wirkt ohne App-Neustart -- Muster wie _build_run_network_scan):
    # host/user aus dem Settings-Repository (Rohwerte), das Passwort als Klartext
    # DIREKT aus dem SecretStore. Anders als beim best-effort-Scan-Merge (_FritzHosts-
    # Wiring) wird hier KEIN Auth-Fehler verschluckt: der Detail-Endpunkt ist ein
    # expliziter Lese-Pfad -> FritzAuthError schlaegt bis in den Router durch (502).
    # Nicht erreichbar/nicht konfiguriert bleibt der Leer-Zustand (reachable=False).
    # Dieser Endpunkt wird NICHT gecacht (jeder Abruf ist ein frischer Schnappschuss).
    def _build_get_fritz_detail() -> GetFritzDetail:
        fritz_host_setting = repository().get("fritz_host")
        fritz_user_setting = repository().get("fritz_user")
        fritz_host = str(fritz_host_setting.value) if fritz_host_setting is not None else ""
        fritz_user = str(fritz_user_setting.value) if fritz_user_setting is not None else ""
        fritz_password = secret_store().get("fritz_password") or ""
        # Wiring-Wrapper statt nacktem Adapter: er uebersetzt die infrastructure-
        # FritzAuthError in den application-FritzDetailAuthError, den der Router faengt.
        return GetFritzDetail(
            _FritzDetailWiring(host=fritz_host, user=fritz_user, password=fritz_password)
        )

    app.include_router(fritz_router)
    app.dependency_overrides[provide_get_fritz_detail] = _build_get_fritz_detail

    # ── metrics-Querschnitt (M.8) ────────────────────────────────────────────
    # Der MetricsReader liest dieselbe cernis.db (devices/rtt_history/sla_samples/
    # scan_history) wie die anderen Repos -- zustandslos (haelt nur den db_path,
    # aggregiert pro snapshot()-Aufruf frisch). Darum EINMAL gebaut und geteilt
    # (lru_cache, Muster wie scan_history_repository); der ExportMetrics-Use-Case
    # wird pro Request frisch darum gewickelt (guenstig, haelt nur den Reader).
    @lru_cache(maxsize=1)
    def metrics_reader() -> SqliteMetricsReader:
        from modules.db_path import get_db_path

        return SqliteMetricsReader(get_db_path())

    app.include_router(metrics_router)
    app.dependency_overrides[provide_export_metrics] = lambda: ExportMetrics(metrics_reader())

    # ── monitoring-Domaene v2 verdrahten (M.9, Regel 5: ports<->infra nur hier) ──
    # REST (status/events/rtt/sla/schedules) ueber duenne Use-Cases im api-Ring; der
    # WS-Handler /ws/monitor lebt im Composition Root (ws_monitor.py), weil er den
    # Broadcaster-Adapter (infra) mit dem RunMonitor-Status (application) verbindet.
    # Die vier sqlite-Repos teilen die cernis.db (lru_cache wie scan_history); pinger/
    # notifier/broadcaster/scheduler sind zustandslos bzw. langlebige Singletons.
    @lru_cache(maxsize=1)
    def rtt_history_repository() -> SqliteRttHistoryRepository:
        from modules.db_path import get_db_path

        return SqliteRttHistoryRepository(get_db_path())

    @lru_cache(maxsize=1)
    def monitor_event_repository() -> SqliteMonitorEventRepository:
        from modules.db_path import get_db_path

        return SqliteMonitorEventRepository(get_db_path())

    @lru_cache(maxsize=1)
    def sla_sample_repository() -> SqliteSlaSampleRepository:
        from modules.db_path import get_db_path

        return SqliteSlaSampleRepository(get_db_path())

    @lru_cache(maxsize=1)
    def schedule_repository() -> SqliteScheduleRepository:
        from modules.db_path import get_db_path

        return SqliteScheduleRepository(get_db_path())

    # Langzeit-Logging-Repos (B-I): drei eigene Tabellen (``monitoring_log_*``),
    # GETRENNT vom fluechtigen Live-Monitor (rtt_history/monitor_events). lru_cache wie
    # die uebrigen sqlite-Repos (teilen die cernis.db). NUR Provider + Endpunkt-
    # Verdrahtung -- KEIN Loop-/Lifespan-Eingriff (Schreibpfad + Auto-Resume = B-II).
    @lru_cache(maxsize=1)
    def logging_task_repository() -> SqliteLoggingTaskRepository:
        from modules.db_path import get_db_path

        return SqliteLoggingTaskRepository(get_db_path())

    @lru_cache(maxsize=1)
    def logging_rtt_repository() -> SqliteLoggingRttRepository:
        from modules.db_path import get_db_path

        return SqliteLoggingRttRepository(get_db_path())

    @lru_cache(maxsize=1)
    def logging_event_repository() -> SqliteLoggingEventRepository:
        from modules.db_path import get_db_path

        return SqliteLoggingEventRepository(get_db_path())

    # Aussenkontakte-Aufzeichnung (E3b) -- drei Repos je eigener sqlite-Tabelle, Muster
    # der logging_*-Factories oben (db_path-Factory, lru_cache-Singleton).
    @lru_cache(maxsize=1)
    def outbound_recording_repository() -> SqliteOutboundRecordingRepository:
        from modules.db_path import get_db_path

        return SqliteOutboundRecordingRepository(get_db_path())

    @lru_cache(maxsize=1)
    def outbound_detail_repository() -> SqliteOutboundDetailRepository:
        from modules.db_path import get_db_path

        return SqliteOutboundDetailRepository(get_db_path())

    @lru_cache(maxsize=1)
    def outbound_aggregate_repository() -> SqliteOutboundAggregateRepository:
        from modules.db_path import get_db_path

        return SqliteOutboundAggregateRepository(get_db_path())

    @lru_cache(maxsize=1)
    def job_scheduler() -> ApschedulerJobScheduler:
        return ApschedulerJobScheduler()

    @lru_cache(maxsize=1)
    def target_source() -> CompositeTargetSource:
        # Liest die Custom-Targets ueber den migrierten settings-Port (NICHT modules).
        return CompositeTargetSource(repository())

    # Broadcaster-SINGLETON: EINE langlebige Instanz, die der RunMonitor-Loop
    # bespielt UND in die die /ws/monitor-Handler subscriben. Beide teilen dieselben
    # Subscriber -- darum lru_cache (genau eine Instanz pro App), kein per-Request-Bau.
    @lru_cache(maxsize=1)
    def monitor_broadcaster() -> WebSocketMonitorBroadcaster:
        return WebSocketMonitorBroadcaster()

    # RunMonitor pro Lifespan einmal gebaut (haelt den Loop-State _status). Bekommt
    # den Broadcaster-Singleton -> seine broadcast()-Frames erreichen die WS-Clients.
    # alert_raiser (A.7a): die monitoring->alerting-Naht. _MonitorAlertRaiser haelt
    # einen frischen RaiseAlert mit den drei alerting-Adaptern (alle weiter unten im
    # alerting-Block definiert -- diese Closure laeuft erst im lifespan, da sind alle
    # Provider da; spaete Namensaufloesung, Muster wie _scheduled_scan). Der RunMonitor
    # bleibt alerting-blind: er ruft nur AlertRaiserPort.raise_alert(event).
    def _build_run_monitor() -> RunMonitor:
        return RunMonitor(
            pinger=MonitorPingerAdapter(),
            rtt_history=rtt_history_repository(),
            event_repo=monitor_event_repository(),
            notifier=MonitorNotifierAdapter(),
            broadcaster=monitor_broadcaster(),
            target_source=target_source(),
            alert_raiser=_MonitorAlertRaiser(
                RaiseAlert(
                    alert_rule_repository(),
                    alert_notifier,
                    smtp_config_adapter(),
                )
            ),
            # Langzeit-Logging-Sink (B-II): haelt die drei logging-Repos (Provider
            # existieren schon). Schreibt pro Tick in die aktiven Logging-Aufgaben --
            # best-effort, der Live-Loop bleibt unberuehrt.
            logging_sink=MonitorLoggingSink(
                logging_task_repository(),
                logging_rtt_repository(),
                logging_event_repository(),
                # 3b: Schwellwert-Notifier -- mappt die Alarm-Flanke auf den vorhandenen
                # alerting-Notifier (Desktop + E-Mail). Bezieht EXAKT die im alerting-
                # Block gebauten Provider (alert_notifier + smtp_config_adapter()), wie
                # der RaiseAlert daneben -- keine neuen Provider, spaete Namensaufloesung.
                threshold_notifier=_ThresholdNotifierWiring(alert_notifier, smtp_config_adapter()),
            ),
        )

    # status_provider: die label-angereicherte {tid:{alive,label}}-Map fuer
    # /api/monitor/status UND den WS-Connect-Frame. Kombiniert RunMonitor.current_status()
    # (rohe {tid: alive}-Map) mit target_source.load() (label, tid-Fallback). Diese
    # Komposition kennt nur der Composition Root -- darum als Callable gereicht. Greift
    # auf den laufenden RunMonitor (app.state) zu; vor dem Start (kein bootstrap) ->
    # leere Map (kein Loop -> nichts gemessen), niemals ein Fehler.
    def _monitor_status() -> dict[str, dict[str, Any]]:
        run_monitor_uc = getattr(app.state, "run_monitor", None)
        raw = run_monitor_uc.current_status() if run_monitor_uc is not None else {}
        targets = target_source().load()
        labels = {t.id: t.label for t in targets}
        return {tid: {"alive": alive, "label": labels.get(tid, tid)} for tid, alive in raw.items()}

    # ManageSchedules: der ScanTriggerCallback (_scheduled_scan) ist HIER gebunden
    # (Weg-3-Umbau, M.9) -- EINE Quelle fuer REST-add UND lifespan-Registrierung.
    app.include_router(monitoring_router)
    app.dependency_overrides[provide_monitor_status] = lambda: _monitor_status
    app.dependency_overrides[provide_get_monitor_events] = lambda: GetMonitorEvents(
        monitor_event_repository()
    )
    app.dependency_overrides[provide_get_rtt_history] = lambda: GetRttHistory(
        rtt_history_repository()
    )
    app.dependency_overrides[provide_get_all_sla_stats] = lambda: GetAllSlaStats(
        sla_sample_repository()
    )
    app.dependency_overrides[provide_get_sla_stats] = lambda: GetSlaStats(sla_sample_repository())
    app.dependency_overrides[provide_get_schedules] = lambda: GetSchedules(schedule_repository())
    app.dependency_overrides[provide_manage_schedules] = lambda: ManageSchedules(
        schedule_repository(), job_scheduler(), _scheduled_scan
    )
    app.dependency_overrides[provide_update_schedule] = lambda: UpdateSchedule(
        schedule_repository()
    )
    # targets-Schreibpfad (M.9-Nachzuegler): Add/Delete auf den migrierten settings-
    # ``repository()`` (Custom-Targets liegen als ``monitor_custom_targets``-Setting).
    # Kein eigenes Repo, keine ``configure``-Folge -- der Loop laedt pro tick frisch.
    app.dependency_overrides[provide_add_monitor_target] = lambda: AddMonitorTarget(repository())
    app.dependency_overrides[provide_delete_monitor_target] = lambda: DeleteMonitorTarget(
        repository()
    )
    # Langzeit-Logging-Lifecycle (B-I Schritt 3): Anlegen + Lebenszyklus ueber dem
    # ``logging_task_repository()``; der Mengen-Befund ueber dem ``logging_rtt_repository()``.
    # NUR Endpunkt-Verdrahtung -- KEIN Lifespan-/Loop-Eingriff (B-II).
    # Auto-Scheduler-Job (3b-3): der Create-Override nutzt den Erben-Wrapper, der bei
    # einem RECURRING-Task zusaetzlich den monitoring_window-Job anlegt (CreateScheduledJob
    # ueber dem scheduled_job_repository() -- spaete Namensaufloesung, die Factory ist im
    # scheduler-Block weiter unten definiert, Muster wie _build_run_monitor/alert_notifier).
    app.dependency_overrides[provide_create_logging_task] = lambda: _CreateLoggingTaskWithSchedule(
        logging_task_repository(),
        CreateScheduledJob(scheduled_job_repository()),
    )
    app.dependency_overrides[provide_list_logging_tasks] = lambda: ListLoggingTasks(
        logging_task_repository()
    )
    app.dependency_overrides[provide_get_logging_task_detail] = lambda: GetLoggingTaskDetail(
        logging_task_repository()
    )
    app.dependency_overrides[provide_start_logging_task] = lambda: StartLoggingTask(
        logging_task_repository()
    )
    app.dependency_overrides[provide_pause_logging_task] = lambda: PauseLoggingTask(
        logging_task_repository()
    )
    app.dependency_overrides[provide_resume_logging_task] = lambda: ResumeLoggingTask(
        logging_task_repository()
    )
    app.dependency_overrides[provide_stop_logging_task] = lambda: StopLoggingTask(
        logging_task_repository()
    )
    # Mitloeschen (3b-3): der Delete-Override nutzt den Erben-Wrapper, der nach dem
    # Loeschen der Task-Definition den verwaisten monitoring_window-Job abraeumt
    # (ListScheduledJobs/DeleteScheduledJob ueber dem scheduled_job_repository()).
    app.dependency_overrides[provide_delete_logging_task] = lambda: (
        _DeleteLoggingTaskWithUnschedule(
            logging_task_repository(),
            ListScheduledJobs(scheduled_job_repository()),
            DeleteScheduledJob(scheduled_job_repository()),
        )
    )
    app.dependency_overrides[provide_check_log_volume] = lambda: CheckLogVolume(
        logging_rtt_repository()
    )
    # Logging-SLA (C-3): EIGENER SLA-Pfad neben GetSlaStats -- Task-Repo (fuer get +
    # interval_s) UND RTT-Repo (all_for), gefuettert in die reine compute_sla_stats.
    app.dependency_overrides[provide_get_logging_task_sla] = lambda: GetLoggingTaskSla(
        logging_task_repository(), logging_rtt_repository()
    )
    # Logging-Events (Schnitt 1b-events): Task-Repo (fuer get + 404) UND Event-Repo
    # (range) -- rohe LoggingEventRow-Flanken, die Wire-Projektion macht der Router.
    app.dependency_overrides[provide_get_logging_task_events] = lambda: GetLoggingTaskEvents(
        logging_task_repository(), logging_event_repository()
    )
    # Serien-RTT (Block 3c): Task-Repo (fuer get + 404) UND RTT-Repo (all_for/range) --
    # rohe LoggingRttSample-Messpunkte fuer die zeitfreie analyze_series; der Router
    # reicht sie zusammen mit den Event-Flanken in die Aggregation.
    app.dependency_overrides[provide_get_logging_task_rtt] = lambda: GetLoggingTaskRtt(
        logging_task_repository(), logging_rtt_repository()
    )

    app.add_api_websocket_route(
        "/ws/monitor", make_ws_monitor(monitor_broadcaster(), _monitor_status)
    )

    # ── alerting-Domaene v2 verdrahten (A.6, Regel 5: ports<->infra nur hier) ──
    # REST-only: alerting hat KEINEN Loop (kein lifespan-Umbau, kein WS). Drei Adapter:
    # das Rule-Repo teilt die cernis.db (lru_cache wie scan_history); der Notifier ist
    # zustandslos; der SmtpConfig-Adapter teilt sich den MIGRIERTEN settings-``repository()``
    # mit der bestehenden settings-Verdrahtung (das smtp_config-Setting lebt dort, nicht in
    # einem eigenen Repo). RaiseAlert hat KEINEN Endpunkt; ab A.7a ist er ueber die
    # monitoring->alerting-Naht (_MonitorAlertRaiser, im _build_run_monitor oben) am
    # monitor-Loop verdrahtet -- er bekommt dort Repo + Notifier + SmtpConfig.
    @lru_cache(maxsize=1)
    def alert_rule_repository() -> SqliteAlertRuleRepository:
        from modules.db_path import get_db_path

        return SqliteAlertRuleRepository(get_db_path())

    alert_notifier = AlertNotifierAdapter()

    def smtp_config_adapter() -> SettingsSmtpConfigAdapter:
        # Teilt das settings-``repository()`` (smtp_config-Setting). Pro Request frisch
        # gewickelt (haelt nur den Repo-Verweis) -- guenstig, kein lru_cache noetig.
        return SettingsSmtpConfigAdapter(repository())

    app.include_router(alerting_router)
    app.dependency_overrides[provide_get_alert_rules] = lambda: GetAlertRules(
        alert_rule_repository()
    )
    app.dependency_overrides[provide_add_alert_rule] = lambda: AddAlertRule(alert_rule_repository())
    app.dependency_overrides[provide_update_alert_rule] = lambda: UpdateAlertRule(
        alert_rule_repository()
    )
    app.dependency_overrides[provide_delete_alert_rule] = lambda: DeleteAlertRule(
        alert_rule_repository()
    )
    app.dependency_overrides[provide_get_alert_history] = lambda: GetAlertHistory(
        alert_rule_repository()
    )
    app.dependency_overrides[provide_get_smtp_config_raw] = lambda: GetSmtpConfigRaw(
        smtp_config_adapter()
    )
    app.dependency_overrides[provide_save_smtp_config] = lambda: SaveSmtpConfig(
        smtp_config_adapter()
    )
    app.dependency_overrides[provide_send_test_alert] = lambda: SendTestAlert(
        smtp_config_adapter(), alert_notifier
    )

    # ── security-Domaene v2 verdrahten (SEC.6, Regel 5: ports<->infra nur hier) ──
    # ARP-Guard: eigenes SQLite (teilt die DB mit settings/devices/scanning). Die drei
    # Inspektoren (cve/tls/creds) sind zustandslose stdlib-Adapter (kein modules-Import,
    # kein ADR-0007). RunArpScan WIEDERVERWENDET die bestehenden scanning-Adapter
    # ``arp_table`` + ``vendor_lookup`` (oben instanziiert) -- KEIN zweiter Adapter.
    # KEINE alerting-Naht: ARP-Alerts feuern keine alerting-Regeln (DF1, Naht-Notiz steht).
    @lru_cache(maxsize=1)
    def arp_guard_repository() -> SqliteArpGuardRepository:
        from modules.db_path import get_db_path

        return SqliteArpGuardRepository(get_db_path())

    cve_lookup_adapter = CveLookupAdapter()
    tls_inspector_adapter = TlsInspectorAdapter()
    default_creds_adapter = DefaultCredsCheckerAdapter()

    app.include_router(security_router)
    # RunArpScan: arp_table + vendor_lookup sind DIESELBEN Instanzen wie im scanning-Block
    # (Wiederverwendung, kein zweiter ArpTable/Vendor-Adapter).
    app.dependency_overrides[provide_run_arp_scan] = lambda: RunArpScan(
        arp_table, vendor_lookup, arp_guard_repository()
    )
    app.dependency_overrides[provide_get_arp_alerts] = lambda: GetArpAlerts(arp_guard_repository())
    app.dependency_overrides[provide_get_arp_baseline] = lambda: GetArpBaseline(
        arp_guard_repository()
    )
    app.dependency_overrides[provide_clear_arp_baseline] = lambda: ClearArpBaseline(
        arp_guard_repository()
    )
    app.dependency_overrides[provide_lookup_cves] = lambda: LookupCves(cve_lookup_adapter)
    app.dependency_overrides[provide_inspect_tls] = lambda: InspectTls(tls_inspector_adapter)
    app.dependency_overrides[provide_check_default_creds] = lambda: CheckDefaultCreds(
        default_creds_adapter
    )

    @app.exception_handler(SecretStoreUnavailableError)
    async def _on_secret_store_unavailable(
        _request: Request, _exc: SecretStoreUnavailableError
    ) -> JSONResponse:
        # Keystore-Ausfall ist ein Fehler, kein stiller Erfolg (ADR 0001).
        logger.error("secret_store_unavailable", operation=_exc.operation, key=_exc.key)
        return JSONResponse(
            status_code=503,
            content={"detail": "Secret-Speicher (OS-Keystore) ist nicht verfuegbar."},
        )

    # ── cve-Domaene verdrahten (ADR 0037, Regel 5: Quer-Domaenen-Naht nur hier) ──
    # CVE-Schwachstellen-Monitoring ueber den bekannten Geraete-Bestand. Die cve-Domaene
    # kennt WEDER security NOCH scanning/devices -- beide Quer-Nähte (Bestand+Ports,
    # NVD-Lookup) laufen AUSSCHLIESSLICH hier ueber quellen-agnostische Provider, die die
    # Fremd-Daten in die cve-eigenen Rand-Typen (InventoryHost/LookupCve) projizieren
    # (Muster BuildTopology, ADR 0035/0036).

    @lru_cache(maxsize=1)
    def cve_finding_repository() -> SqliteCveFindingRepository:
        from modules.db_path import get_db_path

        return SqliteCveFindingRepository(get_db_path())

    @lru_cache(maxsize=1)
    def cve_checkstate_repository() -> SqliteCveCheckStateRepository:
        from modules.db_path import get_db_path

        return SqliteCveCheckStateRepository(get_db_path())

    @lru_cache(maxsize=1)
    def cve_acknowledgement_repository() -> SqliteCveAcknowledgementRepository:
        from modules.db_path import get_db_path

        return SqliteCveAcknowledgementRepository(get_db_path())

    # Host-/Port-QUELLE des Worker (ADR 0037): der JUENGSTE gespeicherte Scan-Record. Er
    # traegt je Host MAC + IP + die offenen Ports MIT Servicename (EnrichedHost.ports), ist
    # PERSISTENT und ueberlebt Neustarts -- der Worker arbeitet damit gegen den letzten
    # bekannten Port-Stand je Host, OHNE dass ein brandneuer Scan noetig ist. Lesepfad wie
    # der topology/analysis-Schnitt B: list(1) -> juengste Summary, get() -> ScanRecord.
    # Ausfallsicher (Schnitt B): kein Scan ODER CorruptScanError -> ehrlich leerer Bestand
    # (der Worker schlaeft dann, kein NVD-Aufruf), kein Crash. Nur Ports mit state=="open"
    # gelten als offen (Muster _flagged_ports ~Z.874).
    class _ScanHistoryInventory:
        def list_hosts(self) -> list[InventoryHost]:
            summaries = scan_history_repository().list(1)
            if not summaries:
                return []
            try:
                record = scan_history_repository().get(summaries[0].scan_id)
            except CorruptScanError:
                logger.warning("cve.inventory_skipped_corrupt_scan", scan_id=summaries[0].scan_id)
                return []
            if record is None:
                return []
            hosts: list[InventoryHost] = []
            for h in record.hosts:
                if not h.mac:
                    # Ohne stabile MAC kein Pruefstand/Befund-Schluessel -> ueberspringen.
                    continue
                open_ports = tuple(
                    InventoryPort(p.port, p.service) for p in h.ports if p.state == "open"
                )
                hosts.append(InventoryHost(mac=h.mac, ip=h.ip, ports=open_ports))
            return hosts

    # CVE-Lookup-NAHT (ADR 0037): WIEDERVERWENDET den vorhandenen security-``cve_lookup_adapter``
    # (oben instanziiert) -- KEIN zweiter NVD-Adapter. Uebersetzt die cve-eigenen
    # InventoryPort -> ports.security.PortQuery und die zurueckkommenden CveFinding ->
    # cve-eigene LookupCve. Ehrlicher NVD-Ausfall (S3) liegt im Adapter (leere Liste +
    # Warn-Log, kein erfundener Befund); diese Naht erfindet nichts dazu.
    class _SecurityCveLookup:
        async def lookup(self, ports: Sequence[InventoryPort]) -> list[LookupCve]:
            queries = [PortQuery(port=p.port, service=p.service) for p in ports]
            findings = await cve_lookup_adapter.lookup_for_host(queries)
            return [
                LookupCve(
                    cve_id=f.cve_id,
                    description=f.description,
                    severity=f.severity,
                    cvss_score=f.cvss_score,
                    published=f.published,
                    port=f.port,
                    service=f.service,
                    url=f.url,
                )
                for f in findings
            ]

    cve_inventory = _ScanHistoryInventory()
    cve_lookup_provider = _SecurityCveLookup()

    # Auffrisch-Intervall (Fall 3) live aus der Setting ``cve_refresh_interval_hours``
    # (Default 24h, 0/leer = Auffrischung AUS). Als Provider-Callable -> Live-Reload, eine
    # geaenderte Setting wirkt beim naechsten tick. Ausfallsicher gegen kaputte Settings
    # (CorruptSettingError) und Nicht-Zahl-Werte -> Default; gibt Sekunden zurueck.
    def _cve_refresh_interval_seconds() -> float:
        hours = _read_cve_int_setting(
            repository(), "cve_refresh_interval_hours", _CVE_DEFAULT_REFRESH_HOURS
        )
        return hours * 3600.0

    def _build_run_cve_monitor() -> RunCveMonitor:
        interval = _read_cve_int_setting(
            repository(), "cve_scan_interval_seconds", _CVE_DEFAULT_SCAN_SECONDS
        )
        return RunCveMonitor(
            inventory=cve_inventory,
            lookup=cve_lookup_provider,
            findings=cve_finding_repository(),
            checkstate=cve_checkstate_repository(),
            refresh_interval_provider=_cve_refresh_interval_seconds,
            interval=interval,
        )

    app.include_router(cve_router)
    app.dependency_overrides[provide_get_active_findings] = lambda: GetActiveFindings(
        cve_finding_repository(), cve_acknowledgement_repository()
    )
    # Etappe 3a (ADR 0037): Lesepfad fuer die QUITTIERTEN Befunde (Spiegelbild, gleiche Repos).
    app.dependency_overrides[provide_get_acknowledged_findings] = lambda: GetAcknowledgedFindings(
        cve_finding_repository(), cve_acknowledgement_repository()
    )
    app.dependency_overrides[provide_get_cve_status] = lambda: GetCveMonitorStatus(
        cve_inventory,
        cve_checkstate_repository(),
        cve_finding_repository(),
        cve_acknowledgement_repository(),
        refresh_interval_provider=_cve_refresh_interval_seconds,
    )

    # Acknowledge-Schreibnaht (ADR 0037, Muster _acknowledge): Pass-Through an record(...).
    def _cve_acknowledge(mac: str, cve_id: str, port: int, action: str) -> None:
        cve_acknowledgement_repository().record(mac, cve_id, port, action)

    app.dependency_overrides[provide_cve_acknowledge] = lambda: _cve_acknowledge

    # ── scheduler-Domaene v2 verdrahten (Block 3a, Etappe 3b, Regel 5: ports<->infra nur hier) ──
    # Der v2-Scheduler haengt -- getrennt vom alten ApschedulerJobScheduler/_scheduled_scan,
    # der unberuehrt daneben weiterlaeuft -- an der laufenden App: ein REST-Router fuer die
    # Verwaltung der Jobs und ein Lifespan-Worker (gestartet weiter unten im Lifespan). Repo-
    # Factory wie die anderen Repos (injizierter db_path via get_db_path()), Muster cve.

    @lru_cache(maxsize=1)
    def scheduled_job_repository() -> SqliteScheduledJobRepository:
        from modules.db_path import get_db_path

        return SqliteScheduledJobRepository(get_db_path())

    # Handler-Registry (job_type -> JobHandler): erster Abnehmer monitoring_window (Block
    # 3b) registriert -- beendet einen RECURRING-Logging-Task am Ende seines
    # Gesamtzeitraums (StopLoggingTask ueber dem logging_task_repository()). Weitere
    # Job-Typen kommen hier dazu.
    _monitoring_window_handler = MonitoringWindowHandler(StopLoggingTask(logging_task_repository()))
    scheduler_handlers: dict[str, JobHandler] = {
        _monitoring_window_handler.job_type: _monitoring_window_handler,
    }

    def _build_run_scheduler() -> RunScheduler:
        return RunScheduler(scheduled_job_repository(), scheduler_handlers)

    # Anlege-Runner: baut aus dem flachen CreateJobBody den domain-DailyWindow + params-Tupel
    # und legt den Job ueber CreateScheduledJob an (Regel 4: die Projektion lebt HIER im
    # Composition Root, der api-Ring kennt domain/application nicht).
    def _scheduler_create(body: CreateJobBody) -> int:
        window = DailyWindow(
            start_minute=body.window.start_minute,
            end_minute=body.window.end_minute,
            weekdays=frozenset(body.window.weekdays),
            from_epoch=body.window.from_epoch,
            until_epoch=body.window.until_epoch,
        )
        params = tuple((k, v) for k, v in body.params)
        return CreateScheduledJob(scheduled_job_repository())(body.job_type, params, window)

    # Lese-Runner: projiziert jeden ScheduledJob auf die flache ScheduledJobOut-Wire-Form
    # (window flach ausgerollt, weekdays sortiert, state als str).
    def _scheduler_list() -> list[ScheduledJobOut]:
        return [
            ScheduledJobOut(
                id=job.id,
                job_type=job.job_type,
                params=[(k, v) for k, v in job.params],
                start_minute=job.window.start_minute,
                end_minute=job.window.end_minute,
                weekdays=sorted(job.window.weekdays),
                from_epoch=job.window.from_epoch,
                until_epoch=job.window.until_epoch,
                state=job.state.value,
            )
            for job in ListScheduledJobs(scheduled_job_repository())()
        ]

    # Zustands-Runner: pause/resume/delete je ein Pass-Through an den jeweiligen Use-Case.
    def _scheduler_pause(job_id: int) -> None:
        PauseScheduledJob(scheduled_job_repository())(job_id)

    def _scheduler_resume(job_id: int) -> None:
        ResumeScheduledJob(scheduled_job_repository())(job_id)

    def _scheduler_delete(job_id: int) -> None:
        DeleteScheduledJob(scheduled_job_repository())(job_id)

    app.include_router(scheduler_router)
    app.dependency_overrides[provide_scheduler_create] = lambda: _scheduler_create
    app.dependency_overrides[provide_scheduler_list] = lambda: _scheduler_list
    app.dependency_overrides[provide_scheduler_pause] = lambda: _scheduler_pause
    app.dependency_overrides[provide_scheduler_resume] = lambda: _scheduler_resume
    app.dependency_overrides[provide_scheduler_delete] = lambda: _scheduler_delete

    # ── capture-Domaene v2 verdrahten (C.4+5, Regel 5: ports<->infra nur hier) ──
    # REST (pcap/lldp) ueber duenne Use-Cases im api-Ring; der WS-Handler /ws/pcap
    # lebt im Composition Root (ws_pcap.py, Broadcaster-Adapter -> WS-Transport).
    # Drei langlebige Singletons (lru_cache, EINE Instanz pro App): der Sniffer (haelt
    # den AsyncSniffer + die scapy-Rohpakete fuer wrpcap), der LLDP-Sniffer und der
    # Broadcaster (den der RunCapture-Loop bespielt UND in den die /ws/pcap-Handler
    # subscriben -- beide teilen dieselben Subscriber). RunCapture + CaptureLldp halten
    # den Loop-State (Stats/Ringpuffer bzw. Nachbartabelle) und sind darum ebenfalls
    # Singletons. capture_task laeuft NICHT im startup (anders als der monitor-Loop) --
    # er startet on-demand ueber POST /api/pcap/start; der lifespan-shutdown cancelt ihn.
    @lru_cache(maxsize=1)
    def packet_sniffer() -> ScapyPacketSniffer:
        return ScapyPacketSniffer()

    @lru_cache(maxsize=1)
    def lldp_sniffer() -> ScapyLldpSniffer:
        return ScapyLldpSniffer()

    @lru_cache(maxsize=1)
    def capture_broadcaster() -> WebSocketCaptureBroadcaster:
        return WebSocketCaptureBroadcaster()

    # Ziel-Pfad der temp-pcap, die RunCapture.stop() schreibt (Altcode: _pcap_file im
    # tempdir mit Zeitstempel-Name -- hier ein fester Name pro App, der bei jedem Stop
    # ueberschrieben wird; status/save lesen den zuletzt geschriebenen Pfad).
    import tempfile

    _capture_pcap_path = str(Path(tempfile.gettempdir()) / "cernis_capture.pcap")

    @lru_cache(maxsize=1)
    def run_capture() -> RunCapture:
        return RunCapture(packet_sniffer(), capture_broadcaster(), _capture_pcap_path)

    @lru_cache(maxsize=1)
    def capture_lldp() -> CaptureLldp:
        return CaptureLldp(lldp_sniffer())

    # StartCapture-Composition-Callable: prueft (StartCapture-Use-Case) und startet bei
    # ok=True den RunCapture-Loop als Task (create_task + app.state.capture_task -- das
    # kennt nur der Composition Root, NICHT der api-Ring). Ein bereits laufender Capture
    # wird nicht doppelt gestartet (Altcode: if _capture_running: return ok) -- der alte
    # Task bleibt, das ``ok`` wird durchgereicht. Gibt das {ok,error} des Use-Case zurueck.
    def _start_capture(interface: str | None, bpf_filter: str, max_packets: int) -> dict[str, Any]:
        result = StartCapture(packet_sniffer())()
        if not result["ok"]:
            return result
        existing = getattr(app.state, "capture_task", None)
        if existing is not None and not existing.done():
            # Bereits ein Capture aktiv -- nicht doppelt starten (altcode-treu).
            return result
        app.state.capture_task = asyncio.create_task(
            run_capture().run(interface, bpf_filter, max_packets)
        )
        return result

    def _stop_capture() -> None:
        run_capture().stop()

    # save-Ziel-Verzeichnis (Filesystem-Policy -> Composition Root, NICHT Use-Case):
    # Desktop/Schreibtisch/Downloads/Home-Fallback, altcode-treu (main.api_pcap_save).
    def _save_dir() -> Path:
        home = Path.home()
        for candidate in [home / "Desktop", home / "Schreibtisch", home / "Downloads", home]:
            if candidate.is_dir():
                return candidate
        return home

    app.include_router(capture_router)
    app.dependency_overrides[provide_start_capture_uc] = lambda: StartCapture(packet_sniffer())
    app.dependency_overrides[provide_start_capture] = lambda: _start_capture
    app.dependency_overrides[provide_stop_capture] = lambda: _stop_capture
    app.dependency_overrides[provide_capture_status] = lambda: run_capture().status
    app.dependency_overrides[provide_recent_packets] = lambda: run_capture().recent_packets
    app.dependency_overrides[provide_pcap_path] = lambda: run_capture().pcap_path
    app.dependency_overrides[provide_save_dir] = lambda: _save_dir
    app.dependency_overrides[provide_capture_lldp] = lambda: capture_lldp()
    app.dependency_overrides[provide_get_lldp_neighbors] = lambda: GetLldpNeighbors(capture_lldp())

    # ── Topologie (ADR 0035): radialer Heimnetz-Graph ──────────────────────────
    # Regel 5: die Quer-Domaenen-Naht laeuft AUSSCHLIESSLICH hier im Composition
    # Root. BuildTopology kennt weder devices/scanning/interfaces noch infra -- es
    # bekommt drei schlanke Provider-Callables, die hier die Fremd-Daten in rohe
    # dicts/den Roh-Wert projizieren (Muster application.export.ScanProvider):
    #   * Hosts  <- WAEHLBARE Quelle (Nutzer-Wahl, s.u.): juengster Scan ODER Bestand,
    #   * Nachbarn <- akkumulierte LLDP/CDP-Tabelle (GetLldpNeighbors),
    #   * Gateway-IP <- primaeres Interface (ListInterfaces, async -> Coroutine-Provider).
    #
    # Host-Quelle als Nutzer-Wahl (Leitprinzip Karl: maximale Entscheidungsfreiheit,
    # Muster AUTO/MANUELL beim Polling): zwei Projektionen, der Endpunkt waehlt per
    # ``?source=`` welche (str -> Projektion-Hebung HIER, nicht im Use-Case).
    #   * "all_known": gesamter device_repository-Bestand (alle je gesehenen Geraete,
    #     auch offline) -- das bisherige Verhalten.
    def _topology_hosts_all_known() -> list[dict[str, str]]:
        devices = GetDevices(device_repository())(known_only=False)
        return [
            {
                "mac": d.mac,
                "ip": d.last_ip or "",
                "hostname": d.hostname,
                "vendor": d.vendor,
            }
            for d in devices
        ]

    #   * "last_scan": nur die Hosts des JUENGSTEN gespeicherten Scans (Live-Bild).
    #     Lesepfad wie der analysis-hosts-Schnitt (Schnitt B, s.u. ~Z.2374): das
    #     bestehende scan_history_repository() (lru_cache, im scanning-Block
    #     verdrahtet) -- list(1) liefert die juengste Summary, get() den ScanRecord
    #     mit den EnrichedHost-Objekten. KEIN neuer Scan-Zugriff, KEINE zweite
    #     Repo-Instanz. Ausfallsicher (Muster Schnitt B): kein Scan ODER ein
    #     CorruptScanError -> ehrlich leere Hostliste, kein Crash.
    def _topology_hosts_last_scan() -> list[dict[str, str]]:
        summaries = scan_history_repository().list(1)
        if not summaries:
            return []
        try:
            record = scan_history_repository().get(summaries[0].scan_id)
        except CorruptScanError:
            logger.warning("topology.hosts_skipped_corrupt_scan", scan_id=summaries[0].scan_id)
            return []
        if record is None:
            return []
        return [
            {
                "mac": h.mac,
                "ip": h.ip,
                "hostname": h.hostname,
                "vendor": h.vendor,
            }
            for h in record.hosts
        ]

    def _topology_neighbors() -> list[dict[str, str]]:
        neighbors = GetLldpNeighbors(capture_lldp())()
        return [
            {
                "source_mac": n.source_mac,
                "chassis_id": n.chassis_id,
                "system_name": n.system_name,
                "system_desc": n.system_desc,
                "port_id": n.port_id,
                "protocol": n.protocol,
            }
            for n in neighbors
        ]

    async def _topology_gateway() -> str:
        interfaces = await ListInterfaces(InterfaceDiscoveryAdapter())()
        for iface in interfaces:
            if iface.is_primary and iface.gateway:
                return iface.gateway
        return ""

    # Factory statt fertigem Use-Case: der Endpunkt reicht die gewaehlte ``source``
    # herein, hier faellt die Entscheidung, WELCHE Host-Projektion ``BuildTopology``
    # bekommt. So bleibt der Use-Case quellen-agnostisch (Regel 5: die Quelle-
    # Unterscheidung lebt in der Verdrahtung). Nachbarn/Gateway sind quellen-
    # unabhaengig und in beiden Faellen identisch.
    def _build_topology_for(source: TopologySource) -> BuildTopology:
        host_provider = (
            _topology_hosts_last_scan if source == "last_scan" else _topology_hosts_all_known
        )
        return BuildTopology(host_provider, _topology_neighbors, _topology_gateway)

    app.dependency_overrides[provide_build_topology] = lambda: _build_topology_for

    app.add_api_websocket_route("/ws/pcap", make_ws_pcap(capture_broadcaster()))

    # ── agent-Domaene v2 verdrahten (A.4+5, Regel 5: ports<->infra nur hier) ──
    # REST-only (Client-Seite): GET/POST/DELETE /api/agents + ping/scan. KEIN WS --
    # der einzige agent-WS (/agent/scan) lebt auf der ZURUECKGESTELLTEN Server-Seite
    # (modules.agent.create_agent_app), die hier nicht verdrahtet wird; der scan-
    # Endpunkt ist REST mit wait_for, der WebsocketsAgentScanClient macht die
    # ausgehende WS-Verbindung INTERN. Das Repository teilt die cernis.db (lru_cache
    # wie scan_history) und legt die remote_agents-Tabelle beim Bau selbst an
    # (_ensure_schema -- darum entfiel init_agents_db im lifespan). Der secret_store()
    # ist der SETTINGS-Singleton (oben): der Agent-Token lebt unter token_key(id) im
    # SELBEN Keystore, Variante-B-Trennung (Stammdaten im Repo, Secret getrennt).
    # Pinger/ScanClient sind zustandslos -> einmal gebaut, pro Request frisch um den
    # Use-Case gewickelt (guenstig). KEIN Exception-Handler noetig: AgentNotFoundError
    # mappt der api-Rand selbst auf 404, alles andere im scan-Pfad auf 503;
    # SecretStoreUnavailableError faengt der bestehende globale 503-Handler.
    @lru_cache(maxsize=1)
    def agent_repository() -> SqliteAgentRepository:
        from modules.db_path import get_db_path

        return SqliteAgentRepository(get_db_path())

    agent_pinger = UrllibAgentPinger()
    agent_scan_client = WebsocketsAgentScanClient()

    app.include_router(agent_router)
    app.dependency_overrides[provide_list_agents] = lambda: ListAgents(agent_repository())
    app.dependency_overrides[provide_save_agent] = lambda: SaveAgent(
        agent_repository(), secret_store()
    )
    app.dependency_overrides[provide_delete_agent] = lambda: DeleteAgent(
        agent_repository(), secret_store()
    )
    app.dependency_overrides[provide_ping_agent] = lambda: PingAgent(
        agent_repository(), agent_pinger, secret_store()
    )
    app.dependency_overrides[provide_scan_via_agent] = lambda: ScanViaAgent(
        agent_repository(), agent_scan_client, secret_store()
    )

    # ── System-/Glue-Endpunkte verdrahten (ADR-0004 P.1) ─────────────────────────
    # Self-contained Glue ohne Domaene. Die vier Provider reichen Infrastruktur in den
    # api-Ring (der infrastructure/modules NICHT kennen darf): Version, der reduzierte
    # Dependency-Report, die Interface-Liste (Uebergangs-Adapter) und der Browser-Opener.

    def _system_info() -> dict[str, Any]:
        # REDUZIERT (ADR-0004 P.1): version + nmap-Binary + nur die v2-real-genutzten
        # Deps. nmap via shutil.which (NICHT modules.portscan._find_nmap). Die mit
        # main.py sterbenden Quer-Deps (pysnmp/reportlab/fritzconnection/...) sind RAUS.
        import importlib.util
        import shutil

        return {
            "version": APP_VERSION,
            "nmap": shutil.which("nmap") is not None,
            "scapy": importlib.util.find_spec("scapy") is not None,
        }

    def _open_url(url: str) -> None:
        # Default-Opener: webbrowser.open. Der Schema-Guard (nur http/https) sitzt im
        # api-Rand (api/system.open_url) -- dieser Opener wird nur bei gueltiger URL
        # gerufen. Lokaler Import: kein webbrowser im App-Bau-Pfad.
        import webbrowser

        webbrowser.open(url)

    app.include_router(system_router)
    app.dependency_overrides[provide_version] = lambda: lambda: APP_VERSION
    app.dependency_overrides[provide_system_info] = lambda: _system_info
    app.dependency_overrides[provide_url_opener] = lambda: _open_url

    # ── interfaces-Domaene v2 verdrahten (I.3, loest den Uebergangs-Endpunkt ab) ──
    # Zustandsloser Adapter direkt instanziiert (Muster ArpTableAdapter): der
    # Use-Case holt die rohen Interfaces ueber den Port und reichert sie fachlich an
    # (type/status/is_primary). Die fruhere system.py-Glue-Naht + der Uebergangs-
    # Adapter infrastructure.interfaces sind entfallen.
    app.include_router(interfaces_router)
    app.dependency_overrides[provide_list_interfaces] = lambda: ListInterfaces(
        InterfaceDiscoveryAdapter()
    )

    # ── traffic-Domaene v2 verdrahten (T.3+T.4b-2, Per-App-Netzwerk-Monitoring) ──
    # GETEILTER Adapter-Singleton (lru_cache, Muster run_capture): Poller UND Leser
    # nutzen DIESELBE PsutilTrafficAdapter-Instanz -- sonst pollt der eine, liest der
    # andere aus einer zweiten Instanz. Der Adapter ist zustandslos, der Singleton
    # ist hier nur Disziplin (eine Quelle), kein State.
    @lru_cache(maxsize=1)
    def _traffic_adapter() -> PsutilTrafficAdapter:
        return PsutilTrafficAdapter()

    # PollThroughput-Singleton: haelt den Mess-/Raten-State ueber die Zeit. AUTO
    # (lifespan) UND MANUELL (Endpunkte) greifen auf DENSELBEN Singleton zu -- so
    # gibt es nur einen State, und der Doppelstart-Schutz (poll_task.done()) hindert
    # zwei parallele Loops. Intervall aus der Config (Vision-Regler).
    @lru_cache(maxsize=1)
    def _poll_throughput() -> PollThroughput:
        return PollThroughput(_traffic_adapter(), interval=cfg.traffic_poll_interval)

    # ListAppTraffic-Runner (Naht current_rates -> rates, Muster _monitor_status):
    # liest die Raten des laufenden Pollers ueber app.state (Fallback {} ohne Poller
    # -> ehrliche Stufe 1, Raten None) und reicht sie an den Use-Case. Greift auf den
    # GETEILTEN Adapter zu (gleiche Quelle wie der Poller).
    async def _list_app_traffic() -> list[Any]:
        poll = getattr(app.state, "poll_throughput", None)
        rates = poll.current_rates() if poll is not None else {}
        return await ListAppTraffic(_traffic_adapter())(rates)

    # MANUELL-Lebenszyklus (Muster _start_capture): startet den Poll-Loop als Task an
    # app.state, kein Doppelstart (task.done()-Check). AUTO (lifespan) nutzt denselben
    # Singleton + dieselben app.state-Keys -- laeuft AUTO bereits, verhindert der
    # done()-Check hier einen zweiten Task.
    def _start_poll() -> dict[str, Any]:
        poll = _poll_throughput()
        app.state.poll_throughput = poll
        existing = getattr(app.state, "poll_task", None)
        if existing is not None and not existing.done():
            return {"ok": True}  # bereits aktiv -- nicht doppelt starten
        app.state.poll_task = asyncio.create_task(poll.run())
        return {"ok": True}

    def _stop_poll() -> None:
        poll = getattr(app.state, "poll_throughput", None)
        if poll is not None:
            poll.stop()
        task = getattr(app.state, "poll_task", None)
        if task is not None:
            task.cancel()

    app.include_router(traffic_router)
    app.dependency_overrides[provide_list_app_traffic] = lambda: _list_app_traffic
    app.dependency_overrides[provide_check_traffic_permission] = lambda: CheckTrafficPermission(
        TrafficPermissionAdapter()
    )
    app.dependency_overrides[provide_start_poll] = lambda: _start_poll
    app.dependency_overrides[provide_stop_poll] = lambda: _stop_poll

    # ── sni-Domaene v2 verdrahten (ADR 0017, passiver SNI-Mitschnitt) ────────────
    # EIN langlebiger Adapter-Singleton (lru_cache, Muster run_capture/_traffic_adapter):
    # der Sniffer haelt die beiden Hintergrund-Threads (scapy-AsyncSniffer + psutil-
    # Poller) + den internen Ringpuffer (deque maxlen). RunSniCapture/GetObservedSni/
    # StartSniCapture teilen DENSELBEN Adapter -- EINE Erfassung pro App. KEIN Autostart
    # (anders als monitor/poll-AUTO): der Sniff startet on-demand ueber POST /api/sni/start.
    @lru_cache(maxsize=1)
    def sni_sniffer() -> ScapySniSniffer:
        return ScapySniSniffer()

    @lru_cache(maxsize=1)
    def run_sni() -> RunSniCapture:
        return RunSniCapture(sni_sniffer())

    # StartSni-Composition-Callable (Muster _start_capture): prueft (StartSniCapture)
    # und startet bei ok=True den Sniff. Anders als capture KEIN asyncio.create_task --
    # der Sniff laeuft in den Adapter-Threads, nicht in einer Coroutine. Der Callable
    # legt den Use-Case auf app.state, damit der lifespan-Shutdown ihn stoppen kann.
    # Ein echter Start-Fehler (Rechte/Geraet) wirft SniError -> globaler 503-Handler;
    # der regulaere Permission-Fall geht ueber die {ok,error}-Naht -> 403 VOR dem Start.
    def _start_sni(interface: str | None) -> dict[str, Any]:
        result = StartSniCapture(sni_sniffer())()
        if not result["ok"]:
            return result
        run_sni_uc = run_sni()
        app.state.run_sni = run_sni_uc
        run_sni_uc.start(interface)  # idempotent gegen einen bereits laufenden Sniff
        return result

    def _stop_sni() -> None:
        run_sni().stop()

    app.include_router(sni_router)
    app.dependency_overrides[provide_start_sni] = lambda: _start_sni
    app.dependency_overrides[provide_stop_sni] = lambda: _stop_sni
    app.dependency_overrides[provide_start_sni_uc] = lambda: StartSniCapture(sni_sniffer())
    app.dependency_overrides[provide_sni_running] = lambda: run_sni().is_running
    app.dependency_overrides[provide_get_observed_sni] = lambda: GetObservedSni(sni_sniffer())

    @app.exception_handler(SniError)
    async def _on_sni_error(_request: Request, exc: SniError) -> JSONResponse:
        # Ein echter Sniff-Start-Fehler (toter Sniffer-Thread/Geraet/scapy) ist ein
        # FEHLER, kein stiller Fallback (ADR 0001/S3). Muster DiagnosticsToolMissing/
        # ResolverToolMissing -> 503: infra-Exception, am Composition Root gemappt.
        logger.error("sni_error", error=str(exc))
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    # ── process-Domaene v2 verdrahten (P.3, reine Lese-Sicht aus /proc) ──────────
    # Zustandslose Adapter direkt instanziiert (Muster interfaces). Kein Poller, kein
    # app.state -- process ist reine Lese-Domaene. Der Runner entscheidet anhand view
    # zwischen flat()/tree() und serialisiert NICHT (das macht der api-Ring) -- er gibt
    # Domaenen-Objekte als list[Any] zurueck (flat: ProcessInfo-Liste; tree:
    # ProcessNode-Wald als Liste). Der api-Ring kennt keine domain-Typen, daher Any.
    def _process_adapter() -> PsutilProcessAdapter:
        return PsutilProcessAdapter()  # zustandslos, pro Aufruf billig

    async def _list_processes(view: str) -> list[Any]:
        uc = ListProcesses(_process_adapter())
        if view == "tree":
            return list(await uc.tree())  # Wald als Liste von ProcessNode
        return await uc.flat()  # flache ProcessInfo-Liste

    app.include_router(process_router)
    app.dependency_overrides[provide_list_processes] = lambda: _list_processes
    app.dependency_overrides[provide_check_process_permission] = lambda: CheckProcessPermission(
        ProcessPermissionAdapter()
    )

    # ── diagnostics-Domaene v2 verdrahten (1a: DNS + traceroute, ADR 0014) ────────
    # Zustandslose Adapter direkt instanziiert (Muster process/interfaces). Kein Poller,
    # kein app.state -- reine Frage-Antwort-Domaene. Die Runner reichen die HTTP-Parameter
    # an die duennen Use-Cases durch und geben das Domaenen-Objekt als Any zurueck (der
    # api-Ring serialisiert, kennt keine domain-Typen).
    async def _resolve_dns(query: str, types: list[str]) -> Any:
        # ``types`` kommt als list[str] vom api-Ring; die Werte sind die DnsRecordType-
        # Literale (FastAPI validiert sie nicht gegen das Literal -- der Adapter reicht
        # unbekannte Typen schlicht an dig weiter, eine leere Antwort ist kein Fehler).
        return await ResolveDns(DigDnsResolver())(query, types)  # type: ignore[arg-type]

    async def _run_traceroute(target: str, privileged: bool) -> Any:
        return await RunTraceroute(SystemTracerouteRunner())(target, privileged)

    app.include_router(diagnostics_router)
    app.dependency_overrides[provide_resolve_dns] = lambda: _resolve_dns
    app.dependency_overrides[provide_run_traceroute] = lambda: _run_traceroute
    app.dependency_overrides[provide_check_traceroute_permission] = lambda: (
        CheckTraceroutePermission(LinuxTraceroutePermission())
    )

    # ── diagnostics 1b: Tool-/Paketmanager-Erkennung verdrahten ───────────────────
    # Zustandslose which-Adapter direkt instanziiert (Muster oben). Der Runner reicht den
    # optionalen ``tools``-Param (None -> alle) an den synchronen Use-Case durch und gibt
    # den ToolReport als Any zurueck (der api-Ring serialisiert, kennt keine domain-Typen).
    # KEINE Selbst-Installation -- der Use-Case liefert nur den Befehls-TEXT.
    def _check_tools(tools: list[str] | None) -> Any:
        return CheckDiagnosticsTools(ShutilToolDetector(), LinuxPackageManagerDetector())(tools)

    app.dependency_overrides[provide_check_tools] = lambda: _check_tools

    # ── diagnostics 2a: Banner-Grabbing verdrahten ────────────────────────────────
    # Zustandsloser asyncio-Socket-Adapter direkt instanziiert (Muster oben). Der Runner
    # reicht target/port an den duennen Use-Case durch und gibt das BannerResult als Any
    # zurueck (der api-Ring serialisiert, kennt keine domain-Typen). KEIN Tool-/Rechte-
    # Thema -- ein gewoehnlicher TCP-Connect. KEINE konfigurierbaren Payloads.
    async def _grab_banner(target: str, port: int) -> Any:
        return await GrabBanner(SocketBannerGrabber())(target, port)

    app.dependency_overrides[provide_grab_banner] = lambda: _grab_banner

    @app.exception_handler(DiagnosticsToolMissing)
    async def _on_diagnostics_tool_missing(
        _request: Request, exc: DiagnosticsToolMissing
    ) -> JSONResponse:
        # Fehlendes System-Binary (dig/traceroute) ist ein Fehler, kein stiller Fallback
        # (ADR 0001). Vorbild SecretStoreUnavailableError: infra-Exception -> 503. Die
        # neutrale Meldung benennt das fehlende Programm; der Install-Hinweis folgt in 1b.
        logger.error("diagnostics_tool_missing", tool=exc.tool)
        return JSONResponse(status_code=503, content={"detail": exc.message})

    # ── diagnostics 2b: externer IP/Port-Check via cpnetcheck verdrahten ───────────
    # Modell D: der Use-Case liest URL (settings-``repository()``) + Token (``secret_store()``,
    # die DIESELBEN lazy-memoisierten Factories wie settings/agent) und ruft den
    # httpx-Provider NUR, wenn beides gesetzt ist. Der Runner reicht die optionale Portliste
    # (None -> reiner IP-Check) an den Use-Case durch und gibt das ExternalCheckResult als
    # Any zurueck (der api-Ring serialisiert, kennt keine domain-Typen). Der Provider ist
    # zustandslos (httpx.AsyncClient pro Aufruf) -- pro Request frisch gewickelt, kein State.
    async def _check_external(ports: list[int] | None) -> Any:
        return await CheckExternalReachability(
            HttpxReachabilityProvider(), repository(), secret_store()
        )(ports)

    app.dependency_overrides[provide_check_external] = lambda: _check_external

    @app.exception_handler(ExternalCheckFailed)
    async def _on_external_check_failed(
        _request: Request, exc: ExternalCheckFailed
    ) -> JSONResponse:
        # Externer cpnetcheck-Dienst gescheitert -> 502 (Bad Gateway, der Fehler liegt im
        # externen Dienst, nicht in CERNIS). Vorbild DiagnosticsToolMissing -> 503: infra-
        # Exception, am Composition Root gemappt. Die Meldung ist NEUTRAL -- der Adapter hat
        # bereits jeden Token/internen Detail entfernt; hier wird NICHTS Zusaetzliches
        # geloggt, was den Token enthalten koennte.
        logger.error("external_check_failed")
        return JSONResponse(status_code=502, content={"detail": exc.message})

    # ── diagnostics 3: Rogue-DHCP-Erkennung verdrahten ────────────────────────────
    # Zustandslose Adapter direkt instanziiert (Muster process/interfaces). Der Use-Case
    # zieht die erwartete Menge selbst (Setting expected_dhcp_servers via repository() ODER
    # Gateway-Fallback ueber den BESTEHENDEN interfaces-Port InterfaceDiscoveryAdapter, Muster
    # wie 2b settings/secret injiziert). Vor dem Discovery prueft er die Root-Rechte
    # (LinuxDhcpPermission); ohne Root wirft er RogueDhcpPermissionError -> 403 (Handler
    # unten), der Probe laeuft NIE blind. Der Runner gibt das RogueDhcpResult als Any zurueck.
    #
    # Persistenz (ADR 0038): der Singleton-Store (SqliteRogueDhcpRepository, eigene
    # rogue_dhcp_latest-Tabelle in cernis.db) wird injiziert + time.time() als checked_ts
    # hereingereicht (KEINE Wanduhr im Use-Case, Muster ResumeActiveLoggingTasks(time.time())).
    # Der Use-Case speichert so nach JEDEM erfolgreichen Lauf ueberschreibend den letzten
    # Stand fuer den spaeteren Sicherheitsbericht. Schema-Init geschieht im Adapter-Konstruktor
    # (lazy-memoisiert wie die anderen Repos -- haelt nur den db_path, zustandslos).
    @lru_cache(maxsize=1)
    def rogue_dhcp_repository() -> SqliteRogueDhcpRepository:
        from modules.db_path import get_db_path

        return SqliteRogueDhcpRepository(get_db_path())

    async def _detect_rogue_dhcp() -> Any:
        import time

        return await DetectRogueDhcp(
            NmapDhcpProbe(),
            LinuxDhcpPermission(),
            repository(),
            InterfaceDiscoveryAdapter(),
            rogue_dhcp_repository(),
        )(time.time())

    app.dependency_overrides[provide_detect_rogue_dhcp] = lambda: _detect_rogue_dhcp
    app.dependency_overrides[provide_check_dhcp_permission] = lambda: CheckDhcpPermission(
        LinuxDhcpPermission()
    )

    @app.exception_handler(RogueDhcpPermissionError)
    async def _on_rogue_dhcp_permission(
        _request: Request, exc: RogueDhcpPermissionError
    ) -> JSONResponse:
        # Rogue-DHCP ohne Root (oder nmap fehlt) -> 403 (die Discovery ist nicht erlaubt,
        # nicht der Dienst kaputt). Ehrliche Sperre, kein stiller Fallback (S3) -- der Probe
        # wurde NICHT gerufen. Muster der Tool-fehlt-/Dienst-Naht: das Mapping sitzt am
        # Composition Root, der api-Ring bleibt clean. Die Meldung ist die Rechte-Begruendung.
        logger.error("rogue_dhcp_permission_denied")
        return JSONResponse(status_code=403, content={"detail": exc.message})

    # ── resolver-Domaene v2 verdrahten (Teilschritt 3, Regel 5: ports<->infra nur hier) ──
    # Vier Quell-Adapter: PTR/Forward-DNS (dig), RDAP (httpx), TLS-Cert (stdlib ssl) sind
    # zustandslos und werden pro Request frisch gewickelt. Die Geo/ASN-DB (CsvGeoAsnDb) ist
    # die EINE Ausnahme: ihr Konstruktor LAEDT die vier CSVs in sortierte Listen -- darum
    # EINMAL beim App-Bau (lru_cache, Muster wie scan_history_repository), NICHT pro Request.
    # Fehlt eine CSV, wirft sie beim ERSTEN Lookup-Bau ResolverDataMissing -> 503 (Handler
    # unten); der Bau selbst ist lazy (erst beim ersten /api/resolve, nicht beim App-Bau --
    # so faellt ein Test ohne Daten-CSVs nicht schon beim create_app um).
    @lru_cache(maxsize=1)
    def geo_asn_db() -> CsvGeoAsnDb:
        return CsvGeoAsnDb()

    # PTR/Forward-DNS-Adapter (dig) EINMAL gebaut und geteilt: er ist zustandslos, und
    # GENAU DIESELBE Instanz traegt sowohl den reichen ResolveEndpoint als auch den
    # schlanken Batch-PTR-Use-Case (Paket 5, Auftrag: eine Instanz wiederverwenden, nicht
    # neu bauen). Kein lru_cache noetig -- der Adapter haelt keinen Zustand.
    ptr_resolver = DigDnsPtrResolver()

    # Runner: reicht ip/port an den ResolveEndpoint-Use-Case durch und gibt das
    # RemoteEndpointFacts als Any zurueck (der api-Ring serialisiert, kennt keine domain-
    # Typen). Die zwei zustandslosen Adapter (RDAP/TLS) pro Aufruf frisch; die Geo-DB und
    # der PTR-Adapter geteilt.
    async def _resolve_endpoint(ip: str, port: int | None) -> Any:
        return await ResolveEndpoint(
            ptr_resolver, RdapClient(), geo_asn_db(), TlsCertReader()
        ).resolve(ip, port)

    # Batch-PTR (Paket 5): EINE langlebige ResolvePtrBatch-Instanz pro App -- ihr
    # prozesslokaler TTL-Cache lebt am Use-Case-Objekt und soll ueber Requests hinweg
    # greifen (eine frische Instanz pro Request haette einen stets leeren Cache). Nutzt
    # DENSELBEN ptr_resolver wie ResolveEndpoint. Der Marker liefert immer diese Instanz.
    resolve_ptr_batch_uc = ResolvePtrBatch(ptr_resolver)

    app.include_router(resolver_router)
    app.dependency_overrides[provide_resolve_endpoint] = lambda: _resolve_endpoint
    app.dependency_overrides[provide_resolve_ptr_batch] = lambda: resolve_ptr_batch_uc

    @app.exception_handler(ResolverToolMissing)
    async def _on_resolver_tool_missing(
        _request: Request, exc: ResolverToolMissing
    ) -> JSONResponse:
        # Fehlendes System-Binary (dig) ist ein Fehler, kein stiller Fallback (ADR 0001).
        # Vorbild DiagnosticsToolMissing -> 503: infra-Exception, am Composition Root
        # gemappt. Die neutrale Meldung benennt das fehlende Programm.
        logger.error("resolver_tool_missing", tool=exc.tool)
        return JSONResponse(status_code=503, content={"detail": exc.message})

    @app.exception_handler(ResolverDataMissing)
    async def _on_resolver_data_missing(
        _request: Request, exc: ResolverDataMissing
    ) -> JSONResponse:
        # Fehlende Geo/ASN-CSV ist ein echter Konfigurationsfehler, kein stiller Leer-
        # Fallback (S3). Gleiches Muster wie ResolverToolMissing -> 503: infra-Exception,
        # am Composition Root gemappt. Die Meldung benennt die fehlende Datei.
        logger.error("resolver_data_missing", path=exc.path)
        return JSONResponse(status_code=503, content={"detail": exc.message})

    # ── outbound-Domaene v2 verdrahten (Block 2, Etappe 2b; Regel 5: Naht nur hier) ──
    # Die Aussenkontakt-Sicht DIESES Hosts fuehrt DREI Quellen zusammen
    # (Verbindungen/Namen/Geo). Der application-Ring (BuildOutboundContacts) nennt
    # KEINE dieser Quell-Domaenen -- die drei quellen-agnostischen Provider werden HIER
    # aus den bestehenden Root-Helfern gebaut (traffic/resolver/sni bleiben getrennt).
    # Reuse der schon in Scope stehenden Helfer: _traffic_adapter(), resolve_ptr_batch_uc,
    # _resolve_endpoint, sni_sniffer()/GetObservedSni -- nichts davon neu bauen.
    async def _outbound_contacts() -> OutboundOverviewOut:
        # (1) Verbindungs-Provider SYNCHRON im Protocol-Sinn: BuildOutboundContacts ruft
        # den Provider synchron, list_connections() ist aber async. Sauberste Loesung im
        # Rahmen der 2a-Signatur: den Snapshot EINMAL hier async holen und einen sync
        # Provider (Closure ueber die schon geholte Liste) hereinreichen. Mappt
        # domain.traffic.Connection -> RawConnection und filtert remote=None raus (der
        # Provider liefert NUR Verbindungen mit Gegenstelle).
        conns = await _traffic_adapter().list_connections()
        raws = [
            RawConnection(
                remote_ip=c.remote.ip,
                remote_port=c.remote.port,
                app_name=c.app_name,
                pid=c.pid,
            )
            for c in conns
            if c.remote is not None
        ]

        def _connections_provider() -> list[RawConnection]:
            return raws

        # (2) Namens-Provider (async, ips -> {ip: hostname|None}): kombiniert SNI (konkreter,
        # app-naeher) mit PTR. Regel pro IP: zuerst der SNI-Hostname, sonst der PTR-Name,
        # sonst None -- ueber alle angefragten IPs.
        async def _hostname_provider(ips: Sequence[str]) -> dict[str, str | None]:
            wanted = set(ips)
            sni_by_ip: dict[str, str] = {}
            for observed in GetObservedSni(sni_sniffer())():
                if observed.remote_ip in wanted:
                    # Erster SNI-Treffer je IP gewinnt (deterministisch ueber die Reihenfolge).
                    sni_by_ip.setdefault(observed.remote_ip, observed.hostname)
            ptr_by_ip = await resolve_ptr_batch_uc(tuple(ips))
            return {ip: sni_by_ip.get(ip) or ptr_by_ip.get(ip) for ip in ips}

        # (3) Geo/Betreiber/ASN-Provider (async, ip -> (country, operator, asn)): projiziert
        # die RemoteEndpointFacts aus _resolve_endpoint defensiv. country: GeoDB vor RDAP-Netz;
        # operator: asn_org (Klartext); asn: asn-Nummer. Jedes Feld kann None sein -- dann
        # bleibt die Komponente None (BuildOutboundContacts kapselt try/except schon; hier nur
        # ehrlich projizieren, S3).
        async def _geo_operator_provider(
            ip: str,
        ) -> tuple[str | None, str | None, str | None]:
            facts = await _resolve_endpoint(ip, None)
            country = facts.country_geodb.value or facts.country_rdap_net.value
            operator = facts.asn_org.value or (f"AS{facts.asn.value}" if facts.asn.value else None)
            asn = facts.asn.value
            return (country, operator, asn)

        overview = await BuildOutboundContacts(
            _connections_provider, _hostname_provider, _geo_operator_provider
        )()
        # Projektion application.OutboundOverview -> api.OutboundOverviewOut (Regel 4:
        # der api-Ring kennt den application-Typ NICHT; die Projektion faellt hier im Root).
        return OutboundOverviewOut(
            contacts=[
                OutboundContactOut(
                    remote_ip=contact.remote_ip,
                    remote_port=contact.remote_port,
                    hostname=contact.hostname,
                    country=contact.country,
                    operator=contact.operator,
                    asn=contact.asn,
                    app_name=contact.app_name,
                    pid=contact.pid,
                    connection_count=contact.connection_count,
                )
                for contact in overview.contacts
            ],
            host_scope=overview.host_scope,
        )

    # Snapshot-Naht des Aussenkontakte-Recorders (E3b): liefert den AKTUELLEN Snapshot
    # DIESES Hosts als list[ContactDelta] (eine je Remote-IP). Nutzt DIESELBE
    # Provider-Kette wie _outbound_contacts (traffic-conns -> RawConnection, SNI+PTR-Namen,
    # Geo/Operator) ueber denselben Use-Case BuildOutboundContacts und mappt dessen
    # OutboundContact-Ergebnisse 1:1 auf ContactDelta -- der sauberste Reuse ohne Duplikat
    # der Gruppierungs-/Anreicherungslogik. Unterschied zu _outbound_contacts: KEINE
    # api-Projektion (kein OutboundOverviewOut), KEIN pid (ContactDelta fuehrt kein pid).
    async def _outbound_contact_deltas() -> list[ContactDelta]:
        conns = await _traffic_adapter().list_connections()
        raws = [
            RawConnection(
                remote_ip=c.remote.ip,
                remote_port=c.remote.port,
                app_name=c.app_name,
                pid=c.pid,
            )
            for c in conns
            if c.remote is not None
        ]

        def _connections_provider() -> list[RawConnection]:
            return raws

        async def _hostname_provider(ips: Sequence[str]) -> dict[str, str | None]:
            wanted = set(ips)
            sni_by_ip: dict[str, str] = {}
            for observed in GetObservedSni(sni_sniffer())():
                if observed.remote_ip in wanted:
                    sni_by_ip.setdefault(observed.remote_ip, observed.hostname)
            ptr_by_ip = await resolve_ptr_batch_uc(tuple(ips))
            return {ip: sni_by_ip.get(ip) or ptr_by_ip.get(ip) for ip in ips}

        async def _geo_operator_provider(
            ip: str,
        ) -> tuple[str | None, str | None, str | None]:
            facts = await _resolve_endpoint(ip, None)
            country = facts.country_geodb.value or facts.country_rdap_net.value
            operator = facts.asn_org.value or (f"AS{facts.asn.value}" if facts.asn.value else None)
            asn = facts.asn.value
            return (country, operator, asn)

        overview = await BuildOutboundContacts(
            _connections_provider, _hostname_provider, _geo_operator_provider
        )()
        # 1:1-Map OutboundContact -> ContactDelta (ohne pid -- ContactDelta fuehrt es nicht;
        # die App-Zuordnung bleibt in app_name).
        return [
            ContactDelta(
                remote_ip=contact.remote_ip,
                remote_port=contact.remote_port,
                hostname=contact.hostname,
                country=contact.country,
                operator=contact.operator,
                asn=contact.asn,
                app_name=contact.app_name,
                connection_count=contact.connection_count,
            )
            for contact in overview.contacts
        ]

    # Worker-Factory des Aussenkontakte-Recorders (E3b, Muster _build_run_cve_monitor):
    # verdrahtet die drei outbound_log-Repos + die Snapshot-Naht _outbound_contact_deltas.
    # interval/retention bleiben Default (rec.interval_s pro Tick, 24-h-Detail-Retention).
    def _build_run_outbound_recorder() -> RunOutboundRecorder:
        return RunOutboundRecorder(
            outbound_recording_repository(),
            outbound_detail_repository(),
            outbound_aggregate_repository(),
            _outbound_contact_deltas,
        )

    app.include_router(outbound_router)
    app.dependency_overrides[provide_outbound_contacts] = lambda: _outbound_contacts

    # ── Aussenkontakte-Aufzeichnung v2 verdrahten (E4; Regel 5: Naht nur hier) ──
    # Lifecycle-/Lese-Use-Cases ueber den drei outbound_log-Repos (E3b, db_path-Factory +
    # lru_cache-Singleton oben). Muster wie die monitoring-Logging-Use-Cases: jeder Marker
    # bekommt eine Lambda, die den Use-Case mit den passenden Repos baut. Der Recorder-Worker
    # (Lifespan) ist davon getrennt -- hier NUR die REST-Endpunkte.
    # CreateOutboundRecording/Start/Pause/Resume/Stop/List/Get arbeiten allein ueber dem
    # Recording-Repo; GetOutboundAggregate ueber dem Aggregate-Repo, GetOutboundDetailRange
    # ueber dem Detail-Repo. DeleteOutboundRecording braucht ALLE DREI Repos (loescht die
    # Definition + raeumt die Aggregate; das Detail-Repo wird gehalten, s. Use-Case-Docstring).
    app.include_router(outbound_log_router)
    app.dependency_overrides[provide_create_outbound_recording] = lambda: CreateOutboundRecording(
        outbound_recording_repository()
    )
    app.dependency_overrides[provide_start_outbound_recording] = lambda: StartOutboundRecording(
        outbound_recording_repository()
    )
    app.dependency_overrides[provide_pause_outbound_recording] = lambda: PauseOutboundRecording(
        outbound_recording_repository()
    )
    app.dependency_overrides[provide_resume_outbound_recording] = lambda: ResumeOutboundRecording(
        outbound_recording_repository()
    )
    app.dependency_overrides[provide_stop_outbound_recording] = lambda: StopOutboundRecording(
        outbound_recording_repository()
    )
    app.dependency_overrides[provide_delete_outbound_recording] = lambda: DeleteOutboundRecording(
        outbound_recording_repository(),
        outbound_detail_repository(),
        outbound_aggregate_repository(),
    )
    app.dependency_overrides[provide_list_outbound_recordings] = lambda: ListOutboundRecordings(
        outbound_recording_repository()
    )
    app.dependency_overrides[provide_get_outbound_recording] = lambda: GetOutboundRecording(
        outbound_recording_repository()
    )
    app.dependency_overrides[provide_get_outbound_aggregate] = lambda: GetOutboundAggregate(
        outbound_aggregate_repository()
    )
    app.dependency_overrides[provide_get_outbound_detail_range] = lambda: GetOutboundDetailRange(
        outbound_detail_repository()
    )

    # ── dns_watch-Domaene v2 verdrahten (Block 2, Etappe 2d-3; Regel 5: Naht nur hier) ──
    # Die DNS-Befund-Sicht DIESES Hosts fuehrt FUENF Quellen zusammen
    # (Verbindungen/Namen/Quittierungen/erwartete-Server/DoH-Listen). Der application-Ring
    # (BuildDnsWatch) nennt KEINE Quell-Domaene -- die Provider werden HIER aus den schon
    # in Scope stehenden Root-Helfern gebaut (NICHTS neu): _traffic_adapter(),
    # GetObservedSni/sni_sniffer(), resolve_ptr_batch_uc, repository() (Settings),
    # _topology_gateway() (Gateway des primaeren Interface). Die zwei editierbaren Listen
    # sind normale Listen-Settings (value = JSON-Liste von IP-Strings).
    @lru_cache(maxsize=1)
    def dns_watch_acknowledgement_repository() -> SqliteDnsWatchAcknowledgementRepository:
        from modules.db_path import get_db_path

        return SqliteDnsWatchAcknowledgementRepository(get_db_path())

    def _dns_watch_read_list(key: str) -> list[str]:
        # Liest einen Settings-Key defensiv als Liste von Strings (S3: kein Wurf bei
        # fehlendem/krummem Wert). get_all() liefert den JSON-decodierten Wert; ist er
        # eine Liste -> als Strings, sonst leere Liste (dann greift der domain-Default).
        value = repository().get_all().get(key)
        if isinstance(value, list):
            return [str(x) for x in value]
        return []

    async def _dns_watch() -> DnsWatchOverviewOut:
        # (1) Verbindungs-Provider: GENAU wie im outbound-Block den Snapshot EINMAL async
        # holen und einen sync Closure-Provider darueber reichen (BuildDnsWatch ruft den
        # Provider synchron). Mappt domain.traffic.Connection -> RawDnsConnection und
        # filtert remote=None raus (nur Verbindungen mit Gegenstelle).
        conns = await _traffic_adapter().list_connections()
        raws = [
            RawDnsConnection(
                remote_ip=c.remote.ip,
                remote_port=c.remote.port,
                l4=c.l4,
                app_name=c.app_name,
                pid=c.pid,
            )
            for c in conns
            if c.remote is not None
        ]

        def _connections_provider() -> list[RawDnsConnection]:
            return raws

        # (2) Namens-Provider (async, ips -> {ip: hostname|None}): dieselbe SNI+PTR-Logik
        # wie im outbound-Block -- eigene lokale Closure (NICHT refaktoriert). Regel pro IP:
        # zuerst der SNI-Hostname, sonst der PTR-Name, sonst None.
        async def _hostname_provider(ips: Sequence[str]) -> dict[str, str | None]:
            wanted = set(ips)
            sni_by_ip: dict[str, str] = {}
            for observed in GetObservedSni(sni_sniffer())():
                if observed.remote_ip in wanted:
                    sni_by_ip.setdefault(observed.remote_ip, observed.hostname)
            ptr_by_ip = await resolve_ptr_batch_uc(tuple(ips))
            return {ip: sni_by_ip.get(ip) or ptr_by_ip.get(ip) for ip in ips}

        # (3) Gateway des primaeren Interface fuer den expected-Default (sonst leer/None);
        # ueber den schon vorhandenen Interface-Weg (_topology_gateway, kein neuer Adapter).
        gateway = await _topology_gateway()

        # (4) Die fuenf Provider fuer BuildDnsWatch: acknowledged liest die quittierten
        # Befund-Schluessel; die zwei Listen-Closures fallen ueber die domain-Defaults
        # (Gateway-Fallback bzw. DoH-Startliste), wenn der Nutzer nichts konfiguriert hat.
        overview = await BuildDnsWatch(
            _connections_provider,
            _hostname_provider,
            dns_watch_acknowledgement_repository().acknowledged_keys,
            lambda: expected_servers_or_default(
                _dns_watch_read_list(DNS_EXPECTED_SERVERS_KEY), gateway
            ),
            lambda: doh_providers_or_default(_dns_watch_read_list(DNS_DOH_PROVIDERS_KEY)),
        )()
        # Projektion application.DnsWatchOverview -> api.DnsWatchOverviewOut (Regel 4:
        # der api-Ring kennt den application-Typ NICHT; die Projektion faellt hier im Root).
        return DnsWatchOverviewOut(
            contacts=[
                DnsContactOut(
                    remote_ip=contact.remote_ip,
                    remote_port=contact.remote_port,
                    category=contact.category,
                    hostname=contact.hostname,
                    app_name=contact.app_name,
                    pid=contact.pid,
                    connection_count=contact.connection_count,
                    acknowledged=contact.acknowledged,
                )
                for contact in overview.contacts
            ],
            host_scope=overview.host_scope,
            counts=dict(overview.counts),
            expected_servers=list(overview.expected_servers),
            doh_providers=list(overview.doh_providers),
        )

    def _dns_watch_acknowledge(remote_ip: str, category: str, action: str) -> None:
        # Schreib-Naht analog _acknowledge: EINE append-only Log-Zeile (ack/unack).
        dns_watch_acknowledgement_repository().record(remote_ip, category, action)

    app.include_router(dns_watch_router)
    app.dependency_overrides[provide_dns_watch] = lambda: _dns_watch
    app.dependency_overrides[provide_dns_watch_acknowledge] = lambda: _dns_watch_acknowledge

    # ── Sicherheitsbericht: Fuenf-Quellen-Projektion (Etappe 2b, Regel 5/Composition Root) ──
    # DIESE Naht KENNT alle fuenf Quell-Domaenen (analysis/cve/security/dns_watch/diagnostics)
    # und darf laut import-linter NUR hier im Composition Root liegen. Sie ruft die fuenf
    # echten Quellen ab, projiziert sie auf die NEUTRALEN Berichts-Typen (ReportPortFinding/
    # ReportCveFinding/ReportNetFinding) und reicht die fertigen Listen an den duennen
    # Use-Case ``BuildSecurityReport`` -> ``build_security_report``. KEIN HTTP-Endpunkt (das
    # ist Etappe 2c); hier nur die ehrliche Datenseite. Die Funktion ist async (zwei Quellen
    # -- DNS-Waechter, jueng. Scan-Helfer -- sind ohnehin async im Bestand) und gibt den
    # fertigen ``SecurityReport`` zurueck SAMT der zwei ehrlichen Statusfelder (has_scan,
    # rogue_dhcp_checked_ts); der Endpunkt-Runner (Etappe 2c) projiziert sie auf die Wire-Form.
    # Rueckgabe als kleines lokales Tupel (SecurityReport, has_scan, checked_ts): beide
    # Statuswerte liegen HIER ohnehin vor (ob ein Scan-record als Basis vorlag, und der
    # rogue-Stand wird unten gelesen) -- so vermeidet die Naht jede Doppelarbeit (keine
    # zweite Scan-/Rogue-Lesung im Endpunkt-Runner, Auftrag Etappe 2c).
    async def _build_security_report_data() -> tuple[SecurityReport, bool, float | None]:
        # (1) JUENGSTER SCAN als Basis (analysis-Schnitt-B-Muster, list(1)->get->record.hosts,
        # ausfallsicher). Kein Scan / kaputter Scan -> ehrlich leere Basis: leere
        # device_labels + leere Findings -> build_security_report liefert Score 100 ueber
        # leere Basis. ``has_scan`` haelt ehrlich fest, OB ein Scan-record als Basis vorlag
        # (record is not None) -- ein leerer, aber existierender Scan zaehlt als has_scan True.
        base_hosts: list[EnrichedHost] = []
        has_scan = False
        summaries = scan_history_repository().list(1)
        if summaries:
            try:
                record = scan_history_repository().get(summaries[0].scan_id)
            except CorruptScanError:
                logger.warning(
                    "security_report.base_scan_skipped_corrupt", scan_id=summaries[0].scan_id
                )
                record = None
            if record is not None:
                has_scan = True
                base_hosts = list(record.hosts)

        # device_label EINES Scan-Hosts: kuratierter Anzeigename (label) falls vorhanden,
        # sonst hostname, sonst ip, sonst mac. EINE Quelle der Label-Bildung (auch der ARP-/
        # DNS-/Rogue-Match-Schluessel unten nutzt ip/mac konsistent zu dieser Reihenfolge).
        def _host_label(host: EnrichedHost) -> str:
            return host.label or host.hostname or host.ip or host.mac

        # (7) device_labels = ALLE Geraete des juengsten Scans (Basis N), unabhaengig davon ob
        # sie Findings haben. Das ``archived``-Flag existiert noch nicht -> alle zaehlen; der
        # archived-Ausschluss dockt spaeter GENAU HIER an (Vorfilter der base_hosts).
        device_labels = [_host_label(host) for host in base_hosts]
        # Schneller mac/ip -> device_label-Index der Basis fuer das Zuordnen der quellen-
        # eigenen Schluessel (CVE liefert mac/ip, ARP ip, DNS remote_ip). Ein Quell-Befund
        # OHNE Basis-Treffer behaelt seinen eigenen Schluessel als Label (s. Kommentar (8)).
        label_by_mac = {host.mac: _host_label(host) for host in base_hosts if host.mac}
        label_by_ip = {host.ip: _host_label(host) for host in base_hosts if host.ip}

        # (2) PORTS: je Host die Achse-B-Bewertung ueber GENAU die vorhandenen Helfer + denselben
        # gefilterten Provider (Single Source, Konsistenz-Invariante NICHT brechen). acked je
        # Host aus dem Acknowledge-Repo abziehen (wie der WS-Pfad). Aus flagged_ports je Stufe
        # ("critical"/"notable") EINEN PortFinding bauen (nur Hosts MIT geflaggten Ports).
        # ``_flagged_ports_for_host`` zieht ``acked`` VOR der Schnittbildung ab -- ein
        # quittierter Port wird nicht mehr geflaggt (darum entfaellt eine ack_port-Liste:
        # quittierte Ports erscheinen schlicht nicht in den offenen flagged_ports).
        provider = _build_filtered_provider(analysis_rule_repository(), repository())
        acknowledged_ports = acknowledgement_repository().acknowledged_ports
        port_findings: list[ReportPortFinding] = []
        for host in base_hosts:
            acked = frozenset(acknowledged_ports(host.mac)) if host.mac else frozenset()
            flagged = _flagged_ports_for_host(host, provider, acked)
            label = _host_label(host)
            for severity in _FLAGGED_SEVERITIES:
                ports = flagged.get(severity, [])
                if not ports:
                    continue
                port_findings.append(
                    ReportPortFinding(
                        device_label=label,
                        ports=", ".join(str(p) for p in sorted(ports)),
                        severity=severity,
                        # Klartext-Grund ohne Mehraufwand/Raten: die getroffenen Ports kommen
                        # ausschliesslich aus host_remote_port-Regeln (ADR 0030) -- eine
                        # generische, ehrliche Begruendung statt einer fragil rekonstruierten
                        # Einzelregel-Beschreibung (kein Raten).
                        reason="auffaellige offene Ports (Achse-B-Regel)",
                    )
                )

        # (3) CVE: aktive Befunde -> ReportCveFinding (severity ROH mitgefuehrt, die Burden-
        # Einstufung laeuft ueber cvss_score). Quittierte -> ack_cve (Spiegelbild). device_label
        # via mac/ip aus der Basis, sonst der Roh-Schluessel (mac||ip) des Befunds selbst.
        def _cve_label(mac: str, ip: str) -> str:
            return label_by_mac.get(mac) or label_by_ip.get(ip) or mac or ip

        def _project_cves(findings: list[ActiveFinding]) -> list[ReportCveFinding]:
            return [
                ReportCveFinding(
                    device_label=_cve_label(f.mac, f.ip),
                    cve_id=f.cve_id,
                    cvss_score=f.cvss_score,
                    severity=f.severity,
                    service=f.service,
                    description=f.description,
                )
                for f in findings
            ]

        cve_active = GetActiveFindings(cve_finding_repository(), cve_acknowledgement_repository())()
        cve_acked = GetAcknowledgedFindings(
            cve_finding_repository(), cve_acknowledgement_repository()
        )()
        cve_findings = _project_cves(cve_active)
        ack_cve = _project_cves(cve_acked)

        net_findings: list[ReportNetFinding] = []
        ack_net: list[ReportNetFinding] = []

        # (4) ARP: je Alert ein NetFinding. severity-Mapping ARP "high"->"critical",
        # "medium"->"notable" (alles andere konservativ "notable"). device_label = betroffene
        # ip (via Basis gemappt, sonst die ip selbst); description aus den echten
        # ArpAlertRecord-Feldern (message + alte/neue MAC), kein Raten. ARP-Alerts kennen kein
        # Quittieren (E.1: Momentaufnahme je Scan) -> nur offene net_findings.
        arp_alerts = GetArpAlerts(arp_guard_repository())()
        for alert in arp_alerts:
            net_findings.append(
                ReportNetFinding(
                    kind="IP-Konflikt",
                    device_label=label_by_ip.get(alert.ip) or alert.ip,
                    description=(
                        f"{alert.message} (alt {alert.old_mac} -> neu {alert.new_mac})"
                        if alert.old_mac or alert.new_mac
                        else alert.message
                    ),
                    severity="critical" if alert.severity == "high" else "notable",
                )
            )

        # (5) DNS-UMGEHUNG: BuildDnsWatch-Overview ueber die schon verdrahtete _dns_watch-Naht
        # holen (kein Re-Wiring). NUR "offen"/"moegliche_doh" werden NetFindings (kind
        # "DNS-Umgehung"); "erwartungsgemaess" NICHT. severity konservativer Default "notable"
        # -- HINWEIS: das DNS-Umgehungs-Severity-Mapping wird spaeter ein editierbares
        # analysis-Setting (dann hier andocken). Quittierte (acknowledged) -> ack_net.
        dns_category_text = {"offen": "offen", "moegliche_doh": "moegliche DoH"}
        dns_overview = await _dns_watch()
        for contact in dns_overview.contacts:
            if contact.category not in dns_category_text:
                continue
            finding = ReportNetFinding(
                kind="DNS-Umgehung",
                device_label=contact.remote_ip or (contact.hostname or ""),
                description=f"DNS-Kontakt eingestuft als {dns_category_text[contact.category]}",
                severity="notable",
            )
            (ack_net if contact.acknowledged else net_findings).append(finding)

        # (6) ROGUE-DHCP: letzten gespeicherten Stand lesen (kein aktiver, root-pflichtiger
        # Probe). None -> KEIN NetFinding (Etappe 2c zeigt den "noch nie geprueft"-Hinweis).
        # Stand mit has_unexpected True -> je UNERWARTETEM Server (is_expected False) ein
        # NetFinding (severity "critical" -- ein fremder DHCP-Server ist ernst). checked_ts
        # kommt aus dem GESPEICHERTEN Stand (KEINE neue Wanduhr), nur formatiert.
        rogue = GetLatestRogueDhcp(rogue_dhcp_repository())()
        # checked_ts des letzten gespeicherten Stands fuer das ehrliche Statusfeld
        # (None = noch nie geprueft). Aus DERSELBEN Lesung -- keine zweite Rogue-Abfrage.
        rogue_checked_ts = rogue.checked_ts if rogue is not None else None
        if rogue is not None and rogue.has_unexpected:
            checked_date = datetime.fromtimestamp(rogue.checked_ts).strftime("%Y-%m-%d %H:%M")
            for server in rogue.servers:
                if server.is_expected:
                    continue
                net_findings.append(
                    ReportNetFinding(
                        kind="Rogue-DHCP",
                        device_label=server.ip,
                        description=f"Unerwarteter DHCP-Server entdeckt (geprueft {checked_date})",
                        severity="critical",
                    )
                )

        # (8) ARP/DNS/Rogue-Findings, deren device_label NICHT in device_labels ist (fremdes
        # Geraet), bleiben TROTZDEM in den Findings-Listen (echte Befunde -> erscheinen in den
        # Berichts-Tabellen). build_device_burdens ordnet Findings per device_label den
        # Basis-Geraeten zu: ein Finding auf einem Nicht-Basis-Label findet kein Basis-Geraet
        # und hebt damit den Score NICHT (die Score-Basis N bleibt der Scan-Bestand) -- das ist
        # akzeptabel und ehrlich (keine kuenstliche Basis-Erweiterung).
        report = BuildSecurityReport()(
            device_labels=device_labels,
            port_findings=port_findings,
            cve_findings=cve_findings,
            net_findings=net_findings,
            ack_port=[],
            ack_cve=ack_cve,
            ack_net=ack_net,
        )
        # Bericht SAMT der zwei ehrlichen Statuswerte zurueck (beide hier ohnehin bekannt):
        # has_scan (ob ein Scan-record als Basis vorlag) + rogue_checked_ts (None = nie geprueft).
        return report, has_scan, rogue_checked_ts

    # ── Sicherheitsbericht: HTTP-Endpunkt-Runner (Etappe 2c, Muster _dns_watch, Regel 4/5) ──
    # Composition-Root-Runner fuer GET /api/report/security: ruft die schon verdrahtete
    # Datenseite _build_security_report_data (liefert SecurityReport + has_scan + checked_ts)
    # und PROJIZIERT den application-Typ SecurityReport auf die api-Wire-Form SecurityReportOut
    # (Score -> ScoreOut, je Finding -> *Out). Die Projektion lebt -- wie bei _dns_watch --
    # HIER im Composition Root, NICHT im Router (Regel 4: der api-Ring kennt application nicht).
    # Keine Wanduhr: rogue_dhcp_checked_ts kommt aus dem GESPEICHERTEN Stand durch die Closure.
    async def _security_report() -> SecurityReportOut:
        report, has_scan, rogue_checked_ts = await _build_security_report_data()
        return SecurityReportOut(
            score=ScoreOut(
                score=report.score.score,
                level=report.score.level,
                device_count=report.score.device_count,
                total_burden=report.score.total_burden,
                critical_devices=report.score.critical_devices,
                notable_devices=report.score.notable_devices,
                clean_devices=report.score.clean_devices,
                contributions=[
                    ScoreContributionOut(
                        device_label=c.device_label,
                        worst_severity=c.worst_severity,
                        burden_value=c.burden_value,
                    )
                    for c in report.score.contributions
                ],
            ),
            port_findings=[
                PortFindingOut(
                    device_label=p.device_label,
                    ports=p.ports,
                    severity=p.severity,
                    reason=p.reason,
                )
                for p in report.port_findings
            ],
            cve_findings=[
                CveFindingOut(
                    device_label=c.device_label,
                    cve_id=c.cve_id,
                    cvss_score=c.cvss_score,
                    severity=c.severity,
                    service=c.service,
                    description=c.description,
                )
                for c in report.cve_findings
            ],
            net_findings=[
                NetFindingOut(
                    kind=n.kind,
                    device_label=n.device_label,
                    description=n.description,
                    severity=n.severity,
                )
                for n in report.net_findings
            ],
            acknowledged_port_findings=[
                PortFindingOut(
                    device_label=p.device_label,
                    ports=p.ports,
                    severity=p.severity,
                    reason=p.reason,
                )
                for p in report.acknowledged_port_findings
            ],
            acknowledged_cve_findings=[
                CveFindingOut(
                    device_label=c.device_label,
                    cve_id=c.cve_id,
                    cvss_score=c.cvss_score,
                    severity=c.severity,
                    service=c.service,
                    description=c.description,
                )
                for c in report.acknowledged_cve_findings
            ],
            acknowledged_net_findings=[
                NetFindingOut(
                    kind=n.kind,
                    device_label=n.device_label,
                    description=n.description,
                    severity=n.severity,
                )
                for n in report.acknowledged_net_findings
            ],
            # device_count = Basis N (Anzahl beruecksichtigter Geraete) aus device_labels.
            device_count=len(report.device_labels),
            has_scan=has_scan,
            rogue_dhcp_checked_ts=rogue_checked_ts,
        )

    # ── Sicherheitsbericht: PDF-Download-Runner (Etappe 4b, Muster _export_scan, Regel 4/5) ──
    # Composition-Root-Runner fuer GET /api/report/security/pdf: ruft die schon verdrahtete
    # Datenseite _build_security_report_data, liest die Wanduhr GENAU HIER (der EINZIGE Ort mit
    # Uhr -- die Projektion _project_security_pdf_model ist rein), projiziert auf das
    # render-fertige SecurityPdfModel und rendert es ueber den zustandslosen ReportlabRenderer.
    # Rueckgabe ist ein kleines lokales Ergebnis-Objekt (content/media_type/filename) -- der
    # api-Ring liest nur diese drei Attribute (Muster ExportResult; Regel 4: kein Typ-Import).
    @dataclass(frozen=True)
    class _SecurityPdfResult:
        content: bytes
        media_type: str
        filename: str

    async def _security_report_pdf() -> _SecurityPdfResult:
        report, has_scan, rogue_checked_ts = await _build_security_report_data()
        # Wanduhr GENAU HIER lesen (einziger Ort) -- Projektion und Modell bleiben rein.
        import time

        now = time.time()
        generated_at_text = "Erstellt am " + datetime.fromtimestamp(now).strftime("%d.%m.%Y %H:%M")
        # Rogue-Pruefdatum aus dem GESPEICHERTEN Stand (nicht aus der Wanduhr): nur formatiert.
        pruefdatum = (
            datetime.fromtimestamp(rogue_checked_ts).strftime("%d.%m.%Y %H:%M")
            if rogue_checked_ts is not None
            else ""
        )
        model = _project_security_pdf_model(
            report, has_scan, generated_at_text, rogue_checked_ts, pruefdatum
        )
        pdf_bytes = ReportlabRenderer().render_security_report_pdf(model)
        datumsteil = datetime.fromtimestamp(now).strftime("%Y-%m-%d")
        return _SecurityPdfResult(
            content=pdf_bytes,
            media_type="application/pdf",
            filename=f"CERNISPRO_Netzwerk-Sicherheitsbericht_{datumsteil}.pdf",
        )

    # ── Benutzerhandbuch: PDF-Download-Runner (Muster _security_report_pdf, Regel 4/5) ──
    # Composition-Root-Runner fuer GET /api/report/manual/pdf: laedt die Hilfe-Inhalte, liest
    # die Wanduhr GENAU HIER (einziger Ort mit Uhr -- _project_manual_pdf_model ist rein),
    # projiziert auf das render-fertige ManualPdfModel und rendert es ueber den zustandslosen
    # ReportlabRenderer (derselbe Import wie der Sicherheitsbericht). Rueckgabe ist ein kleines
    # lokales Ergebnis-Objekt (content/media_type/filename) -- der api-Ring liest nur diese drei.
    @dataclass(frozen=True)
    class _ManualPdfResult:
        content: bytes
        media_type: str
        filename: str

    async def _manual_pdf(lang: str) -> _ManualPdfResult:
        # lang normalisieren: "en" bleibt, jeder andere Wert faellt auf "de" (Auftrag).
        normalized = "en" if lang == "en" else "de"
        help_data = _load_help_content()
        # Wanduhr GENAU HIER lesen (einziger Ort) -- Projektion und Modell bleiben rein.
        import time

        now = time.time()
        generated_at_text = "Erstellt am " + datetime.fromtimestamp(now).strftime("%d.%m.%Y %H:%M")
        if normalized == "en":
            title = "CERNIS PRO 2.0 - User Manual"
            footer_left = "CERNIS PRO 2.0 - User Manual"
        else:
            title = "CERNIS PRO 2.0 - Benutzerhandbuch"
            footer_left = "CERNIS PRO 2.0 - Benutzerhandbuch"
        model = _project_manual_pdf_model(
            help_data, normalized, generated_at_text, footer_left, title
        )
        pdf_bytes = ReportlabRenderer().render_manual_pdf(model)
        if normalized == "en":
            filename = "CERNISPRO_User-Manual.pdf"
        else:
            filename = "CERNISPRO_Benutzerhandbuch.pdf"
        return _ManualPdfResult(content=pdf_bytes, media_type="application/pdf", filename=filename)

    app.include_router(report_router)
    app.dependency_overrides[provide_security_report] = lambda: _security_report
    app.dependency_overrides[provide_security_report_pdf] = lambda: _security_report_pdf
    app.dependency_overrides[provide_manual_pdf] = lambda: _manual_pdf

    # ── Route zum Ziel (ADR 0036): traceroute-Hops + Geo/ASN, zwei getrennte Naehte ──
    # Regel 5: die Quer-Domaenen-Naht (diagnostics-Hops + resolver-Geo/RDAP) faellt
    # AUSSCHLIESSLICH hier im Composition Root. WEDER die diagnostics-Domaene NOCH ihr Port
    # nennt resolver -- die Use-Cases bekommen quellen-agnostische Callables herein (Muster
    # BuildTopology/export.ScanProvider). Bewusst HIER (nach dem resolver-Block), weil beide
    # resolver-Adapter (geo_asn_db/RdapClient) schon in Scope sind -- keine zweite Instanz.
    #
    # HAUPTPFAD (lokal+synchron, schnell, root-frei): BuildRouteGeo bekommt den eigenen
    # RunTraceroute-Use-Case (Hop-Quelle) + ein Geo-Callable, das HIER den lazy geladenen
    # CsvGeoAsnDb-Lookup auf ein rohes dict PROJIZIERT (asn_org bleibt None -- die CSV-DB
    # kennt nur Land + ASN-Nummer; der Klartext-Org-Name kommt optional ueber die zweite
    # Naht, NICHT hier geraten -- ehrliche Leere, kein stiller Fallback S3).
    def _route_geo_lookup(ip: str) -> dict[str, str | None]:
        record = geo_asn_db().lookup(ip)
        return {"country": record.country, "asn": record.asn, "asn_org": record.asn_org}

    async def _build_route_geo(target: str, privileged: bool) -> Any:
        return await BuildRouteGeo(RunTraceroute(SystemTracerouteRunner()), _route_geo_lookup)(
            target, privileged
        )

    # OPTIONALE NACHLADUNG (Netz-I/O ueber RDAP, NUR auf expliziten Abruf): EnrichRouteOrgs
    # bekommt ein Org-Callable, das HIER pro IP den RdapClient ruft und dessen ``org``-Feld
    # (registrant/administrative entity, der Betreibername je IP) auf den rohen ``str | None``
    # PROJIZIERT. Der RdapClient ist laut Port-Vertrag STRENG fehlertolerant (liefert bei
    # jedem Fehlschlag leere Fakten, wirft NIE) -- die Nachladung blockiert/faelscht NIE.
    async def _route_org_lookup(ip: str) -> str | None:
        facts = await RdapClient().lookup(ip)
        return facts.org

    async def _enrich_route_orgs(ips: list[str]) -> Any:
        return await EnrichRouteOrgs(_route_org_lookup)(ips)

    app.dependency_overrides[provide_build_route_geo] = lambda: _build_route_geo
    app.dependency_overrides[provide_enrich_route_orgs] = lambda: _enrich_route_orgs

    # ── export-Domaene v2 verdrahten (Block 1: gespeicherter Scan -> CSV/JSON/PDF, ADR 0015) ──
    # Der ExportScan-Use-Case kennt KEINE scanning-Domaene: er bekommt den Scan ueber ein
    # schlankes scan_provider-Callable (scan_id -> ExportableScan | None), das HIER im
    # Composition Root die scanning-Daten holt UND auf domain.export.Exportable* PROJIZIERT
    # (genau das analysis-Muster mit seiner Observed*-Projektion -- Fremd-Domaenen-Kopplung
    # gehoert in die Verdrahtung, NICHT in domain.export, independence-Contract). Reuse des
    # bestehenden GetScanDetail + scan_history_repository() (lru_cache, im scanning-Block
    # verdrahtet) -- KEINE zweite Instanz. Der Renderer ist der zustandslose ReportlabRenderer.
    def _project_scan_to_exportable(record: Any) -> ExportableScan:
        # record ist ein domain.scanning.ScanRecord; per Attribut-Zugriff auf die schlanken
        # export-Typen projiziert (independence: domain.export kennt scanning NICHT). Die
        # Listen werden so verlustarm uebernommen, wie JSON sie braucht: ports als
        # ExportablePort (protocol fest "tcp" -- PortInfo traegt kein Protokoll-Feld, der
        # socket-/nmap-Scan ist TCP, ADR 0015), mdns/ssdp als menschenlesbare String-Tupel
        # (mDNS-Typ bzw. SSDP-server/st -- so viel, wie verlustarm noetig, ohne die volle
        # scanning-Komplexitaet zu duplizieren).
        hosts = tuple(
            ExportableHost(
                ip=host.ip,
                mac=host.mac,
                vendor=host.vendor,
                hostname=host.hostname,
                rtt_ms=host.rtt_ms,
                os_guess=host.os_guess,
                os_accuracy=host.os_accuracy,
                category=host.category,
                label=host.label,
                tags=tuple(host.tags),
                source=host.source,
                ports=tuple(
                    ExportablePort(port=p.port, protocol="tcp", service=p.service)
                    for p in host.ports
                ),
                mdns_services=tuple(
                    svc.type or svc.name for svc in host.mdns_services if (svc.type or svc.name)
                ),
                ssdp_services=tuple(
                    svc.server or svc.st for svc in host.ssdp_services if (svc.server or svc.st)
                ),
            )
            for host in record.hosts
        )
        return ExportableScan(
            scan_id=record.scan_id,
            cidr=record.cidr,
            host_count=record.host_count,
            scanned_at=record.scanned_at,
            hosts=hosts,
        )

    def _scan_provider(scan_id: int) -> ExportableScan | None:
        # GetScanDetail liefert den ScanRecord | None (None = Scan-ID gibt es nicht, ein
        # gueltiger Zustand). Nur ein gefundener Scan wird projiziert; None reicht der
        # Use-Case in seine ScanNotFoundError -> 404 (kein stiller leerer Export, ADR 0001).
        record = GetScanDetail(scan_history_repository())(scan_id)
        if record is None:
            return None
        return _project_scan_to_exportable(record)

    def _export_scan(scan_id: int, fmt: Literal["csv", "json", "pdf"]) -> Any:
        return ExportScan(_scan_provider, ReportlabRenderer())(scan_id, fmt)

    app.include_router(export_router)
    app.dependency_overrides[provide_export_scan] = lambda: _export_scan

    @app.exception_handler(ScanNotFoundError)
    async def _on_scan_not_found(_request: Request, exc: ScanNotFoundError) -> JSONResponse:
        # Nicht existierende scan_id -> 404 (die Ressource gibt es nicht, kein leerer Export).
        # Muster der diagnostics-Rechte-/Dienst-Naht: das Mapping sitzt am Composition Root,
        # der api-Ring bleibt clean. Reiner application-Zustand (der scan_provider lieferte
        # None) -- kein infra-Ausfall.
        logger.info("export_scan_not_found", scan_id=exc.scan_id)
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    # ── analysis-Domaene v2 verdrahten (AN.3 + A.2, reine Lese-/Rechen-Domaene) ───
    # Lazy-memoisiertes User-Regel-Repo (lru_cache, Muster scan_history_repository):
    # teilt die cernis.db mit dem uebrigen Bestand. Es erfuellt BEIDE analysis-Ports
    # (RuleProvider als Lese-Quelle + UserRuleStore als Verwaltungs-Vertrag).
    @lru_cache(maxsize=1)
    def analysis_rule_repository() -> SqliteUserRuleRepository:
        from modules.db_path import get_db_path

        return SqliteUserRuleRepository(get_db_path())

    # Host-Historie-Repo (C.2): analysis' erstes GEDAECHTNIS (gesehene Host-MACs),
    # teilt die cernis.db (lru_cache, Muster analysis_rule_repository). Zwei getrennte
    # Naehte greifen darauf zu: die SCHREIB-Naht am Scan (ws_scan, record_seen) pflegt
    # die Historie, die LESE-Naht in _analyze_snapshot (known_macs) fuellt daraus
    # ObservedHost.is_known. Scan schreibt, GET /api/analysis liest -- siehe ADR 0013.
    @lru_cache(maxsize=1)
    def host_history_repository() -> SqliteHostHistoryRepository:
        from modules.db_path import get_db_path

        return SqliteHostHistoryRepository(get_db_path())

    # Acknowledge-Audit-Repo (ADR 0031): das append-only Log der quittierten
    # Achse-B-Befunde, teilt die cernis.db (lru_cache, Muster host_history_repository).
    # Zwei Naehte greifen darauf zu: die SCHREIB-Naht am Endpunkt (POST /api/analysis/
    # acknowledge, record) und die LESE-Naht im axis_b-Pfad (acknowledged_ports), die
    # quittierte Ports aus der Bewertung nimmt und ins host_detail-Frame traegt.
    @lru_cache(maxsize=1)
    def acknowledgement_repository() -> SqliteAcknowledgementRepository:
        from modules.db_path import get_db_path

        return SqliteAcknowledgementRepository(get_db_path())

    # Kein Poller, kein app.state, kein lifespan-Eingriff -- wie process. Die zwei
    # Adapter (BuiltinRuleProvider/StaticHelpLinkResolver) sind zustandslos. Die
    # SNAPSHOT-PROJEKTION aus traffic+process lebt HIER im Composition Root, NICHT im
    # Use-Case oder Adapter -- sie kennt BEIDE Fremd-Domaenen (Muster _list_app_traffic /
    # _list_processes / _build_run_network_scan: Fremd-Domaenen-Kopplung gehoert in die
    # Verdrahtung). Reuse der bestehenden Helfer _traffic_adapter()/_process_adapter()
    # (beide oben im traffic- bzw. process-Block definiert) -- KEINE zweite Adapter-Instanz.
    async def _analyze_snapshot() -> list[Any]:
        # Verbindungssicht frisch holen -- DIESELBE Quelle wie _list_app_traffic, aber
        # OHNE Raten (analysis braucht nur die Verbindungen, nicht den Durchsatz -> Stufe 1,
        # rates leer). ListAppTraffic liefert AppTraffic-Gruppen mit .connections; die
        # Connections aller Apps flachen wir zu ObservedConnection.
        apps = await ListAppTraffic(_traffic_adapter())({})
        observed_connections = tuple(
            ObservedConnection(
                app_name=conn.app_name,
                pid=conn.pid,
                remote_ip=conn.remote.ip if conn.remote else None,
                remote_port=conn.remote.port if conn.remote else None,
                l4=conn.l4,
                status=conn.status,
            )
            for app_traffic in apps
            for conn in app_traffic.connections
        )
        # Prozess-Sicht frisch holen (flache ProcessInfo-Liste) und zu ObservedProcess
        # projizieren -- exe_path ist die analysis-relevante Quelle (P.5).
        processes = await ListProcesses(_process_adapter()).flat()
        observed_processes = tuple(
            ObservedProcess(
                pid=p.pid,
                name=p.name,
                kind=classify_kind(p),
                exe_path=p.exe_path,
                cmdline=p.cmdline,
            )
            for p in processes
        )
        # Rechte-Status als Eingabe-Faktum des Snapshots: rootless schweigt der
        # kein-Pfad-Tarnverdacht (mehrdeutig), Root zeigt ihn als notable (AN.3-fix-2).
        # Reuse des BESTEHENDEN Permission-Pfads (CheckProcessPermission +
        # ProcessPermissionAdapter, beide schon im process-Block verdrahtet) -- NICHT
        # os.geteuid direkt, KEINE zweite Instanz-Logik. Die Kopplung an den
        # Permission-Adapter lebt hier in der Verdrahtung; die Domaene sieht nur ein bool.
        perm = CheckProcessPermission(ProcessPermissionAdapter())()
        full_visibility = bool(perm["ok"])
        # hosts-Projektion (B): die dritte Datenquelle ist der JUENGSTE gespeicherte Scan.
        # Anders als connections/processes (live gelesen) sind Hosts nur so aktuell wie
        # dieser Scan -- die Sicht ist "Stand juengster Scan", keine Live-Host-Sicht (das
        # ist die Natur der Quelle, kein Mangel). Reuse des bestehenden
        # scan_history_repository() (lru_cache, im scanning-Block verdrahtet) -- KEINE
        # zweite Instanz. Die Projektion EnrichedHost -> ObservedHost lebt HIER im
        # Composition Root (Fremd-Domaenen-Kopplung gehoert in die Verdrahtung); analysis
        # bekommt nur die offenen Port-NUMMERN (state == "open"), nicht die PortInfo-Objekte
        # (independence-Contract). Kein Scan -> leer (gueltiger Zustand, keine host-Beobachtung).
        summaries = scan_history_repository().list(1)
        hosts_observed: tuple[ObservedHost, ...] = ()
        if summaries:
            try:
                record = scan_history_repository().get(summaries[0].scan_id)
            except CorruptScanError:
                # Host-Schicht ausfallsicher (Entscheidung A): ein unlesbarer juengster
                # Scan darf den Lageueberblick (traffic/process) nicht faellen. KEIN
                # stiller Fallback im verbotenen Sinn -- scan_history.get() wirft weiterhin
                # laut, wer den Scan gezielt abruft; nur diese interpretierende Projektion
                # ueberspringt die unlesbare Host-Quelle. Spaeter in der GUI sichtbar machen
                # ("Host-Daten aus letztem Scan nicht lesbar").
                logger.warning("analysis.hosts_skipped_corrupt_scan", scan_id=summaries[0].scan_id)
                record = None
            if record is not None:
                # Lese-Naht (C.2): die bekannten MACs EINMAL holen (Bulk, statt N
                # is_known-Aufrufe) und je Host is_known setzen. REINER Lesevorgang --
                # die Historie wird beim SCANNEN gepflegt (Schreib-Naht in ws_scan),
                # NICHT hier: GET /api/analysis schreibt nicht (Variante 2, ADR 0013).
                # MAC-lose Hosts -> is_known True (nicht als neu werten, gleiche Linie
                # wie das Repository). Daraus folgt die Baseline: nach dem ersten Scan
                # sind alle gesehenen Hosts bekannt; new_host_seen feuert ab dem zweiten
                # Scan fuer echte Neuzugaenge.
                known = host_history_repository().known_macs()
                # Leere Historie (allererster Scan, kein Vorzustand) -> JEDER Host bekannt:
                # "neu" ist gegen eine leere Baseline bedeutungslos, sonst flaggt der erste
                # Scan ALLE Hosts als new_host_seen. Ab dem zweiten Scan normaler Abgleich.
                # Linie wie MAC-lose -> True.
                history_empty = not known
                hosts_observed = tuple(
                    _observed_host(
                        h,
                        is_known=True if history_empty or not h.mac else (h.mac in known),
                    )
                    for h in record.hosts
                )
        snapshot = Snapshot(
            connections=observed_connections,
            processes=observed_processes,
            hosts=hosts_observed,
            full_process_visibility=full_visibility,
        )
        # ADDITIV (A.2): die Engine sieht die eingebauten Defaults UND die gespeicherten
        # eigenen Regeln -- ueber den CompositeRuleProvider (Defaults zuerst, dann DB).
        # NUR diese eine Zeile der AN.3-Verdrahtung aendert sich; der Rest bleibt.
        # ADR 0023: der Composite-Provider wird zusaetzlich umschlossen, damit per
        # Settings (``analysis_disabled_rules``) abgeschaltete Regel-IDs herausgefiltert
        # werden. Default (kein Key) = alle Regeln aktiv -- rein additiv.
        # ADR 0027: zwischen Composite und Filter sitzt der _ConfiguredRuleProvider, der
        # die per Setting konfigurierbaren Built-in-Regel-Parameter (Schwelle der
        # host_many_high_ports-Regel + die Portlisten von host_remote_access_port/
        # host_backdoor_port) defensiv aus den Settings liest und per dataclasses.replace
        # ueberschreibt. Default (kein/kaputter Key) = die Built-in-Werte aus rules.py.
        # Provider-Stack Composite -> Configured -> Filtered als Single Source (ADR 0029):
        # die frueher hier inline aufgebaute Kette lebt jetzt in _build_filtered_provider
        # (dieselbe Funktion, die auch die WS-Severity-Verdrahtung nutzt). Kein
        # Verhaltenswechsel -- die Engine sieht weiterhin den GEFILTERTEN Stack.
        rule_provider = _build_filtered_provider(analysis_rule_repository(), repository())
        return AnalyzeSnapshot(rule_provider, StaticHelpLinkResolver())(snapshot)

    # ── export-Domaene Block 2 verdrahten (Analyse-Befunde -> CSV/JSON/PDF, ADR 0015) ──
    # Der ExportAnalysis-Use-Case kennt KEINE analysis-Domaene: er bekommt die Befunde ueber
    # ein schlankes, ASYNC analysis_provider-Callable, das HIER im Composition Root die
    # AKTUELLE Analyse frisch erzeugt (Reuse von _analyze_snapshot -- KEINE zweite Snapshot-
    # Projektion) UND auf domain.export.ExportableAnalysis PROJIZIERT (Muster
    # _project_scan_to_exportable / analysis' Observed*-Projektion -- Fremd-Domaenen-Kopplung
    # gehoert in die Verdrahtung, NICHT in domain.export, independence-Contract). generated_at
    # kommt aus der EINEN Zeitquelle (SystemClock, UTC, ISO) -- die Domaene fragt keine Uhr;
    # der Composition Root setzt das Feld direkt in die projizierte ExportableAnalysis. Der
    # Renderer ist der zustandslose ReportlabRenderer (derselbe wie Block 1, generisches
    # PdfReportModel). Anders als der Scan-Export: ASYNC + KEIN analysis_id (die Analyse hat
    # keinen gespeicherten Stand -> "die Analyse von jetzt", kein NotFound).
    export_clock = SystemClock()

    def _project_analysis_to_exportable(
        resolved: list[Any], generated_at: str
    ) -> ExportableAnalysis:
        # resolved ist die list[ResolvedObservation] aus _analyze_snapshot (.observation +
        # .help_url); per Attribut-Zugriff auf die schlanken export-Typen projiziert
        # (independence: domain.export kennt analysis NICHT). severity kommt als str herein
        # (kein Severity-Import). Die Befund-Reihenfolge bleibt die der Eingabe (AnalyzeSnapshot
        # liefert bereits deterministisch sortiert). generated_at ist der ISO-Zeitstempel des
        # Exports (von der Uhr, hier hereingereicht -- die Domaene fragt keine Uhr).
        findings = tuple(
            ExportableFinding(
                rule_id=r.observation.rule_id,
                severity=r.observation.severity,
                title=r.observation.title,
                detail=r.observation.detail,
                subject=r.observation.subject,
                help_kind=r.observation.help_kind,
                help_url=r.help_url,
            )
            for r in resolved
        )
        return ExportableAnalysis(
            generated_at=generated_at,
            findings=findings,
            finding_count=len(findings),
        )

    async def _analysis_provider() -> ExportableAnalysis:
        # Die AKTUELLE Analyse frisch erzeugen -- DERSELBE Pfad wie GET /api/analysis (Reuse
        # _analyze_snapshot, async). generated_at ist der Erzeugungs-Zeitpunkt des Exports
        # (SystemClock, UTC) als ISO-String. Dann auf ExportableAnalysis projizieren.
        resolved = await _analyze_snapshot()
        generated_at = export_clock.now().isoformat()
        return _project_analysis_to_exportable(resolved, generated_at)

    async def _export_analysis(fmt: Literal["csv", "json", "pdf"]) -> Any:
        return await ExportAnalysis(_analysis_provider, ReportlabRenderer())(fmt)

    app.dependency_overrides[provide_export_analysis] = lambda: _export_analysis

    # ── export-Domaene Block 3 verdrahten (Logging-Report -> CSV/JSON/PDF, Schnitt 1a) ──
    # Der ExportLoggingReport-Use-Case kennt KEINE monitoring-Domaene: er bekommt den Report
    # ueber ein schlankes logging_report_provider-Callable (task_id + since/until -> projizierter
    # Report | None), das HIER im Composition Root die drei Logging-Repos liest, den SLA-Kopf
    # ueber die reine compute_sla_stats rechnet UND auf domain.export.ExportableLoggingReport
    # PROJIZIERT (Muster _project_scan_to_exportable / _analysis_provider -- Fremd-Domaenen-
    # Kopplung gehoert in die Verdrahtung, NICHT in domain.export, independence-Contract).
    # Reuse der bestehenden Logging-Repos (logging_task_repository/logging_rtt_repository/
    # logging_event_repository, lru_cache, im Logging-Block verdrahtet) + des export_clock --
    # KEINE zweiten Instanzen. Der Renderer ist der zustandslose ReportlabRenderer.
    #
    # ZEITRAUM-NAHT (markierte Stelle): RTT hat ein all_for (alle Punkte eines Tasks); der
    # LoggingEventRepository hat dagegen KEIN all_for, nur range(task_id, since, until). Statt
    # den Port um ein all_for zu erweitern (schwergewichtig fuer einen Effekt, den range schon
    # liefert) loesen wir den offenen Zeitraum schlank ueber range mit since=0 / until=now+Puffer
    # (die Uhr aus export_clock, der EINEN Zeitquelle -- der Puffer faengt Mess-ts ab, die
    # minimal nach now liegen). Bei gesetztem since/until gilt das halb-offene Fenster [since,
    # until) beider range-Methoden direkt. RTT nutzt all_for nur im voll-offenen Fall (since UND
    # until None) -- sonst ebenfalls range, damit RTT- und Event-Reihe denselben Ausschnitt
    # zeigen.
    def _project_logging_to_exportable(
        task: LoggingTask,
        since: float | None,
        until: float | None,
        generated_at: str,
    ) -> ExportableLoggingReport:
        # Effektive Grenzen fuer die range-Reads: offener since -> 0.0, offener until ->
        # now+Puffer (die Uhr; Mess-ts liegen nie weit in der Zukunft). Beide range-Methoden
        # sind halb-offen [since, until), konsistent zur Domaenen-Fenster-Semantik.
        eff_since = since if since is not None else 0.0
        eff_until = until if until is not None else export_clock.now().timestamp() + 86400.0
        # RTT-Punkte: voll-offen -> all_for (alle Punkte des Tasks); sonst der range-Ausschnitt.
        if since is None and until is None:
            rtt_samples = logging_rtt_repository().all_for(task.id)
        else:
            rtt_samples = logging_rtt_repository().range(task.id, eff_since, eff_until)
        # Events: es gibt kein all_for -- immer range (im offenen Fall mit 0/now+Puffer).
        event_rows = logging_event_repository().range(task.id, eff_since, eff_until)
        # SLA-Kopf ueber die reine compute_sla_stats (Muster GetLoggingTaskSla): die
        # LoggingRttSample (rtt_ms/loss_pct/alive/ts) zu (alive, rtt_ms, ts)-Tupeln formen --
        # das Eingabeformat der Domaenen-Rechnung. interval_s=task.interval_s (korrekte
        # Downtime-Schaetzung pro Task). days=0: KEIN Zeitfenster (der Report rechnet ueber den
        # geladenen Ausschnitt, nicht ueber ein days-Fenster -- GetLoggingTaskSla-Linie).
        sla_rows = [(float(s.alive), s.rtt_ms, s.ts) for s in rtt_samples]
        stats = compute_sla_stats(sla_rows, days=0, interval_s=task.interval_s)
        # Projektion auf die schlanken export-Typen (independence: domain.export kennt
        # monitoring NICHT). generated_at + period_from/to kommen als ISO-Strings herein (die
        # Domaene fragt keine Uhr); offene Grenze -> "".
        rtt_points = tuple(
            ExportableLoggingRtt(ts=s.ts, rtt_ms=s.rtt_ms, loss_pct=s.loss_pct, alive=s.alive)
            for s in rtt_samples
        )
        events = tuple(
            ExportableLoggingEvent(ts=e.ts, event_type=e.event_type, rtt_ms=e.rtt_ms)
            for e in event_rows
        )
        # period_from/to als lesbare ISO-Strings der since/until-Grenzen (offene Grenze ->
        # ""). BEWUSST die LOKALE fromtimestamp (datetime.fromtimestamp ohne tz) -- konsistent
        # zu domain._ts_to_iso, das die Mess-/Event-Zeitstempel im selben Bericht ebenfalls
        # lokal darstellt; so passen Kopf-Zeitraum und Punkt-Zeitstempel zusammen (der
        # generated_at-Kopf ist UTC, aber das ist der Erzeugungs-, kein Mess-Zeitstempel).
        return ExportableLoggingReport(
            task_label=task.label,
            task_purpose=task.purpose,
            target_id=task.target_id,
            generated_at=generated_at,
            period_from=datetime.fromtimestamp(since).isoformat() if since is not None else "",
            period_to=datetime.fromtimestamp(until).isoformat() if until is not None else "",
            uptime_pct=stats["uptime_pct"],
            avg_rtt_ms=stats["avg_rtt_ms"],
            downtime_mins=stats["downtime_mins"],
            sample_count=stats["samples"],
            rtt_points=rtt_points,
            events=events,
        )

    def _logging_report_provider(
        task_id: str, since: float | None, until: float | None
    ) -> ExportableLoggingReport | None:
        # logging_task_repository().get liefert den LoggingTask | None (None = task_id gibt es
        # nicht, ein gueltiger Zustand). Nur ein gefundener Task wird projiziert; None reicht
        # der Use-Case in seine LoggingReportNotFound -> 404 (kein stiller leerer Export).
        task = logging_task_repository().get(task_id)
        if task is None:
            return None
        generated_at = export_clock.now().isoformat()
        return _project_logging_to_exportable(task, since, until, generated_at)

    def _export_logging(
        task_id: str, fmt: Literal["csv", "json", "pdf"], since: float | None, until: float | None
    ) -> Any:
        return ExportLoggingReport(_logging_report_provider, ReportlabRenderer())(
            task_id, fmt, since, until
        )

    app.dependency_overrides[provide_export_logging] = lambda: _export_logging

    @app.exception_handler(LoggingReportNotFound)
    async def _on_logging_report_not_found(
        _request: Request, exc: LoggingReportNotFound
    ) -> JSONResponse:
        # Nicht existierende task_id -> 404 (die Ressource gibt es nicht, kein leerer Export).
        # Muster des ScanNotFoundError-Handlers: das Mapping sitzt am Composition Root, der
        # api-Ring bleibt clean. Reiner application-Zustand (der Provider lieferte None).
        logger.info("export_logging_not_found", task_id=exc.task_id)
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    # A.2-Verwaltungs-Runner: der api-Ring bleibt domain-frei -- das Bauen der
    # domain.Rule aus dem Request-DTO + der Aufruf der Use-Cases passiert HIER im
    # Composition Root (Muster _analyze_snapshot). Alle drei nutzen dasselbe Repo.
    def _add_user_rules(bodies: list[UserRuleBody]) -> list[Any]:
        new_rules = [
            Rule(
                id=body.id,
                severity=body.severity,  # type: ignore[arg-type]
                help_kind=body.help_kind,  # type: ignore[arg-type]
                kind=body.kind,  # type: ignore[arg-type]
                title=body.title,
                detail_template=body.detail_template,
                path_prefixes=tuple(body.path_prefixes),
                ports=frozenset(body.ports),
                threshold=body.threshold,
            )
            for body in bodies
        ]
        return AddUserRules(analysis_rule_repository())(new_rules)

    def _list_user_rules() -> list[Any]:
        return list(ListUserRules(analysis_rule_repository())())

    def _list_all_rules() -> list[tuple[Any, bool]]:
        # ADR 0028: ALLE aktuell aktiven Regeln (Built-in + User) fuer den UI-Block
        # "Regel-An/Aus". Quelle ist DERSELBE Provider-Stack wie die Engine, aber bewusst
        # nur bis ``configured`` (NACH der 5a-Injektion von Schwelle/Portlisten) -- der
        # ``_FilteredRuleProvider`` wird hier NICHT angewandt, denn die UI muss auch die
        # deaktivierten Regeln sehen, um sie wieder einschalten zu koennen. Das
        # ``disabled``-Flag pro Regel kommt aus DERSELBEN defensiven Lese-Quelle wie der
        # Filter (``_read_disabled_rule_ids``) -- so sehen Engine-Filter und UI-Liste
        # garantiert dieselbe Menge. Kaputtes/fehlendes Setting -> leere disabled-Menge
        # (fail-safe: die UI zeigt im Zweifel alles als aktiv, niemand wird heimlich
        # abgeschaltet; S3-konform geloggt in der freien Funktion).
        # UNGEFILTERTER Stack bis ``configured`` (ADR 0029, Single Source): dieselbe
        # Composite->Configured-Kette wie der Engine-Pfad, aber OHNE den
        # ``_FilteredRuleProvider`` -- die UI muss auch deaktivierte Regeln sehen, um sie
        # wieder einschalten zu koennen. Das ``disabled``-Flag kommt aus DERSELBEN
        # defensiven Lese-Quelle wie der Filter (``_read_disabled_rule_ids``).
        configured = _build_configured_provider(analysis_rule_repository(), repository())
        disabled = _read_disabled_rule_ids(repository())
        return [(rule, rule.id in disabled) for rule in configured.get_rules()]

    def _delete_user_rule(rule_id: str) -> None:
        analysis_rule_repository().delete_rule(rule_id)

    # Acknowledge-Schreibnaht (ADR 0031): reicht den record-Schreibpfad des Audit-Repos
    # als AcknowledgeRunner heraus (Pass-Through, Muster _delete_user_rule). Der api-Ring
    # bleibt repo-frei; die Validierung (port-Range/severity/action) macht das Body-DTO.
    def _acknowledge(mac: str, port: int, severity: str, action: str) -> None:
        acknowledgement_repository().record(mac, port, severity, action)

    app.include_router(analysis_router)
    app.dependency_overrides[provide_analyze] = lambda: _analyze_snapshot
    # Service-Lookup (Stueck 1): der reine domain-Lookup ``service_for_port`` wird hier
    # als ServiceLookupRunner herausgereicht -- der api-Ring bleibt domain-frei, die
    # Kopplung an die Domaene lebt im Composition Root.
    app.dependency_overrides[provide_service_lookup] = lambda: service_for_port
    app.dependency_overrides[provide_add_user_rules] = lambda: _add_user_rules
    app.dependency_overrides[provide_list_user_rules] = lambda: _list_user_rules
    app.dependency_overrides[provide_list_all_rules] = lambda: _list_all_rules
    app.dependency_overrides[provide_delete_user_rule] = lambda: _delete_user_rule
    app.dependency_overrides[provide_acknowledge] = lambda: _acknowledge

    # ── maintenance-Domaene v2 verdrahten (Etappe 3, Regel 5: ports<->infra nur hier) ──
    # Die Wartungs-Funktion (Daten loeschen) komponiert die zwei Stufen aus den BEREITS
    # vorhandenen Repo-Factories des uebrigen Bestands -- KEINE eigenen Repos, KEINE
    # zweiten Instanzen. Stufe 1 (ResetScanData) leert die Befund-/Verlaufstabellen;
    # Stufe 2 (FactoryReset) fuehrt erst die ganze Stufe 1 aus (dieselbe Instanz, die
    # auch der Stufe-1-Endpunkt nutzt -- der Use-Case komponiert sie selbst) und raeumt
    # DANACH Geraete, Settings, Regeln, Monitoring (Scheduler-Jobs zuerst, dann Tabellen),
    # Alert-Regeln und Agenten ab. Der Scheduler ist die SELBE gecachte Instanz wie bei
    # ManageSchedules (job_scheduler(), lru_cache) -- KEINE zweite. Die Factories liegen
    # ueber den gesamten create_app-Scope verteilt; die Closures loesen ihre Namen erst
    # beim Request auf (alle Factories sind dann definiert).
    #
    # Verdrahtet als Use-Case-INSTANZ (Muster der devices-POST-Use-Cases): das Override
    # liefert die Instanz, der Router ruft ihre ``run``-Methode. Stufe-1- und Stufe-2-
    # Instanz teilen sich DIESELBE ResetScanData (FactoryReset komponiert sie) -- darum
    # einmal lazy memoisiert, damit beide Endpunkte/Use-Cases dieselbe Instanz sehen.
    @lru_cache(maxsize=1)
    def reset_scan_data_use_case() -> ResetScanData:
        return ResetScanData(
            scan_history=scan_history_repository(),
            cve_findings=cve_finding_repository(),
            cve_checkstate=cve_checkstate_repository(),
            cve_acknowledgements=cve_acknowledgement_repository(),
            known_hosts=host_history_repository(),
            analysis_acknowledgements=acknowledgement_repository(),
            arp_guard=arp_guard_repository(),
        )

    @lru_cache(maxsize=1)
    def factory_reset_use_case() -> FactoryReset:
        return FactoryReset(
            reset_scan_data=reset_scan_data_use_case(),
            devices=device_repository(),
            settings=repository(),
            user_rules=analysis_rule_repository(),
            schedules=schedule_repository(),
            scheduler=job_scheduler(),
            rtt_history=rtt_history_repository(),
            monitor_events=monitor_event_repository(),
            sla_samples=sla_sample_repository(),
            logging_tasks=logging_task_repository(),
            logging_rtt=logging_rtt_repository(),
            logging_events=logging_event_repository(),
            outbound_recordings=outbound_recording_repository(),
            outbound_detail=outbound_detail_repository(),
            outbound_aggregate=outbound_aggregate_repository(),
            alert_rules=alert_rule_repository(),
            agents=agent_repository(),
            dns_watch_acknowledgements=dns_watch_acknowledgement_repository(),
            scheduled_jobs=scheduled_job_repository(),
            secret_store=secret_store(),
        )

    # Granularer Baukasten (Stufe 1 waehlbar): zieht alle Repos aus den BESTEHENDEN
    # Factories -- KEINE eigenen Repos, KEINE zweiten Instanzen (Muster ResetScanData).
    @lru_cache(maxsize=1)
    def delete_selected_use_case() -> DeleteSelectedData:
        return DeleteSelectedData(
            scan_history=scan_history_repository(),
            cve_findings=cve_finding_repository(),
            cve_checkstate=cve_checkstate_repository(),
            cve_acknowledgements=cve_acknowledgement_repository(),
            arp_guard=arp_guard_repository(),
            analysis_acknowledgements=acknowledgement_repository(),
            known_hosts=host_history_repository(),
            rtt_history=rtt_history_repository(),
            monitor_events=monitor_event_repository(),
            sla_samples=sla_sample_repository(),
            logging_tasks=logging_task_repository(),
            logging_rtt=logging_rtt_repository(),
            logging_events=logging_event_repository(),
            outbound_recordings=outbound_recording_repository(),
            outbound_detail=outbound_detail_repository(),
            outbound_aggregate=outbound_aggregate_repository(),
        )

    app.include_router(maintenance_router)
    app.dependency_overrides[provide_reset_scan_data] = reset_scan_data_use_case
    app.dependency_overrides[provide_delete_selected] = delete_selected_use_case
    app.dependency_overrides[provide_factory_reset] = factory_reset_use_case

    # ── Frontend-Serving ── MUSS als LETZTES registriert werden ──────────────────
    # Der "/"-Mount faengt alle zuvor NICHT gematchten Pfade. Deshalb hier ganz am
    # Ende von create_app -- nach /health, settings_router und allen kuenftigen
    # Routern -, sonst verschluckt er deren Routen. Serving ist nebeneffektfrei und
    # daher NICHT an bootstrap_on_startup gekoppelt; fehlt das Frontend, laeuft die
    # App API-only.
    frontend_dir = _resolve_frontend_dir(cfg.frontend_dir)
    if frontend_dir is not None:
        app.mount("/", _SpaStaticFiles(directory=frontend_dir, html=True), name="frontend")
        logger.info("frontend_serving_enabled", directory=str(frontend_dir))
    else:
        logger.info("frontend_serving_disabled")

    return app


app = create_app()
