"""Composition Root von CERNIS PRO 2.0.

Einziger Ort, an dem alle Ringe zusammenkommen: konfiguriert Logging und
Middleware, baut die FastAPI-App und verdrahtet (ab Schritt 6) ``ports/`` <->
``infrastructure/`` per Dependency Injection. Bewusst von den import-linter-
Vertraegen ausgenommen (Composition-Root-Ausnahme, Regel 5).

Lifespan-Kontext statt ``@app.on_event`` (siehe docs/migration_notes.md,
fastapi/starlette).
"""

import asyncio
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
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
    provide_add_user_rules,
    provide_analyze,
    provide_delete_user_rule,
    provide_list_user_rules,
)
from api.analysis import router as analysis_router
from api.capture import (
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
from api.devices import (
    provide_delete_device,
    provide_get_device,
    provide_get_device_stats,
    provide_get_devices,
    provide_record_scanned_host,
    provide_update_device_meta,
)
from api.devices import router as devices_router
from api.diagnostics import (
    provide_check_dhcp_permission,
    provide_check_external,
    provide_check_tools,
    provide_check_traceroute_permission,
    provide_detect_rogue_dhcp,
    provide_grab_banner,
    provide_resolve_dns,
    provide_run_traceroute,
)
from api.diagnostics import router as diagnostics_router
from api.export import provide_export_analysis, provide_export_scan
from api.export import router as export_router
from api.interfaces import provide_list_interfaces
from api.interfaces import router as interfaces_router
from api.metrics import provide_export_metrics
from api.metrics import router as metrics_router
from api.monitoring import (
    provide_add_monitor_target,
    provide_delete_monitor_target,
    provide_get_all_sla_stats,
    provide_get_monitor_events,
    provide_get_rtt_history,
    provide_get_schedules,
    provide_get_sla_stats,
    provide_manage_schedules,
    provide_monitor_status,
    provide_update_schedule,
)
from api.monitoring import router as monitoring_router
from api.process import provide_check_process_permission, provide_list_processes
from api.process import router as process_router
from api.resolver import provide_resolve_endpoint, provide_resolve_ptr_batch
from api.resolver import router as resolver_router
from api.scanning import (
    provide_get_arp_table,
    provide_get_scan_detail,
    provide_get_scan_history,
    provide_lookup_vendor,
)
from api.scanning import router as scanning_router
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
    CaptureLldp,
    GetLldpNeighbors,
    RunCapture,
    StartCapture,
)
from application.devices import (
    DeleteDevice,
    GetDevice,
    GetDevices,
    GetDeviceStats,
    RecordScannedHost,
    UpdateDeviceMeta,
)
from application.diagnostics import (
    CheckDhcpPermission,
    CheckDiagnosticsTools,
    CheckExternalReachability,
    CheckTraceroutePermission,
    DetectRogueDhcp,
    GrabBanner,
    ResolveDns,
    RogueDhcpPermissionError,
    RunTraceroute,
)
from application.export import ExportAnalysis, ExportScan, ScanNotFoundError
from application.interfaces import ListInterfaces
from application.metrics import ExportMetrics
from application.monitoring import (
    AddMonitorTarget,
    DeleteMonitorTarget,
    GetAllSlaStats,
    GetMonitorEvents,
    GetRttHistory,
    GetSchedules,
    GetSlaStats,
    ManageSchedules,
    RunMonitor,
    UpdateSchedule,
)
from application.process import CheckProcessPermission, ListProcesses
from application.resolver import ResolveEndpoint, ResolvePtrBatch
from application.scanning import (
    GetArpTable,
    GetScanDetail,
    GetScanHistory,
    LookupVendor,
    RunNetworkScan,
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
from domain.analysis import ObservedConnection, ObservedHost, ObservedProcess, Rule, Snapshot
from domain.export import (
    ExportableAnalysis,
    ExportableFinding,
    ExportableHost,
    ExportablePort,
    ExportableScan,
)
from domain.monitoring import MonitorEvent, MonitorEventType
from domain.process import classify_kind
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
from infrastructure.analysis_host_history_db import SqliteHostHistoryRepository
from infrastructure.analysis_rules_db import SqliteUserRuleRepository
from infrastructure.capture import (
    ScapyLldpSniffer,
    ScapyPacketSniffer,
    WebSocketCaptureBroadcaster,
)
from infrastructure.clock import SystemClock
from infrastructure.config import APP_NAME, APP_VERSION, AppConfig
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
from infrastructure.export_pdf import ReportlabRenderer
from infrastructure.interfaces_linux import InterfaceDiscoveryAdapter
from infrastructure.logging import configure_logging
from infrastructure.metrics import SqliteMetricsReader
from infrastructure.monitoring import (
    ApschedulerJobScheduler,
    CompositeTargetSource,
    MonitorNotifierAdapter,
    MonitorPingerAdapter,
    SqliteMonitorEventRepository,
    SqliteRttHistoryRepository,
    SqliteScheduleRepository,
    SqliteSlaSampleRepository,
    WebSocketMonitorBroadcaster,
)
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
from infrastructure.scanning.arp_table import ArpTableAdapter
from infrastructure.scanning.fritz_hosts import FritzAuthError, FritzHostsAdapter
from infrastructure.scanning.host_discovery import HostDiscoveryAdapter
from infrastructure.scanning.hostname_resolver import HostnameResolverAdapter
from infrastructure.scanning.ipv6_enrichment import Ipv6EnrichmentAdapter
from infrastructure.scanning.mdns import MdnsAdapter
from infrastructure.scanning.port_scanner import PortScannerAdapter
from infrastructure.scanning.scan_history import CorruptScanError, SqliteScanHistoryRepository
from infrastructure.scanning.ssdp import SsdpAdapter
from infrastructure.scanning.vendor_lookup import VendorLookupAdapter
from infrastructure.secret_store import KeyringSecretStore, SecretStoreUnavailableError
from infrastructure.security import (
    CveLookupAdapter,
    DefaultCredsCheckerAdapter,
    SqliteArpGuardRepository,
    TlsInspectorAdapter,
)
from infrastructure.settings_repository import SqliteSettingsRepository
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
    app.dependency_overrides[provide_get_device] = lambda: GetDevice(device_repository())
    app.dependency_overrides[provide_update_device_meta] = lambda: UpdateDeviceMeta(
        device_repository()
    )
    app.dependency_overrides[provide_delete_device] = lambda: DeleteDevice(device_repository())
    # RecordScannedHost hat (noch) keinen Endpunkt -- hier verdrahtet und bereit-
    # gestellt, damit die spaeter migrierte scanning-Domaene ihn konsumiert.
    app.dependency_overrides[provide_record_scanned_host] = lambda: RecordScannedHost(
        device_repository(), device_clock
    )

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

    app.add_api_websocket_route(
        "/ws/scan",
        make_ws_scan(_build_run_network_scan, _build_record_scanned_host, _build_record_seen),
    )

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
    async def _detect_rogue_dhcp() -> Any:
        return await DetectRogueDhcp(
            NmapDhcpProbe(), LinuxDhcpPermission(), repository(), InterfaceDiscoveryAdapter()
        )()

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
                hosts_observed = tuple(
                    ObservedHost(
                        ip=h.ip,
                        hostname=h.hostname,
                        vendor=h.vendor,
                        open_ports=frozenset(p.port for p in h.ports if p.state == "open"),
                        is_known=(h.mac in known) if h.mac else True,
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
        rule_provider = _CompositeRuleProvider(BuiltinRuleProvider(), analysis_rule_repository())
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

    def _delete_user_rule(rule_id: str) -> None:
        analysis_rule_repository().delete_rule(rule_id)

    app.include_router(analysis_router)
    app.dependency_overrides[provide_analyze] = lambda: _analyze_snapshot
    app.dependency_overrides[provide_add_user_rules] = lambda: _add_user_rules
    app.dependency_overrides[provide_list_user_rules] = lambda: _list_user_rules
    app.dependency_overrides[provide_delete_user_rule] = lambda: _delete_user_rule

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
