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
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response
from starlette.types import Scope

from api.settings import (
    provide_get_settings,
    provide_update_secret,
    provide_update_setting,
)
from api.settings import router as settings_router
from application.settings import GetSettings, UpdateSecret, UpdateSetting
from infrastructure.config import APP_NAME, APP_VERSION, AppConfig
from infrastructure.logging import configure_logging
from infrastructure.secret_store import KeyringSecretStore, SecretStoreUnavailableError
from infrastructure.settings_repository import SqliteSettingsRepository

# ── ÜBERGANGS-KRÜCKE P2.1b: Bootstrap-Init aus dem Altcode (modules/) ──────────
# app.py ist Bootstrap-Owner und ruft die Init-/Teardown-Funktionen der noch
# nicht migrierten Domaenen (monitoring, scheduler, sla, alerting, agent,
# devices) UEBERGANGSWEISE direkt aus modules/ auf. Diese Importe sind bewusst
# nur hier erlaubt (Composition Root, nicht vom import-linter analysiert); ein
# Guardrail-Contract verbietet den Ringen jeden modules/-Import. Jede Gruppe
# faellt weg, sobald die jeweilige Domaene migriert ist.
from modules.agent import init_agents_db
from modules.alerting import init_alerts_db
from modules.devices_db import init_devices_db
from modules.interfaces import get_interfaces
from modules.monitor import (
    MonitorTarget,
    run_monitor,
    stop_monitor,
)
from modules.monitor import (
    configure as configure_monitor,
)
from modules.scheduler import init_schedule_db, start_scheduler, stop_scheduler
from modules.sla import init_sla_db
from modules.storage import get_setting, init_db

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


def _build_monitor_targets() -> list[Any]:
    """Monitor-Targets aus Interfaces + Settings (wie main.py, ohne toten wlan/lan-Code)."""
    targets: list[Any] = []
    for iface in get_interfaces():
        if iface.gateway and iface.ipv4:
            targets.append(
                MonitorTarget(
                    id=f"gw_{iface.name}",
                    label=f"Gateway ({iface.name})",
                    host=iface.gateway,
                    interface=iface.name,
                    enabled=True,
                )
            )
    targets.append(
        MonitorTarget(
            id="internet_primary",
            label="Internet (Google DNS)",
            host="8.8.8.8",
            interface="",
            enabled=True,
        )
    )
    targets.append(
        MonitorTarget(
            id="internet_secondary",
            label="Internet (Cloudflare)",
            host="1.1.1.1",
            interface="",
            enabled=True,
        )
    )
    custom = get_setting("monitor_custom_targets", [])
    for t in custom or []:
        targets.append(MonitorTarget(**t))
    return targets


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
        # versehentlichem Doppelstart. Sequenz exakt wie main.py (P2.1a-Contract).
        if cfg.bootstrap_on_startup:
            _check_version_upgrade()
            init_db()
            init_devices_db()
            configure_monitor(_build_monitor_targets(), interval=5)
            # Referenz auf app.state halten (verhindert vorzeitige GC des Tasks).
            _app.state.monitor_task = asyncio.create_task(run_monitor())
            init_schedule_db()
            init_sla_db()
            init_alerts_db()
            init_agents_db()
            start_scheduler(_scheduled_scan)
        yield
        if cfg.bootstrap_on_startup:
            stop_monitor()
            stop_scheduler()
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
