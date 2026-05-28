"""Composition Root von CERNIS PRO 2.0.

Einziger Ort, an dem alle Ringe zusammenkommen: konfiguriert Logging und
Middleware, baut die FastAPI-App und verdrahtet (ab Schritt 6) ``ports/`` <->
``infrastructure/`` per Dependency Injection. Bewusst von den import-linter-
Vertraegen ausgenommen (Composition-Root-Ausnahme, Regel 5).

Lifespan-Kontext statt ``@app.on_event`` (siehe docs/migration_notes.md,
fastapi/starlette).
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import lru_cache

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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

logger = structlog.get_logger()


def create_app(config: AppConfig | None = None) -> FastAPI:
    """Baut die FastAPI-App. ``config=None`` liest die Konfiguration aus der Umgebung."""
    cfg = config or AppConfig()
    configure_logging(level=cfg.log_level, json_logs=cfg.log_json)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        # Hier werden ab Schritt 6 Adapter/Use-Cases verdrahtet und ueber
        # app.state bereitgestellt; in einem finally analog wieder freigegeben.
        logger.info("startup", service=APP_NAME, version=APP_VERSION)
        yield
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

    return app


app = create_app()
