"""Anwendungs-Konfiguration aus Umgebungsvariablen (pydantic-settings).

Liest die Laufzeit-Konfiguration ueber den Praefix ``CERNIS_`` aus der Umgebung
bzw. einer ``.env``-Datei. Infrastruktur-Concern: bindet die Anwendung an die
Aussenwelt (Environment). Wird im Composition Root (``app.py``) instanziiert.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict

APP_NAME = "cernis-pro"
APP_VERSION = "2.0.0.dev0"


class AppConfig(BaseSettings):
    """Laufzeit-Konfiguration. Felder per ``CERNIS_<FELD>`` ueberschreibbar."""

    model_config = SettingsConfigDict(
        env_prefix="CERNIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Restriktive CORS-Allowlist statt allow_origins=["*"] (Finding S1).
    # Defaults decken Tauri v2 (macOS/Windows/Linux) und die Vite-/Tauri-
    # Dev-Server ab; in Produktion wird das Frontend ohnehin same-origin
    # ausgeliefert. Ueber CERNIS_CORS_ALLOW_ORIGINS (JSON-Liste) anpassbar.
    cors_allow_origins: list[str] = [
        "tauri://localhost",
        "http://tauri.localhost",
        "http://localhost:1420",
        "http://localhost:5173",
    ]

    log_level: str = "INFO"
    log_json: bool = False

    # Ob beim App-Start der (uebergangsweise aus modules/ stammende) Bootstrap-
    # Init laeuft: DB-/Monitor-/Scheduler-Setup. Default False -> app.py ist NOCH
    # NICHT der produktive Einstiegspunkt (main.py bleibt es bis P2.3) und faehrt
    # keine echten Background-Tasks/DB-Writes hoch; das schuetzt zugleich vor
    # Doppelstart gegen die reale DB. Der Einstiegspunkt-Wechsel (P2.3) setzt
    # CERNIS_BOOTSTRAP_ON_STARTUP=true und dokumentiert so den Uebergang.
    bootstrap_on_startup: bool = False

    # Verzeichnis des gebauten React-Frontends (frontend-dist). Hat Vorrang vor
    # der automatischen Suche (siehe app._resolve_frontend_dir). None -> Suche;
    # findet sich keins, laeuft die App API-only ohne Frontend-Serving.
    frontend_dir: str | None = None
