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
