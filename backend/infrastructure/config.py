"""Anwendungs-Konfiguration aus Umgebungsvariablen (pydantic-settings).

Liest die Laufzeit-Konfiguration ueber den Praefix ``CERNIS_`` aus der Umgebung
bzw. einer ``.env``-Datei. Infrastruktur-Concern: bindet die Anwendung an die
Aussenwelt (Environment). Wird im Composition Root (``app.py``) instanziiert.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict

APP_NAME = "cernis-pro"


def _lese_build_version() -> str:
    """Volle interne Version inkl. Build-Metadaten (SemVer-Build-Metadata).

    Im CI wird VOR dem Build ``infrastructure/_build_version.py`` mit einer
    Konstante ``BUILD_VERSION`` erzeugt (z. B. ``"2.0.0+x64deb.a1b2c3d"``) und
    von PyInstaller mit eingefroren -- damit ist die Build-Version in der
    installierten App verfuegbar, ohne dass zur Laufzeit eine Env gesetzt sein
    muss. Fehlt die Datei (Dev-Betrieb, nie committet), gilt der Fallback
    ``"2.0.0"``. Die Datei liegt in ``infrastructure/`` -- config.py ist
    ebenfalls ``infrastructure/`` -> hexagonal erlaubt.
    """
    try:
        # Die Datei existiert nur im CI-Build (nie committet) -> mypy kennt sie
        # nicht; der ImportError-Zweig ist der Dev-Normalfall.
        from infrastructure._build_version import (  # type: ignore[import-not-found]
            BUILD_VERSION,
        )
    except ImportError:
        return "2.0.0"
    return str(BUILD_VERSION)


# Volle interne Version. Enthaelt im CI-Build die SemVer-Build-Metadaten
# ("2.0.0+x64deb.<sha>"), im Dev schlicht "2.0.0".
APP_VERSION = _lese_build_version()


def display_version(version: str = APP_VERSION) -> str:
    """Anzeige-Form aus der internen Version: ``"2.0.0+x64deb.a1b2c3d"`` ->
    ``"2.0.0 (x64deb.a1b2c3d)"``. Ohne Build-Metadaten (kein ``"+"``) bleibt sie
    unveraendert (``"2.0.0"`` -> ``"2.0.0"``). Nach aussen/GUI = Anzeige-Form.
    """
    kern, trenner, metadaten = version.partition("+")
    if not trenner:
        return version
    return f"{kern} ({metadaten})"


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
        # Die deb-GUI laedt das Frontend vom Backend-Port (tauri.conf.json
        # url = http://127.0.0.1:8765), daher ist diese Adresse ein legitimer
        # Same-Origin. Diese Allowlist speist REST-CORS UND die WS-Origin-Guards
        # (/ws/scan, /ws/monitor, /ws/pcap); ohne die Ergaenzung blockt der
        # Origin-Guard den WebSocket-Handshake der installierten App
        # ("Scan-Verbindung unterbrochen"). Fremde Webseiten haben nie diesen
        # Origin -> F-01-Schutz gegen Fremd-Origins bleibt wirksam.
        "http://127.0.0.1:8765",
        "http://localhost:8765",
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

    # Per-App-Durchsatz (traffic Stufe 2): ob der Poller beim Start als Dauer-Loop
    # mitlaeuft (AUTO). Greift NUR zusammen mit ``bootstrap_on_startup`` (kein Poll
    # in Tests/ohne produktiven Owner). Default False -> der Durchsatz wird erst auf
    # Anforderung erfasst (MANUELL ueber POST /api/traffic/poll/start), sparsam wie
    # der capture-Loop. Ueber ``CERNIS_TRAFFIC_POLL_AUTO`` einschaltbar.
    traffic_poll_auto: bool = False

    # Poll-Intervall des Durchsatz-Pollers in Sekunden (Vision-"Regler": kleiner =
    # feiner aufgeloeste Momentanrate, mehr Last). Gilt fuer AUTO und MANUELL.
    # Ueber ``CERNIS_TRAFFIC_POLL_INTERVAL`` anpassbar.
    traffic_poll_interval: float = 1.0

    # Verzeichnis des gebauten React-Frontends (frontend-dist). Hat Vorrang vor
    # der automatischen Suche (siehe app._resolve_frontend_dir). None -> Suche;
    # findet sich keins, laeuft die App API-only ohne Frontend-Serving.
    frontend_dir: str | None = None
