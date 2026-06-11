"""Use-Cases der diagnostics-Domaene -- DNS-Aufloesung + traceroute + Rechte-Naht.

Orchestrieren die Ports (``DnsResolver``/``TracerouteRunner``/
``TraceroutePermissionPort``). Kennen ``domain/`` und ``ports/``, NIEMALS
``infrastructure/`` (maschinell per import-linter erzwungen). Ports kommen per
Constructor-Injection als Protocol-Typ herein -- nie ein konkreter Adapter.

Drei Use-Cases (duenn, Muster ``ListProcesses``/``CheckProcessPermission``):

* ``ResolveDns`` -- duenner Lese-Pass-Through ueber den ``DnsResolver``.
* ``RunTraceroute`` -- duenner Pass-Through ueber den ``TracerouteRunner`` (die
  ``privileged``-Wahl reicht der Use-Case unveraendert durch -- bewusste Nutzerwahl).
* ``CheckTraceroutePermission`` -- die ``{ok, error}``-Rechte-Naht (Muster
  ``CheckProcessPermission``): ``is_available`` -> ``check_permission`` -> dict. Hier
  bedeutet ``ok=True``: die privilegierte (genauere) Methode ist verfuegbar; ``ok=False``
  + Text: nur die unprivilegierte (ungenauere) Methode, mit Begruendung.

Block 2a:

* ``GrabBanner`` -- duenner Pass-Through ueber den ``BannerGrabber`` (Muster
  ``RunTraceroute``): das Anklopfen ueber den Grabber durchreichen, keine eigene Logik.

Block 1b:

* ``CheckDiagnosticsTools`` -- duenne Orchestrierung (Muster der uebrigen UCs): ermittelt
  pro Tool die Verfuegbarkeit (``ToolDetector``) und den Paketmanager
  (``PackageManagerDetector``) und ruft die reine domain-Funktion ``assemble_report``.
  Keine eigene Logik ausser Orchestrierung; synchron (reine lokale Checks, Muster
  ``CheckTraceroutePermission``). ``requested_tools`` None/leer -> ``ALL_TOOLS``
  (Erstinstallation: alle pruefen); sonst genau die genannten (Laufzeit). Unbekannte
  Tool-Namen (nicht in ``TOOL_PACKAGES``) werden defensiv ignoriert (nicht erfunden).

Block 2b:

* ``CheckExternalReachability`` -- der externe IP/Port-Check (Modell D). Liest Token
  (``SecretStore``, Muster agent ``secret_store.get(...) or ""``) + URL
  (``SettingsRepository``, Default-Fallback ``DEFAULT_CPNETCHECK_URL`` wenn nicht gesetzt)
  und ruft den ``ExternalReachabilityProvider`` NUR, wenn Token UND URL gesetzt sind. Sonst
  ehrlich ``ExternalCheckResult(configured=False, ...)`` mit neutralem Hinweis -- KEIN
  Aufruf nach aussen (ADR 0001, kein stiller Fallback). Eine Methode mit optionaler
  Portliste (``ports=None`` -> reiner IP-Check; Liste -> IP + Port-Check), passend zu den
  zwei api-Routen. Dienst-Fehler (``ExternalCheckError`` des Providers) werden NICHT
  verschluckt: sie laufen durch zum api-Rand, der sie (Muster ``DiagnosticsToolMissing`` ->
  503) auf **502** abbildet -- konsistent zum bestehenden diagnostics-Durchwurf-Muster.
"""

from collections.abc import Sequence

from domain.diagnostics import (
    ALL_TOOLS,
    TOOL_PACKAGES,
    BannerResult,
    DnsRecordType,
    DnsResult,
    ExternalCheckResult,
    ToolReport,
    TracerouteResult,
    assemble_report,
    validate_requested_ports,
)
from ports.diagnostics import (
    BannerGrabber,
    DnsResolver,
    ExternalReachabilityProvider,
    PackageManagerDetector,
    ToolDetector,
    TraceroutePermissionPort,
    TracerouteRunner,
)
from ports.settings import SecretStore, SettingsRepository

# Default-cpnetcheck-URL, falls das (NICHT-geheime) Setting ``cpnetcheck_url`` nicht
# gesetzt ist. Die Konstante lebt HIER in der diagnostics-Schicht (NICHT in settings --
# settings ist ein generischer KV-Store ohne Default-Mechanik). Der Use-Case faellt bei
# Abwesenheit des Settings auf diesen Wert zurueck (austauschbar ueber das Setting).
DEFAULT_CPNETCHECK_URL = "https://cpnetcheck.bach.world"

# Settings-/Secret-Keys des externen Checks. ``cpnetcheck_token`` ist ein Secret
# (domain.settings.SECRET_KEYS -> redigiert, nur ueber UpdateSecret setzbar); die URL ist
# ein normales Setting. Hier als benannte Konstanten, damit der Lese-Pfad eindeutig ist.
_CPNETCHECK_TOKEN_KEY = "cpnetcheck_token"
_CPNETCHECK_URL_KEY = "cpnetcheck_url"

# Neutraler Hinweis fuer den nicht-konfigurierten Zustand (Modell D, ADR 0001). KEIN
# stiller Fallback -- der Zustand wird explizit benannt, nicht verschwiegen.
_NOT_CONFIGURED_HINT = (
    "Externer Check nicht konfiguriert: bitte cpnetcheck-URL und Token in den Einstellungen setzen."
)


class ResolveDns:
    """DNS-Aufloesung: duenner Lese-Pass-Through ueber den ``DnsResolver``.

    Duenn (Muster ``ListProcesses.flat``): die Abfrage ueber den Resolver durchreichen,
    keine eigene Logik. Keine Antwort (leere ``records``) ist KEIN Fehler -- der Resolver
    liefert ein ``DnsResult`` mit leeren ``records``.
    """

    def __init__(self, resolver: DnsResolver) -> None:
        self._resolver = resolver

    async def __call__(self, query: str, types: Sequence[DnsRecordType]) -> DnsResult:
        """Loest ``query`` fuer die angefragten ``types`` auf (duenner Pass-Through)."""
        return await self._resolver.resolve(query, types)


class RunTraceroute:
    """traceroute: duenner Pass-Through ueber den ``TracerouteRunner``.

    Duenn (Muster ``ListProcesses.flat``): die Messung ueber den Runner durchreichen. Die
    ``privileged``-Wahl wird UNVERAENDERT weitergegeben -- bewusste Nutzerwahl, kein
    Default-Raten und keine Selbst-Eskalation (privileged laeuft nur, wenn der Prozess die
    Rechte ohnehin hat; sonst meldet der Runner ehrlich die unprivilegierte Methode).
    """

    def __init__(self, runner: TracerouteRunner) -> None:
        self._runner = runner

    async def __call__(self, target: str, privileged: bool) -> TracerouteResult:
        """Misst den Pfad zu ``target`` (duenner Pass-Through; ``privileged`` durchgereicht)."""
        return await self._runner.run(target, privileged)


class GrabBanner:
    """Banner-Grabbing (2a): duenner Pass-Through ueber den ``BannerGrabber``.

    Duenn (Muster ``RunTraceroute``): das Anklopfen ueber den Grabber durchreichen, keine
    eigene Logik. Der Port kommt per Constructor-Injection als Protocol-Typ herein -- nie
    ein konkreter Adapter. Ehrliche Semantik liegt im Grabber/der Domaene (kein erfundener
    Banner) -- der Use-Case reicht das ``BannerResult`` unveraendert durch.
    """

    def __init__(self, grabber: BannerGrabber) -> None:
        self._grabber = grabber

    async def __call__(self, target: str, port: int) -> BannerResult:
        """Klopft an ``target:port`` und liest die Begruessung (duenner Pass-Through)."""
        return await self._grabber.grab(target, port)


class CheckTraceroutePermission:
    """Rechte-Naht wie process: is_available -> check_permission -> {ok, error}.

    Duenn (Muster ``CheckProcessPermission``): prueft Verfuegbarkeit (Binary da?) und dann
    die Methoden-Tiefe (``check_permission``) ueber den Rechte-Port und gibt die
    ``{ok, error}``-Form zurueck. Hier bedeutet ``ok=True``: die privilegierte (genauere)
    Methode ist verfuegbar (Root); ``ok=False`` + Text: nur die unprivilegierte
    (ungenauere) Methode, mit Begruendung. Der api-Rand reicht die Form unveraendert durch.
    """

    def __init__(self, permission: TraceroutePermissionPort) -> None:
        self._permission = permission

    def __call__(self) -> dict[str, object]:
        """``{"ok": True, "error": ""}`` bei moeglicher Root-Methode, sonst ``ok=False`` + Grund.

        ``is_available`` False -> Binary nicht nutzbar (``traceroute`` fehlt). Sonst
        ``check_permission``: ein nicht-leerer Text ist die Begruendung (genauere Methode
        braucht Root) -> ``ok=False`` (nur unprivilegierte Methode). ``None`` -> die
        privilegierte (genauere) Methode ist moeglich.
        """
        if not self._permission.is_available():
            return {
                "ok": False,
                "error": "Das Programm 'traceroute' ist auf dieser Plattform nicht verfuegbar.",
            }
        text = self._permission.check_permission()
        return {"ok": text is None, "error": text or ""}

    def is_available(self) -> bool:
        """Reiner Verfuegbarkeits-Check (fuer einen spaeteren ``/available``-Pfad)."""
        return self._permission.is_available()

    def check_permission(self) -> str | None:
        """Rechte-Begruendung oder ``None`` (fuer einen spaeteren ``permission_error``)."""
        return self._permission.check_permission()


class CheckDiagnosticsTools:
    """Tool-Bericht (1b): orchestriert Detector + Paketmanager -> ``assemble_report``.

    Duenn (Muster ``CheckTraceroutePermission``): keine eigene Logik ausser Orchestrierung.
    Die Ports kommen per Constructor-Injection als Protocol-Typ herein -- nie ein konkreter
    Adapter. Synchron, weil beide Erkennungen reine lokale Checks sind (which-basiert).
    """

    def __init__(self, detector: ToolDetector, pm: PackageManagerDetector) -> None:
        self._detector = detector
        self._pm = pm

    def __call__(self, requested_tools: Sequence[str] | None) -> ToolReport:
        """Prueft die angefragten (oder alle) Tools -> ``ToolReport``.

        ``requested_tools`` ``None`` ODER leer -> ``ALL_TOOLS`` (Erstinstallations-Fall:
        alle registrierten Tools pruefen). Sonst genau die genannten (Laufzeit-Fall);
        unbekannte Tool-Namen (nicht in ``TOOL_PACKAGES``) werden defensiv ignoriert
        (nicht erfunden). Pro Tool die Verfuegbarkeit (``detector.is_available``), dazu der
        Manager (``pm.detect()``), dann die reine domain-Funktion ``assemble_report``.
        """
        if requested_tools:
            tools = [tool for tool in requested_tools if tool in TOOL_PACKAGES]
        else:
            tools = list(ALL_TOOLS)
        availability = {tool: self._detector.is_available(tool) for tool in tools}
        manager = self._pm.detect()
        return assemble_report(manager, availability, tools)


class CheckExternalReachability:
    """Externer IP/Port-Check via cpnetcheck (2b, Modell D): nur aktiv bei URL+Token.

    Orchestriert den ``ExternalReachabilityProvider`` mit der Settings-/Secret-Naht: liest
    den Token (``SecretStore``, Muster agent: ``get(...) or ""``) und die URL
    (``SettingsRepository``, Default-Fallback ``DEFAULT_CPNETCHECK_URL``). Ist Token ODER
    URL leer -> ``ExternalCheckResult(configured=False, ...)`` mit neutralem Hinweis, OHNE
    Aufruf nach aussen (ADR 0001, kein stiller Fallback). Sonst ruft er den Provider und
    baut das ``ExternalCheckResult(configured=True, ...)``.

    Die Ports kommen per Constructor-Injection als Protocol-Typ herein -- nie ein konkreter
    Adapter (settings_repo + secret_store ebenfalls als Protocol, Muster agent). Dienst-/
    Netzfehler (``ExternalCheckError``) verschluckt der Use-Case NICHT: sie laufen durch zum
    api-Rand (-> 502), konsistent zum bestehenden diagnostics-Durchwurf-Muster
    (``DiagnosticsToolMissing`` -> 503). EINE Methode mit optionaler Portliste passt zu den
    zwei api-Routen (``ports=None`` -> reiner IP-Check; Liste -> IP + Port-Check).
    """

    def __init__(
        self,
        provider: ExternalReachabilityProvider,
        settings_repo: SettingsRepository,
        secret_store: SecretStore,
    ) -> None:
        self._provider = provider
        self._settings_repo = settings_repo
        self._secret_store = secret_store

    async def __call__(self, ports: Sequence[int] | None = None) -> ExternalCheckResult:
        """Fuehrt den externen Check aus -> ``ExternalCheckResult`` (Modell D).

        ``ports`` ``None``/leer -> reiner IP-Check (``get_external_ip``); sonst zusaetzlich
        Port-Check (``check_ports``) ueber die client-seitig validierten Ports
        (``validate_requested_ports`` -- Bereich/max/dedup). Token leer ODER URL leer ->
        ``configured=False`` + neutraler Hinweis, KEIN Aufruf nach aussen. Sonst Provider-
        Aufruf; eine ``ExternalCheckError`` des Providers wird NICHT gefangen (Durchwurf ->
        api-Rand -> 502).
        """
        # Token als Klartext aus dem SecretStore (Muster agent: ``get(...) or ""`` -- ein
        # nicht gesetzter Token ist "" und damit leer). Die URL ueber das (Roh-)Setting;
        # fehlt es ODER ist sein Wert leer -> Default-Konstante (austauschbar ueber das
        # Setting, kein settings-interner Default-Mechanismus).
        token = self._secret_store.get(_CPNETCHECK_TOKEN_KEY) or ""
        url_setting = self._settings_repo.get(_CPNETCHECK_URL_KEY)
        url = (
            str(url_setting.value)
            if url_setting is not None and url_setting.value
            else DEFAULT_CPNETCHECK_URL
        )
        # Modell D: nur aktiv, wenn Token UND URL gesetzt sind. Der Token ist die echte
        # Huerde (die URL hat einen Default) -- ohne Token kein Aufruf nach aussen.
        if not token or not url:
            return ExternalCheckResult(
                configured=False,
                checked_ip=None,
                family=None,
                ports=(),
                error=_NOT_CONFIGURED_HINT,
            )
        requested = validate_requested_ports(ports) if ports else ()
        if requested:
            ip, port_results = await self._provider.check_ports(url, token, requested)
            return ExternalCheckResult(
                configured=True,
                checked_ip=ip.ip,
                family=ip.family,
                ports=port_results,
                error=None,
            )
        ip = await self._provider.get_external_ip(url, token)
        return ExternalCheckResult(
            configured=True,
            checked_ip=ip.ip,
            family=ip.family,
            ports=(),
            error=None,
        )
