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

Block 3:

* ``DetectRogueDhcp`` -- die Rogue-DHCP-Erkennung. Bestimmt die ERWARTETE Server-Menge:
  das Nutzer-Setting ``expected_dhcp_servers`` (Liste) ueber ``SettingsRepository``, wenn
  gesetzt+nicht-leer; SONST Fallback auf das Gateway des primaeren Interface (ueber den
  bestehenden ``InterfaceDiscoveryPort`` + die reine domain-Funktion ``select_primary`` --
  NICHT direkt ein Adapter, Muster wie 2b ``settings_repo``/``secret_store`` injiziert).
  Kein Gateway ermittelbar -> erwartete Menge leer (die Domaene behandelt das: alle
  gefundenen gelten dann als unerwartet). VOR ``probe.discover()`` wird die Root-Rechte-
  Pruefung (``DhcpPermissionPort``) ausgewertet -- fehlt Root, wird der Probe NICHT gerufen,
  sondern eine ``RogueDhcpPermissionError`` geworfen (ehrliche Sperre, kein blindes Laufen).
  Die Klassifikation (erwartet vs. unerwartet) macht die reine domain-Funktion
  ``classify_dhcp_servers``.
* ``CheckDhcpPermission`` -- die ``{ok, error}``-Rechte-Naht (Muster
  ``CheckTraceroutePermission``): ``is_available`` -> ``check_permission`` -> dict.
  ``ok=False`` + Text, wenn nmap fehlt ODER kein Root (Rogue-DHCP ist root-pflichtig ohne
  Alternative -- anders als traceroute KEINE rootless Methode).
* ``GetLatestRogueDhcp`` -- duenner Lese-Pass-Through ueber den ``RogueDhcpStore`` (ADR
  0038): liefert den letzten gespeicherten Stand (``LatestRogueDhcp``) oder ``None`` (noch
  nie geprueft). Stil wie ``ResolveDns`` -- der Bericht liest den Stand, ohne einen aktiven
  (root-pflichtigen) Probe auszuloesen.

Block 3 / Persistenz (ADR 0038): ``DetectRogueDhcp`` bekommt einen OPTIONALEN
``RogueDhcpStore`` injiziert und speichert nach JEDEM erfolgreichen Lauf UEBERSCHREIBEND den
letzten Stand. Warum die Schreibnaht IM Use-Case (nicht erst am Composition Root): der
bestehende Stil verdrahtet Persistenz-Nebenwirkungen in den Use-Case (Muster
``RunArpScan`` -> ``ArpGuardRepository``; ``DetectRogueDhcp`` liest ohnehin schon
``SettingsRepository``/``InterfaceDiscoveryPort``) -- so bleibt "speichere den letzten
Lauf" eine einzige, getestete Naht statt einer am Composition Root nachgeklebten. Der Store
ist OPTIONAL (Default ``None`` = nicht persistieren), damit reine Erkennungs-Aufrufe (und
die bestehenden Tests) ohne Speicher weiterlaufen. ``checked_ts`` kommt als PARAMETER von
``__call__`` herein (vom Composition Root, ``time.time()``) -- KEINE Wanduhr im Use-Case
(Muster der zeitfreien Use-Cases ``cve.RunDripCheck(now, ...)`` / monitoring; S3-konform).
"""

from collections.abc import Awaitable, Callable, Sequence

from application.diagnostics.errors import RogueDhcpPermissionError
from domain.diagnostics import (
    ALL_TOOLS,
    TOOL_PACKAGES,
    BannerResult,
    DnsRecordType,
    DnsResult,
    ExternalCheckResult,
    RogueDhcpResult,
    ToolReport,
    TracerouteResult,
    assemble_report,
    classify_dhcp_servers,
    validate_requested_ports,
)
from domain.interfaces import select_primary
from ports.diagnostics import (
    BannerGrabber,
    DhcpPermissionPort,
    DhcpProbe,
    DnsResolver,
    ExternalReachabilityProvider,
    LatestRogueDhcp,
    PackageManagerDetector,
    RogueDhcpStore,
    ToolDetector,
    TraceroutePermissionPort,
    TracerouteRunner,
)
from ports.interfaces import InterfaceDiscoveryPort
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

# Setting-Key der NUTZERLISTE erwarteter DHCP-Server (Block 3, NICHT-geheim, Liste). Wird
# ueber die bestehenden settings-Use-Cases (UpdateSetting) gesetzt/geloescht und hier ueber
# ``SettingsRepository`` gelesen -- kein neuer Setting-Mechanismus (SettingValue erlaubt
# list). Ist es gesetzt+nicht-leer -> es ist die Erwartungsmenge; sonst Gateway-Fallback.
_EXPECTED_DHCP_SERVERS_KEY = "expected_dhcp_servers"

# Neutraler Hinweis fuer den nicht-konfigurierten Zustand (Modell D, ADR 0001). KEIN
# stiller Fallback -- der Zustand wird explizit benannt, nicht verschwiegen.
_NOT_CONFIGURED_HINT = (
    "Externer Check nicht konfiguriert: bitte cpnetcheck-URL und Token in den Einstellungen setzen."
)

# Quellen-AGNOSTISCHE Geo-Naht (ADR 0036, Hauptpfad): ``BuildRouteGeo`` reichert jeden
# antwortenden Hop ueber dieses Callable an -- IP -> rohes ``{country, asn, asn_org}``-dict.
# Es ist BEWUSST ein dict (KEIN ``GeoAsnRecord``): so nennt die diagnostics-Domaene die
# resolver-Domaene NICHT (import-linter independence). Die echte Geo-Quelle (CsvGeoAsnDb)
# wird erst im Composition Root (app.py) eingehaengt -- der Use-Case kennt sie nicht.
GeoLookup = Callable[[str], dict[str, str | None]]

# Quellen-AGNOSTISCHE RDAP-Naht (ADR 0036, optionale Nachladung): ``EnrichRouteOrgs``
# loest den Betreibernamen je IP ueber dieses Callable auf -- IP -> Org-Name oder ``None``.
# Wie ``GeoLookup`` BEWUSST ein roher Typ (str|None, KEIN resolver-domain-Typ): die
# diagnostics-Domaene nennt resolver nicht. Async, weil die echte Quelle (RdapClient) Netz-
# I/O macht; STRENG fehlertolerant (liefert ``None`` statt zu werfen) -- am Rand verdrahtet.
OrgLookup = Callable[[str], Awaitable[str | None]]


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


class BuildRouteGeo:
    """Route-zum-Ziel (ADR 0036): traceroute-Hops je IP lokal mit Geo/ASN anreichern.

    Quellen-AGNOSTISCH (Muster ``BuildTopology``/``application.export``): bekommt den
    ``RunTraceroute``-Use-Case (eigene diagnostics-Domaene -- erlaubt) UND ein rohes
    ``GeoLookup``-Callable (IP -> ``{country, asn, asn_org}``-dict) per Constructor-Injection.
    Das Geo-Callable nennt die resolver-Domaene NICHT (es reicht ein dict herein) -- die
    echte Quelle (CsvGeoAsnDb) faellt erst im Composition Root, die independence-Naht bleibt
    hart (weder diagnostics-Domaene noch -Port kennt resolver). KEIN ``infrastructure``.

    LOKAL + SYNCHRON im Geo-Teil (der Lookup ist ein lokaler DB-Treffer, kein Netz-I/O):
    der Hauptpfad bleibt schnell und root-frei. ``asn_org`` traegt der lokale DB-Lookup
    BEWUSST ``None`` (die CSV-DB kennt nur Land + ASN-Nummer; der Klartext-Betreibername
    kommt -- nur auf expliziten Nutzer-Abruf -- aus ``EnrichRouteOrgs``/RDAP, nicht hier
    geraten). Das ist ehrliche Leere, KEIN stiller Fallback (S3).

    EHRLICHE LUECKEN: ein nicht-antwortender Hop (``address=None``) wird NICHT per Geo
    angefragt und behaelt ``country/asn/asn_org = None`` -- die Luecke bleibt als Hop
    sichtbar (kein Weglassen, kein erfundener Wert). Gibt ROHE ``list[dict]`` zurueck; die
    Wire-Form baut der api-Rand.
    """

    def __init__(self, run_traceroute: RunTraceroute, geo_lookup: GeoLookup) -> None:
        self._run_traceroute = run_traceroute
        self._geo_lookup = geo_lookup

    async def __call__(self, target: str, privileged: bool) -> dict[str, object]:
        """Misst den Pfad zu ``target`` und reichert jeden antwortenden Hop lokal an.

        ``privileged`` wird unveraendert an ``RunTraceroute`` durchgereicht (bewusste
        Nutzerwahl, keine Selbst-Eskalation). Pro Hop: hat er eine ``address``, wird sie
        lokal+synchron ueber ``geo_lookup`` aufgeloest (``country``/``asn`` aus der DB,
        ``asn_org`` ehrlich ``None``); ist die ``address`` ``None`` (Timeout-Luecke), bleibt
        der Hop ohne Geo-Felder (``None``) -- die Luecke bleibt sichtbar. Gibt rohe
        ``{target, privileged, hops:[{hop, address, rtt_ms, country, asn, asn_org}]}`` zurueck.
        """
        result = await self._run_traceroute(target, privileged)
        hops: list[dict[str, object]] = []
        for hop in result.hops:
            geo: dict[str, str | None] = (
                self._geo_lookup(hop.address) if hop.address is not None else {}
            )
            hops.append(
                {
                    "hop": hop.hop,
                    "address": hop.address,
                    "rtt_ms": hop.rtt_ms,
                    "country": geo.get("country"),
                    "asn": geo.get("asn"),
                    "asn_org": geo.get("asn_org"),
                }
            )
        return {"target": result.target, "privileged": result.privileged, "hops": hops}


class EnrichRouteOrgs:
    """Optionale Org-Namen-Nachladung (ADR 0036): RDAP-Org je Hop-IP, nur auf Abruf.

    GETRENNT vom lokalen Hauptpfad (``BuildRouteGeo``): diese Naht macht Netz-I/O (RDAP)
    und laeuft NUR auf expliziten Nutzer-Abruf (Frontend-Schalter, Default AUS). Bekommt ein
    rohes ``OrgLookup``-Callable (IP -> Org-Name|``None``) per Constructor-Injection -- es
    nennt die resolver-Domaene NICHT (roher ``str | None``), die echte RDAP-Quelle faellt
    erst im Composition Root. KEIN ``infrastructure``, independence bleibt hart.

    BATCH ueber die deduplizierten, ANTWORTENDEN Hop-IPs (nicht pro Hop einzeln, nicht ueber
    die ASN): RDAP loest pro IP auf (der RdapClient liefert den Org-Namen je IP, nicht je
    ASN), und mehrere Hops teilen sich oft eine IP/ein Netz -- Dedup spart Netz-Aufrufe. Eine
    private/Luecken-IP (``None``) hat keinen Eintrag. STRENG fehlertolerant: scheitert/haengt
    eine Aufloesung, bleibt der Name ``None`` (der Port-Vertrag des RDAP-Adapters wirft nie)
    -- die Nachladung blockiert NIE und faelscht NIE einen Namen (S3).

    Gibt eine rohe ``{ip: org}``-Map zurueck (nur IPs mit gefundenem Namen); der api-Rand
    projiziert sie, das Frontend blendet die Namen in die bereits geladene Liste ein.
    """

    def __init__(self, org_lookup: OrgLookup) -> None:
        self._org_lookup = org_lookup

    async def __call__(self, ips: Sequence[str]) -> dict[str, str]:
        """Loest den Org-Namen je eindeutiger ``ip`` ueber RDAP auf -> ``{ip: org}``-Map.

        Dedupliziert die ``ips`` (Reihenfolge des ersten Vorkommens), fragt jede ueber
        ``org_lookup`` ab und nimmt nur die mit einem nicht-leeren Namen in die Map auf. Eine
        gescheiterte/leere Aufloesung liefert ``None`` -> die IP fehlt schlicht in der Map
        (ehrliche Leere, kein erfundener Name). Leere/komplett erfolglose Eingabe -> leere Map.
        """
        seen: set[str] = set()
        orgs: dict[str, str] = {}
        for ip in ips:
            if not ip or ip in seen:
                continue
            seen.add(ip)
            org = await self._org_lookup(ip)
            if org:
                orgs[ip] = org
        return orgs


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


class CheckDhcpPermission:
    """Rechte-Naht fuer Rogue-DHCP: is_available -> check_permission -> {ok, error}.

    Duenn (Muster ``CheckTraceroutePermission``): prueft Verfuegbarkeit (``nmap`` da?) und
    dann die Root-Rechte (``check_permission``) ueber den Rechte-Port und gibt die
    ``{ok, error}``-Form zurueck. Anders als traceroute (das eine ungenauere rootless-Methode
    kennt) ist Rogue-DHCP ROOT-PFLICHTIG ohne Alternative: ``ok=True`` heisst, das DHCP
    DISCOVER ist moeglich (Root vorhanden); ``ok=False`` + Text heisst, es ist GESPERRT
    (nmap fehlt ODER kein Root). Der api-Rand reicht die Form unveraendert durch.
    """

    def __init__(self, permission: DhcpPermissionPort) -> None:
        self._permission = permission

    def __call__(self) -> dict[str, object]:
        """``{"ok": True, "error": ""}`` wenn Discovery moeglich, sonst ``ok=False`` + Grund.

        ``is_available`` False -> Binary nicht nutzbar (``nmap`` fehlt). Sonst
        ``check_permission``: ein nicht-leerer Text ist die Sperr-Begruendung (Rogue-DHCP
        braucht Root, keine rootless Alternative) -> ``ok=False``. ``None`` -> Root vorhanden,
        Discovery moeglich -> ``ok=True``.
        """
        if not self._permission.is_available():
            return {
                "ok": False,
                "error": "Das Programm 'nmap' ist auf dieser Plattform nicht verfuegbar.",
            }
        text = self._permission.check_permission()
        return {"ok": text is None, "error": text or ""}

    def is_available(self) -> bool:
        """Reiner Verfuegbarkeits-Check (fuer einen spaeteren ``/available``-Pfad)."""
        return self._permission.is_available()

    def check_permission(self) -> str | None:
        """Rechte-Begruendung oder ``None`` (fuer einen spaeteren ``permission_error``)."""
        return self._permission.check_permission()


class DetectRogueDhcp:
    """Rogue-DHCP-Erkennung (3): erwartete Menge bestimmen, Discovery, klassifizieren.

    Orchestriert vier Ports (``DhcpProbe``/``DhcpPermissionPort``/``SettingsRepository``/
    ``InterfaceDiscoveryPort``) + zwei reine domain-Funktionen (``select_primary`` fuer das
    Fallback-Gateway, ``classify_dhcp_servers`` fuer die Klassifikation). Die Ports kommen
    per Constructor-Injection als Protocol-Typ herein -- nie ein konkreter Adapter (Muster
    wie 2b ``settings_repo``/``secret_store`` injiziert; die Gateway-Quelle ist der
    bestehende interfaces-Port, NICHT ein Adapter).

    ERWARTETE MENGE: das Nutzer-Setting ``expected_dhcp_servers`` (Liste) wenn gesetzt+nicht-
    leer; SONST Fallback auf das Gateway des primaeren Interface (``select_primary`` ueber die
    rohen Interfaces des Ports). Kein Gateway -> leere Erwartung (die Domaene behandelt das:
    alle gefundenen gelten dann als unerwartet).

    ROOT-PFLICHT: VOR ``probe.discover()`` wird ``permission`` ausgewertet. Fehlt Root (oder
    nmap), wird der Probe NICHT gerufen, sondern ``RogueDhcpPermissionError`` geworfen --
    ehrliche Sperre, kein blindes Laufen gegen fehlendes Root, keine Selbst-Eskalation.
    """

    def __init__(
        self,
        probe: DhcpProbe,
        permission: DhcpPermissionPort,
        settings_repo: SettingsRepository,
        interfaces: InterfaceDiscoveryPort,
        store: RogueDhcpStore | None = None,
    ) -> None:
        self._probe = probe
        self._permission = permission
        self._settings_repo = settings_repo
        self._interfaces = interfaces
        # OPTIONAL (ADR 0038): ist ein Store injiziert, wird der letzte erfolgreiche Lauf
        # ueberschreibend gespeichert; sonst (Default None) reine Erkennung ohne Persistenz.
        self._store = store

    async def __call__(self, checked_ts: float | None = None) -> RogueDhcpResult:
        """Fuehrt die Rogue-DHCP-Erkennung aus -> ``RogueDhcpResult``.

        Erst die Rechte-Pruefung (root-pflichtig): nmap fehlt ODER kein Root ->
        ``RogueDhcpPermissionError`` (der Probe wird NICHT gerufen). Sonst die erwartete
        Menge bestimmen (Setting ODER Gateway-Fallback), das DHCP DISCOVER ueber den Probe
        senden und die rohen Funde + erwartete Menge an die reine domain-Funktion
        ``classify_dhcp_servers`` uebergeben.

        Persistenz (ADR 0038): ist ein ``RogueDhcpStore`` injiziert UND ``checked_ts``
        gegeben (Unix-ts vom Composition Root, ``time.time()`` -- KEINE Wanduhr hier), wird
        der erfolgreiche Lauf ueberschreibend gespeichert (der letzte Stand fuer den
        spaeteren Bericht). Fehlt eins von beiden, laeuft die reine Erkennung wie bisher.
        """
        # Root-pflichtig, keine rootless Alternative -- VOR dem Discovery sperren (S3).
        if not self._permission.is_available():
            raise RogueDhcpPermissionError(
                "Das Programm 'nmap' ist auf dieser Plattform nicht verfuegbar."
            )
        permission_error = self._permission.check_permission()
        if permission_error is not None:
            raise RogueDhcpPermissionError(permission_error)
        expected = await self._expected_servers()
        found = await self._probe.discover()
        result = classify_dhcp_servers(found, expected)
        # Letzten Stand ueberschreibend speichern (nur wenn Store + Zeitstempel da sind).
        # Port-neutral: die Domaenen-``DhcpServer`` werden in rohe (ip, mac, is_expected)-
        # Tupel uebersetzt (der Store-Vertrag kennt keine domain-Typen).
        if self._store is not None and checked_ts is not None:
            self._store.save_latest(
                [(s.ip, s.mac, s.is_expected) for s in result.servers],
                result.expected,
                result.has_unexpected,
                checked_ts,
            )
        return result

    async def _expected_servers(self) -> list[str]:
        """Ermittelt die erwartete DHCP-Server-Menge: Nutzer-Setting ODER Gateway-Fallback.

        Setting ``expected_dhcp_servers`` (Liste) wenn gesetzt+nicht-leer -> dessen
        String-Eintraege (typfremde Eintraege werden defensiv uebersprungen, nicht
        erfunden). Sonst Fallback: das Gateway des primaeren Interface (``select_primary``
        ueber die rohen Interfaces). Kein primaeres Interface / kein Gateway -> leere Liste
        (die Domaene behandelt das: alle gefundenen gelten dann als unerwartet).
        """
        setting = self._settings_repo.get(_EXPECTED_DHCP_SERVERS_KEY)
        if setting is not None and isinstance(setting.value, list):
            configured = [item for item in setting.value if isinstance(item, str) and item.strip()]
            if configured:
                return configured
        return await self._gateway_fallback()

    async def _gateway_fallback(self) -> list[str]:
        """Gateway des primaeren Interface als Erwartungsmenge -- leer, wenn keins.

        Holt die rohen Interfaces ueber den Port, bestimmt das primaere ueber die reine
        domain-Funktion ``select_primary`` (deterministisch) und nimmt dessen ``gateway``.
        Kein primaeres Interface ODER kein Gateway gesetzt -> leere Liste (kein Raten).
        """
        interfaces = await self._interfaces.discover()
        primary_name = select_primary(interfaces)
        if primary_name is None:
            return []
        for iface in interfaces:
            if iface.name == primary_name and iface.gateway:
                return [iface.gateway]
        return []


class GetLatestRogueDhcp:
    """Letzter Rogue-DHCP-Stand (ADR 0038): duenner Lese-Pass-Through ueber den Store.

    Duenn (Muster ``ResolveDns``/``ListProcesses.flat``): den letzten gespeicherten Stand
    ueber den ``RogueDhcpStore`` durchreichen, keine eigene Logik. ``None`` (noch nie
    geprueft) wird unveraendert weitergereicht -- ehrliche Abwesenheit, KEIN Ersatz-Stand.
    Der Store kommt per Constructor-Injection als Protocol-Typ herein -- nie ein konkreter
    Adapter. Zweck: der Bericht liest den Stand, OHNE einen aktiven (root-pflichtigen) Probe
    auszuloesen.
    """

    def __init__(self, store: RogueDhcpStore) -> None:
        self._store = store

    def __call__(self) -> LatestRogueDhcp | None:
        """Liefert den letzten gespeicherten Stand (``LatestRogueDhcp``) oder ``None``."""
        return self._store.load_latest()
