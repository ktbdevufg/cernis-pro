"""WebSocket-Handler ``/ws/scan`` -- lebt im Composition Root, NICHT im api-Ring.

Warum hier und nicht in ``api/``: Die Event->Frame-Uebersetzung braucht die
``domain``-Event-Typen (``match``/``assert_never`` ueber die ``ScanEvent``-Union)
UND die Adapter-Exceptions (``NmapScanError``/``FritzAuthError`` aus
``infrastructure``). Beide Importe sind dem api-Ring per import-linter verboten
(api -> nur application, nicht domain/ports/infrastructure). ``backend/ws_scan.py``
liegt flach in ``backend/`` -- kein Submodul eines ``root_package`` -, ist also
wie ``app.py`` von den Contracts ausgenommen (Composition-Root-Ausnahme).

Der Handler bekommt die ``RunNetworkScan``-Factory injiziert (gebaut in
``app.py`` mit den konkreten Adaptern) -- er konstruiert den Use-Case NICHT selbst,
haelt aber keinen api-Ring-Reinheitsanspruch (er IST Composition Root).

Frame-Protokoll: am S.1-Characterization-Contract (``test_ws_scan_contract``), mit
EINER bewussten v2-Erweiterung (S.7f): ``host_found`` UND ``host_detail`` tragen ein
``source``-Feld (ping/arp/fritzbox) -- der v1-Altcode trug das nur inkonsistent (nur
bei Fritz/ARP, dort ohne ``is_unknown``). Der Characterization-Test bleibt unberuehrt
(er friert v1 ein, mockt ``main.ws_scan``); die v2-Frame-Form lebt im v2-eigenen
``test_ws_scan_handler``. Die ``ScanEvent``-Union wird per ``match`` + ``assert_never``
erschoepfend in JSON-Frames uebersetzt -- ein neuer Event-Typ ohne ``case`` bricht in mypy.

Fehlerpfad (S.5-Entscheidung 3 / S.6-Merkposten 2): ``NmapScanError`` /
``FritzAuthError`` propagieren aus ``RunNetworkScan.run`` (der Use-Case faengt sie
bewusst NICHT). HIER werden sie gefangen und in einen sauberen ``error``-Frame
uebersetzt -- KEIN roher 500er/WS-Abbruch. Beide zusammen behandelt.

devices-Projektion (S.7d): Pro ``HostEnriched`` wird der Host auf einen
``devices.ScannedHost`` projiziert und ueber ``RecordScannedHost`` in die
devices-DB verbucht -- VOR dem ``host_detail``-Frame (Altcode-Reihenfolge:
persistieren, dann senden). Das ist ein SEITENEFFEKT in eine FREMDE Domaene und
gehoert bewusst HIER (Composition Root), NICHT in den scanning-Use-Case: der
bleibt eine reine Funktion ``ScanConfig -> Event-Strom`` ohne devices-Vokabular
(scanning soll nicht wissen, dass es devices gibt -- der import-linter erlaubt
``scanning -> devices`` zwar, aber "erlaubt" ist nicht "sauber"). Best-effort
(Entscheidung 3C-Linie): ein ``RecordScannedHost``-Fehler (DB gesperrt o.ae.) wird
gefangen + geloggt, der Scan laeuft weiter -- die Projektion ist ein Nebeneffekt,
kein Scan-Zweck; ein devices-DB-Problem darf die Scan-Anzeige nicht killen. Mit
Log ist es kein stiller S3-Fallback.

HostFound-Timing (S.6-Merkposten 1): Der HostDiscoveryAdapter (Variante A)
buendelt die ``HostFound`` nach den Ticks; der Use-Case gibt das unveraendert
weiter. Dieser Handler uebernimmt die Reihenfolge der Events 1:1 -- er sortiert
NICHT um. Die v1-interleaved-Reihenfolge wird bewusst NICHT wiederhergestellt:
Frame-Reihenfolge folgt dem Event-Strom des Use-Case. (Dokumentiert, nicht
stillschweigend.)
"""

from collections.abc import Awaitable, Callable
from typing import Any, assert_never

import structlog
from fastapi import WebSocket

from application.devices.errors import DeviceNotFoundError
from domain.devices import ScannedHost
from domain.scanning import (
    EnrichedHost,
    HostEnriched,
    HostFound,
    Info,
    PhaseChanged,
    Progress,
    ScanCompleted,
    ScanConfig,
    ScanError,
    ScanEvent,
    ScanStarted,
)
from infrastructure.scanning.fritz_hosts import FritzAuthError
from infrastructure.scanning.port_scanner import NmapScanError

logger = structlog.get_logger()

# Adapter-Exceptions, die der Use-Case bewusst durchwirft (S.5) und die hier in
# einen ``error``-Frame uebersetzt werden -- statt eines rohen 500ers/Abbruchs.
_ADAPTER_ERRORS = (NmapScanError, FritzAuthError)

# Factory-Typ: app.py liefert eine Funktion, die pro Verbindung einen frischen
# RunNetworkScan-Use-Case baut (mit den konkreten Adaptern verdrahtet).
RunScanFactory = Callable[[], Any]

# Factory-Typ fuer den devices-Projektions-Use-Case (RecordScannedHost). app.py
# liefert eine Funktion, die ihn frisch baut (mit DeviceRepository + Clock).
RecordHostFactory = Callable[[], Any]

# Factory-Typ fuer die analysis-Host-Historie-Schreibnaht (C.2). app.py liefert eine
# Funktion, die ein ``record_seen``-Callable ``(mac) -> None`` zurueckgibt (aus dem
# SqliteHostHistoryRepository). Pro Verbindung einmal geholt -- wie record_host.
RecordSeenFactory = Callable[[], Any]

# Factory-Typ fuer den GetDevice-Use-Case (Baseline-Anreicherung). app.py liefert eine
# Funktion, die ihn frisch baut (mit DeviceRepository) -- pro Verbindung einmal. Liest
# die kuratierten Felder (label/tags/notes), mit denen das host_detail-Frame angereichert
# wird (die devices-DB ist die Wahrheit fuer kuratierte Felder; der Scan traegt sie leer).
GetDeviceFactory = Callable[[], Any]

# Factory-Typ fuer die ``is_known``-Lese-Naht (Baseline-Anreicherung). app.py liefert eine
# Funktion, die ein ``is_known``-Callable ``(mac) -> bool`` aus dem
# SqliteHostHistoryRepository zurueckgibt (analog zu RecordSeenFactory). Liefert den
# VORZUSTAND der Historie -- pro HostEnriched VOR record_seen gelesen, sonst waere jeder
# Host sofort "bekannt".
IsKnownFactory = Callable[[], Any]

# Factory-Typ fuer die analysis-Severity-Bewertung (Achse B, ADR 0029). app.py liefert eine
# Funktion, die pro Verbindung ein Callable ``(EnrichedHost, bool) -> Severity | None``
# zurueckgibt (gebaut aus einer ``AnalyzeSnapshot``-Instanz mit dem GEFILTERTEN Provider).
# Es bewertet den LIVE-Host gegen die konfigurierten Regeln und liefert die hoechste
# Auffaelligkeit ("critical"/"notable") oder None -- STRIKT GETRENNT von new_ports (Achse A,
# Port-History). Pro Verbindung einmal geholt, wie die uebrigen Factories.
SeverityFactory = Callable[[], Any]


def _project(host: EnrichedHost) -> ScannedHost:
    """Projiziert einen scanning-``EnrichedHost`` auf einen devices-``ScannedHost``.

    Lebt im Composition Root (darf beide Domaenen), NICHT im scanning-Use-Case.
    ``ports`` (PortInfo-Objekte) -> ``open_ports`` (int-Tupel). ``category`` wird
    bewusst NICHT projiziert -- ``ScannedHost`` hat es nicht (Kategorie ist
    kuratiert, kein Scan-Stammdatum; deckt sich mit dem Altcode-Upsert).
    """
    return ScannedHost(
        mac=host.mac,
        ip=host.ip,
        vendor=host.vendor,
        hostname=host.hostname,
        os_guess=host.os_guess,
        open_ports=tuple(p.port for p in host.ports),
    )


def _event_to_frame(event: ScanEvent) -> dict[str, Any]:
    """Uebersetzt ein ``ScanEvent`` in seinen WS-Frame (S.1-Contract-Shapes)."""
    match event:
        case ScanStarted(cidr=cidr, total_hosts=total_hosts):
            return {"type": "scan_started", "cidr": cidr, "total_hosts": total_hosts}
        case PhaseChanged(phase=phase, status="running", total=total):
            return {"type": "phase", "phase": phase, "status": "running", "total": total}
        case PhaseChanged(phase=phase, status="done", alive_count=alive_count):
            return {"type": "phase", "phase": phase, "status": "done", "alive_count": alive_count}
        case PhaseChanged(phase=phase, status=other_status):
            # Defensiv: jeder andere phase-Status -> minimaler Frame (kein S.1-Fall,
            # aber vollstaendig statt KeyError).
            return {"type": "phase", "phase": phase, "status": other_status}
        case HostFound(
            ip=ip, mac=mac, vendor=vendor, rtt_ms=rtt_ms, is_unknown=is_unknown, source=source
        ):
            # ``source`` (ping/arp/fritzbox) EINHEITLICH in jedem Frame (S.7f, 1A):
            # macht die S.7-Merge-Arbeit nach aussen sichtbar. Bewusste Abweichung
            # vom v1-Murks (v1 trug source NUR bei Fritz/ARP, dort dafuer kein
            # is_unknown -- drei Shapes). v2: ein einheitlicher Shape, der Client
            # kann sich aufs Feld verlassen.
            return {
                "type": "host_found",
                "ip": ip,
                "rtt_ms": rtt_ms,
                "mac": mac,
                "vendor": vendor,
                "is_unknown": is_unknown,
                "source": source,
            }
        case Progress(phase=phase, completed=completed, total=total, pct=pct):
            return {
                "type": "progress",
                "phase": phase,
                "completed": completed,
                "total": total,
                "pct": pct,
            }
        case HostEnriched(host=host):
            return _host_detail_frame(host)
        case Info(message=message):
            return {"type": "info", "message": message}
        case ScanCompleted(total_found=total_found):
            return {"type": "scan_complete", "total_found": total_found}
        case ScanError(message=message):
            return {"type": "error", "message": message}
        case _:
            assert_never(event)


def _host_detail_frame(host: Any) -> dict[str, Any]:
    """``EnrichedHost`` -> ``host_detail``-Frame (26 Keys, S.1-Contract + v2-Erweiterungen).

    ``host`` ist ein ``domain.EnrichedHost``; verschachtelte Domaenen-Objekte
    werden per Attribut-Zugriff serialisiert (tuple -> list).
    """
    return {
        "type": "host_detail",
        "ip": host.ip,
        "mac": host.mac,
        "vendor": host.vendor,
        "rtt_ms": host.rtt_ms,
        "hostname": host.hostname,
        "smb_name": host.smb_name,
        "smb_domain": host.smb_domain,
        "os_guess": host.os_guess,
        "os_accuracy": host.os_accuracy,
        "scan_method": host.scan_method,
        "ports": [{"port": p.port, "state": p.state, "service": p.service} for p in host.ports],
        "mdns_services": [
            {
                "name": s.name,
                "type": s.type,
                "port": s.port,
                "hostname": s.hostname,
                "is_ndi": s.is_ndi,
                "properties": [list(pair) for pair in s.properties],
            }
            for s in host.mdns_services
        ],
        "ssdp_services": [
            {"server": s.server, "st": s.st, "location": s.location} for s in host.ssdp_services
        ],
        "is_ndi": host.is_ndi,
        "is_unknown": host.is_unknown,
        "category": host.category,
        "label": host.label,
        "tags": list(host.tags),
        "notes": host.notes,
        # is_known-Default True ("bekannt, sofern nicht anders angereichert"). Der
        # ECHTE Wert wird im Loop aus dem VORZUSTAND der Host-Historie bestimmt
        # (baseline_known, gelesen VOR record_seen) und ueberschreibt diesen Default.
        # Hier bewusst KEIN Historie-Zugriff: _host_detail_frame ist eine reine
        # Projektion ohne I/O; die Anreicherung braucht die Historie und gehoert in
        # den Loop. Der Default haelt das Frame-Schema konsistent -- is_known ist
        # IMMER vorhanden, auch falls die Anreicherung mal uebersprungen wird
        # (MAC-lose/nicht ermittelbare Hosts gelten als bekannt).
        "is_known": True,
        # is_changed-Default False ("keine IP-Aenderung, sofern nicht angereichert").
        # Der Composition-Root-Loop ueberschreibt mit dem echten Wert (Vorzustand-IP
        # vs. Scan-IP, gelesen VOR record_seen). Haelt das Frame-Schema konsistent.
        "is_changed": False,
        # new_ports-Default [] ("keine neuen Ports, sofern nicht angereichert", ADR 0026).
        # Der Composition-Root-Loop ueberschreibt mit dem echten Wert (Vorzustand-Ports
        # vs. Scan-Ports, gelesen VOR record_seen/record_host). Haelt das Frame-Schema
        # konsistent -- new_ports IMMER vorhanden, auch falls die Anreicherung mal
        # uebersprungen wird (neue/MAC-lose Hosts haben keinen Vorzustand -> keine
        # "neuen Ports seit letztem Scan"). _host_detail_frame bleibt reine Projektion
        # ohne I/O; die Anreicherung braucht den Vorzustand und gehoert in den Loop.
        "new_ports": [],
        # analysis_severity-Default None ("keine Auffaelligkeit, sofern nicht angereichert",
        # Achse B, ADR 0029). Der Composition-Root-Loop ueberschreibt mit der hoechsten
        # Severity ("critical"/"notable") des Live-Hosts gegen die konfigurierten Regeln --
        # STRIKT GETRENNT von new_ports (Achse A, Port-History). Haelt das Frame-Schema
        # konsistent: analysis_severity ist IMMER vorhanden, auch falls die Anreicherung mal
        # uebersprungen wird (best-effort). _host_detail_frame bleibt reine Projektion ohne
        # I/O; die Bewertung braucht die injizierte Severity-Callable und gehoert in den Loop.
        "analysis_severity": None,
        # source (ping/arp/fritzbox) auch am persistenten Host (S.7f): die Quelle
        # haengt jetzt durchgaengig am gespeicherten Host, nicht nur am fluechtigen
        # host_found-Frame.
        "source": host.source,
        # Weitere IPs derselben MAC (MAC-Gruppierung): Proxy-ARP/Spoofing-Info,
        # verlustfrei am primaeren Host -- leere Liste im Normalfall.
        "additional_ips": list(host.additional_ips),
    }


def _build_config(raw: dict[str, Any]) -> ScanConfig:
    """Baut ``ScanConfig`` aus dem WS-JSON (Multi-CIDR comma-split, wie Altcode).

    Ungueltige Werte (leeres/kaputtes CIDR) wirft ``ScanConfig.__post_init__`` als
    ``ValueError`` -- der Aufrufer uebersetzt das in einen ``error``-Frame.
    """
    cidr_raw = str(raw.get("cidr", "192.168.1.0/24"))
    cidrs = tuple(c.strip() for c in cidr_raw.split(",") if c.strip())
    return ScanConfig(
        cidrs=cidrs,
        ping_timeout=float(raw.get("ping_timeout", 1.5)),
        port_scan=bool(raw.get("port_scan", True)),
        port_mode=str(raw.get("port_mode", "socket")),
        mdns_scan=bool(raw.get("mdns_scan", True)),
        mdns_duration=float(raw.get("mdns_duration", 8.0)),
        resolve_hostnames=bool(raw.get("resolve_hostnames", True)),
        smb_scan=bool(raw.get("smb_scan", False)),
        ssdp_scan=bool(raw.get("ssdp_scan", True)),
        max_concurrent_ping=int(raw.get("max_concurrent_ping", 64)),
        max_concurrent_ports=int(raw.get("max_concurrent_ports", 100)),
        custom_ports=tuple(raw["custom_ports"]) if raw.get("custom_ports") else None,
    )


def make_ws_scan(
    run_scan_factory: RunScanFactory,
    record_host_factory: RecordHostFactory,
    record_seen_factory: RecordSeenFactory,
    get_device_factory: GetDeviceFactory,
    is_known_factory: IsKnownFactory,
    severity_factory: SeverityFactory,
) -> Callable[[WebSocket], Awaitable[None]]:
    """Baut den ``/ws/scan``-Handler mit injizierter ``RunNetworkScan``-Factory.

    ``run_scan_factory()`` liefert pro Verbindung einen frischen, mit den
    konkreten Adaptern verdrahteten ``RunNetworkScan``-Use-Case (gebaut in app.py).
    ``record_host_factory()`` liefert den ``RecordScannedHost``-Use-Case fuer die
    devices-Projektion (S.7d) -- pro Verbindung einmal gebaut.
    ``record_seen_factory()`` liefert das ``record_seen``-Callable der analysis-
    Host-Historie (C.2) -- ebenfalls pro Verbindung einmal geholt. Diese zweite,
    UNABHAENGIGE Schreib-Naht traegt jeden gesehenen Host (per MAC) in die Historie
    ein und bildet so die BASELINE fuer die analysis-Regel ``new_host_seen``: der
    erste Scan macht alle Hosts "bekannt", "neu" feuert erst ab dem zweiten Scan fuer
    echte Neuzugaenge (Scan schreibt, GET /api/analysis liest -- siehe ADR 0013).

    ``get_device_factory()`` liefert den ``GetDevice``-Use-Case und ``is_known_factory()``
    das ``is_known``-Callable der Host-Historie -- beide pro Verbindung einmal geholt, fuer
    die Baseline-Anreicherung des ``host_detail``-Frames (ADR 0019): das Frame traegt
    kuenftig die gespeicherten kuratierten Felder (label/tags/notes aus der devices-DB)
    und ein echtes ``is_known`` aus dem VORZUSTAND der Historie (gelesen VOR record_seen,
    sonst waere jeder Host sofort "bekannt"). Beide Lese-Pfade sind best-effort: ein Fehler
    laesst die Anreicherung aus (im Zweifel "bekannt"/keine Kuratierung), der Scan laeuft
    weiter.

    ``severity_factory()`` liefert das analysis-Severity-Callable
    ``(EnrichedHost, bool) -> Severity | None`` (Achse B, ADR 0029) -- ebenfalls pro
    Verbindung einmal geholt. Es bewertet den LIVE-Host gegen die konfigurierten Regeln und
    liefert die hoechste Auffaelligkeit ("critical"/"notable") oder None ins neue Frame-Feld
    ``analysis_severity``. STRIKT GETRENNT von new_ports (Achse A, Port-History): die
    Bewertung haengt am aktuellen Portstand, nicht an der Differenz, und braucht KEINE
    Kuratierung (auch ein brandneuer Host kann auffaellige Ports haben). Best-effort wie die
    uebrigen Anreicherungen (Fehler -> None + Log, der Scan laeuft weiter).
    """

    async def ws_scan(websocket: WebSocket) -> None:
        await websocket.accept()

        # 1. Config aus dem WS-JSON. Kaputtes JSON ODER ungueltiges CIDR
        #    (ValueError aus ScanConfig) -> error-Frame, dann Ende.
        try:
            raw = await websocket.receive_json()
            config = _build_config(raw)
        except ValueError as exc:
            await websocket.send_json({"type": "error", "message": str(exc)})
            return
        except Exception as exc:
            await websocket.send_json({"type": "error", "message": str(exc)})
            return

        # 2. Scan ausfuehren, jedes Event als Frame senden. Adapter-Exceptions
        #    (NmapScanError/FritzAuthError) propagieren aus dem Generator -> hier
        #    in einen error-Frame uebersetzt, KEIN roher 500er (S.6-Merkposten 2).
        use_case = run_scan_factory()
        record_host = record_host_factory()
        record_seen = record_seen_factory()
        get_device = get_device_factory()
        is_known = is_known_factory()
        severity = severity_factory()
        try:
            async for event in use_case.run(config):
                if isinstance(event, HostEnriched):
                    # Baseline-Anreicherung (ADR 0019): der VORZUSTAND der Historie
                    # MUSS VOR record_seen gelesen werden -- sonst ist jeder Host
                    # sofort "bekannt" (record_seen traegt ihn ja gerade ein). Leere
                    # MAC -> is_known True (MAC-lose Hosts sind nie "neu").
                    baseline_known = _is_known_safe(is_known, event.host.mac)
                    # Kuratierte Felder + Vorzustands-IP aus der devices-DB lesen --
                    # die DB ist die Wahrheit fuer label/tags/notes, der frische Scan
                    # traegt sie leer. WICHTIG (ADR 0020): Dieser Lesevorgang muss VOR
                    # dem devices-Upsert (_record_host -> RecordScannedHost -> merge_scan)
                    # laufen, denn merge_scan ueberschreibt last_ip UNBEDINGT mit der
                    # neuen Scan-IP. Fuer den is_changed-Vergleich (DHCP-Lease-Wechsel)
                    # brauchen wir aber den VORZUSTAND von last_ip -- also erst lesen,
                    # dann schreiben. Auf label/tags/notes hat der Upsert keinen Einfluss
                    # (sie bleiben kuratiert), die Verlegung ist fuer sie folgenlos.
                    kuratiert = _lese_kuratierung(get_device, event.host.mac)
                    # devices-Projektion (S.7d): pro angereichertem Host VOR dem Frame
                    # persistieren (Altcode-Reihenfolge: erst devices-DB, dann senden).
                    # analysis-Host-Historie (C.2): pro Host NEBEN der devices-Projektion
                    # die MAC in die Historie eintragen -- die Baseline fuer new_host_seen.
                    # Beide Naehte sind best-effort und unabhaengig; die Reihenfolge ist
                    # unkritisch (keine schreibt der anderen Daten vor).
                    _record_host(record_host, event.host)
                    _record_seen_host(record_seen, event.host)
                    frame = _host_detail_frame(event.host)
                    frame["is_known"] = baseline_known
                    # is_changed (ADR 0020): bekanntes Geraet, dessen gespeicherte IP
                    # von der aktuellen Scan-IP abweicht (typisch DHCP-Lease-Wechsel).
                    # Disjunkt zu "neu": ein neues Geraet hat keine Kuratierung/last_ip
                    # (None) -> nie is_changed. last_ip stammt aus dem Vorzustand (s.o.).
                    is_changed = False
                    if kuratiert is not None:
                        frame["label"] = kuratiert["label"]
                        frame["tags"] = kuratiert["tags"]
                        frame["notes"] = kuratiert["notes"]
                        alte_ip = kuratiert.get("last_ip")
                        if alte_ip is not None and alte_ip != event.host.ip:
                            is_changed = True
                        # new_ports (ADR 0026): seit dem letzten Scan NEU offene Ports.
                        # Aktueller Portstand IDENTISCH zur _project-Projektion gebildet
                        # (alle host.ports-Nummern, KEIN state-Filter), sonst vergleichen
                        # wir Ungleiches. Vorzustand aus der devices-DB (open_ports, VOR
                        # dem Upsert gelesen). NUR Zugaenge zaehlen (Mengen-Differenz),
                        # weggefallene Ports sind kein "neuer Port". Disjunkt zu "neues
                        # Geraet": kein kuratiert -> kein Vorzustand -> new_ports bleibt [].
                        aktuelle_ports = {p.port for p in event.host.ports}
                        alte_ports = set(kuratiert.get("open_ports") or [])
                        frame["new_ports"] = sorted(aktuelle_ports - alte_ports)
                    frame["is_changed"] = is_changed
                    # analysis_severity (Achse B, ADR 0029): die hoechste Auffaelligkeit des
                    # LIVE-Hosts gegen die konfigurierten Regeln. UNABHAENGIG von ``kuratiert``
                    # gesetzt -- Achse B braucht keine Kuratierung (auch ein brandneuer Host
                    # kann auffaellige Ports haben) und ist STRIKT GETRENNT von new_ports
                    # (Achse A). ``baseline_known`` (vor record_seen gelesen) ist die is_known-
                    # Eingabe der Engine. Best-effort wie die uebrigen Anreicherungen.
                    frame["analysis_severity"] = _severity_safe(
                        severity, event.host, baseline_known
                    )
                    await websocket.send_json(frame)
                else:
                    # Alle anderen Events unveraendert (insb. host_found bleibt ohne
                    # Anreicherung -- keine kuratierten Felder, kein verlaessliches
                    # is_known; erst host_detail traegt die Baseline).
                    await websocket.send_json(_event_to_frame(event))
        except _ADAPTER_ERRORS as exc:
            await websocket.send_json({"type": "error", "message": str(exc)})

    return ws_scan


def _record_host(record_host: Any, host: EnrichedHost) -> None:
    """Verbucht einen angereicherten Host in der devices-DB (best-effort, S.7d).

    Hosts OHNE MAC werden uebersprungen: ``ScannedHost``/``RecordScannedHost`` sind
    MAC-keyed; eine leere MAC erzeugte einen wertlosen Phantom-Eintrag. Bewusste
    Abweichung vom Altcode, der bedingungslos ``update_device_from_scan`` rief.

    Ein Fehler (z.B. gesperrte DB) wird gefangen + geloggt, der Scan laeuft weiter
    (best-effort, Entscheidung 3C-Linie): die Projektion ist ein Nebeneffekt, kein
    Scan-Zweck. Mit Warn-Log ist es kein stiller S3-Fallback.
    """
    if not host.mac:
        return
    try:
        record_host(_project(host))
    except Exception as exc:
        logger.warning("record_scanned_host_failed", ip=host.ip, mac=host.mac, error=str(exc))


def _record_seen_host(record_seen: Any, host: EnrichedHost) -> None:
    """Traegt die Host-MAC in die analysis-Host-Historie ein (best-effort, C.2).

    Die zweite, von der devices-Projektion UNABHAENGIGE Schreib-Naht. Sie pflegt das
    "schon gesehen?"-Gedaechtnis, aus dem die analysis-Lese-Naht (``_analyze_snapshot``
    in app.py) spaeter ``ObservedHost.is_known`` fuellt -- und damit die BASELINE der
    Regel ``new_host_seen`` (ADR 0013): nach dem ERSTEN Scan sind alle gesehenen Hosts
    bekannt, "neu" feuert ab dem ZWEITEN Scan fuer echte Neuzugaenge.

    Hosts OHNE MAC werden uebersprungen -- gleiche Linie wie ``_record_host`` und das
    Repository (``record_seen`` ist MAC-keyed; ohne stabile Identitaet waere "neu" nur
    Rauschen). Ein Fehler (z.B. gesperrte DB) wird gefangen + geloggt, der Scan laeuft
    weiter (best-effort wie die devices-Projektion). Mit Warn-Log kein stiller
    S3-Fallback.
    """
    if not host.mac:
        return
    try:
        record_seen(host.mac)
    except Exception as exc:
        logger.warning("record_seen_host_failed", ip=host.ip, mac=host.mac, error=str(exc))


def _is_known_safe(is_known: Any, mac: str) -> bool:
    """Liest den Historie-Vorzustand best-effort (ADR 0019): bekannt? (mac) -> bool.

    Reiner Lesevorgang. Wirft das Callable (z.B. gesperrte DB), wird der Fehler
    gefangen + geloggt und ``True`` zurueckgegeben -- im Zweifel "bekannt", lieber
    kein faelschliches "neu". Das ist konsistent mit der Leere-MAC-Linie des
    Repositories (leere MAC -> is_known True). Kein Scan-Abbruch.
    """
    try:
        return bool(is_known(mac))
    except Exception as exc:
        logger.warning("host_is_known_failed", mac=mac, error=str(exc))
        return True


def _severity_safe(severity: Any, host: EnrichedHost, is_known: bool) -> str | None:
    """Bewertet den Live-Host best-effort (Achse B, ADR 0029) -> "critical"/"notable"/None.

    Reine Bewertung des aktuellen Portstands (kein I/O, kein Historie-Schreibpfad). Wirft
    das Severity-Callable, wird der Fehler gefangen + geloggt und ``None`` zurueckgegeben
    -- "im Zweifel keine Auffaelligkeit". Das ist konsistent mit der best-effort-Linie der
    uebrigen Frame-Anreicherungen (``_is_known_safe``/``_lese_kuratierung``): ein Fehler in
    der Bewertung darf den Scan NICHT faellen. Mit Warn-Log kein stiller S3-Fallback.
    """
    try:
        result = severity(host, is_known)
    except Exception as exc:
        logger.warning("host_analysis_severity_failed", ip=host.ip, error=str(exc))
        return None
    return result if result is None else str(result)


def _lese_kuratierung(get_device: Any, mac: str) -> dict[str, Any] | None:
    """Liest die kuratierten devices-Felder best-effort (ADR 0019) -> dict | None.

    Leere MAC -> ``None`` (kein Geraet ohne stabile Identitaet). ``GetDevice`` gibt
    ein ``DeviceWithHistory`` zurueck -- die kuratierten Felder liegen auf
    ``.device`` (label/tags/notes). Unbekannte MAC (``DeviceNotFoundError``) -> ``None``
    (Host noch nie als device gespeichert, keine Kuratierung). Jeder ANDERE Fehler
    (z.B. gesperrte DB) wird gefangen + geloggt -> ``None`` (best-effort, kein
    Scan-Abbruch). Mit Warn-Log kein stiller S3-Fallback.
    """
    if not mac:
        return None
    try:
        result = get_device(mac)
    except DeviceNotFoundError:
        return None
    except Exception as exc:
        logger.warning("host_get_device_failed", mac=mac, error=str(exc))
        return None
    device = result.device
    # last_ip = VORZUSTANDS-IP aus der devices-DB (ADR 0020): Grundlage fuer den
    # is_changed-Vergleich (DHCP-Lease-Wechsel). Der Aufrufer liest diese Kuratierung
    # VOR dem devices-Upsert (RecordScannedHost), sonst traegt last_ip schon die neue
    # Scan-IP. Additiv zu label/tags/notes -- ein Lesevorgang, kein zweiter DB-Zugriff.
    # open_ports = VORZUSTANDS-Portstand aus der devices-DB (ADR 0026): Grundlage fuer
    # den neue-Ports-Vergleich (Achse A, Port-History). GENAUSO wie last_ip vom Aufrufer
    # VOR dem devices-Upsert gelesen (merge_scan ueberschreibt open_ports UNBEDINGT mit
    # dem neuen Scan-Stand). Additiv -- derselbe eine Lesevorgang.
    return {
        "label": device.label,
        "tags": list(device.tags),
        "notes": device.notes,
        "last_ip": device.last_ip,
        "open_ports": list(device.open_ports),
    }
