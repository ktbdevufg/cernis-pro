"""Use-Cases der cve-Domaene: Drip-Worker (``RunCveMonitor``) + Lese-Use-Cases.

Kennt ``domain/cve`` und ``ports/cve``, NIE ``infrastructure``/``modules`` (import-linter).
Die Ports kommen per Constructor-Injection herein; die Zeit ist stdlib (``time.time()``,
Muster ``RunMonitor`` -- ``import time`` ist erlaubt, es ist keine Domaenenlogik).

DRIP-WORKER (ADR 0037): pro ``tick`` wird HOECHSTENS EIN faelliger Host MIT NVD-Aufruf
geprueft (gedrosselt). Faellig = einer der drei Faelle (``domain.cve.policy.due_reason``:
neu / Ports geaendert / ueberfaellig). Kein faelliger Host (oder leerer Bestand) ->
``tick`` kehrt OHNE NVD-Aufruf zurueck (der Worker "schlaeft"). So rattert ein Neustart
NICHT alles neu durch -- die Faelligkeit haengt am persistierten ``last_checked_ts`` je
Host, nicht am Prozess-Start (Resume/Idempotenz).

ZUSTANDSANZEIGE, KEIN JOURNAL (Befund 56): der Worker ERSETZT den Befundstand eines
Geraets (``replace_for_host``), statt ihn nur zu ergaenzen. Betroffen sind ausschliesslich
Hosts, die der Bestand fuehrt; ein gesehener Host OHNE offene Ports verliert seine
Befunde vollstaendig (ohne jeden NVD-Aufruf, darum ungedrosselt), ein Host, den der
Bestand NICHT fuehrt, bleibt unangetastet. Faellt ein QUITTIERTER Befund weg, wird
vorher ein ``unack`` angehaengt, damit die alte Quittierung beim Wiederauftauchen nicht
still wieder greift.

LOOP-FORM (testbar, Muster RunMonitor): ``tick()`` ist EINE Iteration (voll mit Fakes
deterministisch testbar). ``run()`` ist nur der Rahmen ``while self._running: tick();
sleep(interval)``. ``stop()`` setzt das Flag.

FEHLERTOLERANZ (S3/streng): ein fehlschlagender Host-Lookup (NVD down) wird GELOGGT und
killt den Loop NICHT -- der Pruefstand wird in diesem Fall NICHT fortgeschrieben (der
Host bleibt faellig, naechster Versuch spaeter), und es wird KEIN erfundener Befund
geschrieben (NVD-Ausfall ist ehrlich: Befunde bleiben unveraendert). Das ist die harte
Randbedingung des Ersetzen-Pfads: der Lookup steht VOR jedem Schreibzugriff, ein
NVD-Ausfall loescht NIE Befunde.
"""

import asyncio
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import structlog

from domain.cve.models import CveFindingRecord
from domain.cve.policy import DEFAULT_NEW_WINDOW_SECONDS, DueReason, due_reason, is_new
from ports.cve import (
    CveAcknowledgementRepository,
    CveCheckStateRepository,
    CveFindingRepository,
    CveLookupProvider,
    HostInventoryProvider,
    InventoryHost,
    LookupCve,
)

__all__ = [
    "ActiveFinding",
    "GetAcknowledgedFindings",
    "GetActiveFindings",
    "GetCveMonitorStatus",
    "MonitorStatus",
    "RunCveMonitor",
]

_logger = structlog.get_logger(__name__)

# Drosselung des Drip-Worker: ein faelliger Host pro Intervall (Default 20s, ADR 0037).
# Der NVD-sleep(0.6) des CveLookupAdapter kommt OBENDRAUF (pro Port). Bewusst gemaechlich:
# die Verzoegerung ist explizit OK -- Befunde duerfen 30+ min spaeter vollstaendig sein.
DEFAULT_SCAN_INTERVAL_SECONDS: int = 20


# ── Worker ───────────────────────────────────────────────────────────────────


class RunCveMonitor:
    """Gedrosselter CVE-Drip-Worker: pro ``tick`` hoechstens EIN Host MIT NVD-Aufruf.

    Er ERSETZT den Befundstand des behandelten Hosts (Zustandsanzeige, kein Journal --
    Befund 56). Faellige Hosts OHNE offene Ports werden rein lokal abgeglichen (Befunde
    auf leer) und sind darum NICHT gedrosselt: sie erzeugen keinen Netzverkehr.

    ``refresh_interval_provider`` liefert das Auffrisch-Intervall (Sekunden) bei JEDER
    ``tick`` frisch -- so wirkt eine geaenderte ``cve_refresh_interval_hours``-Setting
    sofort (Live-Reload, Muster MonitorTargetSource). ``<= 0`` schaltet Fall 3 ab.
    """

    def __init__(
        self,
        inventory: HostInventoryProvider,
        lookup: CveLookupProvider,
        findings: CveFindingRepository,
        checkstate: CveCheckStateRepository,
        acknowledgements: CveAcknowledgementRepository,
        refresh_interval_provider: Callable[[], float],
        interval: int = DEFAULT_SCAN_INTERVAL_SECONDS,
        now_provider: Callable[[], float] = time.time,
    ) -> None:
        self._inventory = inventory
        self._lookup = lookup
        self._findings = findings
        self._checkstate = checkstate
        self._acknowledgements = acknowledgements
        self._refresh_interval_provider = refresh_interval_provider
        self._interval = interval
        self._now = now_provider
        self._running = False

    def _due_hosts(
        self, now: float, refresh_interval: float
    ) -> tuple[list[InventoryHost], tuple[InventoryHost, DueReason] | None]:
        """Teilt die faelligen Hosts in "portlos" und "hoechstens EINER mit Ports" (ADR 0037).

        Die Drosselung gilt fuer NETZVERKEHR: portlose Hosts brauchen keinen NVD-Aufruf,
        ihr Abgleich ist rein lokal (Befunde auf leer, Pruefstand fortschreiben) -- darum
        werden ALLE faelligen portlosen Hosts im selben Tick abgearbeitet, waehrend nur
        EIN faelliger Host MIT Ports geprueft wird.

        Reihenfolge = Bestands-Reihenfolge des Providers (deterministisch). Der erste
        faellige Host mit Ports gewinnt; die uebrigen kommen in den naechsten Ticks dran.
        """
        portless: list[InventoryHost] = []
        with_ports: tuple[InventoryHost, DueReason] | None = None
        for host in self._inventory.list_hosts():
            current_ports = frozenset(p.port for p in host.ports)
            state = self._checkstate.get(host.mac)
            reason = due_reason(state, current_ports, now, refresh_interval)
            if reason is DueReason.NOT_DUE:
                continue
            if not current_ports:
                # Gesehener Host OHNE offene Ports (Befund 56): NICHT mehr stillschweigend
                # uebersprungen -- er hat fachlich KEINE Befunde mehr und wird ohne jeden
                # NVD-Aufruf abgeglichen. Weil kein Netzverkehr entsteht, greift die
                # Drosselung hier nicht (kein `break`, alle werden gesammelt).
                portless.append(host)
            elif with_ports is None:
                with_ports = (host, reason)
        return portless, with_ports

    async def tick(self) -> None:
        """Eine Iteration: alle portlosen faelligen Hosts + hoechstens EINEN mit NVD-Aufruf."""
        now = self._now()
        refresh_interval = self._refresh_interval_provider()
        portless, with_ports = self._due_hosts(now, refresh_interval)
        for host in portless:
            self._clear_host(host, now)
        if with_ports is None:
            # Kein faelliger Host mit Ports / leerer Bestand -> KEIN NVD-Aufruf.
            return
        host, reason = with_ports
        await self._check_host(host, reason, now)

    def _clear_host(self, host: InventoryHost, now: float) -> None:
        """Gleicht einen gesehenen Host OHNE offene Ports ab: leere Befundmenge, kein Lookup.

        Befund 56: ohne offene Ports gibt es fachlich nichts zu finden, also traegt der
        Host danach KEINEN Befund mehr. Rein lokal -- kein NVD-Aufruf, kein Netzverkehr.

        Der Pruefstand wird mit dem LEEREN Port-Set fortgeschrieben. Damit ist derselbe
        Host im naechsten Tick NOT_DUE (``state`` vorhanden, ``checked_ports`` gleich leer,
        innerhalb des Auffrisch-Intervalls) -- der Fall wird nicht zur Dauerbeschaeftigung.
        """
        removed = self._findings.list_for_host(host.mac)
        # Reihenfolge wie in ``_check_host``: unack VOR dem Ersetzen (siehe dort).
        self._unack_removed(removed)
        self._findings.replace_for_host(host.mac, [])
        self._checkstate.record(host.mac, frozenset(), now)
        _logger.info("cve_host_cleared_no_ports", mac=host.mac, removed=len(removed))

    async def _check_host(self, host: InventoryHost, reason: DueReason, now: float) -> None:
        """Prueft EINEN Host: NVD-Lookup -> Befundstand ERSETZEN -> Pruefstand fortschreiben.

        Streng fehlertolerant: schlaegt der Lookup fehl, wird das GELOGGT, der Pruefstand
        NICHT fortgeschrieben (Host bleibt faellig) und KEIN Befund veraendert (ehrlicher
        NVD-Ausfall, S3). Ein einzelner Host-Fehler killt den Loop NIE.

        Der Lookup steht BEWUSST vor jedem Schreibzugriff (Befund 56): erst wenn eine
        vollstaendige, frische Befundmenge vorliegt, wird der alte Stand ersetzt. Ein
        NVD-Ausfall darf niemals Befunde loeschen -- ein veralteter Bestand ist harmlos,
        ein leergeraeumter verschweigt echte Schwachstellen.
        """
        try:
            found = await self._lookup.lookup(host.ports)
        except Exception as exc:
            # NVD/Lookup down -> ehrlich: Befunde unveraendert, Pruefstand NICHT
            # fortgeschrieben (Host bleibt faellig), kein erfundener Befund.
            _logger.warning("cve_host_lookup_failed", mac=host.mac, error=str(exc))
            return

        # Neue Befundmenge des Hosts bilden. ``first_seen_ts`` wird je Tripel bewahrt
        # (``_find_existing`` liest den alten Stand) -- ein bleibender Befund darf durch
        # das Ersetzen NICHT wieder als "neu" auffloppen.
        #
        # ENTDOPPLUNG je (cve_id, port), ERSTER Treffer gewinnt (B1): ``cve_findings``
        # traegt den PRIMARY KEY (mac, cve_id, port) und verlangt damit Eindeutigkeit.
        # ``replace_for_host`` fuegt mit BLANKEM INSERT ein (kein ON CONFLICT wie
        # ``upsert``) -- meldet der Lookup dasselbe Paar zweimal, wirft SQLite, die
        # Transaktion rollt zurueck und die Ausnahme ENTKAEME dem Schreibpfad: das
        # ``try`` in ``_check_host`` umschliesst nur den Lookup, nicht das Schreiben.
        # Der Adapter darf streng bleiben, weil genau diese Stelle die Zusicherung gibt.
        # Die uebrige Reihenfolge des Lookups bleibt erhalten (dict haelt sie).
        unique: dict[tuple[str, int], LookupCve] = {}
        for cve in found:
            unique.setdefault((cve.cve_id, cve.port), cve)
        records = [
            CveFindingRecord(
                mac=host.mac,
                cve_id=cve.cve_id,
                port=cve.port,
                severity=cve.severity,
                cvss_score=cve.cvss_score,
                description=cve.description,
                url=cve.url,
                published=cve.published,
                ip=host.ip,
                service=cve.service,
                first_seen_ts=self._first_seen_for(host.mac, cve.cve_id, cve.port, now),
                last_seen_ts=now,
            )
            for cve in unique.values()
        ]

        # Quittierungen der WEGFALLENDEN Tripel aufheben (Befund 56/B4), BEVOR ersetzt
        # wird -- die Reihenfolge ist tragend: bricht der Vorgang zwischen unack und
        # Ersetzen ab, ist ein noch vorhandener Befund SICHTBAR statt versteckt. Das ist
        # der harmlosere der zwei moeglichen Fehler.
        keeping = {(r.cve_id, r.port) for r in records}
        self._unack_removed(
            [r for r in self._findings.list_for_host(host.mac) if (r.cve_id, r.port) not in keeping]
        )

        # Der Befundstand des Hosts wird ERSETZT, nicht ergaenzt: was NVD diesmal nicht
        # mehr meldet (weggefallener Port, zurueckgezogene CVE), verschwindet. Die Liste
        # ist eine Zustandsanzeige, kein Journal.
        self._findings.replace_for_host(host.mac, records)

        # Pruefstand erst NACH erfolgreichem Lookup fortschreiben -- so bleibt ein Host
        # bei NVD-Ausfall faellig (oben: early return) und wird beim naechsten Mal erneut
        # versucht. Das gepruefte Port-Set ist das aktuelle offene Set (Fall-2-Basis).
        checked_ports = frozenset(p.port for p in host.ports)
        self._checkstate.record(host.mac, checked_ports, now)
        _logger.info(
            "cve_host_checked",
            mac=host.mac,
            reason=str(reason),
            ports=len(checked_ports),
            findings=len(found),
        )

    def _unack_removed(self, removed: Sequence[CveFindingRecord]) -> None:
        """Haengt fuer jeden wegfallenden, effektiv QUITTIERTEN Befund ein ``unack`` an.

        Das Quittierungs-Log ist append-only (ADR 0031) und wird NIE geloescht -- ohne
        diesen Gegen-Eintrag griffe eine alte Quittierung still wieder, wenn dasselbe
        Tripel spaeter erneut auftaucht: der Befund waere sofort wieder versteckt, ohne
        dass ihn je jemand fuer diesen neuen Vorfall quittiert hat.

        Nicht-quittierte Tripel bekommen NICHTS -- ein ``unack`` auf etwas Unquittiertes
        waere reines Log-Rauschen.
        """
        if not removed:
            return
        acked = self._acknowledgements.acknowledged_keys()
        for record in removed:
            key = (record.mac, record.cve_id, record.port)
            if key in acked:
                self._acknowledgements.record(record.mac, record.cve_id, record.port, "unack")

    def _first_seen_for(self, mac: str, cve_id: str, port: int, now: float) -> float:
        """``first_seen_ts`` eines Tripels: der alte Wert, wenn es ihn schon gab, sonst ``now``."""
        existing = self._find_existing(mac, cve_id, port)
        return existing.first_seen_ts if existing is not None else now

    def _find_existing(self, mac: str, cve_id: str, port: int) -> CveFindingRecord | None:
        """Sucht einen bestehenden Befund (fuer die first_seen-Bewahrung beim Ersetzen)."""
        for record in self._findings.list_for_host(mac):
            if record.cve_id == cve_id and record.port == port:
                return record
        return None

    async def run(self) -> None:
        """Endlos-Rahmen: tickt bis ``stop()``. Die Logik sitzt in ``tick``."""
        self._running = True
        while self._running:
            await self.tick()
            await asyncio.sleep(self._interval)

    def stop(self) -> None:
        """Setzt das Loop-Flag (Abbruch nach der laufenden Iteration)."""
        self._running = False


# ── Lese-Use-Cases ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ActiveFinding:
    """Ein AKTIVER (nicht quittierter) CVE-Befund + abgeleitetes ``is_new``-Flag.

    Rohe Daten fuer den api-Rand (der die Wire-Form baut, kein ``.to_dict()`` hier).
    ``is_new`` ist die Domaenen-Ableitung aus ``first_seen_ts`` (``policy.is_new``).
    """

    mac: str
    ip: str
    cve_id: str
    port: int
    service: str
    severity: str
    cvss_score: float
    description: str
    url: str
    published: str
    first_seen_ts: float
    last_seen_ts: float
    is_new: bool


class GetActiveFindings:
    """Liefert die AKTIVEN Befunde (Bestand minus quittierte) mit ``is_new``-Flag.

    "Aktiv" = der (mac, cve_id, port) ist NICHT effektiv quittiert (ADR 0031/0037: der
    aktive Warnstand sind die Befunde minus den Quittierungen). Quittierte werden NICHT
    geloescht, nur hier herausgefiltert. ``is_new`` wird mit ``now_provider()`` (Default
    ``time.time``) als ``now`` gegen das 24h-Fenster berechnet.
    """

    def __init__(
        self,
        findings: CveFindingRepository,
        acknowledgements: CveAcknowledgementRepository,
        new_window_seconds: float = DEFAULT_NEW_WINDOW_SECONDS,
        now_provider: Callable[[], float] = time.time,
    ) -> None:
        self._findings = findings
        self._acknowledgements = acknowledgements
        self._new_window_seconds = new_window_seconds
        self._now = now_provider

    def __call__(self, mac: str | None = None) -> list[ActiveFinding]:
        """Aktive Befunde -- alle (``mac=None``) oder nur eines Hosts."""
        now = self._now()
        acked = self._acknowledgements.acknowledged_keys()
        records = self._findings.list_for_host(mac) if mac else self._findings.list_all()
        active: list[ActiveFinding] = []
        for r in records:
            if (r.mac, r.cve_id, r.port) in acked:
                continue
            active.append(
                ActiveFinding(
                    mac=r.mac,
                    ip=r.ip,
                    cve_id=r.cve_id,
                    port=r.port,
                    service=r.service,
                    severity=r.severity,
                    cvss_score=r.cvss_score,
                    description=r.description,
                    url=r.url,
                    published=r.published,
                    first_seen_ts=r.first_seen_ts,
                    last_seen_ts=r.last_seen_ts,
                    is_new=is_new(r.first_seen_ts, now, self._new_window_seconds),
                )
            )
        return active


class GetAcknowledgedFindings:
    """Spiegelbild zu ``GetActiveFindings``: liefert die QUITTIERTEN Befunde mit Daten.

    Etappe 3a (ADR 0037): der Lesepfad fuer die ausgeblendeten Befunde. "Quittiert" =
    der (mac, cve_id, port) ist effektiv quittiert (sein juengster ack/unack-Eintrag ist
    ``ack``). Wo ``GetActiveFindings`` diese Tripel HERAUSfiltert, BEHAELT dieser Use-Case
    genau sie -- volle Daten aus dem Findings-Repo, gefiltert ueber ``acknowledged_keys()``.

    Gleiche ``ActiveFinding``-Form (die Wire-Form ist identisch, ``_finding_to_dict`` greift
    wieder): ``is_new`` ist fuer ausgeblendete Befunde fachlich weniger relevant, wird aber
    konsistent berechnet (keine Sonderform). Reihenfolge = die des Findings-Repos
    (severity-stark zuerst, wie aktiv).
    """

    def __init__(
        self,
        findings: CveFindingRepository,
        acknowledgements: CveAcknowledgementRepository,
        new_window_seconds: float = DEFAULT_NEW_WINDOW_SECONDS,
        now_provider: Callable[[], float] = time.time,
    ) -> None:
        self._findings = findings
        self._acknowledgements = acknowledgements
        self._new_window_seconds = new_window_seconds
        self._now = now_provider

    def __call__(self, mac: str | None = None) -> list[ActiveFinding]:
        """Quittierte Befunde -- alle (``mac=None``) oder nur eines Hosts."""
        now = self._now()
        acked = self._acknowledgements.acknowledged_keys()
        records = self._findings.list_for_host(mac) if mac else self._findings.list_all()
        result: list[ActiveFinding] = []
        for r in records:
            if (r.mac, r.cve_id, r.port) not in acked:
                continue
            result.append(
                ActiveFinding(
                    mac=r.mac,
                    ip=r.ip,
                    cve_id=r.cve_id,
                    port=r.port,
                    service=r.service,
                    severity=r.severity,
                    cvss_score=r.cvss_score,
                    description=r.description,
                    url=r.url,
                    published=r.published,
                    first_seen_ts=r.first_seen_ts,
                    last_seen_ts=r.last_seen_ts,
                    is_new=is_new(r.first_seen_ts, now, self._new_window_seconds),
                )
            )
        return result


@dataclass(frozen=True)
class MonitorStatus:
    """Schlanker Pruef-/Worker-Status (rohe Zahlen, der api-Rand baut die Wire-Form).

    ``hosts_total`` = bekannte Hosts MIT offenen Ports im Bestand; ``hosts_due`` = davon
    aktuell faellig (Faelle 1-3); ``hosts_checked`` = Hosts mit Pruefstand; ``findings_total``
    = alle persistierten Befunde; ``findings_active`` = davon nicht quittiert.
    """

    hosts_total: int
    hosts_due: int
    hosts_checked: int
    findings_total: int
    findings_active: int


class GetCveMonitorStatus:
    """Berechnet den Pruef-/Worker-Status (fuer den schlanken Statusendpunkt).

    Liest den Bestand + Pruefstaende + Befunde und leitet die Zahlen ab. KEIN NVD-Aufruf
    (rein lokal). ``hosts_due`` nutzt dieselbe Faelligkeits-Logik wie der Worker.
    """

    def __init__(
        self,
        inventory: HostInventoryProvider,
        checkstate: CveCheckStateRepository,
        findings: CveFindingRepository,
        acknowledgements: CveAcknowledgementRepository,
        refresh_interval_provider: Callable[[], float],
        now_provider: Callable[[], float] = time.time,
    ) -> None:
        self._inventory = inventory
        self._checkstate = checkstate
        self._findings = findings
        self._acknowledgements = acknowledgements
        self._refresh_interval_provider = refresh_interval_provider
        self._now = now_provider

    def __call__(self) -> MonitorStatus:
        now = self._now()
        refresh_interval = self._refresh_interval_provider()
        hosts = [h for h in self._inventory.list_hosts() if h.ports]
        due = 0
        for host in hosts:
            current_ports = frozenset(p.port for p in host.ports)
            state = self._checkstate.get(host.mac)
            if due_reason(state, current_ports, now, refresh_interval) is not DueReason.NOT_DUE:
                due += 1
        all_findings = self._findings.list_all()
        acked = self._acknowledgements.acknowledged_keys()
        active = sum(1 for r in all_findings if (r.mac, r.cve_id, r.port) not in acked)
        return MonitorStatus(
            hosts_total=len(hosts),
            hosts_due=due,
            hosts_checked=len(self._checkstate.all_states()),
            findings_total=len(all_findings),
            findings_active=active,
        )
