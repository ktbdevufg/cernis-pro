"""Use-Cases der security-Domaene (arp_guard + drei Inspektoren).

Kennt NUR ``domain`` + ``ports`` (import-linter: NIE infrastructure/api). Die
Cross-Domaenen-Ports ``ArpTablePort``/``VendorLookupPort`` stammen aus
``ports.scanning`` -- sie werden per Constructor INJIZIERT (Muster
``infrastructure/monitoring/target_source.py`` / ``RunMonitor``: fremde Ports kommen
ueber DI, nicht ueber Domaenen-Kopplung). ``ports`` -> ``ports`` ist erlaubt und der
Use-Case kennt ohnehin nur Protocol-Typen.

RunArpScan orchestriert verhaltensgleich zum Altcode ``modules/arp_guard._scan_arp_sync``
(Sequenz unten). Die ERKENNUNG selbst (ip_conflict/mac_changed/severity) liegt in
``domain.security.detect_arp_anomalies`` (SEC.2, dort getestet) -- hier NUR die
Orchestrierung (wer ruft wen, in welcher Reihenfolge).

UHR-FREI: der SEC.4-Adapter (``SqliteArpGuardRepository``) setzt die Zeitspalten
(``ts``/``datetime`` der Alerts, ``first_seen``/``last_seen`` der Baseline) selbst am
Rand. RunArpScan reicht nur ``ArpEntry``/``ArpAlert`` durch, braucht keine ``now``-Quelle
(anders als RaiseAlert/RunMonitor, deren Domaene den Timestamp traegt).
"""

from collections.abc import Sequence

from domain.security import ArpAlert, ArpEntry, detect_arp_anomalies
from ports.scanning import ArpTablePort, VendorLookupPort
from ports.security import (
    ArpGuardRepository,
    CredFinding,
    CveFinding,
    CveLookup,
    DefaultCredsChecker,
    PortQuery,
    TlsFinding,
    TlsInspector,
)

# ── RunArpScan (Kern -- orchestriert, spiegelt _scan_arp_sync AS-IS) ─────────


class RunArpScan:
    """Fuehrt einen ARP-Scan aus: Tabelle holen, Anomalien erkennen, persistieren.

    Spiegelt die Altcode-Sequenz ``_scan_arp_sync`` (modules/arp_guard.py:146-205):

        1. ARP-Tabelle holen (``ArpTablePort``) + Vendor je MAC (``VendorLookupPort``)
           -> ``ArpEntry``-Liste (``current``). (Altcode: ``get_arp_table`` +
           ``lookup_vendor`` pro Eintrag.)
        2. ``clear_alerts()`` -- die MOMENTAUFNAHME-NAHT (E.1): der Altcode ruft
           ``_clear_alerts()`` VOR dem Scan (arp_guard.py:149) -> ``arp_alerts`` enthaelt
           danach NUR die Alerts DIESES Scans. Hier exakt so platziert. Charakterisierungs-
           treu -- KEINE Heilung zu echter Historie (Phase-4-Produktentscheidung).
        3. ``load_baseline()`` (Repo) -> ``baseline``.
        4. ``detect_arp_anomalies(current, baseline)`` (domain SEC.2) -> ``alerts``.
        5. ``save_alert`` je Alert (Repo; Adapter setzt ts/datetime).
        6. ``save_baseline_entry`` je current-Eintrag (Repo; Adapter setzt first/last_seen,
           Altcode ``_save_baseline`` pro IP).

    Abweichung von der Altcode-VERSCHRAENKUNG (verhaltensaequivalent, dokumentiert): der
    Altcode ruft ``_save_alert``/``_save_baseline`` VERSCHRAENKT in den Erkennungs-
    schleifen. Da die Erkennung in SEC.2 eine reine Funktion ist (gibt alle Alerts
    zurueck), trennt RunArpScan sauber: erst detect, dann alle save_alert, dann alle
    save_baseline_entry. Ergebnis (gespeicherte Alerts + finale Baseline) ist identisch.

    Reihenfolge clear -> detect -> save_alert -> save_baseline ist der Vertrag (SEC.5-Test).
    """

    def __init__(
        self,
        arp_table: ArpTablePort,
        vendor_lookup: VendorLookupPort,
        repository: ArpGuardRepository,
    ) -> None:
        self._arp_table = arp_table
        self._vendor_lookup = vendor_lookup
        self._repository = repository

    async def __call__(self) -> list[ArpAlert]:
        # 1. ARP-Tabelle -> ArpEntry-Liste (Vendor vorberechnet, wie SEC.2 erwartet).
        table = await self._arp_table.get_arp_table()  # {ip: mac}
        current = [
            ArpEntry(ip=ip, mac=mac, vendor=self._vendor_lookup.lookup(mac))
            for ip, mac in table.items()
        ]

        # 2. Momentaufnahme-Naht (E.1): clear VOR dem Scan (Altcode arp_guard.py:149).
        self._repository.clear_alerts()

        # 3. Baseline laden.
        baseline = self._repository.load_baseline()

        # 4. Erkennung (reine Domaenenfunktion, SEC.2).
        alerts = detect_arp_anomalies(current, baseline)

        # 5. Alerts persistieren (Adapter setzt ts/datetime).
        for alert in alerts:
            self._repository.save_alert(alert)

        # 6. Baseline aktualisieren (Adapter setzt first/last_seen; Altcode pro IP).
        for entry in current:
            self._repository.save_baseline_entry(entry)

        return alerts


# ── ARP-Lese-/Verwaltungs-Use-Cases (duenne Pass-Throughs) ──────────────────


class GetArpAlerts:
    """Die juengsten ARP-Alerts (neueste zuerst). Wegen E.1 praktisch nur der letzte Scan."""

    def __init__(self, repository: ArpGuardRepository) -> None:
        self._repository = repository

    def __call__(self, limit: int = 50) -> list[ArpAlert]:
        return self._repository.recent_alerts(limit)


class GetArpBaseline:
    """Die aktuelle ARP-Baseline (alle bekannten ip/mac/vendor-Eintraege)."""

    def __init__(self, repository: ArpGuardRepository) -> None:
        self._repository = repository

    def __call__(self) -> list[ArpEntry]:
        return self._repository.load_baseline()


class ClearArpBaseline:
    """Leert die ARP-Baseline (Altcode ``clear_baseline``; laesst Alerts unberuehrt)."""

    def __init__(self, repository: ArpGuardRepository) -> None:
        self._repository = repository

    def __call__(self) -> None:
        self._repository.clear_baseline()


# ── Inspektor-Use-Cases (duenne Pass-Throughs, async) ───────────────────────


class LookupCves:
    """CVE-Lookup fuer die offenen Ports eines Hosts (Pass-Through zum CveLookup-Port)."""

    def __init__(self, cve_lookup: CveLookup) -> None:
        self._cve_lookup = cve_lookup

    async def __call__(self, ports: Sequence[PortQuery]) -> list[CveFinding]:
        return await self._cve_lookup.lookup_for_host(ports)


class InspectTls:
    """TLS-Inspektion der HTTPS-Ports eines Hosts (Pass-Through zum TlsInspector-Port)."""

    def __init__(self, tls_inspector: TlsInspector) -> None:
        self._tls_inspector = tls_inspector

    async def __call__(self, host: str, ports: Sequence[int]) -> list[TlsFinding]:
        return await self._tls_inspector.inspect_host(host, ports)


class CheckDefaultCreds:
    """Default-Credential-Check eines Hosts (Pass-Through zum DefaultCredsChecker-Port).

    INTRUSIV (aktive Logins) -- die Ethik-/Opt-in-Frage ist DF5 (als Finding
    dokumentiert), KEIN technischer Gate hier.
    """

    def __init__(self, creds_checker: DefaultCredsChecker) -> None:
        self._creds_checker = creds_checker

    async def __call__(
        self, host: str, ports: Sequence[PortQuery], vendor: str = ""
    ) -> list[CredFinding]:
        return await self._creds_checker.check_host(host, ports, vendor)
