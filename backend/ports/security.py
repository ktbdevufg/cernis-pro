"""Ports der security-Domaene: ARP-Guard-Persistenz + drei Inspektoren.

Vier Vertraege, gruppiert nach Belang:

* **Persistenz** -- ``ArpGuardRepository``: EIN Port fuer BEIDE Tabellen
  (``arp_baseline`` + ``arp_alerts``), Muster ``AlertRuleRepository``/
  ``ScanHistoryRepository`` ("ein Port = kohaerente Einheit"). Die Momentaufnahme-
  Semantik (``clear_alerts`` vor jedem Scan, SEC.1-Befund E.1) ist KEIN Domaenen-
  Verhalten -- sie lebt im SEC.5-Use-Case, der ``clear_alerts()`` + ``save_alert()``
  orchestriert. Der Port stellt nur die kohaerenten DB-Operationen bereit.

* **Drei Inspektoren** -- ``CveLookup`` / ``TlsInspector`` / ``DefaultCredsChecker``.
  Schmale I/O-Vertraege OHNE Domaenenlogik (DF2: cve/tls/creds haben keine
  Domaene, werden in SEC.4 reimplementiert). Die Result-Typen sind schmale frozen
  dataclasses AM RAND (hier, NICHT in ``domain/security``) -- konsistent zum
  scanning-Muster (``ScanRecord``/``ScanSummary`` sind Datentraeger): typisiert
  (nicht dict, sonst mypy-blind an der api-Grenze), aber kein Domaenenmodell
  (keine Logik, kein Verhalten). Charakterisierungstreu zu den SEC.1b-Altcode-
  Ergebnissen (``CVEEntry``/``TLSResult``/``CredResult``) -- ohne ``.to_dict()``,
  ohne Zeit/datetime.

ARP-Tabelle + Vendor: KEINE eigenen SEC-Ports. Die arp_guard-Erkennung braucht die
System-ARP-Tabelle (``{ip: mac}``) + Hersteller-Lookup -- beides ist BEREITS migriert
als ``ports.scanning.ArpTablePort`` (S.7a) + ``ports.scanning.VendorLookupPort``
(S.4a). Der SEC.5-Use-Case bekommt diese zwei scanning-Ports INJIZIERT (Muster
``infrastructure/monitoring/target_source.py``, das ``ports.settings.SettingsRepository``
nutzt: Cross-Domaenen-Port-Nutzung ueber Injektion/Adapter, nicht ueber
``ports/security -> ports/scanning``). Damit braucht SEC KEIN ADR-0007: der
modules-Zugriff auf die ARP-Tabelle liegt im scanning-Adapter unter dessen
ADR-0007-Zeile, SEC beruehrt ``modules`` nie.

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster settings/monitoring/
scanning/alerting). Vertragspruefung statisch ueber mypy + Verdrahtung im Composition
Root.

I/O-/Netz-Methoden der Inspektoren sind ``async`` (NVD-HTTP / TLS-Handshake / aktive
Logins -- blockierend; der SEC.4-Adapter kapselt ueber ``run_in_executor``, die
Methode bleibt ``async``). Das Persistenz-Repo ist ``sync`` (sqlite schnell genug,
Muster scanning/monitoring/alerting).

``ports/`` kennt NUR ``domain/security``-Typen + stdlib (import-linter "ports kennen
hoechstens domain"); ``modules/``/``infrastructure/`` sind verboten.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from domain.security import ArpAlert, ArpEntry

# ── Persistenz ────────────────────────────────────────────────────────────


class ArpGuardRepository(Protocol):
    """Persistenz der ARP-Baseline (``arp_baseline``) und -Alerts (``arp_alerts``).

    EIN Vertrag fuer beide Tabellen (s. Modul-Docstring). Liefert/nimmt Domaenen-
    typen (``ArpEntry``/``ArpAlert``); die Zeitspalten (``first_seen``/``last_seen``
    der Baseline, ``ts``/``datetime`` der Alerts) setzt/fuellt der SEC.4-Adapter --
    sie sind NICHT Teil der Domaenentypen (Persistenz-Rand, SEC.2-Entscheidung).
    """

    def load_baseline(self) -> list[ArpEntry]:
        """Alle bekannten Baseline-Eintraege (``arp_baseline``) als ``ArpEntry``.

        Leere Baseline -> ``[]``, niemals ``None``.
        """
        ...

    def save_baseline_entry(self, entry: ArpEntry) -> None:
        """Upsert eines Baseline-Eintrags (INSERT OR REPLACE auf ``ip``).

        ``first_seen`` bleibt beim ersten Sehen erhalten, ``last_seen`` aktualisiert
        der Adapter (Altcode ``_save_baseline``-Semantik) -- der Use-Case reicht nur
        ip/mac/vendor.
        """
        ...

    def clear_baseline(self) -> None:
        """Leert ``arp_baseline`` vollstaendig (Altcode ``clear_baseline``).

        Beruehrt ``arp_alerts`` NICHT (SEC.1-Vertrag 7).
        """
        ...

    def save_alert(self, alert: ArpAlert) -> None:
        """Schreibt einen erkannten Alert in ``arp_alerts`` (Altcode ``_save_alert``).

        Der Adapter ergaenzt ``ts``/``datetime`` (Persistenz-Rand).
        """
        ...

    def recent_alerts(self, limit: int) -> list[ArpAlert]:
        """Die juengsten Alerts (``ORDER BY ts DESC LIMIT``), neueste zuerst.

        Wegen der Momentaufnahme-Semantik (Use-Case ruft ``clear_alerts`` vor jedem
        Scan) enthaelt ``arp_alerts`` praktisch nur den letzten Scan -- der ``limit``
        ist dadurch faktisch wirkungslos (SEC.1-Befund E.1), bleibt aber am Vertrag.
        """
        ...

    def clear_alerts(self) -> None:
        """Leert ``arp_alerts`` (Altcode ``_clear_alerts``).

        Der SEC.5-Use-Case ruft das VOR jedem Scan -> Momentaufnahme statt Historie.
        """
        ...


# ── Inspektoren (schmale I/O-Vertraege, kein Domaenen-Modell) ───────────────


@dataclass(frozen=True)
class PortQuery:
    """Ein offener Port als Inspektor-Eingabe (port + optionaler service-Name).

    Spiegelt die Altcode-``list[dict]``-Eingabe (``{"port": int, "service": str}``)
    typisiert; von cve/tls/creds gemeinsam genutzt.
    """

    port: int
    service: str = ""


@dataclass(frozen=True)
class CveFinding:
    """Ein CVE-Treffer (charakterisierungstreu zu Altcode ``CVEEntry``, ohne to_dict).

    Felder 1:1 zu ``CVEEntry`` (8 Felder, gleiche Typen). BEWUSST OHNE ``is_public``/
    ``risk_level`` (DF3): diese Felder gehoeren NICHT zu ``CVEEntry``, sondern haengt
    der Altcode-Endpunkt ``/api/cve/lookup-v2`` ans dict an -- ein TOTER Pfad, weil das
    Frontend (ReportView) nie ``port_forwards`` sendet -> ``is_public`` immer ``false``,
    ``risk_level`` nie gerendert (SEC.1b-Befund E.6). SEC.6 baut den Endpunkt ohne
    diesen Pfad neu (API-Vertrag darf brechen). KEINE stille Wire-Divergenz -- bewusste,
    dokumentierte Streichung.
    """

    cve_id: str
    description: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    cvss_score: float
    published: str
    port: int = 0
    service: str = ""
    url: str = ""


@dataclass(frozen=True)
class TlsCertInfo:
    """Zertifikats-Detail eines TLS-Befunds (Altcode ``CertInfo``, ohne to_dict).

    Felder 1:1 zu ``CertInfo`` (9 Felder). ``san`` ist hier ``tuple`` statt der
    Altcode-``list`` (frozen-Pflicht: list ist unhashbar/mutable). RANDWANDEL, Wire-
    treu: JSON kennt keinen Tuple -> ``json.dumps(tuple)`` == JSON-Array (identisch zu
    list), der SEC.6-api-Rand serialisiert es Altcode-treu (analog bool->int bei
    alerting).
    """

    subject: str = ""
    issuer: str = ""
    san: tuple[str, ...] = ()
    not_before: str = ""
    not_after: str = ""
    days_remaining: int = 0
    is_expired: bool = False
    is_self_signed: bool = False
    serial: str = ""


@dataclass(frozen=True)
class TlsFinding:
    """Ein TLS-Inspektions-Ergebnis je Port (Altcode ``TLSResult``, ohne to_dict).

    ``cert`` ist ``None``, wenn kein Zertifikat gelesen werden konnte. ``warnings``
    ist ein Tupel (unveraenderlich, Muster frozen).
    """

    host: str
    port: int
    reachable: bool = False
    tls_version: str = ""
    cipher_name: str = ""
    cipher_bits: int = 0
    cert: TlsCertInfo | None = None
    grade: str = ""  # A / B / C / F
    warnings: tuple[str, ...] = ()
    error: str = ""


@dataclass(frozen=True)
class CredFinding:
    """Ein gefundenes Default-Credential-Paar (Altcode ``CredResult``, ohne to_dict)."""

    host: str
    port: int
    service: str
    username: str
    password: str
    success: bool
    method: str  # http_basic / http_form / ssh / ftp
    note: str = ""


class CveLookup(Protocol):
    """Schlaegt CVEs fuer die offenen Ports eines Hosts nach (NVD-Abfrage).

    Externer HTTP-Call (NVD-API) -> ``async``. SEC.4 reimplementiert das stdlib-basiert
    und heilt den S3-Fallback (Netzfehler -> expliziter Fehler statt stillem ``[]``,
    SEC.1b-Befund E.2). Keine Treffer -> ``[]``.
    """

    async def lookup_for_host(self, ports: Sequence[PortQuery]) -> list[CveFinding]:
        """CVEs fuer die gegebenen Ports, nach Severity sortiert (Altcode-Reihenfolge)."""
        ...


class TlsInspector(Protocol):
    """Inspiziert die TLS-Konfiguration der HTTPS-faehigen Ports eines Hosts.

    TLS-Handshake (blockierend) -> ``async``. SEC.4 reimplementiert das und heilt den
    Cert-Datum-S3-Fallback (E.5) + den SSLError-Handler-Crash (SEC.1b-Befund). Keine
    HTTPS-Ports / nichts erreichbar -> ``[]``.
    """

    async def inspect_host(self, host: str, ports: Sequence[int]) -> list[TlsFinding]:
        """TLS-Befunde je inspizierbarem Port (nicht erreichbare Ports entfallen)."""
        ...


class DefaultCredsChecker(Protocol):
    """Testet bekannte Default-Credentials gegen die offenen Ports eines Hosts.

    AKTIVE Login-Versuche (HTTP-Basic / FTP, blockierend) -> ``async``. INTRUSIV
    (echte Anmeldeversuche -- SEC.1b/DF5, als Finding dokumentiert). SEC.4
    reimplementiert das und heilt die Netzfehler-S3-Fallbacks (E.4b/E.4c). ``vendor``
    waehlt geraetespezifische Credential-Listen; leer -> generische Web-Defaults.
    Keine Treffer -> ``[]``.
    """

    async def check_host(
        self, host: str, ports: Sequence[PortQuery], vendor: str = ""
    ) -> list[CredFinding]:
        """Gefundene funktionierende Default-Credentials (leer wenn keine)."""
        ...


__all__ = [
    "ArpGuardRepository",
    "CredFinding",
    "CveFinding",
    "CveLookup",
    "DefaultCredsChecker",
    "PortQuery",
    "TlsCertInfo",
    "TlsFinding",
    "TlsInspector",
]
