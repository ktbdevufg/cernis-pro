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

from domain.security import ArpAlert, ArpEntry, DefaultCredsEintrag, PruefFall

# ── ARP-Lese-Records (Wire-nahe Rand-Typen MIT Zeit, NICHT domain) ──────────
#
# Die Domaenentypen ArpEntry/ArpAlert sind bewusst ZEITFREI (SEC.2: Zeit ist
# Persistenz-Rand). Der Lese-/Wire-Pfad braucht aber die DB-Zeitspalten (das Frontend
# rendert ``alert.datetime`` + ``baseline.first_seen/last_seen``). Diese Read-Records
# tragen die Zeit -- analog ``ScanRecord``/``ScanSummary`` (Read-Views mit Zeit), aber
# hier in ``ports`` statt domain, konsistent zu CveFinding/TlsFinding (SEC-Rand-Typen).
# Der SCHREIB-/Erkennungs-Pfad (RunArpScan) nutzt weiter die zeitfreien Domaenentypen.


@dataclass(frozen=True)
class ArpAlertRecord:
    """Lese-View eines gespeicherten ARP-Alerts (= ArpAlert-Felder + ts + datetime).

    Was ``recent_alerts()`` liefert. KEIN ``id``: der Altcode-``get_arp_alerts``-dict
    trug die AUTOINCREMENT-``id`` mit (``SELECT *``), aber das Frontend (SecurityView)
    liest sie nie -- bewusste Streichung (toter Wire-Ballast, analog dem alerting
    ``events-id``-Befund). ``ts`` ist epoch-float, ``datetime`` ISO-Text (beide aus den
    DB-Spalten; der SEC.4-Adapter setzt sie beim ``save_alert``).
    """

    alert_type: str
    ip: str
    old_mac: str
    new_mac: str
    old_vendor: str
    new_vendor: str
    severity: str
    message: str
    ts: float
    datetime: str


@dataclass(frozen=True)
class ArpBaselineRecord:
    """Lese-View eines Baseline-Eintrags (= ip/mac/vendor + first_seen + last_seen).

    Was ``load_baseline_records()`` liefert. Felder 1:1 zur Altcode-``get_arp_baseline``-
    dict-Form. ``first_seen``/``last_seen`` epoch-float (DB-Spalten, vom Adapter gesetzt).
    """

    ip: str
    mac: str
    vendor: str
    first_seen: float
    last_seen: float


# ── Persistenz ────────────────────────────────────────────────────────────


class ArpGuardRepository(Protocol):
    """Persistenz der ARP-Baseline (``arp_baseline``) und -Alerts (``arp_alerts``).

    EIN Vertrag fuer beide Tabellen (s. Modul-Docstring). Liefert/nimmt Domaenen-
    typen (``ArpEntry``/``ArpAlert``); die Zeitspalten (``first_seen``/``last_seen``
    der Baseline, ``ts``/``datetime`` der Alerts) setzt/fuellt der SEC.4-Adapter --
    sie sind NICHT Teil der Domaenentypen (Persistenz-Rand, SEC.2-Entscheidung).
    """

    def load_baseline(self) -> list[ArpEntry]:
        """Alle Baseline-Eintraege als ZEITFREIE ``ArpEntry`` (fuer RunArpScan/Erkennung).

        Leere Baseline -> ``[]``, niemals ``None``. Der Lese-/Wire-Pfad (Frontend braucht
        first_seen/last_seen) nutzt ``load_baseline_records`` -- diese Methode bleibt
        bewusst zeitfrei, weil die Erkennung (SEC.2) keine Zeit liest.
        """
        ...

    def load_baseline_records(self) -> list[ArpBaselineRecord]:
        """Alle Baseline-Eintraege als ``ArpBaselineRecord`` MIT Zeit (Lese-/Wire-Pfad).

        Wie ``load_baseline``, aber mit ``first_seen``/``last_seen`` -- fuer den
        ``GetArpBaseline``-Lese-Use-Case (Frontend rendert die Zeitspalten). Leer -> ``[]``.
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

    def recent_alerts(self, limit: int) -> list[ArpAlertRecord]:
        """Die juengsten Alerts als ``ArpAlertRecord`` (mit ts/datetime), neueste zuerst.

        Lese-/Wire-Pfad (das Frontend rendert ``datetime``). ``ORDER BY ts DESC LIMIT``.
        Wegen der Momentaufnahme-Semantik (Use-Case ruft ``clear_alerts`` vor jedem Scan)
        enthaelt ``arp_alerts`` praktisch nur den letzten Scan -- der ``limit`` ist
        dadurch faktisch wirkungslos (SEC.1-Befund E.1), bleibt aber am Vertrag.
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
        """Gefundene funktionierende Default-Credentials (leer wenn keine).

        BESTAND (Rueckwaertskompatibilitaet): raet die Credential-Liste ueber ``vendor``
        (generische Web-Defaults ohne vendor). Bleibt am Vertrag, auch wenn der intelligente
        Etappe-B-Workflow stattdessen ``check_host_mit_kandidaten`` nutzt.
        """
        ...

    async def check_host_mit_kandidaten(
        self,
        host: str,
        ports: Sequence[PortQuery],
        kandidaten: Sequence[tuple[str, str]],
    ) -> list[CredFinding]:
        """Prueft GENAU die uebergebenen Kandidaten gegen GENAU die uebergebenen Ports.

        Der intelligente Etappe-B-Pfad: KEIN blindes Port-Raten und KEINE generische
        Credential-Liste -- die vom Aufrufer AUSGEWAEHLTEN ``(username, password)``-Paare
        werden gegen die uebergebenen offenen ``ports`` getestet. ``kandidaten`` leer oder
        ``ports`` leer -> ``[]`` (nichts zu pruefen). Die TLS-Haertung (strikt +
        self-signed-Fallback mit note) und das Rate-Limit (1 s zwischen Versuchen) des
        Adapters gelten fuer diesen Pfad EBENSO. Keine Treffer -> ``[]``.
        """
        ...


# ── Standardzugangs-Liste: Lese-Port vs. Verwaltungs-/Schreib-Port ──────────
#
# ZWEI Protocols, BEWUSST getrennt nach Belang (Muster ``ports.analysis``
# RuleProvider vs. UserRuleStore): der Lese-Pfad (``DefaultCredsListReader``) ist die
# reine Abfrage-Quelle -- was der spaetere Scan-/Anzeige-Pfad braucht; der Verwaltungs-
# Pfad (``DefaultCredsListStore``) ist der validierende Schreib-/Pflege-Vertrag, den die
# CRUD-Use-Cases nutzen. Ein Adapter kann beide erfuellen (``get_eintraege`` deckt beide
# ab), aber die VERTRAEGE sind getrennt, damit der Lese-Konsument nichts vom Schreiben
# weiss. Die MATCHING-Logik (finde_fuer_hersteller_modell) lebt im ADAPTER, nicht im Port
# -- hier nur die Signatur.
#
# Synchron (kein Netz-/Loop-I/O -- lokaler SQLite-Zugriff, Muster ArpGuardRepository).
# KEIN ``@runtime_checkable`` (Modul-Konvention: statische Pruefung ueber mypy +
# Verdrahtung im Composition Root).


class DefaultCredsListReader(Protocol):
    """Lese-Port der Standardzugangs-Liste -- reine Abfrage-Quelle.

    ``get_eintraege`` liefert ALLE Eintraege (Verwaltungs-/Anzeige-Sicht);
    ``finde_fuer_hersteller_modell`` ist die geraetebezogene Abfrage (nur die passenden,
    aktiven Eintraege). Die Matching-Regel steckt im Adapter, nicht im Vertrag.
    """

    def get_eintraege(self) -> list[DefaultCredsEintrag]:
        """Alle gespeicherten Eintraege. Leere Liste (``[]``) ist ein gueltiger Zustand."""
        ...

    def finde_fuer_hersteller_modell(
        self, hersteller: str, modell: str
    ) -> list[DefaultCredsEintrag]:
        """Die zu Hersteller/Modell passenden, AKTIVEN Eintraege (Matching im Adapter).

        Kein Treffer -> ``[]`` (der implizite Zustand "unbekannt" -- kein Eintrag
        vorhanden, KEIN Fehler).
        """
        ...


class DefaultCredsListStore(Protocol):
    """Verwaltungs-/Schreib-Port der Standardzugangs-Liste -- CRUD + reset.

    BEWUSST getrennt vom ``DefaultCredsListReader``: jener ist die reine Lese-Quelle,
    dieser der validierende Pflege-Vertrag, den die CRUD-Use-Cases nutzen. ``get_eintraege``
    ist deckungsgleich mit dem Reader (ein Store IST eine Quelle). Der Adapter validiert
    beim Schreiben ueber ``domain.security.validate_eintraege`` und wirft bei Issues.
    """

    def get_eintraege(self) -> list[DefaultCredsEintrag]:
        """Alle gespeicherten Eintraege (deckungsgleich mit dem Reader)."""
        ...

    def add_eintrag(self, eintrag: DefaultCredsEintrag) -> None:
        """Fuegt einen neuen Eintrag hinzu (validierend; wirft bei Issues/Duplikat-id)."""
        ...

    def update_eintrag(self, eintrag: DefaultCredsEintrag) -> None:
        """Aktualisiert einen bestehenden Eintrag (validierend; ueber die eintrag_id)."""
        ...

    def delete_eintrag(self, eintrag_id: str) -> None:
        """Loescht einen Eintrag ueber seine eintrag_id."""
        ...

    def set_aktiv(self, eintrag_id: str, aktiv: bool) -> None:
        """Schaltet einen Eintrag aktiv/inaktiv, ohne ihn zu loeschen."""
        ...

    def reset_auf_standard(self) -> None:
        """Stellt die mitgelieferten Eintraege wieder her (herkunft='mitgeliefert').

        Loescht alle Zeilen mit ``herkunft='mitgeliefert'`` und schreibt den Seed frisch;
        benutzer-eigene Eintraege (``herkunft='benutzer'``) bleiben unangetastet.
        """
        ...


# ── Standardzugangs-Pruef-Historie: Lese-Views + Persistenz-Port ────────────
#
# Etappe B protokolliert JEDE durchgefuehrte Pruefung (drei-Faelle-Ergebnis + gefundene
# Findings) in einer eigenen Tabelle -- ANALOG ``ScanHistoryRepository``: ``list`` liefert
# Zusammenfassungen OHNE den Findings-Blob, ``get`` das Detail MIT Findings. Zwei schmale
# Read-Views (Rand-Typen MIT Zeit, wie ``ArpAlertRecord``/``ScanSummary``): die Uhr
# (``geprueft_at``) lebt im Adapter, NICHT in der Domaene. Sync (lokaler SQLite-Zugriff).


@dataclass(frozen=True)
class PruefHistorieSummary:
    """Lese-View eines Historien-Datensatzes OHNE Findings-Blob (Muster ``ScanSummary``).

    Was ``list_eintraege`` liefert: die id + Metadaten (``geprueft_at`` ISO-UTC-Text,
    host/hersteller/modell, der ``fall`` als ``PruefFall``, ``treffer_count``). Der
    Findings-Blob kommt erst per ``get_eintrag(eintrag_id)`` (Charakterisierung
    ``ScanHistoryRepository.list`` ohne ``result_json``).
    """

    eintrag_id: int
    geprueft_at: str
    host: str
    hersteller: str
    modell: str
    fall: PruefFall
    treffer_count: int


@dataclass(frozen=True)
class PruefHistorieDetail:
    """Lese-View eines Historien-Datensatzes MIT Findings (Muster ``ScanRecord``).

    Was ``get_eintrag`` liefert: wie ``PruefHistorieSummary``, plus die verlustfreie
    ``findings``-Tuple (die gespeicherten ``CredFinding``). Unbekannte id -> ``None``
    (nicht dieser Typ) -- s. ``DefaultCredsHistoryRepository.get_eintrag``.
    """

    eintrag_id: int
    geprueft_at: str
    host: str
    hersteller: str
    modell: str
    fall: PruefFall
    treffer_count: int
    findings: tuple[CredFinding, ...]


class DefaultCredsHistoryRepository(Protocol):
    """Persistenz der Standardzugangs-Pruef-Historie (Tabelle ``default_creds_history``).

    Muster ``ScanHistoryRepository``: ``add_eintrag`` schreibt einen Datensatz (Findings
    verlustfrei als JSON-Blob), ``list_eintraege`` liefert die neuesten Zusammenfassungen
    OHNE Blob, ``get_eintrag`` das Detail MIT Findings (unbekannte id -> ``None``). Die
    Zeit (``geprueft_at``) setzt der Adapter (``datetime.now(UTC)``), sie ist NICHT Teil
    eines Domaenentyps. Sync (lokaler SQLite-Zugriff, Muster ``ArpGuardRepository``).
    """

    def add_eintrag(
        self,
        host: str,
        hersteller: str,
        modell: str,
        fall: PruefFall,
        findings: Sequence[CredFinding],
    ) -> None:
        """Speichert einen Historien-Datensatz (``treffer_count = len(findings)``).

        Der Adapter setzt ``geprueft_at`` (ISO-UTC) und serialisiert ``findings``
        verlustfrei. Leere ``findings`` (z. B. Fall "entwarnung"/"keine_infos") sind ein
        gueltiger Zustand -> ``treffer_count = 0``.
        """
        ...

    def list_eintraege(self, limit: int = 50) -> list[PruefHistorieSummary]:
        """Die neuesten Datensaetze als ``PruefHistorieSummary``, neueste zuerst.

        OHNE Findings-Blob (Muster ``ScanHistoryRepository.list``). ``ORDER BY id DESC
        LIMIT``. Leere Historie -> ``[]``.
        """
        ...

    def get_eintrag(self, eintrag_id: int) -> PruefHistorieDetail | None:
        """Ein Datensatz MIT Findings (``PruefHistorieDetail``). Unbekannte id -> ``None``.

        KEIN stiller Fallback bei kaputtem ``ergebnis_json`` -- der Adapter wirft dann einen
        Fehler MIT id-Bezug (Muster ``CorruptScanError``).
        """
        ...


__all__ = [
    "ArpAlertRecord",
    "ArpBaselineRecord",
    "ArpGuardRepository",
    "CredFinding",
    "CveFinding",
    "CveLookup",
    "DefaultCredsChecker",
    "DefaultCredsHistoryRepository",
    "DefaultCredsListReader",
    "DefaultCredsListStore",
    "PortQuery",
    "PruefHistorieDetail",
    "PruefHistorieSummary",
    "TlsCertInfo",
    "TlsFinding",
    "TlsInspector",
]
