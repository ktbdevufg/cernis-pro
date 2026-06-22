"""Ports (Vertraege) der cve-Domaene -- Persistenz + quellen-agnostische Provider.

Drei Persistenz-Vertraege (alle ``sync`` -- lokaler SQLite-Zugriff, Muster der uebrigen
Repos) und zwei Provider-Vertraege fuer die quer-domaenigen Quellen (beide werden im
Composition Root mit quellen-agnostischen Callables verdrahtet, Muster BuildTopology /
ADR 0035/0036 -- die cve-Domaene/-Ports nennen WEDER ``security`` NOCH ``scanning``/
``devices``):

* ``CveFindingRepository``      -- Befund-Persistenz (Upsert + Lese-Views).
* ``CveCheckStateRepository``   -- per-Host-Pruefstand (last_checked + Port-Set).
* ``CveAcknowledgementRepository`` -- append-only ack/unack-Audit (ADR-0031-Muster).
* ``HostInventoryProvider``     -- liefert den bekannten Geraete-Bestand MIT offenen Ports.
* ``CveLookupProvider``         -- schlaegt CVEs fuer die offenen Ports eines Hosts nach.

``ports/`` kennt nur ``domain/cve``-Typen + stdlib (import-linter "ports kennen hoechstens
domain"). KEIN ``@runtime_checkable`` (Muster der uebrigen Domaenen, statische Pruefung
ueber mypy + Verdrahtung im Composition Root).
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from domain.cve.models import CveFindingRecord, HostCheckState

__all__ = [
    "CveAcknowledgementRepository",
    "CveCheckStateRepository",
    "CveFindingRepository",
    "CveLookupProvider",
    "HostInventoryProvider",
    "InventoryHost",
    "InventoryPort",
    "LookupCve",
]


# ── Provider-Rand-Typen (quellen-agnostisch, KEIN security/scanning-Bezug) ───────
#
# Diese frozen dataclasses sind die ENTKOPPELNDE Naht: der HostInventoryProvider
# projiziert den (fremden) Bestand IN diese cve-eigenen Typen, der CveLookupProvider
# liefert die NVD-Treffer als cve-eigene ``LookupCve``. So nennt KEIN cve-Code je
# ``EnrichedHost``/``PortInfo``/``CveFinding`` (security/scanning) -- die Quelle bleibt
# im Composition Root, hier kommen nur rohe, domaeneneutrale Werte an.


@dataclass(frozen=True)
class InventoryPort:
    """Ein offener Port eines Bestands-Hosts (port + optionaler service-Name)."""

    port: int
    service: str = ""


@dataclass(frozen=True)
class InventoryHost:
    """Ein bekannter Host aus dem Bestand MIT seinem zuletzt bekannten offenen Port-Stand.

    ``mac`` ist die stabile Identitaet (Pruefstand + Befund haengen daran); ``ip`` ist die
    zuletzt bekannte Adresse (Kontext im Befund). ``ports`` ist der letzte bekannte offene
    Port-Stand des Hosts -- der Worker arbeitet damit AUCH OHNE brandneuen Scan (ADR 0037).
    Ein Host OHNE offene Ports (leeres ``ports``) ist legitim (nichts zu pruefen).
    """

    mac: str
    ip: str
    ports: tuple[InventoryPort, ...]


@dataclass(frozen=True)
class LookupCve:
    """Ein NVD-Treffer, wie ihn der CveLookupProvider liefert (cve-eigener Rand-Typ).

    Felder deckungsgleich mit den NVD-Daten von ``CveFinding`` (security), aber hier
    cve-eigen -- die Naht (security-Adapter -> dieser Typ) lebt im Composition Root.
    """

    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published: str
    port: int
    service: str = ""
    url: str = ""


# ── Provider-Vertraege ──────────────────────────────────────────────────────────


class HostInventoryProvider(Protocol):
    """Liefert den bekannten Geraete-Bestand MIT offenen Ports (Worker-Host-Quelle).

    ``sync`` -- lokaler DB-Lesezugriff (devices + scan_history) im Composition-Root-
    Adapter. Leerer Bestand -> ``[]`` (der Worker schlaeft dann, KEIN NVD-Aufruf).
    Ausfallsicher (CorruptScanError/leer) liegt im Adapter, NICHT hier.
    """

    def list_hosts(self) -> list[InventoryHost]:
        """Alle bekannten Hosts mit ihrem zuletzt bekannten offenen Port-Stand."""
        ...


class CveLookupProvider(Protocol):
    """Schlaegt CVEs fuer die offenen Ports EINES Hosts nach (NVD-Abfrage).

    ``async`` -- externer HTTP-Call (NVD), im Composition Root mit dem vorhandenen
    ``CveLookupAdapter`` (security-infra) verdrahtet. Fehlertolerant: NVD down ->
    ``[]`` (geloggt im Adapter), KEIN erfundener Befund (S3). Keine Treffer -> ``[]``.
    """

    async def lookup(self, ports: Sequence[InventoryPort]) -> list[LookupCve]:
        """CVEs fuer die gegebenen offenen Ports (Severity-sortiert, leer wenn keine)."""
        ...


# ── Persistenz-Vertraege ────────────────────────────────────────────────────────


class CveFindingRepository(Protocol):
    """Persistenz der CVE-Befunde -- Upsert (Identitaet mac+cve_id+port) + Lese-Views.

    ``sync`` (lokaler SQLite-Zugriff). ``CREATE TABLE IF NOT EXISTS`` im Adapter
    (idempotentes Schema, injizierter db_path -- Muster der uebrigen Repos).
    """

    def upsert(self, record: CveFindingRecord) -> None:
        """Legt einen Befund an ODER frischt ihn auf (Identitaet mac+cve_id+port).

        Neuer (mac, cve_id, port) -> INSERT mit ``first_seen_ts`` aus dem Record.
        Bekannter -> nur ``last_seen_ts`` (+ veraenderliche NVD-Felder) aktualisieren,
        ``first_seen_ts`` bleibt UNVERAENDERT (Basis fuers is_new-Flag, ADR 0037).
        """
        ...

    def list_all(self) -> list[CveFindingRecord]:
        """Alle persistierten Befunde (ueber alle Hosts). Leer -> ``[]``."""
        ...

    def list_for_host(self, mac: str) -> list[CveFindingRecord]:
        """Alle Befunde eines Hosts. Leere/unbekannte MAC -> ``[]``."""
        ...

    def clear_all(self) -> None:
        """Leert alle CVE-Befunde (nur die eigene Tabelle)."""
        ...


class CveCheckStateRepository(Protocol):
    """Persistenz des per-Host-Pruefstands (last_checked_ts + geprueftes Port-Set).

    ``sync``. Pro MAC genau EIN Stand (Upsert auf mac). Grundlage der Faelligkeit
    (Faelle 2+3, ``domain.cve.policy.due_reason``).
    """

    def get(self, mac: str) -> HostCheckState | None:
        """Pruefstand einer MAC, oder ``None`` wenn der Host NOCH NIE geprueft wurde.

        ``None`` ist Fall 1 (neuer Host) -- ein legitimer Zustand, kein Fehler.
        """
        ...

    def record(self, mac: str, ports: frozenset[int], checked_ts: float) -> None:
        """Setzt/aktualisiert den Pruefstand einer MAC (Upsert auf mac).

        Nach einer Pruefung aufgerufen -- haelt ``last_checked_ts`` und das gepruefte
        Port-Set fest, sodass die naechste Faelligkeits-Entscheidung darauf aufbaut.
        """
        ...

    def all_states(self) -> list[HostCheckState]:
        """Alle Pruefstaende (Status-Endpunkt: wie viele Hosts geprueft). Leer -> ``[]``."""
        ...

    def clear_all(self) -> None:
        """Leert alle per-Host-Pruefstaende (nur die eigene Tabelle)."""
        ...


class CveAcknowledgementRepository(Protocol):
    """Append-only ack/unack-Audit der Befunde (ADR-0031-Muster, ADR 0037).

    ``sync``. Granularitaet PORT-GENAU pro (mac, cve_id, port) -- konsistent zur Befund-
    Identitaet (ADR 0037). Quittierte werden NICHT geloescht, nur markiert; der effektive
    Status ergibt sich aus dem JUENGSTEN Eintrag je (mac, cve_id, port).
    """

    def record(self, mac: str, cve_id: str, port: int, action: str) -> None:
        """Schreibt EINE neue Log-Zeile (``ack`` oder ``unack``) -- nie Update/Delete."""
        ...

    def acknowledged_keys(self) -> set[tuple[str, str, int]]:
        """Die effektiv quittierten (mac, cve_id, port)-Tripel ueber ALLE Hosts.

        Reine Ableitung: ein Tripel ist quittiert, wenn sein JUENGSTER Eintrag
        ``action == 'ack'`` ist (ein spaeteres ``unack`` hebt es wieder auf). Leer -> ``set()``.
        """
        ...

    def clear_all(self) -> None:
        """Leert das gesamte ack-Log (nur die eigene Tabelle)."""
        ...
