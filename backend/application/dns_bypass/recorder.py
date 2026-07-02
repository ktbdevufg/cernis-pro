"""Persistenter Schreibpfad-Worker des netzweiten DNS-Umgehungs-Waechters (ADR 0042, Etappe 3).

Der laufende Aufzeichnungs-Kern: startet die DNS-Quelle, leert je ``tick`` ihren gepushten
Query-Puffer (``poll_queries``) und SCHREIBT die Anfragen in SQLite -- KEIN RAM-Puffer mehr
(Muster ``RunOutboundRecorder``): jede gepollte Anfrage geht als DETAIL-Zeile in den Store
(alle Anfragen, auch erwartete -- fuer den spaeteren erwartungsgemaess-vs-Umgeher-Vergleich),
und NUR die Umgehungen (Drei-Zustands-Urteil ``domain.dns_trust.bypass_verdict`` == ``BYPASS``)
werden je (``src_ip``, ``dst_ip``) per Merge-Upsert ins Aggregat verdichtet. Ein oeffentlicher
Resolver/Bedrohungslisten-Treffer ist definitionsgemaess eine Umgehung; der eigene, noch nicht
bestaetigte Resolver ist "noch nicht eingeordnet" (kein Befund). Am Tick-Ende laeuft IMMER die
zeit-basierte
DETAIL-Retention (``delete_older_than``). Der Bericht liest kuenftig aus SQLite, nicht mehr
aus einem Speicher-Puffer.

WICHTIGER UNTERSCHIED zum outbound_log-Recorder: der DNS-Sniffer PUSHT Queries in eine deque
(der Quell-``poll_queries`` leert sie) -- dieser Recorder ist daher KEIN periodischer
Snapshot-Worker, sondern ein PUFFER-LEERPUMP-Worker. Anders als outbound_log kennt er KEINE
Modi (DETAIL/AGGREGATE) -- der DNS-Waechter schreibt IMMER Detail UND Aggregat gleichzeitig.

Strukturell wie ``RunOutboundRecorder``: ``import time`` ist erlaubt (keine Domaenenlogik,
nur die Uhr fuer den Loop, via ``now_provider`` injizierbar und so deterministisch testbar);
``run()`` ist nur der Rahmen ``while self._active: tick(); sleep``, die ganze Arbeit sitzt in
``tick``.

Quellen-agnostisch: die ECHTE DNS-Quelle (der ``DnsHelperClient``) UND die drei Repos fallen
erst im Composition Root (Etappe 4) -- der Recorder kennt nur das lokal definierte
``DnsQuerySource``-Protocol und die Port-Protocols (Muster ``RunOutboundRecorder``: kein
Fremd-Adapter im application-Ring, der infrastructure-Client wird NICHT importiert).

``tick`` ist best-effort: der ganze Rumpf liegt in ``try/except``, ein Fehler wird via
``structlog.warning`` geloggt und GESCHLUCKT, nie geworfen (Muster ``RunOutboundRecorder.tick``
-- ein werfendes ``poll_queries``/Repo killt den Loop nie).
"""

import asyncio
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress
from typing import Any, Protocol

import structlog

from domain.dns_bypass import (
    BypassDelta,
    RawDnsQuery,
    merge_bypass,
)
from domain.dns_trust import (
    BypassVerdict,
    DnsServerCategory,
    DnsTrustState,
    bypass_verdict,
)
from ports.dns_bypass import (
    DnsBypassAggregateRepository,
    DnsBypassDetailRepository,
    DnsBypassRecordingRepository,
)

__all__ = [
    "DnsBypassRecorder",
    "DnsQuerySource",
    "DnsServerTrustLookup",
]

# Synchron lesende Naht (ADR 0043, E4): liefert je Ziel-IP das Paar
# ``(Kategorie, Trust-Zustand)`` aus dem Vertrauens-Bestand -- oder ``None``, wenn die IP
# (noch) NICHT im Bestand steht. Der Recorder-Tick ist synchron und darf keinen Event-Loop
# treiben; die echte Lese-Verdrahtung (Repo-Lookup) faellt im Composition Root (Regel 5).
# Der application-Ring nennt KEINEN dns_trust-Adapter -- nur die Domaenen-Enums + die
# reine ``bypass_verdict``-Funktion.
DnsServerTrustLookup = Callable[[str], tuple[DnsServerCategory, DnsTrustState] | None]

_logger = structlog.get_logger(__name__)


class DnsQuerySource(Protocol):
    """Schmale, lokal definierte Naht zur DNS-Quelle (Muster ``ContactSnapshotProvider``).

    Genau die ``DnsHelperClient``-Schnittstelle -- aber als lokales Protocol, damit der
    application-Ring den infrastructure-Client NICHT importiert. Die echte Verdrahtung
    faellt erst im Composition Root (Etappe 4).
    """

    def start(self, interface: str | None) -> str | None:
        """Startet die Quelle. ``None`` bei Erfolg, sonst ein Fehlertext."""
        ...

    def poll_queries(self) -> list[dict[str, Any]]:
        """Leert den Query-Puffer und gibt die rohen Query-dicts zurueck."""
        ...

    def stop(self) -> None:
        """Stoppt die Quelle (idempotent)."""
        ...

    def is_running(self) -> bool:
        """Ob die Quelle gerade laeuft."""
        ...


class DnsBypassRecorder:
    """Persistenter Puffer-Leerpump-Worker: pumpt ``poll_queries`` in SQLite.

    Quellen-AGNOSTISCH (Muster ``RunOutboundRecorder``): bekommt eine ``DnsQuerySource``
    UND die drei Persistenz-Ports per Constructor-Injection -- der Recorder nennt keinen
    infrastructure-Adapter. Der Aufzeichnungs-ZUSTAND lebt in SQLite (Detail + Aggregat),
    NICHT im Speicher. Der Recorder haelt nur die aktive ``recording_id`` (die Aufzeichnung,
    in die er gerade schreibt) und das ``aktiv``-Flag.

    ``trust_lookup`` liefert je Ziel-IP das Paar ``(Kategorie, Trust-Zustand)`` aus dem
    Vertrauens-Bestand (ADR 0043, E4) -- oder ``None`` fuer eine (noch) unbekannte IP. Die
    Umgehungs-Klassifikation ist damit KEINE flache IP-Mengen-Pruefung mehr, sondern das
    Drei-Zustands-Urteil ``domain.dns_trust.bypass_verdict(Kategorie, Trust-Zustand)``:
    nur ``BYPASS`` wird aggregiert; ``EXPECTED`` (vertraut) und ``UNCLASSIFIED`` (noch nicht
    eingeordnet -- z. B. der eigene Pi-hole vor der Bestaetigung) sind KEIN Befund. Eine
    unbekannte IP (``None``) gilt als ``UNCLASSIFIED`` -- kein Fehlalarm; sie wird erst durch
    die Vertrauens-Erfassung (``dns_trust_sync``, laeuft in DIESEM Tick VOR der
    Klassifikation) eingeordnet und beim naechsten Vergleich korrekt bewertet.

    ``dns_trust_sync`` ist eine OPTIONALE, best-effort Naht (ADR 0043, E3): je in diesem Tick
    verarbeiteter Ziel-IP wird sie einmalig awaited, damit die Umgehungs-Ziele in den
    Vertrauens-Bestand kommen. Der Composition Root fuellt sie mit ``SyncDnsTrustServer``
    (Regel 5) -- der application-Ring nennt KEINEN dns_trust-Adapter/-Use-Case; ``None``
    (Default) laesst die Erfassung schlicht aus. Sie liegt INNERHALB des ``tick``-``try`` und
    ist damit best-effort: ein Fehler killt den Loop nie.

    ``run()`` ist nur der Rahmen ``while self._active: tick(); sleep`` -- die Arbeit sitzt in
    ``tick``, best-effort: ein werfendes ``poll_queries``/Repo wird geloggt und geschluckt,
    der Loop laeuft weiter.
    """

    def __init__(
        self,
        source: DnsQuerySource,
        recordings: DnsBypassRecordingRepository,
        detail: DnsBypassDetailRepository,
        aggregate: DnsBypassAggregateRepository,
        trust_lookup: DnsServerTrustLookup,
        poll_interval_s: int = 2,
        retention_max_age_s: int = 86400,
        now_provider: Callable[[], float] = time.time,
        dns_trust_sync: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self._source = source
        self._recordings = recordings
        self._detail = detail
        self._aggregate = aggregate
        self._trust_lookup = trust_lookup
        self._dns_trust_sync = dns_trust_sync
        self._poll_interval_s = poll_interval_s
        self._retention_max_age_s = retention_max_age_s
        self._now = now_provider
        self._active = False
        self._interface: str | None = None
        # Die Aufzeichnung, in die der Recorder gerade schreibt (``None``, solange keine
        # laeuft). Der Start-Use-Case legt sie an und setzt sie hier ueber ``start``.
        self._recording_id: str | None = None

    def start(self, interface: str | None, recording_id: str) -> str | None:
        """Startet die Quelle + bindet die aktive Aufzeichnung. ``None`` = ok, sonst Fehlertext.

        Kein Doppelstart: laeuft die Aufzeichnung schon, ``None`` zurueck. Sonst
        ``source.start(interface)``; bei Fehlertext bleibt der Recorder NICHT aktiv und gibt
        den Text durch (keine stille Aktivierung). Bei Erfolg wird die aktive
        ``recording_id`` gesetzt, ``aktiv=True`` gesetzt und ``None`` zurueckgegeben.
        """
        if self._active:
            return None
        error = self._source.start(interface)
        if error is not None:
            return error
        self._interface = interface
        self._recording_id = recording_id
        self._active = True
        return None

    async def run(self) -> None:
        """Endlos-Rahmen: tickt bis ``stop()``. Die Arbeit sitzt in ``tick``."""
        while self._active:
            await self.tick()
            await asyncio.sleep(self._poll_interval_s)

    async def tick(self) -> None:
        """Eine Iteration (best-effort): Query-Puffer der Quelle in SQLite schreiben + Retention.

        Der GANZE Rumpf liegt in ``try/except`` (Muster ``RunOutboundRecorder.tick``):

        1. ``source.poll_queries()`` abrufen, jedes rohe dict auf ``RawDnsQuery`` mappen
           (``src_ip``/``dst_ip``/``l4`` Pflicht; ``qname`` optional -> ``""`` wenn fehlt).
        2. ``now`` holen.
        3. Fuer JEDE Anfrage eine DETAIL-Zeile schreiben (auch erwartete -- fuer den
           spaeteren erwartungsgemaess-vs-Umgeher-Vergleich).
        4. Je distinct Ziel-IP (best-effort) ``dns_trust_sync`` awaiten, damit die Ziele in
           den Vertrauens-Bestand kommen (ADR 0043, E3). Laeuft VOR der Klassifikation, damit
           eine frisch gesehene IP (z. B. ``8.8.8.8``) noch in DIESEM Tick eingeordnet ist.
           Nur wenn eine Naht gesetzt ist; einmal je Ziel-IP (dedupliziert).
        5. NUR fuer Umgehungen (``bypass_verdict(trust_lookup(dst_ip))`` == ``BYPASS``) einen
           ``BypassDelta`` bilden, den Vorzustand lesen, ``merge_bypass`` rechnen und ins
           Aggregat upserten. ``EXPECTED``/``UNCLASSIFIED`` sind KEIN Befund.
        6. Am ENDE IMMER die DETAIL-Retention (``delete_older_than(now - retention)``).

        Solange keine Aufzeichnung aktiv ist (``recording_id`` None), wird NICHT geschrieben
        -- die Retention laeuft aber trotzdem (Muster outbound-Recorder). Ein Fehler (z. B.
        ein werfendes ``poll_queries``/Repo) wird geloggt und GESCHLUCKT, nie geworfen.
        """
        try:
            now = self._now()
            recording_id = self._recording_id
            if recording_id is not None:
                # (1)+(3) ALLE Anfragen mappen + als DETAIL schreiben; distinct Ziele merken.
                queries: list[RawDnsQuery] = []
                seen_dst_ips: set[str] = set()
                for raw in self._source.poll_queries():
                    query = RawDnsQuery(
                        src_ip=raw["src_ip"],
                        dst_ip=raw["dst_ip"],
                        l4=raw["l4"],
                        qname=raw.get("qname", ""),
                    )
                    queries.append(query)
                    seen_dst_ips.add(query.dst_ip)
                    # DETAIL speichert ALLE Anfragen (auch erwartete).
                    self._detail.save(
                        recording_id,
                        now,
                        query.src_ip,
                        query.dst_ip,
                        query.l4,
                        query.qname,
                    )
                # (4) Ziele in den Vertrauens-Bestand aufnehmen (best-effort, je Ziel einmal)
                # -- VOR der Klassifikation, damit ``trust_lookup`` sie unten schon kennt.
                # JEDER Aufruf ist einzeln gekapselt (``suppress``): eine werfende Erfassung
                # darf die nachfolgende Klassifikation/Aggregation NICHT verhindern.
                if self._dns_trust_sync is not None:
                    for dst_ip in seen_dst_ips:
                        with suppress(Exception):
                            await self._dns_trust_sync(dst_ip)
                # (5) AGGREGAT nur fuer Umgehungen: Drei-Zustands-Urteil je Ziel (E4).
                for query in queries:
                    if self._verdict(query.dst_ip) is not BypassVerdict.BYPASS:
                        continue
                    delta = BypassDelta(
                        src_ip=query.src_ip,
                        dst_ip=query.dst_ip,
                        qname=query.qname,
                        count=1,
                    )
                    existing = self._aggregate.get(recording_id, query.src_ip, query.dst_ip)
                    merged = merge_bypass(existing, delta, now)
                    self._aggregate.upsert(recording_id, merged)
            # IMMER zum Schluss (egal ob aktiv oder nicht): DETAIL-Retention. So verfaellt
            # roher Detail-Verlauf zuverlaessig nach ``retention_max_age_s``, auch ueber
            # mehrere Aufzeichnungen / Neustarts hinweg (Muster outbound-Recorder).
            cutoff = now - self._retention_max_age_s
            self._detail.delete_older_than(cutoff)
        except Exception as exc:
            # Best-effort: ein Tick-Fehler darf den Loop nie killen.
            _logger.warning("dns_bypass_recorder_tick_failed", error=str(exc))

    def _verdict(self, dst_ip: str) -> BypassVerdict:
        """Drei-Zustands-Urteil je Ziel-IP (ADR 0043, E4) ueber die injizierte Trust-Naht.

        Liest ``(Kategorie, Trust-Zustand)`` synchron aus dem Bestand und faellt sie ueber
        die reine ``bypass_verdict`` zusammen. Eine (noch) unbekannte IP (``trust_lookup``
        liefert ``None``) gilt als ``UNCLASSIFIED`` -- KEIN Fehlalarm, sie wird durch die
        vorgelagerte Vertrauens-Erfassung erst eingeordnet.
        """
        record = self._trust_lookup(dst_ip)
        if record is None:
            return BypassVerdict.UNCLASSIFIED
        category, trust_state = record
        return bypass_verdict(category, trust_state)

    def stop(self) -> None:
        """Beendet die Aufzeichnung: ``aktiv=False``, aktive Aufzeichnung loesen, Quelle stoppen."""
        self._active = False
        self._recording_id = None
        self._source.stop()

    def is_active(self) -> bool:
        """Ob gerade eine Aufzeichnung laeuft."""
        return self._active

    def active_recording_id(self) -> str | None:
        """Die Aufzeichnung, in die der Recorder gerade schreibt (``None``, wenn keine)."""
        return self._recording_id
