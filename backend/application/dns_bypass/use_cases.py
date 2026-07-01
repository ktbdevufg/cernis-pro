"""Use-Case des DNS-Umgehungs-Waechters (ADR 0042, Etappe 2): ``BuildDnsBypass``.

Fuehrt die vom Sniffer erkannten DNS-Anfragen mit der erwarteten-Resolver-Menge zu einer
Umgehungs-Sicht zusammen: je Anfrage entscheidet die reine ``domain.dns_bypass``-Logik, ob
ihr Ziel eine Umgehung ist; die Umgehungen werden je (``src_ip``, ``dst_ip``) aggregiert.
Kennt ``application/dns_bypass`` und die reine ``domain/dns_bypass`` (Modelle +
Klassifikation) -- NIE ``infrastructure``, NIE ``modules`` (import-linter) und KEINE
Fremd-Domaene (kein ``dns_watch``/``devices``/``blocklist``). Die Quellen kommen
quellen-AGNOSTISCH per Constructor-Injection als schmale Protocols/Callables herein (Muster
``BuildDnsWatch``). Die echte Verdrahtung faellt erst im Composition Root.

FACHLICHE GRENZE (ADR 0042): die Domaene bekommt die Quell-IP als ROHEN Schluessel. Die
Zuordnung Quell-IP -> Geraet (Bestand) und die DoH-Blocklist-Bewertung liegen NICHT hier,
sondern spaeter im Composition Root (Regel 5). Auch die "erwartet-oder-Gateway"-Ableitung
der erwarteten Menge (``domain.dns_watch.expected_servers_or_default``) faellt dort -- der
``ExpectedServersProvider`` bekommt die fertige Menge hier bereits herein.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from application.dns_bypass.recorder import DnsBypassRecorder
from domain.dns_bypass import (
    AggregatedBypass,
    DnsBypassFinding,
    DnsBypassOverview,
    DnsBypassRecording,
    DnsBypassRecordingState,
    RawDnsQuery,
    is_bypass,
)
from domain.dns_bypass import (
    start as domain_start,
)
from domain.dns_bypass import (
    stop as domain_stop,
)
from ports.dns_bypass import (
    DnsBypassAggregateRepository,
    DnsBypassDetailRepository,
    DnsBypassRecordingRepository,
    DnsQueryProvider,
)

__all__ = [
    "BuildDnsBypass",
    "DnsBypassReport",
    "DnsQueryProvider",
    "ExpectedServersProvider",
    "GetDnsBypassReport",
    "StartDnsBypassRecording",
    "StopDnsBypassRecording",
]

# Bis zu so viele distinct qnames werden je Befund als Beleg mitgefuehrt (gedeckelt,
# damit ein lautes Geraet die Sicht nicht aufblaeht). Reines Aggregations-Datum.
_MAX_SAMPLE_QNAMES = 5


# ── Quellen-agnostische Nahtstelle (lokal definiert, KEINE Fremd-Domaenentypen) ──

# Liefert die erwartete-Resolver-Menge (roh). Die "erwartet-oder-Gateway"-Ableitung
# (``domain.dns_watch.expected_servers_or_default``) und die Persistenz liegen im
# Composition Root -- hier nur die Naht. Sync -- ein lokaler Lese-Snapshot.
ExpectedServersProvider = Callable[[], Sequence[str]]


class BuildDnsBypass:
    """Aggregiert die DNS-Umgehungen aus den injizierten Quellen.

    Quellen-AGNOSTISCH (Muster ``BuildDnsWatch``): bekommt einen ``DnsQueryProvider`` (die
    vom Sniffer erkannten Anfragen) und einen ``ExpectedServersProvider`` (die erwartete
    Menge) per Constructor-Injection -- keiner nennt eine Fremd-Domaene. Die echte
    Verdrahtung faellt erst im Composition Root.

    KLASSIFIKATION (rein, ``domain/dns_bypass``): je Anfrage entscheidet ``is_bypass``, ob
    ihr Ziel NICHT in der erwarteten Menge liegt; nur Umgehungen werden aggregiert.

    AGGREGATIONS-REGEL: die Umgehungen werden nach (``src_ip``, ``dst_ip``) gruppiert -- ein
    ``DnsBypassFinding`` je Paar. ``query_count`` zaehlt die Anfragen der Gruppe;
    ``sample_qnames`` sind bis zu 5 distinct nicht-leere qnames in Erst-Vorkommen-
    Reihenfolge (dokumentierte, deterministische Regel).

    REIHENFOLGE deterministisch: ``query_count`` absteigend (Lautestes zuerst), dann
    ``src_ip`` aufsteigend, dann ``dst_ip`` aufsteigend (stabiler Tie-Breaker).
    """

    def __init__(
        self,
        queries: DnsQueryProvider,
        expected_servers: ExpectedServersProvider,
    ) -> None:
        self._queries = queries
        self._expected_servers = expected_servers

    def __call__(self) -> DnsBypassOverview:
        """Baut die ``DnsBypassOverview`` (Klassifikation + Aggregation der Umgehungen).

        Holt die erwartete Menge, klassifiziert jede Anfrage, gruppiert die Umgehungen nach
        (``src_ip``, ``dst_ip``), zaehlt die Gesamt-/Umgehungs-/Erwartungs-Anfragen sowie
        die distinct Umgehungs-Geraete und gibt die deterministisch sortierten Befunde mit
        der erwarteten Menge als Beleg zurueck. Keine Umgehung ergibt leere ``findings`` und
        ``bypass_total``/``bypass_devices`` = 0 -- die erwartete Menge ist trotzdem als
        Beleg gefuellt.
        """
        # Erwartete Menge holen + defensiv in eine normalisierte Menge ueberfuehren (gleiche
        # Form wie die domain-Logik vergleicht: strip + lower).
        expected = tuple(self._expected_servers())
        expected_set = {ip.strip().lower() for ip in expected}

        queries = self._queries()
        queries_total = len(queries)

        grouped = self._group_bypasses(queries, expected_set)
        bypass_total = sum(count for (count, _samples) in grouped.values())
        expected_total = queries_total - bypass_total
        bypass_devices = len({src_ip for (src_ip, _dst_ip) in grouped})

        findings = [
            DnsBypassFinding(
                src_ip=src_ip,
                dst_ip=dst_ip,
                query_count=count,
                sample_qnames=tuple(samples),
            )
            for (src_ip, dst_ip), (count, samples) in grouped.items()
        ]
        findings.sort(key=lambda f: (-f.query_count, f.src_ip, f.dst_ip))

        return DnsBypassOverview(
            findings=tuple(findings),
            expected_servers=expected,
            queries_total=queries_total,
            bypass_total=bypass_total,
            expected_total=expected_total,
            bypass_devices=bypass_devices,
        )

    @staticmethod
    def _group_bypasses(
        queries: Sequence[RawDnsQuery],
        expected_set: set[str],
    ) -> dict[tuple[str, str], tuple[int, list[str]]]:
        """Gruppiert die Umgehungen nach (``src_ip``, ``dst_ip``).

        Nicht-Umgehungen (``is_bypass`` -> ``False``) werden uebersprungen. Je Paar wird der
        Zaehler hochgezaehlt und ``sample_qnames`` gepflegt: bis zu ``_MAX_SAMPLE_QNAMES``
        distinct nicht-leere qnames in Erst-Vorkommen-Reihenfolge. Einfuege-Reihenfolge =
        erstes Vorkommen je Paar (deterministisch).
        """
        grouped: dict[tuple[str, str], tuple[int, list[str]]] = {}
        for query in queries:
            if not is_bypass(query, expected_set):
                continue
            key = (query.src_ip, query.dst_ip)
            existing = grouped.get(key)
            if existing is None:
                samples: list[str] = []
                grouped[key] = (1, samples)
            else:
                count, samples = existing
                grouped[key] = (count + 1, samples)
            if query.qname and query.qname not in samples and len(samples) < _MAX_SAMPLE_QNAMES:
                samples.append(query.qname)
        return grouped


# ── Steuerungs-Use-Cases (Muster Start/StopOutboundRecording) ──


class StartDnsBypassRecording:
    """Legt eine BENANNTE Aufzeichnung an, startet sie und bindet sie an den Recorder.

    Muster ``CreateOutboundRecording`` + ``StartOutboundRecording`` in einem Schritt (der
    DNS-Waechter kennt keinen getrennten Anlege-/Start-Lebenszyklus): erzeugt eine NEUE
    ``DnsBypassRecording`` im Zustand ``CREATED`` (``recording_id``/``now`` kommen als
    Parameter herein -- der Rand liefert ``uuid4``/``time.time()``, der Use-Case haelt keine
    Uhr), fuehrt den Domaenen-Uebergang ``start`` mit der ERWARTETEN-Menge-Momentaufnahme
    durch (ehrlicher Beleg, gegen welche Menge klassifiziert wird) und legt die gestartete
    Aufzeichnung ab (``recordings.save``).

    Danach ``source.start(interface)`` ueber den Recorder, der die aktive ``recording_id``
    setzt. Der ``start``-Fehlertext der Quelle wird EHRLICH durchgereicht (``None`` = ok,
    sonst der Fehlertext) -- KEIN stiller Fallback. Die Aufzeichnungs-DEFINITION bleibt dann
    zwar als ``ACTIVE`` in der DB (der Recorder ist aber NICHT aktiv, schreibt also nichts);
    das aufzuraeumen ist Sache eines spaeteren Stop/Cleanup -- hier wird der Fehler nur
    ehrlich gemeldet.
    """

    def __init__(
        self,
        recorder: DnsBypassRecorder,
        recordings: DnsBypassRecordingRepository,
        expected_servers_provider: Callable[[], Sequence[str]],
        default_label: str = "DNS-Umgehungs-Aufzeichnung",
        default_purpose: str = "",
    ) -> None:
        self._recorder = recorder
        self._recordings = recordings
        self._expected_servers_provider = expected_servers_provider
        self._default_label = default_label
        self._default_purpose = default_purpose

    def __call__(
        self,
        interface: str | None,
        recording_id: str,
        now: float,
        label: str | None = None,
        purpose: str | None = None,
    ) -> str | None:
        # Erwartete-Menge-Momentaufnahme fuer den Domaenen-``start`` (ehrlicher Beleg).
        expected_servers = tuple(self._expected_servers_provider())
        recording = DnsBypassRecording(
            id=recording_id,
            label=label if label is not None else self._default_label,
            purpose=purpose if purpose is not None else self._default_purpose,
            state=DnsBypassRecordingState.CREATED,
            created_at=now,
            interface=interface,
        )
        started = domain_start(recording, now, expected_servers)
        self._recordings.save(started)
        # Quelle starten + aktive recording_id im Recorder setzen; Fehlertext ehrlich durch.
        return self._recorder.start(interface, recording_id)


class StopDnsBypassRecording:
    """Stoppt die aktive DNS-Umgehungs-Aufzeichnung: Domaenen-``stop`` -> ``save`` -> Recorder.

    Muster ``StopOutboundRecording``, aber die aktive ``recording_id`` kommt vom Recorder
    (er haelt sie): liegt eine aktive Aufzeichnung vor, wird ihre Definition geladen, der
    Domaenen-Uebergang ``stop`` durchgefuehrt und die beendete Definition abgelegt
    (``recordings.save``). Danach IMMER ``recorder.stop()`` (Quelle stoppen, idempotent/
    best-effort).

    Robust gegen Randfaelle: ist keine Aufzeichnung aktiv oder ihre Definition fehlt (z. B.
    manuell geloescht), wird KEINE Transition erzwungen -- es bleibt beim ``recorder.stop()``
    (kein Wurf, kein stiller Fehler).
    """

    def __init__(
        self,
        recorder: DnsBypassRecorder,
        recordings: DnsBypassRecordingRepository,
    ) -> None:
        self._recorder = recorder
        self._recordings = recordings

    def __call__(self) -> None:
        recording_id = self._recorder.active_recording_id()
        if recording_id is not None:
            recording = self._recordings.get(recording_id)
            if recording is not None and recording.state is DnsBypassRecordingState.ACTIVE:
                finished = domain_stop(recording)
                self._recordings.save(finished)
        self._recorder.stop()


# ── Lese-Use-Case fuer den PERSISTENTEN Bericht (Etappe 3) ────────────────────


@dataclass(frozen=True)
class DnsBypassReport:
    """Der aus SQLite gelesene Umgehungs-Bericht EINER Aufzeichnung (Lese-Datentraeger).

    ``recording`` ist die zugrunde liegende Aufzeichnungs-Definition (``None``, wenn es noch
    keine gibt -- dann ist alles leer). ``aggregates`` sind die verdichteten Umgehungs-
    Datensaetze dieser Aufzeichnung (lauteste zuerst, wie vom Aggregat-Repo geliefert);
    ``queries_total`` ist die Zahl ALLER in dieser Aufzeichnung gespeicherten DETAIL-Zeilen
    (auch der erwarteten), damit der Rand ``expected_total = queries_total - bypass_total``
    ehrlich bilden kann.
    """

    recording: DnsBypassRecording | None
    aggregates: tuple[AggregatedBypass, ...]
    queries_total: int


class GetDnsBypassReport:
    """Liest den persistenten Umgehungs-Bericht der aktiven bzw. juengsten Aufzeichnung.

    Ersetzt den frueheren RAM-Puffer-Lesepfad (Etappe 3): der Bericht kommt jetzt aus SQLite.
    Wahl der Aufzeichnung: die ERSTE ``ACTIVE`` (host-weit hoechstens eine); gibt es keine
    aktive, die JUENGSTE nach ``created_at`` (``list_all`` ist aufsteigend sortiert -> das
    letzte Element). Gibt es gar keine Aufzeichnung -> leerer Bericht.

    ``aggregates`` kommen roh aus ``aggregate.list_for`` (lauteste zuerst). ``queries_total``
    zaehlt die DETAIL-Zeilen dieser Aufzeichnung im Fenster ``[0, until)`` -- der Aufrufer
    reicht ``until`` (die aktuelle Uhr) herein, der Use-Case haelt keine Uhr (Hausmuster).
    """

    def __init__(
        self,
        recordings: DnsBypassRecordingRepository,
        detail: DnsBypassDetailRepository,
        aggregate: DnsBypassAggregateRepository,
    ) -> None:
        self._recordings = recordings
        self._detail = detail
        self._aggregate = aggregate

    def __call__(self, until: float) -> DnsBypassReport:
        recording = self._pick_recording()
        if recording is None:
            return DnsBypassReport(recording=None, aggregates=(), queries_total=0)
        aggregates = tuple(self._aggregate.list_for(recording.id))
        queries_total = len(self._detail.range(recording.id, 0.0, until))
        return DnsBypassReport(
            recording=recording,
            aggregates=aggregates,
            queries_total=queries_total,
        )

    def _pick_recording(self) -> DnsBypassRecording | None:
        """Erste ``ACTIVE`` Aufzeichnung, sonst die juengste, sonst ``None``."""
        recordings = self._recordings.list_all()
        for rec in recordings:
            if rec.state is DnsBypassRecordingState.ACTIVE:
                return rec
        return recordings[-1] if recordings else None
