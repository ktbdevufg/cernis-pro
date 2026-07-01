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

from application.dns_bypass.recorder import DnsBypassRecorder
from domain.dns_bypass import (
    DnsBypassFinding,
    DnsBypassOverview,
    RawDnsQuery,
    is_bypass,
)
from ports.dns_bypass import DnsQueryProvider

__all__ = [
    "BuildDnsBypass",
    "DnsQueryProvider",
    "ExpectedServersProvider",
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
    """Startet eine DNS-Umgehungs-Aufzeichnung ueber den ``DnsBypassRecorder``.

    Anders als ``StartOutboundRecording`` gibt es hier KEINE Repo-/Domaenen-Transition
    und keine SQLite-Aufzeichnungsdefinition -- der Recorder haelt den Zustand selbst
    (schlanke Variante, Etappe 4a). Der Use-Case leert vor dem Start den Sammelpuffer
    (sauberer Neustart) und reicht das ``start``-Ergebnis ehrlich durch (``None`` = ok,
    sonst der Fehlertext der Quelle).
    """

    def __init__(self, recorder: DnsBypassRecorder) -> None:
        self._recorder = recorder

    def __call__(self, interface: str | None) -> str | None:
        self._recorder.clear()
        return self._recorder.start(interface)


class StopDnsBypassRecording:
    """Stoppt die DNS-Umgehungs-Aufzeichnung ueber den ``DnsBypassRecorder``.

    Schlank wie ``StopOutboundRecording``, aber ohne Repo-/Domaenen-Transition: der
    Recorder haelt den Zustand selbst und ``stop`` ist idempotent/best-effort.
    """

    def __init__(self, recorder: DnsBypassRecorder) -> None:
        self._recorder = recorder

    def __call__(self) -> None:
        self._recorder.stop()
