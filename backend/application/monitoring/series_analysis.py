"""Serien-Auswertung als reine, zeitfreie Lese-Aggregation (Block 3c, Etappe 1).

Eine RECURRING-Serie ist EIN durchgehender ``LoggingTask``. Diese Datei rechnet aus
den vorhandenen Logging-Daten EINER Serie -- den dichten RTT-Samples
(``LoggingRttSample``) und den Ereignis-Flanken (``LoggingEventRow``) -- die
Auswertungs-Kennzahlen. Sie ist REINE LESESICHT: KEINE neue Messlogik, KEIN Sink,
KEINE Persistenz, KEIN Scheduler. Die Repos liefern die Daten bereits aufsteigend
nach ``ts`` (Ports ``LoggingRttRepository.all_for``/``range`` und
``LoggingEventRepository.range``); der Aufrufer (Router, Etappe 2) reicht sie herein.

ZEITFREI wie die Domaene (CLAUDE.md, ADR 0002): KEINE Uhr, KEINE Zeitzonen-/
Wanduhr-Rechnung in dieser Datei. Die lokale Umrechnung Unix-ts -> ``minute_of_day``
und ``day_key`` (lokales Datum) macht der spaetere Router und reicht sie ueber
``enrich`` je Outage herein -- so bleibt die Aggregation voll testbar, ohne dass die
Zeitzone des Testlaufs das Ergebnis beeinflusst. Outages OHNE diese Anreicherung
(``minute_of_day``/``day_key`` ``None``) tauchen weiter in der vollstaendigen
``outages``-Liste auf (Detailtabelle), werden aber aus Heatmap/Ranking ausgespart
(kein stiller Fehler -- sie verschwinden nur aus dem Zeitraster).

ABBRUCH-SEMANTIK: ein ``"down"``-Event eroeffnet einen Abbruch, das naechste
``"up"``-Event schliesst ihn (Dauer = ``ts_up - ts_down``). Ein offener Abbruch ohne
folgendes ``"up"`` (Serie endet im Ausfall) bleibt mit ``end_ts=None`` als "noch
offen" markiert und zaehlt mit Dauer bis zum letzten bekannten Event-``ts``.

Muster aus der Nachbarschaft uebernommen: frozen dataclasses als Ergebnis-Datentraeger
(``models.py``/``logging_task.py``), reine Funktionen, die via Parameter alle
Zeit-/Kontext-Werte hereingereicht bekommen (kein ``time.time()``).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from math import ceil
from statistics import fmean

from domain.monitoring import CaptureMode, LoggingEventRow, LoggingRttSample

# Das Ereignis-Vokabular der Flanken am Port-Rand (roher ``str`` aus dem
# MonitorEventType-Vokabular, s. LoggingEventRow-Docstring): "down" eroeffnet einen
# Abbruch, "up" schliesst ihn. Hier als Konstanten gefuehrt, damit die Paarungslogik
# nicht auf verstreute String-Literale baut.
_EVENT_DOWN = "down"
_EVENT_UP = "up"


# ── Ergebnis-Datentraeger (frozen) ──────────────────────────────────────────


@dataclass(frozen=True)
class OutageInterval:
    """EIN Ausfall-Intervall der Serie (down -> up, oder noch offen).

    ``start_ts`` ist der ``ts`` des oeffnenden ``"down"``-Events, ``end_ts`` der ``ts``
    des schliessenden ``"up"``-Events oder ``None``, wenn der Abbruch am Serienende
    noch offen ist. ``duration_s`` ist ``end_ts - start_ts`` (geschlossen) bzw. die
    Dauer bis zum letzten bekannten Event-``ts`` (offen).

    ``minute_of_day``/``day_key`` sind die vom Router gesetzte lokale Anreicherung
    (Tagesfenster-Minute bzw. ISO-Datum ``yyyy-mm-dd`` aus ``start_ts`` in lokaler
    Zeit). Beide ``None``, solange nicht angereichert -- die Aggregation rechnet hier
    KEINE Wanduhr (s. Modul-Docstring). Outages mit ``None`` bleiben in der
    ``outages``-Liste, fallen aber aus Heatmap/Ranking heraus.
    """

    start_ts: float
    end_ts: float | None
    duration_s: float
    minute_of_day: int | None = None
    day_key: str | None = None


@dataclass(frozen=True)
class HeatmapSlot:
    """Ein Tageszeit-Bucket des Ausfall-Rasters.

    ``minute_of_day`` ist die gebucketete Tagesfenster-Minute (untere Bucket-Grenze,
    ``(minute_of_day // slot_minutes) * slot_minutes``), ``outage_count`` die Zahl der
    Abbrueche, deren ``start_ts`` in diesen Bucket faellt.
    """

    minute_of_day: int
    outage_count: int


@dataclass(frozen=True)
class RankEntry:
    """Ein Rang-Eintrag des Tageszeit-Rankings.

    ``minute_of_day`` ist der Tageszeit-Slot (gebucketet wie in der Heatmap),
    ``day_count`` die Zahl DISTINKTER Tage (``day_key``) mit mindestens einem Abbruch
    in diesem Slot, ``longest_outage_s`` die laengste Einzel-Abbruchdauer im Slot.
    """

    minute_of_day: int
    day_count: int
    longest_outage_s: float


@dataclass(frozen=True)
class LatencySlot:
    """Ein Tageszeit-Bucket der Latenz-Spitzen (zweite fachliche Achse neben Outages).

    ``minute_of_day`` ist die gebucketete Tagesfenster-Minute (untere Bucket-Grenze,
    ``(minute_of_day // slot_minutes) * slot_minutes`` -- gleiche Bucketung wie
    ``HeatmapSlot``), ``sample_count`` die Zahl der GUELTIGEN ``alive``-Samples im Slot
    (Sentinel ``-1.0`` und nicht erreichbare ausgespart), ``p95_rtt_ms`` das
    95-Perzentil (nearest-rank) und ``max_rtt_ms`` das Maximum der ``rtt_ms`` dieser
    gueltigen Samples. NICHT gerundet -- das macht Router/Frontend.
    """

    minute_of_day: int
    sample_count: int
    p95_rtt_ms: float
    max_rtt_ms: float


@dataclass(frozen=True)
class EnrichedRttSample:
    """Ein bereits lokal angereicherter RTT-Messpunkt fuer die Latenz-Aggregation.

    ``LoggingRttSample`` traegt BEWUSST keine Anzeige-Felder (``minute_of_day``/
    ``day_key``) und soll nicht verschmutzt werden -- darum nimmt die Latenz-Aggregation
    die Samples NICHT roh, sondern als Liste dieser angereicherten Datentraeger entgegen.
    Die Anreicherung (Unix-``ts`` -> ``minute_of_day`` in LOKALER Zeit) baut der Router
    (``_enrich_rtt_local``), damit ``series_analysis`` weiter uhrfrei bleibt -- dieselbe
    Naht wie ``enrich`` bei den Outages. ``rtt_ms``/``alive`` sind roh aus dem Sample
    (Sentinel ``-1.0`` bleibt erhalten); die Gueltigkeitspruefung macht
    ``build_latency_slots``.
    """

    rtt_ms: float
    alive: bool
    minute_of_day: int


@dataclass(frozen=True)
class SeriesMetrics:
    """Die verdichteten Kennzahlen der Serie.

    ``availability_pct`` ist der Anteil ``alive=True`` an allen RTT-Samples * 100
    (leere Sample-Liste -> ``100.0``, ehrlicher Leerzustand; NICHT gerundet -- das
    macht Router/Frontend). ``outage_count`` ist die Zahl der Abbrueche,
    ``avg_outage_s`` ihre mittlere Dauer (leer -> ``0.0``), ``worst_slot_minute`` der
    Tageszeit-Slot mit den meisten Abbruechen (``None``, wenn keiner im Raster liegt).
    """

    availability_pct: float
    outage_count: int
    avg_outage_s: float
    worst_slot_minute: int | None


@dataclass(frozen=True)
class SeriesAnalysis:
    """Das Gesamtergebnis der Serien-Auswertung (alles, was der Router herausreicht).

    ``metrics`` traegt die verdichteten Kennzahlen, ``outages`` die VOLLSTAENDIGE
    Abbruch-Liste (auch un-angereicherte), ``heatmap``/``ranking`` die
    Tageszeit-Sichten (nur angereicherte Outages). ``has_latency`` sagt, ob die Serie
    RTT-Latenz fuehrt (``capture_mode == REACHABILITY_LATENCY``) -- das steuert, ob
    der Router eine Latenz-Sicht anbietet.

    ``latency_slots`` ist die zweite fachliche Achse: Latenz-Spitzen je Tageszeit-Slot
    (aus den lokal angereicherten RTT-Samples). Sie wird IMMER berechnet; bei leerer
    Eingabe ist sie leer (ehrlicher Leerzustand) -- das Frontend zeigt sie nur, wenn
    ``has_latency`` ``True`` ist. Default leere Liste (``field(default_factory=list)``)
    ans Ende, damit bestehende positionsbasierte Konstruktionen gueltig bleiben.
    """

    metrics: SeriesMetrics
    outages: list[OutageInterval]
    heatmap: list[HeatmapSlot]
    ranking: list[RankEntry]
    has_latency: bool
    latency_slots: list[LatencySlot] = field(default_factory=list)


# ── Reine Funktionen (keine I/O, keine Uhr) ─────────────────────────────────


def build_outages(events: list[LoggingEventRow]) -> list[OutageInterval]:
    """Paart ``"down"``/``"up"``-Flanken zu Ausfall-Intervallen.

    Ein ``"down"`` eroeffnet einen Abbruch, das naechste ``"up"`` schliesst ihn
    (``duration_s = ts_up - ts_down``). Mehrfach-``"down"`` ohne zwischenliegendes
    ``"up"`` halten den bereits offenen Abbruch (das erste ``"down"`` bleibt
    ``start_ts``); ein ``"up"`` ohne offenen Abbruch wird ignoriert. Ein am Serienende
    offen gebliebener Abbruch bekommt ``end_ts=None`` und ``duration_s`` bis zum
    LETZTEN Event-``ts`` der Liste (gibt es keinen -- bei offenem Abbruch unmoeglich,
    da das ``"down"`` selbst ein Event ist --, ``0.0``). ``events`` wird aufsteigend
    nach ``ts`` erwartet (Repo-Vertrag); ``minute_of_day``/``day_key`` bleiben hier
    ``None`` (setzt der Router via ``enrich``).
    """
    outages: list[OutageInterval] = []
    open_start: float | None = None
    last_ts = events[-1].ts if events else 0.0

    for event in events:
        if event.event_type == _EVENT_DOWN:
            # Erstes "down" eroeffnet; ein weiteres "down" bei bereits offenem Abbruch
            # haelt den urspruenglichen Start (kein neues Intervall).
            if open_start is None:
                open_start = event.ts
        elif event.event_type == _EVENT_UP and open_start is not None:
            # "up" schliesst NUR einen offenen Abbruch; ohne offenen wird es ignoriert.
            outages.append(
                OutageInterval(
                    start_ts=open_start,
                    end_ts=event.ts,
                    duration_s=event.ts - open_start,
                )
            )
            open_start = None

    if open_start is not None:
        # Serie endet im Ausfall: offener Abbruch bis zum letzten bekannten Event-ts.
        outages.append(
            OutageInterval(
                start_ts=open_start,
                end_ts=None,
                duration_s=last_ts - open_start,
            )
        )

    return outages


def _slot_of(minute_of_day: int, slot_minutes: int) -> int:
    """Untere Bucket-Grenze einer Tagesminute (``(m // slot) * slot``)."""
    return (minute_of_day // slot_minutes) * slot_minutes


def build_heatmap(outages: list[OutageInterval], slot_minutes: int) -> list[HeatmapSlot]:
    """Zaehlt Abbrueche je Tageszeit-Bucket.

    Gruppiert nach ``(minute_of_day // slot_minutes) * slot_minutes``. Die
    ``minute_of_day``-Werte sind bereits vorberechnet (vom Router via ``enrich``) --
    diese Funktion rechnet KEINE Wanduhr/Zeitzone. Outages mit ``minute_of_day=None``
    werden uebersprungen (sie bleiben in der ``outages``-Liste, nur nicht im Raster).
    Die Slots sind aufsteigend nach ``minute_of_day`` sortiert.
    """
    counts: dict[int, int] = defaultdict(int)
    for outage in outages:
        if outage.minute_of_day is None:
            continue
        counts[_slot_of(outage.minute_of_day, slot_minutes)] += 1
    return [
        HeatmapSlot(minute_of_day=slot, outage_count=count)
        for slot, count in sorted(counts.items())
    ]


def build_ranking(outages: list[OutageInterval], slot_minutes: int) -> list[RankEntry]:
    """Rankt Tageszeit-Slots nach distinkten Ausfall-Tagen, dann laengstem Abbruch.

    Gruppiert nach Tageszeit-Slot (wie ``build_heatmap``). Je Slot: ``day_count`` =
    Zahl DISTINKTER ``day_key``-Tage mit einem Abbruch im Slot, ``longest_outage_s`` =
    laengste Einzel-Abbruchdauer im Slot. Sortiert ABSTEIGEND nach ``day_count``, bei
    Gleichstand nach ``longest_outage_s`` (ebenfalls absteigend), schliesslich nach
    ``minute_of_day`` aufsteigend als stabiler Tiebreaker.

    Outages ohne ``minute_of_day`` werden ganz uebersprungen; Outages ohne ``day_key``
    gehen NICHT in die Tageszaehlung ein (analog Heatmap -- kein "eigener Tag"-Fallback),
    tragen aber weiter zur ``longest_outage_s`` ihres Slots bei (die Dauer ist auch ohne
    lokales Datum bekannt).
    """
    days_per_slot: dict[int, set[str]] = defaultdict(set)
    longest_per_slot: dict[int, float] = defaultdict(float)

    for outage in outages:
        if outage.minute_of_day is None:
            continue
        slot = _slot_of(outage.minute_of_day, slot_minutes)
        if outage.day_key is not None:
            days_per_slot[slot].add(outage.day_key)
        if outage.duration_s > longest_per_slot[slot]:
            longest_per_slot[slot] = outage.duration_s

    entries = [
        RankEntry(
            minute_of_day=slot,
            day_count=len(days_per_slot[slot]),
            longest_outage_s=longest_per_slot[slot],
        )
        for slot in longest_per_slot
    ]
    entries.sort(key=lambda e: (-e.day_count, -e.longest_outage_s, e.minute_of_day))
    return entries


def build_latency_slots(enriched: list[EnrichedRttSample], slot_minutes: int) -> list[LatencySlot]:
    """Verdichtet angereicherte RTT-Samples zu Latenz-Spitzen je Tageszeit-Slot.

    Nur GUELTIGE Samples zaehlen: ``alive`` ``True`` UND ``rtt_ms >= 0.0`` -- der
    Sentinel ``-1.0`` und nicht erreichbare Punkte sind keine Latenzwerte und werden
    ausgespart (Haltung wie ``latency_threshold``: nicht erreichbar ist keine
    Latenz-Ueberschreitung). Gruppiert nach ``(minute_of_day // slot_minutes) *
    slot_minutes`` (gleiche Bucketung wie ``build_heatmap``, ueber ``_slot_of``). Je Slot:
    ``sample_count`` = Zahl gueltiger Samples, ``p95_rtt_ms`` = 95-Perzentil nach
    nearest-rank (aufsteigend sortiert, Index ``ceil(0.95 * n) - 1``, geclamped auf
    ``[0, n-1]``), ``max_rtt_ms`` = Maximum. Leere Eingabe -> leere Liste. Aufsteigend
    nach ``minute_of_day`` sortiert (wie ``build_heatmap``). Reine Funktion: keine I/O,
    keine Uhr -- die lokale Anreicherung kommt vom Router (s. ``EnrichedRttSample``).
    """
    rtts_per_slot: dict[int, list[float]] = defaultdict(list)
    for sample in enriched:
        if not sample.alive or sample.rtt_ms < 0.0:
            continue
        rtts_per_slot[_slot_of(sample.minute_of_day, slot_minutes)].append(sample.rtt_ms)

    slots: list[LatencySlot] = []
    for slot, rtts in sorted(rtts_per_slot.items()):
        rtts.sort()
        n = len(rtts)
        # nearest-rank: Index = ceil(0.95 * n) - 1, geclamped auf [0, n-1].
        index = min(max(ceil(0.95 * n) - 1, 0), n - 1)
        slots.append(
            LatencySlot(
                minute_of_day=slot,
                sample_count=n,
                p95_rtt_ms=rtts[index],
                max_rtt_ms=rtts[-1],
            )
        )
    return slots


def compute_metrics(
    rtt: list[LoggingRttSample], outages: list[OutageInterval], slot_minutes: int
) -> SeriesMetrics:
    """Verdichtet RTT-Samples + Outages zu den Serien-Kennzahlen.

    ``availability_pct`` = Anteil ``alive=True`` an allen Samples * 100 (leere Liste
    -> ``100.0``, ehrlicher Leerzustand; NICHT gerundet -- das macht Router/Frontend).
    ``outage_count`` = ``len(outages)``. ``avg_outage_s`` = Mittel der ``duration_s``
    ueber geschlossene UND offene Outages (leer -> ``0.0``). ``worst_slot_minute`` =
    ``minute_of_day`` des Slots mit den meisten Abbruechen (``None``, wenn kein Outage
    angereichert ist) -- aus der Heatmap abgeleitet, damit das "schlimmste" Fenster
    konsistent zur Heatmap-Bucketung ist.
    """
    availability_pct = 100.0 if not rtt else sum(1 for s in rtt if s.alive) / len(rtt) * 100.0
    avg_outage_s = 0.0 if not outages else fmean(o.duration_s for o in outages)

    heatmap = build_heatmap(outages, slot_minutes)
    worst_slot_minute: int | None = None
    if heatmap:
        # Slot mit den meisten Abbruechen; bei Gleichstand der frueheste (max ist
        # stabil und behaelt bei gleichem count den zuerst gesehenen -- die Slots sind
        # aufsteigend nach minute_of_day sortiert).
        worst_slot_minute = max(heatmap, key=lambda slot: slot.outage_count).minute_of_day

    return SeriesMetrics(
        availability_pct=availability_pct,
        outage_count=len(outages),
        avg_outage_s=avg_outage_s,
        worst_slot_minute=worst_slot_minute,
    )


def analyze_series(
    capture_mode: CaptureMode,
    rtt: list[LoggingRttSample],
    events: list[LoggingEventRow],
    slot_minutes: int,
    enrich: Callable[[list[OutageInterval]], list[OutageInterval]] | None,
    enriched_rtt: list[EnrichedRttSample] | None = None,
) -> SeriesAnalysis:
    """Orchestriert die Auswertung EINER Serie aus RTT-Samples + Event-Flanken.

    Baut zuerst die Outages (``build_outages``), reicht sie -- falls ``enrich``
    gegeben -- durch den vom Router gereichten Anreicherer (er setzt je Outage
    ``minute_of_day`` + ``day_key`` aus ``start_ts`` in LOKALER Zeit; diese Datei
    rechnet keine Wanduhr). Ist ``enrich`` ``None``, bleiben beide Felder ``None`` --
    Heatmap und Ranking sind dann leer, die ``outages``-Liste trotzdem vollstaendig.
    ``has_latency`` ist ``True`` genau fuer ``CaptureMode.REACHABILITY_LATENCY``.

    ``enriched_rtt`` sind die bereits lokal angereicherten RTT-Samples (Router-Naht
    ``_enrich_rtt_local``) fuer die Latenz-Spitzen-Achse. Sie werden IMMER ueber
    ``build_latency_slots`` verdichtet; bei leerer (Default ``None`` -> leere) Liste sind
    die ``latency_slots`` leer (ehrlicher Leerzustand). ``has_latency`` bleibt davon
    unberuehrt -- das Frontend zeigt die Latenz-Sicht nur, wenn ``has_latency`` ``True`` ist.
    """
    outages = build_outages(events)
    if enrich is not None:
        outages = enrich(outages)

    heatmap = build_heatmap(outages, slot_minutes)
    ranking = build_ranking(outages, slot_minutes)
    metrics = compute_metrics(rtt, outages, slot_minutes)
    latency_slots = build_latency_slots(enriched_rtt or [], slot_minutes)

    return SeriesAnalysis(
        metrics=metrics,
        outages=outages,
        heatmap=heatmap,
        ranking=ranking,
        has_latency=capture_mode == CaptureMode.REACHABILITY_LATENCY,
        latency_slots=latency_slots,
    )
