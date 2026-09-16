"""Tests des persistenten DNS-Bypass-Schreibpfad-Workers (Etappe 3) gegen Fakes.

Reine application-Schicht: KEIN echter Helfer-Subprozess, KEINE echte SQLite -- jeweils EIN
``asyncio.run(recorder.tick())`` (Muster ``test_recorder`` aus outbound_log) mit einer
in-memory ``DnsQuerySource`` und in-memory Fakes der drei Persistenz-Ports. ``run()`` wird
NICHT ueber einen echten asyncio-sleep-Loop getestet -- nur ``tick()``/``start()``/``stop()``
direkt. Belegt:

* T1 start mit Fehlertext -> Recorder NICHT aktiv, Text durchgereicht, keine recording_id.
* T2 start ok -> aktiv + recording_id gesetzt; nach ``tick()`` ist JEDE Query als
  DETAIL-Zeile im Store (auch die erwartete), und NUR die Umgehungen sind aggregiert.
* T3 mehrere ticks verdichten dieselbe (src,dst)-Umgehung per Merge-Upsert (query_count
  summiert, sample_qnames distinct).
* T4 solange keine Aufzeichnung aktiv ist (kein start) schreibt tick NICHTS, laesst aber
  die Retention laufen.
* T5 ``tick`` ist best-effort: ein werfendes ``poll_queries`` -> kein Wurf, kein Schreiben.
* T6 am Tick-Ende laeuft IMMER die DETAIL-Retention (``delete_older_than(now - max_age)``).
* T7 ``stop()`` -> nicht mehr aktiv, recording_id geloest, ``source.stop()`` gerufen.
* T8 die optionale ``dns_trust_sync``-Naht (ADR 0043, E3): je distinct Ziel-IP EINMAL
  awaited (nur bei aktiver Aufzeichnung); eine werfende Naht killt den Tick nicht.
* T9 die Drei-Zustands-Klassifikation (ADR 0043, E4) ueber die ``trust_lookup``-Naht:
  TRUSTED -> erwartet (kein Aggregat), REJECTED sowie NEUTRAL+public/threat -> Umgehung
  (Aggregat), NEUTRAL+local/unknown sowie eine unbekannte IP -> "noch nicht eingeordnet"
  (KEIN Aggregat, kein Fehlalarm).
"""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from application.dns_bypass import DnsBypassRecorder
from domain.dns_bypass import AggregatedBypass
from domain.dns_trust import DnsServerCategory, DnsTrustState


class _FakeDnsQuerySource:
    """In-memory ``DnsQuerySource``-Fake: liefert vordefinierte Batches nacheinander.

    ``start_error`` konfiguriert das ``start``-Ergebnis (``None`` = ok, sonst Fehlertext).
    ``batches`` ist eine Liste von Query-dict-Batches; jeder ``poll_queries``-Aufruf gibt den
    naechsten Batch zurueck (leer, wenn keiner mehr da ist). ``poll_error``, wenn gesetzt,
    laesst ``poll_queries`` werfen (fuer den best-effort-Test). ``stop_calls`` zaehlt die
    ``stop``-Aufrufe.
    """

    def __init__(
        self,
        batches: list[list[dict[str, Any]]] | None = None,
        start_error: str | None = None,
        poll_error: Exception | None = None,
    ) -> None:
        self._batches = list(batches or [])
        self._start_error = start_error
        self._poll_error = poll_error
        self._running = False
        self.stop_calls = 0
        self.started_interface: str | None = None

    def start(self, interface: str | None) -> str | None:
        if self._start_error is not None:
            return self._start_error
        self.started_interface = interface
        self._running = True
        return None

    def poll_queries(self) -> list[dict[str, Any]]:
        if self._poll_error is not None:
            raise self._poll_error
        if not self._batches:
            return []
        return self._batches.pop(0)

    def stop(self) -> None:
        self.stop_calls += 1
        self._running = False

    def is_running(self) -> bool:
        return self._running


class _FakeDetailRepo:
    """In-memory ``DnsBypassDetailRepository``-Fake: sammelt ``save``-Zeilen, zaehlt Retention.

    ``saved`` haelt je Aufruf ein Tupel ``(recording_id, ts, src_ip, dst_ip, l4, qname)``.
    ``delete_calls`` zaehlt die Retention-Aufrufe, ``last_cutoff`` haelt den zuletzt
    uebergebenen absoluten Cutoff.
    """

    def __init__(self) -> None:
        self.saved: list[tuple[str, float, str, str, str, str]] = []
        self.delete_calls = 0
        self.last_cutoff: float | None = None

    def save(
        self,
        recording_id: str,
        ts: float,
        src_ip: str,
        dst_ip: str,
        l4: str,
        qname: str,
    ) -> None:
        self.saved.append((recording_id, ts, src_ip, dst_ip, l4, qname))

    def range(self, recording_id: str, since: float, until: float) -> list[Any]:  # pragma: no cover
        return []

    def delete_older_than(self, cutoff_ts: float) -> int:
        self.delete_calls += 1
        self.last_cutoff = cutoff_ts
        return 0

    def count(self) -> int:  # pragma: no cover
        return len(self.saved)

    def clear_all(self) -> None:  # pragma: no cover
        self.saved = []


class _FakeAggregateRepo:
    """In-memory ``DnsBypassAggregateRepository``-Fake: haelt je (rec,src,dst) einen Datensatz.

    ``upsert`` ersetzt (INSERT OR REPLACE) den Datensatz der Kombination; ``get`` liest den
    Vorzustand (fuer den Merge-Lesepfad des Recorders).
    """

    def __init__(self) -> None:
        self.store: dict[tuple[str, str, str], AggregatedBypass] = {}

    def upsert(self, recording_id: str, aggregate: AggregatedBypass) -> None:
        self.store[(recording_id, aggregate.src_ip, aggregate.dst_ip)] = aggregate

    def get(self, recording_id: str, src_ip: str, dst_ip: str) -> AggregatedBypass | None:
        return self.store.get((recording_id, src_ip, dst_ip))

    def list_for(self, recording_id: str) -> list[AggregatedBypass]:
        return [agg for (rec_id, _s, _d), agg in self.store.items() if rec_id == recording_id]

    def delete_for(self, recording_id: str) -> None:  # pragma: no cover
        for key in [k for k in self.store if k[0] == recording_id]:
            del self.store[key]

    def count(self) -> int:  # pragma: no cover
        return len(self.store)

    def clear_all(self) -> None:  # pragma: no cover
        self.store = {}


class _FakeRecordingRepo:
    """In-memory ``DnsBypassRecordingRepository``-Fake (vom Recorder selbst NICHT genutzt).

    Der Recorder schreibt Definitionen nicht -- das machen die Use-Cases. Wird hier nur zur
    Konstruktor-Vollstaendigkeit uebergeben.
    """

    def __init__(self) -> None:
        self.store: dict[str, Any] = {}

    def save(self, recording: Any) -> None:  # pragma: no cover
        self.store[recording.id] = recording

    def get(self, recording_id: str) -> Any | None:  # pragma: no cover
        return self.store.get(recording_id)

    def list_all(self) -> list[Any]:  # pragma: no cover
        return list(self.store.values())

    def delete(self, recording_id: str) -> None:  # pragma: no cover
        self.store.pop(recording_id, None)

    def clear_all(self) -> None:  # pragma: no cover
        self.store = {}


# Kurz-Aliase fuer die Trust-Records im Test (ADR 0043, E4). Ein ``trust_map`` bildet je
# Ziel-IP das Paar ``(Kategorie, Trust-Zustand)`` ab, das die injizierte ``trust_lookup``-
# Naht liefert; eine NICHT gelistete IP -> ``None`` (Recorder wertet das als UNCLASSIFIED).
_TRUSTED_GATEWAY = (DnsServerCategory.GATEWAY, DnsTrustState.TRUSTED)
_PUBLIC_NEUTRAL = (DnsServerCategory.PUBLIC_RESOLVER, DnsTrustState.NEUTRAL)
_LOCAL_NEUTRAL = (DnsServerCategory.LOCAL_PRIVATE, DnsTrustState.NEUTRAL)


def _make_recorder(
    source: _FakeDnsQuerySource,
    *,
    trust_map: dict[str, tuple[DnsServerCategory, DnsTrustState]] | None = None,
    now: float = 1000.0,
    retention_max_age_s: int = 86400,
    dns_trust_sync: Callable[[str], Awaitable[None]] | None = None,
) -> tuple[DnsBypassRecorder, _FakeDetailRepo, _FakeAggregateRepo]:
    """Verdrahtet den Recorder mit den drei Fakes; fixe Uhr fuer deterministische ts.

    ``trust_map`` speist die synchrone ``trust_lookup``-Naht (E4): je Ziel-IP das Paar
    ``(Kategorie, Trust-Zustand)``; eine unbekannte IP -> ``None`` (UNCLASSIFIED).
    """
    records = dict(trust_map or {})
    detail = _FakeDetailRepo()
    aggregate = _FakeAggregateRepo()
    recordings = _FakeRecordingRepo()
    recorder = DnsBypassRecorder(
        source=source,
        recordings=recordings,
        detail=detail,
        aggregate=aggregate,
        trust_lookup=lambda ip: records.get(ip),
        retention_max_age_s=retention_max_age_s,
        now_provider=lambda: now,
        dns_trust_sync=dns_trust_sync,
    )
    return recorder, detail, aggregate


def test_start_mit_fehlertext_nicht_aktiv_und_durchgereicht() -> None:
    # T1: start mit Fehlertext -> Recorder NICHT aktiv, Text durchgereicht, keine recording_id.
    source = _FakeDnsQuerySource(start_error="DNS-Helfer nicht erreichbar")
    recorder, _detail, _agg = _make_recorder(source)

    result = recorder.start("eth0", "rec-1")

    assert result == "DNS-Helfer nicht erreichbar"
    assert recorder.is_active() is False
    assert recorder.active_recording_id() is None


def test_start_ok_tick_schreibt_detail_alle_und_aggregat_nur_umgehungen() -> None:
    # T2: start ok -> aktiv + recording_id; tick schreibt JEDE Query als Detail (auch die
    # erwartete), aggregiert aber NUR die Umgehung.
    source = _FakeDnsQuerySource(
        batches=[
            [
                # erwartet (Gateway TRUSTED -> EXPECTED) -> Detail ja, Aggregat nein
                {"src_ip": "10.0.0.5", "dst_ip": "192.168.0.1", "l4": "udp", "qname": "ok.example"},
                # Umgehung (public resolver NEUTRAL -> BYPASS) -> Detail ja, Aggregat ja;
                # fehlendes qname -> ""
                {"src_ip": "10.0.0.6", "dst_ip": "8.8.8.8", "l4": "tcp"},
            ]
        ]
    )
    recorder, detail, aggregate = _make_recorder(
        source,
        trust_map={"192.168.0.1": _TRUSTED_GATEWAY, "8.8.8.8": _PUBLIC_NEUTRAL},
        now=1000.0,
    )

    assert recorder.start("eth0", "rec-1") is None
    assert recorder.is_active() is True
    assert recorder.active_recording_id() == "rec-1"

    asyncio.run(recorder.tick())

    # DETAIL: beide Anfragen, fehlendes qname -> ""
    assert detail.saved == [
        ("rec-1", 1000.0, "10.0.0.5", "192.168.0.1", "udp", "ok.example"),
        ("rec-1", 1000.0, "10.0.0.6", "8.8.8.8", "tcp", ""),
    ]
    # AGGREGAT: nur die Umgehung
    aggs = aggregate.list_for("rec-1")
    assert len(aggs) == 1
    agg = aggs[0]
    assert agg.src_ip == "10.0.0.6"
    assert agg.dst_ip == "8.8.8.8"
    assert agg.query_count == 1
    assert agg.first_seen == 1000.0
    assert agg.last_seen == 1000.0
    assert agg.sample_qnames == ()  # leeres qname -> keine Stichprobe


def test_mehrere_ticks_verdichten_umgehung_per_merge_upsert() -> None:
    # T3: dieselbe (src,dst)-Umgehung ueber zwei ticks -> query_count summiert, sample_qnames
    # distinct, first_seen bleibt, last_seen wandert.
    source = _FakeDnsQuerySource(
        batches=[
            [{"src_ip": "10.0.0.6", "dst_ip": "8.8.8.8", "l4": "udp", "qname": "a.example"}],
            [{"src_ip": "10.0.0.6", "dst_ip": "8.8.8.8", "l4": "udp", "qname": "b.example"}],
        ]
    )
    recorder, _detail, aggregate = _make_recorder(
        source, trust_map={"8.8.8.8": _PUBLIC_NEUTRAL}, now=2000.0
    )
    recorder.start(None, "rec-1")

    asyncio.run(recorder.tick())
    asyncio.run(recorder.tick())

    aggs = aggregate.list_for("rec-1")
    assert len(aggs) == 1
    agg = aggs[0]
    assert agg.query_count == 2
    assert agg.sample_qnames == ("a.example", "b.example")


def test_tick_ohne_aktive_aufzeichnung_schreibt_nichts_aber_retention_laeuft() -> None:
    # T4: kein start -> keine recording_id -> tick schreibt NICHTS, laesst aber die Retention
    # laufen.
    source = _FakeDnsQuerySource(
        batches=[[{"src_ip": "10.0.0.6", "dst_ip": "8.8.8.8", "l4": "udp", "qname": "x"}]]
    )
    recorder, detail, aggregate = _make_recorder(source)

    asyncio.run(recorder.tick())

    assert detail.saved == []
    assert aggregate.list_for("rec-1") == []
    assert detail.delete_calls == 1


def test_tick_ist_best_effort_werfendes_poll_kein_wurf() -> None:
    # T5: tick ist best-effort: eine werfende poll_queries -> kein Wurf, nichts geschrieben.
    source = _FakeDnsQuerySource(poll_error=RuntimeError("Puffer kaputt"))
    recorder, detail, aggregate = _make_recorder(source)
    recorder.start(None, "rec-1")

    asyncio.run(recorder.tick())  # darf NICHT werfen

    assert detail.saved == []
    assert aggregate.list_for("rec-1") == []


def test_tick_ende_faehrt_immer_detail_retention() -> None:
    # T6: am Tick-Ende IMMER delete_older_than(now - retention_max_age_s).
    source = _FakeDnsQuerySource(batches=[[]])
    recorder, detail, _agg = _make_recorder(source, now=5000.0, retention_max_age_s=100)
    recorder.start(None, "rec-1")

    asyncio.run(recorder.tick())

    assert detail.delete_calls == 1
    assert detail.last_cutoff == 4900.0


def test_stop_deaktiviert_loest_recording_und_ruft_source_stop() -> None:
    # T7: stop() -> nicht mehr aktiv, recording_id geloest, source.stop() gerufen.
    source = _FakeDnsQuerySource()
    recorder, _detail, _agg = _make_recorder(source)
    recorder.start(None, "rec-1")
    assert recorder.is_active() is True

    recorder.stop()

    assert recorder.is_active() is False
    assert recorder.active_recording_id() is None
    assert source.stop_calls == 1


def test_tick_erfasst_ziel_ips_ueber_dns_trust_sync_einmal_je_ziel() -> None:
    # T8a: je DISTINCT Ziel-IP dieses Ticks wird dns_trust_sync GENAU einmal awaited --
    # unabhaengig davon, ob das Ziel erwartet oder eine Umgehung ist (reine Erfassung).
    source = _FakeDnsQuerySource(
        batches=[
            [
                {"src_ip": "10.0.0.5", "dst_ip": "192.168.0.1", "l4": "udp", "qname": "a"},
                {"src_ip": "10.0.0.6", "dst_ip": "8.8.8.8", "l4": "udp", "qname": "b"},
                # zweite Anfrage an dasselbe Ziel -> keine zweite Erfassung
                {"src_ip": "10.0.0.7", "dst_ip": "8.8.8.8", "l4": "udp", "qname": "c"},
            ]
        ]
    )
    synced: list[str] = []

    async def _sync(ip: str) -> None:
        synced.append(ip)

    recorder, _detail, _agg = _make_recorder(
        source, trust_map={"192.168.0.1": _TRUSTED_GATEWAY}, dns_trust_sync=_sync
    )
    recorder.start(None, "rec-1")

    asyncio.run(recorder.tick())

    # beide distinct Ziele genau einmal (Reihenfolge egal -> Set-Vergleich).
    assert set(synced) == {"192.168.0.1", "8.8.8.8"}
    assert len(synced) == 2


def test_tick_ohne_aktive_aufzeichnung_ruft_dns_trust_sync_nicht() -> None:
    # T8b: kein start -> keine recording_id -> die Erfassung laeuft NICHT (kein Schreibpfad).
    source = _FakeDnsQuerySource(
        batches=[[{"src_ip": "10.0.0.6", "dst_ip": "8.8.8.8", "l4": "udp", "qname": "x"}]]
    )
    synced: list[str] = []

    async def _sync(ip: str) -> None:  # pragma: no cover - darf nie laufen
        synced.append(ip)

    recorder, _detail, _agg = _make_recorder(source, dns_trust_sync=_sync)

    asyncio.run(recorder.tick())  # kein start()

    assert synced == []


def test_tick_werfendes_dns_trust_sync_killt_tick_nicht() -> None:
    # T8c: eine werfende dns_trust_sync-Naht -> kein Wurf; Detail/Aggregat sind trotzdem
    # geschrieben (die Erfassung ist je Ziel einzeln gekapselt, VOR der Aggregation).
    source = _FakeDnsQuerySource(
        batches=[[{"src_ip": "10.0.0.6", "dst_ip": "8.8.8.8", "l4": "udp", "qname": "a"}]]
    )

    async def _sync(ip: str) -> None:
        raise RuntimeError("Vertrauens-Erfassung kaputt")

    recorder, detail, aggregate = _make_recorder(
        source, trust_map={"8.8.8.8": _PUBLIC_NEUTRAL}, dns_trust_sync=_sync
    )
    recorder.start(None, "rec-1")

    asyncio.run(recorder.tick())  # darf NICHT werfen

    # Detail wurde geschrieben; die (werfende) Erfassung laeuft VOR der Aggregation, ist aber
    # je Ziel einzeln gekapselt (suppress) -- danach wird die Umgehung trotzdem aggregiert.
    assert len(detail.saved) == 1
    assert len(aggregate.list_for("rec-1")) == 1


def test_tick_drei_zustands_klassifikation_ueber_trust_lookup() -> None:
    # T9a: die E4-Klassifikation je Ziel ueber die trust_lookup-Naht. In EINEM Tick fuenf
    # Ziele mit verschiedenen (Kategorie, Trust)-Records -- NUR die echten Umgehungen
    # (REJECTED, NEUTRAL+public) landen im Aggregat; TRUSTED/NEUTRAL-lokal/unbekannt nicht.
    source = _FakeDnsQuerySource(
        batches=[
            [
                {"src_ip": "10.0.0.1", "dst_ip": "192.168.0.1", "l4": "udp", "qname": "gw"},
                {"src_ip": "10.0.0.2", "dst_ip": "8.8.8.8", "l4": "udp", "qname": "pub"},
                {"src_ip": "10.0.0.3", "dst_ip": "192.168.0.53", "l4": "udp", "qname": "pi"},
                {"src_ip": "10.0.0.4", "dst_ip": "1.2.3.4", "l4": "udp", "qname": "rej"},
                {"src_ip": "10.0.0.5", "dst_ip": "9.9.9.9", "l4": "udp", "qname": "unk"},
            ]
        ]
    )
    recorder, detail, aggregate = _make_recorder(
        source,
        trust_map={
            "192.168.0.1": _TRUSTED_GATEWAY,  # TRUSTED -> EXPECTED (kein Aggregat)
            "8.8.8.8": _PUBLIC_NEUTRAL,  # NEUTRAL+public -> BYPASS
            "192.168.0.53": _LOCAL_NEUTRAL,  # NEUTRAL+lokal -> UNCLASSIFIED (kein Aggregat)
            "1.2.3.4": (DnsServerCategory.UNKNOWN, DnsTrustState.REJECTED),  # REJECTED -> BYPASS
            # 9.9.9.9 fehlt im Bestand -> None -> UNCLASSIFIED (kein Aggregat, kein Fehlalarm)
        },
        now=1000.0,
    )
    recorder.start(None, "rec-1")

    asyncio.run(recorder.tick())

    # DETAIL: ALLE fuenf Anfragen (unabhaengig vom Urteil).
    assert len(detail.saved) == 5
    # AGGREGAT: NUR die zwei echten Umgehungen (public NEUTRAL + REJECTED).
    aggs = aggregate.list_for("rec-1")
    assert {agg.dst_ip for agg in aggs} == {"8.8.8.8", "1.2.3.4"}


def test_tick_threat_neutral_zaehlt_als_umgehung() -> None:
    # T9b: ein Bedrohungslisten-Treffer ist auch im Zustand NEUTRAL definitionsgemaess eine
    # Umgehung (ohne Nutzer-Ablehnung).
    source = _FakeDnsQuerySource(
        batches=[[{"src_ip": "10.0.0.9", "dst_ip": "6.6.6.6", "l4": "udp", "qname": "bad"}]]
    )
    recorder, _detail, aggregate = _make_recorder(
        source,
        trust_map={"6.6.6.6": (DnsServerCategory.THREAT_LISTED, DnsTrustState.NEUTRAL)},
        now=1000.0,
    )
    recorder.start(None, "rec-1")

    asyncio.run(recorder.tick())

    aggs = aggregate.list_for("rec-1")
    assert len(aggs) == 1
    assert aggs[0].dst_ip == "6.6.6.6"


def test_tick_nachtraegliche_trust_aenderung_wirkt_ohne_neustart() -> None:
    # T9c: dieselbe IP, zwei ticks -- erst NEUTRAL+lokal (UNCLASSIFIED, kein Aggregat), dann
    # nach REJECT (im Bestand geaendert) eine Umgehung. Die trust_lookup-Naht wird bei JEDEM
    # Tick frisch gelesen -> die Aenderung wirkt ohne Neustart.
    source = _FakeDnsQuerySource(
        batches=[
            [{"src_ip": "10.0.0.3", "dst_ip": "192.168.0.53", "l4": "udp", "qname": "a"}],
            [{"src_ip": "10.0.0.3", "dst_ip": "192.168.0.53", "l4": "udp", "qname": "b"}],
        ]
    )
    # Veraenderbarer Record-Store, den die trust_lookup-Naht bei jedem Tick frisch liest.
    records: dict[str, tuple[DnsServerCategory, DnsTrustState]] = {"192.168.0.53": _LOCAL_NEUTRAL}
    detail = _FakeDetailRepo()
    aggregate = _FakeAggregateRepo()
    recorder = DnsBypassRecorder(
        source=source,
        recordings=_FakeRecordingRepo(),
        detail=detail,
        aggregate=aggregate,
        trust_lookup=lambda ip: records.get(ip),
        now_provider=lambda: 1000.0,
    )
    recorder.start(None, "rec-1")

    asyncio.run(recorder.tick())  # noch NEUTRAL+lokal -> UNCLASSIFIED
    assert aggregate.list_for("rec-1") == []

    # Nutzer lehnt den Server nachtraeglich ab -> beim naechsten Tick eine Umgehung.
    records["192.168.0.53"] = (DnsServerCategory.LOCAL_PRIVATE, DnsTrustState.REJECTED)

    asyncio.run(recorder.tick())  # jetzt REJECTED -> BYPASS
    aggs = aggregate.list_for("rec-1")
    assert len(aggs) == 1
    assert aggs[0].dst_ip == "192.168.0.53"
