"""Tests von ``BuildDnsBypass`` gegen In-Memory-Fakes/Spies der Quellen.

Keine echte Sniffer-Quelle/Persistenz noetig -- wir testen die reine Aggregations-/
Klassifikations-Logik gegen die quellen-agnostischen Callables. Kern der Behauptungen:

(1) Nur Umgehungen (Ziel nicht in erwarteter Menge) werden aufgenommen; erwartete Ziele
    zaehlen bei ``expected_total``, ergeben aber kein finding.
(2) Umgehungen werden je (``src_ip``, ``dst_ip``) gruppiert; ``query_count`` stimmt,
    ``sample_qnames`` sind distinct, nicht-leer, auf 5 gedeckelt, in Erst-Vorkommen-
    Reihenfolge.
(3) Der IP-Vergleich gegen die erwartete Menge ist defensiv normalisiert (strip + lower).
(4) Leere erwartete Menge -> jede Anfrage ist Umgehung.
(5) Die Reihenfolge ist deterministisch (query_count absteigend, dann src_ip aufsteigend,
    dann dst_ip aufsteigend).
(6) ``expected_servers`` wird als roher Beleg durchgereicht.

Sync -- der Use-Case macht kein I/O (anders als ``BuildDnsWatch``, das PTR async holt).
"""

from collections.abc import Sequence

from application.dns_bypass import (
    BuildDnsBypass,
    DnsBypassOverview,
    RawDnsQuery,
)

# ── In-Memory-Fake der Query-Quelle ───────────────────────────────────────────


class FakeQueries:
    """``DnsQueryProvider``-Fake: gibt einen festen Snapshot zurueck."""

    def __init__(self, queries: Sequence[RawDnsQuery]) -> None:
        self._queries = list(queries)
        self.calls = 0

    def __call__(self) -> Sequence[RawDnsQuery]:
        self.calls += 1
        return self._queries


def _query(src_ip: str, dst_ip: str, qname: str = "", l4: str = "udp") -> RawDnsQuery:
    """Baut eine schmale Anfrage -- nur src/dst/qname sind fuer die Logik relevant."""
    return RawDnsQuery(src_ip=src_ip, dst_ip=dst_ip, l4=l4, qname=qname)


def _build(
    queries: Sequence[RawDnsQuery],
    *,
    expected: Sequence[str] = (),
) -> BuildDnsBypass:
    """Verdrahtet ``BuildDnsBypass`` mit Fakes; die erwartete Menge als simples Lambda."""
    return BuildDnsBypass(
        queries=FakeQueries(queries),
        expected_servers=lambda: list(expected),
    )


def _run(use_case: BuildDnsBypass) -> DnsBypassOverview:
    """Fuehrt den Use-Case aus."""
    return use_case()


# ── (T1) Leere Queries ────────────────────────────────────────────────────────


def test_leere_queries_alle_zaehler_null_und_beleg_durchgereicht() -> None:
    """Keine Anfragen -> alle Zaehler 0, findings leer, expected_servers durchgereicht."""
    overview = _run(_build([], expected=["192.168.0.1"]))

    assert overview.findings == ()
    assert overview.queries_total == 0
    assert overview.bypass_total == 0
    assert overview.expected_total == 0
    assert overview.bypass_devices == 0
    assert overview.expected_servers == ("192.168.0.1",)


# ── (T2) Erwartetes Ziel -> kein finding ──────────────────────────────────────


def test_erwartetes_ziel_ergibt_kein_finding() -> None:
    """dst_ip in der erwarteten Menge -> KEIN finding; expected_total zaehlt, bypass 0."""
    queries = [_query("10.0.0.5", "192.168.0.1", qname="example.com")]
    overview = _run(_build(queries, expected=["192.168.0.1"]))

    assert overview.findings == ()
    assert overview.queries_total == 1
    assert overview.expected_total == 1
    assert overview.bypass_total == 0
    assert overview.bypass_devices == 0


# ── (T3) Nicht-erwartetes Ziel -> ein finding ─────────────────────────────────


def test_nicht_erwartetes_ziel_ergibt_finding() -> None:
    """dst_ip NICHT erwartet -> ein finding; bypass_total/bypass_devices korrekt."""
    queries = [_query("10.0.0.5", "8.8.8.8", qname="tracker.example")]
    overview = _run(_build(queries, expected=["192.168.0.1"]))

    assert len(overview.findings) == 1
    finding = overview.findings[0]
    assert finding.src_ip == "10.0.0.5"
    assert finding.dst_ip == "8.8.8.8"
    assert finding.query_count == 1
    assert finding.sample_qnames == ("tracker.example",)
    assert overview.queries_total == 1
    assert overview.bypass_total == 1
    assert overview.expected_total == 0
    assert overview.bypass_devices == 1


# ── (T4) Normalisierung der erwarteten Menge ──────────────────────────────────


def test_normalisierung_verhindert_umgehungs_fehlalarm() -> None:
    """expected mit Grossbuchstaben/Whitespace trifft trotzdem -> keine Umgehung."""
    queries = [_query("10.0.0.5", "2001:db8::1", qname="example.com")]
    overview = _run(_build(queries, expected=["  2001:DB8::1 "]))

    assert overview.findings == ()
    assert overview.bypass_total == 0
    assert overview.expected_total == 1


# ── (T5) Aggregation: query_count + gedeckelte, distinct sample_qnames ─────────


def test_aggregation_zaehlt_und_deckelt_distinct_qnames_in_erst_reihenfolge() -> None:
    """Mehrere Queries derselben (src,dst): count summiert; sample_qnames distinct, <=5."""
    queries = [
        _query("10.0.0.5", "8.8.8.8", qname="a.example"),
        _query("10.0.0.5", "8.8.8.8", qname="b.example"),
        _query("10.0.0.5", "8.8.8.8", qname="a.example"),  # Duplikat -> nicht erneut
        _query("10.0.0.5", "8.8.8.8", qname=""),  # leer -> nie aufgenommen
        _query("10.0.0.5", "8.8.8.8", qname="c.example"),
        _query("10.0.0.5", "8.8.8.8", qname="d.example"),
        _query("10.0.0.5", "8.8.8.8", qname="e.example"),
        _query("10.0.0.5", "8.8.8.8", qname="f.example"),  # 6. distinct -> gedeckelt
    ]
    overview = _run(_build(queries, expected=["192.168.0.1"]))

    assert len(overview.findings) == 1
    finding = overview.findings[0]
    assert finding.query_count == 8
    # bis 5 distinct, nicht-leer, in Erst-Vorkommen-Reihenfolge; f.example faellt raus.
    assert finding.sample_qnames == (
        "a.example",
        "b.example",
        "c.example",
        "d.example",
        "e.example",
    )
    assert overview.bypass_total == 8
    assert overview.bypass_devices == 1


# ── (T6) Leere erwartete Menge -> alles Umgehung ──────────────────────────────


def test_leere_erwartete_menge_macht_jede_query_zur_umgehung() -> None:
    """Leere expected -> jede Anfrage ist Umgehung."""
    queries = [
        _query("10.0.0.5", "192.168.0.1"),
        _query("10.0.0.6", "1.1.1.1"),
    ]
    overview = _run(_build(queries, expected=[]))

    assert overview.bypass_total == 2
    assert overview.expected_total == 0
    assert overview.bypass_devices == 2
    assert len(overview.findings) == 2


# ── (T7) Deterministische Reihenfolge ─────────────────────────────────────────


def test_reihenfolge_count_absteigend_dann_src_dann_dst() -> None:
    """query_count absteigend, dann src_ip aufsteigend, dann dst_ip aufsteigend."""
    queries = [
        # (10.0.0.9, 8.8.8.8): count 1
        _query("10.0.0.9", "8.8.8.8"),
        # (10.0.0.5, 9.9.9.9): count 2 (lauter -> zuerst)
        _query("10.0.0.5", "9.9.9.9"),
        _query("10.0.0.5", "9.9.9.9"),
        # (10.0.0.5, 1.1.1.1): count 1, selber src wie oben, kleineres dst
        _query("10.0.0.5", "1.1.1.1"),
    ]
    overview = _run(_build(queries, expected=["192.168.0.1"]))

    order = [(f.src_ip, f.dst_ip, f.query_count) for f in overview.findings]
    assert order == [
        ("10.0.0.5", "9.9.9.9", 2),  # hoechster count zuerst
        ("10.0.0.5", "1.1.1.1", 1),  # count 1: src gleich, dst 1.1.1.1 < 8.8.8.8
        ("10.0.0.9", "8.8.8.8", 1),  # count 1: groesseres src zuletzt
    ]


# ── Steuerungs-Use-Cases (Start/StopDnsBypassRecording) ───────────────────────


class _SpyRecorder:
    """``DnsBypassRecorder``-Spy: zeichnet ``clear``/``start``/``stop`` in Reihenfolge auf.

    ``start`` gibt das konfigurierte Ergebnis zurueck (``None`` = ok, sonst Fehlertext),
    damit ``StartDnsBypassRecording`` das Durchreichen belegt werden kann.
    """

    def __init__(self, start_result: str | None = None) -> None:
        self._start_result = start_result
        self.calls: list[str] = []
        self.started_interface: str | None = None

    def clear(self) -> None:
        self.calls.append("clear")

    def start(self, interface: str | None) -> str | None:
        self.calls.append("start")
        self.started_interface = interface
        return self._start_result

    def stop(self) -> None:
        self.calls.append("stop")


def test_start_use_case_clear_vor_start_und_reicht_ergebnis_durch() -> None:
    """StartDnsBypassRecording ruft clear VOR start und reicht das start-Ergebnis durch."""
    from application.dns_bypass import StartDnsBypassRecording

    recorder = _SpyRecorder(start_result=None)
    use_case = StartDnsBypassRecording(recorder)  # type: ignore[arg-type]

    result = use_case("eth0")

    assert result is None
    assert recorder.calls == ["clear", "start"]
    assert recorder.started_interface == "eth0"


def test_start_use_case_reicht_fehlertext_durch() -> None:
    """StartDnsBypassRecording reicht einen Fehlertext der Quelle ehrlich durch."""
    from application.dns_bypass import StartDnsBypassRecording

    recorder = _SpyRecorder(start_result="DNS-Helfer nicht erreichbar")
    use_case = StartDnsBypassRecording(recorder)  # type: ignore[arg-type]

    result = use_case(None)

    assert result == "DNS-Helfer nicht erreichbar"
    assert recorder.calls == ["clear", "start"]


def test_stop_use_case_ruft_recorder_stop() -> None:
    """StopDnsBypassRecording ruft recorder.stop."""
    from application.dns_bypass import StopDnsBypassRecording

    recorder = _SpyRecorder()
    use_case = StopDnsBypassRecording(recorder)  # type: ignore[arg-type]

    use_case()

    assert recorder.calls == ["stop"]
