"""Domaenen-Tests der DNS-Umgehungs-Aufzeichnung (``domain/dns_bypass/recording.py``).

Deckt die zwei Zustandsuebergaenge (``start``/``stop``, inkl. unzulaessiger), das
``edit`` (label/purpose in jedem Zustand), den eingefrorenen ``expected_servers``-Beleg
sowie die reine ``merge_bypass``-Aggregation (inkl. ``sample_qnames``-Deckel und
Distinct-Regel) ab. Reine, zeitfreie Logik -- ``now``/``effective_start`` werden ueberall
explizit hereingereicht.
"""

import pytest

from domain.dns_bypass.recording import (
    MAX_SAMPLE_QNAMES,
    AggregatedBypass,
    BypassDelta,
    DnsBypassRecording,
    DnsBypassRecordingState,
    InvalidDnsBypassRecordingTransition,
    edit,
    merge_bypass,
    start,
    stop,
)


def _make(
    *,
    state: DnsBypassRecordingState = DnsBypassRecordingState.CREATED,
    effective_start: float | None = None,
    interface: str | None = "eth0",
    expected_servers: tuple[str, ...] = (),
) -> DnsBypassRecording:
    """Baut eine Aufzeichnung mit sprechenden Defaults fuer die Tests."""
    return DnsBypassRecording(
        id="rec-1",
        label="Testlauf",
        purpose="DNS-Umgehungen beobachten",
        state=state,
        created_at=1000.0,
        effective_start=effective_start,
        interface=interface,
        expected_servers=expected_servers,
    )


# --- Zustandsuebergaenge -------------------------------------------------------


def test_start_setzt_active_effective_start_und_beleg() -> None:
    rec = _make(state=DnsBypassRecordingState.CREATED)
    started = start(rec, effective_start=1234.0, expected_servers=("192.168.1.1",))
    assert started.state is DnsBypassRecordingState.ACTIVE
    assert started.effective_start == 1234.0
    assert started.expected_servers == ("192.168.1.1",)
    # Original unveraendert (frozen).
    assert rec.state is DnsBypassRecordingState.CREATED
    assert rec.expected_servers == ()


@pytest.mark.parametrize(
    "state",
    [DnsBypassRecordingState.ACTIVE, DnsBypassRecordingState.FINISHED],
)
def test_start_aus_falschem_state_wirft(state: DnsBypassRecordingState) -> None:
    rec = _make(state=state)
    with pytest.raises(InvalidDnsBypassRecordingTransition):
        start(rec, effective_start=1234.0, expected_servers=())


def test_start_ueberschreibt_gesetzten_effective_start_nicht() -> None:
    # Defensiv: ein bereits gesetzter effective_start wird vom Guard nicht ueberschrieben.
    rec = _make(state=DnsBypassRecordingState.CREATED, effective_start=42.0)
    started = start(rec, effective_start=999.0, expected_servers=())
    assert started.effective_start == 42.0


def test_stop_aus_active_leert_effective_start_und_haelt_beleg() -> None:
    rec = _make(
        state=DnsBypassRecordingState.ACTIVE,
        effective_start=1000.0,
        expected_servers=("9.9.9.9",),
    )
    stopped = stop(rec)
    assert stopped.state is DnsBypassRecordingState.FINISHED
    assert stopped.effective_start is None  # Ruecksetzung bei stop
    assert stopped.expected_servers == ("9.9.9.9",)  # Beleg bleibt


@pytest.mark.parametrize(
    "state",
    [DnsBypassRecordingState.CREATED, DnsBypassRecordingState.FINISHED],
)
def test_stop_aus_falschem_state_wirft(state: DnsBypassRecordingState) -> None:
    rec = _make(state=state)
    with pytest.raises(InvalidDnsBypassRecordingTransition):
        stop(rec)


def test_transition_fehler_traegt_transition_und_state() -> None:
    rec = _make(state=DnsBypassRecordingState.FINISHED)
    with pytest.raises(InvalidDnsBypassRecordingTransition) as excinfo:
        stop(rec)
    assert excinfo.value.transition == "stop"
    assert excinfo.value.state is DnsBypassRecordingState.FINISHED


def test_invalid_transition_ist_keine_value_error() -> None:
    # Eigenstaendiger Domaenen-Fehler -- NICHT von ValueError abgeleitet.
    assert not issubclass(InvalidDnsBypassRecordingTransition, ValueError)


def test_kein_paused_im_lebenszyklus() -> None:
    # Bewusste Reduktion: der Lebenszyklus ist schlank (CREATED/ACTIVE/FINISHED).
    assert {s.value for s in DnsBypassRecordingState} == {"created", "active", "finished"}


# --- edit ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "state",
    [
        DnsBypassRecordingState.CREATED,
        DnsBypassRecordingState.ACTIVE,
        DnsBypassRecordingState.FINISHED,
    ],
)
def test_edit_label_purpose_in_jedem_state_erlaubt(state: DnsBypassRecordingState) -> None:
    rec = _make(state=state, effective_start=500.0, expected_servers=("1.1.1.1",))
    edited = edit(rec, label="Geaendert", purpose="Neuer Zweck")
    assert edited.label == "Geaendert"
    assert edited.purpose == "Neuer Zweck"
    # Zustand, Zeitfelder, interface und Beleg bleiben unberuehrt.
    assert edited.state is state
    assert edited.created_at == rec.created_at
    assert edited.effective_start == rec.effective_start
    assert edited.interface == rec.interface
    assert edited.expected_servers == rec.expected_servers
    # Original bleibt unveraendert (frozen).
    assert rec.label == "Testlauf"


# --- merge_bypass --------------------------------------------------------------


def test_merge_neuanlage_aus_none() -> None:
    delta = BypassDelta(src_ip="10.0.0.5", dst_ip="8.8.8.8", qname="example.com", count=3)
    agg = merge_bypass(None, delta, now=2000.0)
    assert agg.src_ip == "10.0.0.5"
    assert agg.dst_ip == "8.8.8.8"
    assert agg.first_seen == 2000.0
    assert agg.last_seen == 2000.0
    assert agg.query_count == 3
    assert agg.sample_qnames == ("example.com",)


def test_merge_neuanlage_leerer_qname_ergibt_leere_stichprobe() -> None:
    delta = BypassDelta(src_ip="10.0.0.5", dst_ip="8.8.8.8", qname="", count=1)
    agg = merge_bypass(None, delta, now=2000.0)
    assert agg.sample_qnames == ()
    assert agg.query_count == 1


def test_merge_summiert_query_count_und_bewahrt_first_seen() -> None:
    existing = merge_bypass(
        None,
        BypassDelta(src_ip="10.0.0.5", dst_ip="8.8.8.8", qname="a.com", count=3),
        now=2000.0,
    )
    merged = merge_bypass(
        existing,
        BypassDelta(src_ip="10.0.0.5", dst_ip="8.8.8.8", qname="b.com", count=5),
        now=3000.0,
    )
    assert merged.first_seen == 2000.0  # bleibt
    assert merged.last_seen == 3000.0
    assert merged.query_count == 8  # 3 + 5
    assert merged.sample_qnames == ("a.com", "b.com")


def test_merge_sample_qnames_distinct_in_erst_vorkommen_reihenfolge() -> None:
    agg = merge_bypass(
        None,
        BypassDelta(src_ip="s", dst_ip="d", qname="a.com", count=1),
        now=1.0,
    )
    # gleicher qname erneut -> nicht doppelt
    agg = merge_bypass(agg, BypassDelta(src_ip="s", dst_ip="d", qname="a.com", count=1), now=2.0)
    # neuer qname -> angehaengt
    agg = merge_bypass(agg, BypassDelta(src_ip="s", dst_ip="d", qname="b.com", count=1), now=3.0)
    assert agg.sample_qnames == ("a.com", "b.com")
    assert agg.query_count == 3


def test_merge_leerer_qname_erweitert_stichprobe_nicht() -> None:
    agg = merge_bypass(
        None,
        BypassDelta(src_ip="s", dst_ip="d", qname="a.com", count=1),
        now=1.0,
    )
    agg = merge_bypass(agg, BypassDelta(src_ip="s", dst_ip="d", qname="", count=1), now=2.0)
    assert agg.sample_qnames == ("a.com",)
    assert agg.query_count == 2  # Zaehler laeuft trotzdem


def test_merge_sample_qnames_deckel_bei_max() -> None:
    agg: AggregatedBypass | None = None
    # Sechs distinct qnames einspielen -- der Deckel liegt bei MAX_SAMPLE_QNAMES.
    for i in range(MAX_SAMPLE_QNAMES + 1):
        agg = merge_bypass(
            agg,
            BypassDelta(src_ip="s", dst_ip="d", qname=f"q{i}.com", count=1),
            now=float(i),
        )
    assert agg is not None
    assert len(agg.sample_qnames) == MAX_SAMPLE_QNAMES
    # Erst-Vorkommen bleiben, das ueberzaehlige wird verworfen.
    assert agg.sample_qnames == tuple(f"q{i}.com" for i in range(MAX_SAMPLE_QNAMES))
    assert agg.query_count == MAX_SAMPLE_QNAMES + 1  # jeder Zyklus zaehlt


def test_merge_haelt_src_und_dst_des_bestands() -> None:
    existing = AggregatedBypass(
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        first_seen=1.0,
        last_seen=1.0,
        query_count=1,
        sample_qnames=(),
    )
    delta = BypassDelta(src_ip="10.0.0.1", dst_ip="8.8.8.8", qname="x.com", count=2)
    merged = merge_bypass(existing, delta, now=5.0)
    assert merged.src_ip == "10.0.0.1"
    assert merged.dst_ip == "8.8.8.8"
    assert merged.query_count == 3
    assert merged.last_seen == 5.0
    assert merged.sample_qnames == ("x.com",)
