"""Domaenen-Tests der Aussenkontakte-Aufzeichnung (``domain/outbound_log.py``).

Deckt die ``__post_init__``-Invarianten, das ``is_recording_active``-Praedikat, die vier
Zustandsuebergaenge (inkl. unzulaessiger) sowie die reine ``merge_contact``-Aggregation
ab. Reine, zeitfreie Logik -- ``now`` wird ueberall explizit hereingereicht.
"""

import pytest

from domain.outbound_log import (
    ALLOWED_INTERVALS,
    DEFAULT_INTERVAL_S,
    MAX_DETAIL_DURATION_S,
    AggregatedContact,
    ContactDelta,
    DetailDepth,
    InvalidRecordingTransition,
    OutboundRecording,
    RecordingMode,
    RecordingState,
    is_recording_active,
    merge_contact,
    pause,
    resume,
    start,
    stop,
)


def _make(
    *,
    mode: RecordingMode = RecordingMode.AGGREGATE,
    state: RecordingState = RecordingState.CREATED,
    interval_s: int = DEFAULT_INTERVAL_S,
    effective_start: float | None = None,
    max_duration_s: int | None = None,
) -> OutboundRecording:
    """Baut eine Aufzeichnung mit sprechenden Defaults fuer die Tests."""
    return OutboundRecording(
        id="rec-1",
        label="Testlauf",
        purpose="Aussenkontakte beobachten",
        mode=mode,
        depth=DetailDepth.ANONYMOUS,
        state=state,
        interval_s=interval_s,
        created_at=1000.0,
        effective_start=effective_start,
        max_duration_s=max_duration_s,
    )


# --- __post_init__-Invarianten -------------------------------------------------


@pytest.mark.parametrize("interval_s", list(ALLOWED_INTERVALS))
def test_post_init_akzeptiert_erlaubte_intervalle(interval_s: int) -> None:
    rec = _make(interval_s=interval_s)
    assert rec.interval_s == interval_s


@pytest.mark.parametrize("interval_s", [0, 1, 29, 31, 59, 120, 600, -60])
def test_post_init_lehnt_ungueltige_intervalle_ab(interval_s: int) -> None:
    with pytest.raises(ValueError):
        _make(interval_s=interval_s)


@pytest.mark.parametrize("max_duration_s", [1, 60, MAX_DETAIL_DURATION_S])
def test_post_init_detail_max_duration_innerhalb_grenzen(max_duration_s: int) -> None:
    rec = _make(mode=RecordingMode.DETAIL, max_duration_s=max_duration_s)
    assert rec.max_duration_s == max_duration_s


@pytest.mark.parametrize("max_duration_s", [0, MAX_DETAIL_DURATION_S + 1, -1])
def test_post_init_detail_max_duration_ausserhalb_grenzen_wirft(max_duration_s: int) -> None:
    with pytest.raises(ValueError):
        _make(mode=RecordingMode.DETAIL, max_duration_s=max_duration_s)


def test_post_init_detail_max_duration_none_erlaubt() -> None:
    rec = _make(mode=RecordingMode.DETAIL, max_duration_s=None)
    assert rec.max_duration_s is None


def test_post_init_aggregate_ignoriert_max_duration_grenzen() -> None:
    # Bei AGGREGATE wird der DETAIL-Deckel NICHT erzwungen -- modusfremde Kombi erlaubt.
    rec = _make(mode=RecordingMode.AGGREGATE, max_duration_s=MAX_DETAIL_DURATION_S + 999)
    assert rec.max_duration_s == MAX_DETAIL_DURATION_S + 999


# --- is_recording_active -------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        (RecordingState.CREATED, False),
        (RecordingState.ACTIVE, True),
        (RecordingState.PAUSED, False),
        (RecordingState.FINISHED, False),
    ],
)
def test_aggregate_aktiv_nur_im_active_state(state: RecordingState, expected: bool) -> None:
    rec = _make(mode=RecordingMode.AGGREGATE, state=state)
    assert is_recording_active(rec, now=5000.0) is expected


def test_detail_aktiv_im_fenster() -> None:
    rec = _make(
        mode=RecordingMode.DETAIL,
        state=RecordingState.ACTIVE,
        effective_start=1000.0,
        max_duration_s=600,
    )
    assert is_recording_active(rec, now=1000.0) is True  # Start inklusiv
    assert is_recording_active(rec, now=1300.0) is True


def test_detail_inaktiv_vor_dem_fenster() -> None:
    rec = _make(
        mode=RecordingMode.DETAIL,
        state=RecordingState.ACTIVE,
        effective_start=1000.0,
        max_duration_s=600,
    )
    assert is_recording_active(rec, now=999.0) is False


def test_detail_inaktiv_am_und_nach_dem_fensterende() -> None:
    rec = _make(
        mode=RecordingMode.DETAIL,
        state=RecordingState.ACTIVE,
        effective_start=1000.0,
        max_duration_s=600,
    )
    assert is_recording_active(rec, now=1600.0) is False  # Ende exklusiv
    assert is_recording_active(rec, now=2000.0) is False


def test_detail_inaktiv_ohne_effective_start() -> None:
    rec = _make(
        mode=RecordingMode.DETAIL,
        state=RecordingState.ACTIVE,
        effective_start=None,
        max_duration_s=600,
    )
    assert is_recording_active(rec, now=1300.0) is False


def test_detail_inaktiv_ohne_max_duration() -> None:
    rec = _make(
        mode=RecordingMode.DETAIL,
        state=RecordingState.ACTIVE,
        effective_start=1000.0,
        max_duration_s=None,
    )
    assert is_recording_active(rec, now=1300.0) is False


def test_detail_inaktiv_wenn_nicht_active_state() -> None:
    rec = _make(
        mode=RecordingMode.DETAIL,
        state=RecordingState.PAUSED,
        effective_start=1000.0,
        max_duration_s=600,
    )
    assert is_recording_active(rec, now=1300.0) is False


# --- Zustandsuebergaenge -------------------------------------------------------


def test_start_setzt_active_und_effective_start() -> None:
    rec = _make(state=RecordingState.CREATED)
    started = start(rec, effective_start=1234.0)
    assert started.state is RecordingState.ACTIVE
    assert started.effective_start == 1234.0
    assert rec.state is RecordingState.CREATED  # Original unveraendert (frozen)


@pytest.mark.parametrize(
    "state",
    [RecordingState.ACTIVE, RecordingState.PAUSED, RecordingState.FINISHED],
)
def test_start_aus_falschem_state_wirft(state: RecordingState) -> None:
    rec = _make(state=state)
    with pytest.raises(InvalidRecordingTransition):
        start(rec, effective_start=1234.0)


def test_pause_aus_active() -> None:
    rec = _make(state=RecordingState.ACTIVE)
    assert pause(rec).state is RecordingState.PAUSED


@pytest.mark.parametrize(
    "state",
    [RecordingState.CREATED, RecordingState.PAUSED, RecordingState.FINISHED],
)
def test_pause_aus_falschem_state_wirft(state: RecordingState) -> None:
    rec = _make(state=state)
    with pytest.raises(InvalidRecordingTransition):
        pause(rec)


def test_resume_aus_paused() -> None:
    rec = _make(state=RecordingState.PAUSED)
    assert resume(rec).state is RecordingState.ACTIVE


@pytest.mark.parametrize(
    "state",
    [RecordingState.CREATED, RecordingState.ACTIVE, RecordingState.FINISHED],
)
def test_resume_aus_falschem_state_wirft(state: RecordingState) -> None:
    rec = _make(state=state)
    with pytest.raises(InvalidRecordingTransition):
        resume(rec)


@pytest.mark.parametrize("state", [RecordingState.ACTIVE, RecordingState.PAUSED])
def test_stop_aus_active_oder_paused(state: RecordingState) -> None:
    rec = _make(state=state, effective_start=1000.0)
    stopped = stop(rec)
    assert stopped.state is RecordingState.FINISHED
    assert stopped.effective_start is None  # Ruecksetzung bei stop


@pytest.mark.parametrize("state", [RecordingState.CREATED, RecordingState.FINISHED])
def test_stop_aus_falschem_state_wirft(state: RecordingState) -> None:
    rec = _make(state=state)
    with pytest.raises(InvalidRecordingTransition):
        stop(rec)


def test_effective_start_invariant_ueber_pause_resume() -> None:
    # Erster Start setzt effective_start; pause/resume lassen ihn UNVERAENDERT.
    rec = start(_make(state=RecordingState.CREATED), effective_start=500.0)
    paused = pause(rec)
    assert paused.effective_start == 500.0
    resumed = resume(paused)
    assert resumed.effective_start == 500.0


def test_start_ueberschreibt_gesetzten_effective_start_nicht() -> None:
    # Defensiv: ein bereits gesetzter effective_start wird vom Guard nicht ueberschrieben.
    rec = _make(state=RecordingState.CREATED, effective_start=42.0)
    started = start(rec, effective_start=999.0)
    assert started.effective_start == 42.0


def test_transition_fehler_traegt_transition_und_state() -> None:
    rec = _make(state=RecordingState.FINISHED)
    with pytest.raises(InvalidRecordingTransition) as excinfo:
        pause(rec)
    assert excinfo.value.transition == "pause"
    assert excinfo.value.state is RecordingState.FINISHED


def test_invalid_recording_transition_ist_keine_value_error() -> None:
    # Eigenstaendiger Domaenen-Fehler -- NICHT von ValueError abgeleitet.
    assert not issubclass(InvalidRecordingTransition, ValueError)


# --- merge_contact -------------------------------------------------------------


def _full_delta(connection_count: int = 3) -> ContactDelta:
    return ContactDelta(
        remote_ip="93.184.216.34",
        remote_port=443,
        hostname="example.com",
        country="US",
        operator="Edgecast",
        asn="AS15133",
        app_name="firefox",
        connection_count=connection_count,
    )


def test_merge_neuanlage_aus_none() -> None:
    delta = _full_delta(connection_count=3)
    contact = merge_contact(None, delta, now=2000.0)
    assert contact.remote_ip == "93.184.216.34"
    assert contact.first_seen == 2000.0
    assert contact.last_seen == 2000.0
    assert contact.total_count == 3
    assert contact.peak_count == 3
    assert contact.remote_port == 443
    assert contact.hostname == "example.com"
    assert contact.country == "US"
    assert contact.operator == "Edgecast"
    assert contact.asn == "AS15133"
    assert contact.app_name == "firefox"


def test_merge_summiert_total_und_bewahrt_first_seen() -> None:
    existing = merge_contact(None, _full_delta(connection_count=3), now=2000.0)
    merged = merge_contact(existing, _full_delta(connection_count=5), now=3000.0)
    assert merged.first_seen == 2000.0  # bleibt
    assert merged.last_seen == 3000.0
    assert merged.total_count == 8  # 3 + 5


def test_merge_peak_count_ist_maximum_des_einzelzyklus() -> None:
    existing = merge_contact(None, _full_delta(connection_count=7), now=2000.0)
    # kleinerer Folge-Zyklus -> peak bleibt 7
    merged = merge_contact(existing, _full_delta(connection_count=2), now=3000.0)
    assert merged.peak_count == 7
    assert merged.total_count == 9
    # groesserer Zyklus -> peak waechst
    merged2 = merge_contact(merged, _full_delta(connection_count=20), now=4000.0)
    assert merged2.peak_count == 20


def test_merge_bewahrt_alte_anreicherung_bei_none_delta() -> None:
    existing = merge_contact(None, _full_delta(connection_count=1), now=2000.0)
    leer = ContactDelta(
        remote_ip="93.184.216.34",
        remote_port=None,
        hostname=None,
        country=None,
        operator=None,
        asn=None,
        app_name=None,
        connection_count=4,
    )
    merged = merge_contact(existing, leer, now=3000.0)
    # Anreicherung wird NICHT geloescht
    assert merged.remote_port == 443
    assert merged.hostname == "example.com"
    assert merged.country == "US"
    assert merged.operator == "Edgecast"
    assert merged.asn == "AS15133"
    assert merged.app_name == "firefox"
    # Zaehler aktualisieren trotzdem
    assert merged.total_count == 5
    assert merged.last_seen == 3000.0


def test_merge_uebernimmt_neue_anreicherung_wenn_delta_gesetzt() -> None:
    # Erst leer angelegt, dann mit Werten angereichert.
    leer = ContactDelta(
        remote_ip="93.184.216.34",
        remote_port=None,
        hostname=None,
        country=None,
        operator=None,
        asn=None,
        app_name=None,
        connection_count=1,
    )
    existing = merge_contact(None, leer, now=2000.0)
    assert existing.hostname is None
    merged = merge_contact(existing, _full_delta(connection_count=2), now=3000.0)
    assert merged.hostname == "example.com"
    assert merged.country == "US"
    assert merged.remote_port == 443


def test_merge_haelt_remote_ip_des_bestands() -> None:
    existing = AggregatedContact(
        remote_ip="10.0.0.1",
        first_seen=1.0,
        last_seen=1.0,
        total_count=1,
        peak_count=1,
        remote_port=None,
        hostname=None,
        country=None,
        operator=None,
        asn=None,
        app_name=None,
    )
    delta = ContactDelta(
        remote_ip="10.0.0.1",
        remote_port=80,
        hostname=None,
        country=None,
        operator=None,
        asn=None,
        app_name=None,
        connection_count=2,
    )
    merged = merge_contact(existing, delta, now=5.0)
    assert merged.remote_ip == "10.0.0.1"
