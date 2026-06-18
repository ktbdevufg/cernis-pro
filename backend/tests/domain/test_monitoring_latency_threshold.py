"""Unit-Tests der Schwellwert-Alarm-Domaene (Schnitt 1, domain, zeitfrei).

Deckt die reine ``evaluate_sample``-Logik ab: die Hysterese (Alarm erst nach N
aufeinanderfolgenden Verletzungen), die Flanken-Semantik (einmal feuern pro Episode,
kein Dauerfeuer), das Zuruecksetzen bei Entspannung (danach feuert eine neue Serie
WIEDER), beide Bedingungen (``LATENCY_ABOVE``/``UNREACHABLE``), den
RTT-Sentinel-Sonderfall und die scharfe (strikte) Grenzwert-Pruefung. Keine Uhr,
keine Persistenz -- ``state``/``rtt_ms``/``alive`` kommen als Parameter rein.
"""

from domain.monitoring import (
    INITIAL_STATE,
    LatencyThreshold,
    ThresholdCondition,
    ThresholdState,
    evaluate_sample,
)


def _latency(
    *,
    limit_ms: float = 100.0,
    consecutive_n: int = 3,
) -> LatencyThreshold:
    """Baut eine LATENCY_ABOVE-Regel mit sprechenden Defaults fuer die Faelle."""
    return LatencyThreshold(
        condition=ThresholdCondition.LATENCY_ABOVE,
        limit_ms=limit_ms,
        consecutive_n=consecutive_n,
    )


def _unreachable(*, consecutive_n: int = 3) -> LatencyThreshold:
    """Baut eine UNREACHABLE-Regel (limit_ms ist hier fachlich irrelevant)."""
    return LatencyThreshold(
        condition=ThresholdCondition.UNREACHABLE,
        limit_ms=0.0,
        consecutive_n=consecutive_n,
    )


# --- Defaults / Datentraeger --------------------------------------------------


def test_threshold_defaults() -> None:
    # consecutive_n=3, notify_desktop=True, notify_email=False (Auftrags-Defaults).
    threshold = LatencyThreshold(condition=ThresholdCondition.LATENCY_ABOVE, limit_ms=50.0)
    assert threshold.consecutive_n == 3
    assert threshold.notify_desktop is True
    assert threshold.notify_email is False


def test_initial_state_constant() -> None:
    # Startzustand vor der ersten Messung: keine Serie, kein Alarm.
    assert ThresholdState(streak=0, in_alarm=False) == INITIAL_STATE


# --- LATENCY_ABOVE: Hysterese + Flanke ----------------------------------------


def test_latency_below_limit_never_fires() -> None:
    # Unter dem Grenzwert -> keine Verletzung, streak bleibt 0, kein fired.
    threshold = _latency(limit_ms=100.0, consecutive_n=3)
    state, fired = evaluate_sample(threshold, INITIAL_STATE, rtt_ms=50.0, alive=True)
    assert fired is False
    assert state == ThresholdState(streak=0, in_alarm=False)


def test_latency_fires_only_on_nth_violation() -> None:
    # N-1 Ueberschreitungen feuern nicht, die N-te feuert (die Alarm-Flanke).
    threshold = _latency(limit_ms=100.0, consecutive_n=3)
    state = INITIAL_STATE

    state, fired = evaluate_sample(threshold, state, rtt_ms=150.0, alive=True)
    assert (state.streak, state.in_alarm, fired) == (1, False, False)

    state, fired = evaluate_sample(threshold, state, rtt_ms=150.0, alive=True)
    assert (state.streak, state.in_alarm, fired) == (2, False, False)

    state, fired = evaluate_sample(threshold, state, rtt_ms=150.0, alive=True)
    assert (state.streak, state.in_alarm, fired) == (3, True, True)


def test_latency_holds_alarm_without_refiring() -> None:
    # (N+1)-te Ueberschreitung feuert NICHT erneut -- in_alarm haelt (kein Dauerfeuer).
    threshold = _latency(limit_ms=100.0, consecutive_n=3)
    state = INITIAL_STATE
    for _ in range(3):
        state, fired = evaluate_sample(threshold, state, rtt_ms=150.0, alive=True)
    assert fired is True  # die N-te hat gefeuert

    state, fired = evaluate_sample(threshold, state, rtt_ms=150.0, alive=True)
    assert fired is False
    assert (state.streak, state.in_alarm) == (4, True)


def test_latency_relaxation_resets_and_refires() -> None:
    # Entspannung (ein Wert unter dem Grenzwert) setzt zurueck; danach feuert eine
    # erneute N-Serie WIEDER (Flanke, kein Einmal-und-nie-wieder).
    threshold = _latency(limit_ms=100.0, consecutive_n=3)
    state = INITIAL_STATE
    for _ in range(3):
        state, _ = evaluate_sample(threshold, state, rtt_ms=150.0, alive=True)
    assert state.in_alarm is True

    # Entspannung: einmal unter dem Grenzwert -> komplettes Reset, kein fired.
    state, fired = evaluate_sample(threshold, state, rtt_ms=50.0, alive=True)
    assert fired is False
    assert state == ThresholdState(streak=0, in_alarm=False)

    # Erneute N Ueberschreitungen -> feuert wieder bei der N-ten.
    state, fired = evaluate_sample(threshold, state, rtt_ms=150.0, alive=True)
    assert fired is False
    state, fired = evaluate_sample(threshold, state, rtt_ms=150.0, alive=True)
    assert fired is False
    state, fired = evaluate_sample(threshold, state, rtt_ms=150.0, alive=True)
    assert fired is True
    assert state.in_alarm is True


def test_consecutive_n_one_fires_immediately() -> None:
    # N=1 -> die erste Verletzung feuert sofort.
    threshold = _latency(limit_ms=100.0, consecutive_n=1)
    state, fired = evaluate_sample(threshold, INITIAL_STATE, rtt_ms=150.0, alive=True)
    assert fired is True
    assert state == ThresholdState(streak=1, in_alarm=True)


# --- LATENCY_ABOVE: scharfe Grenzwert-Pruefung (Mutations-Probe) ---------------


def test_latency_exactly_at_limit_does_not_violate() -> None:
    # > ist strikt: ein Wert GENAU am Limit verletzt NICHT (kein fired, kein streak).
    threshold = _latency(limit_ms=100.0, consecutive_n=1)
    state, fired = evaluate_sample(threshold, INITIAL_STATE, rtt_ms=100.0, alive=True)
    assert fired is False
    assert state == ThresholdState(streak=0, in_alarm=False)


def test_latency_just_above_limit_violates() -> None:
    # Knapp ueber dem Limit verletzt -> bei N=1 sofort fired.
    threshold = _latency(limit_ms=100.0, consecutive_n=1)
    state, fired = evaluate_sample(threshold, INITIAL_STATE, rtt_ms=100.0001, alive=True)
    assert fired is True
    assert state.streak == 1


# --- UNREACHABLE --------------------------------------------------------------


def test_unreachable_counts_when_not_alive() -> None:
    # alive=False zaehlt als Verletzung; bei N=3 feuert die dritte.
    threshold = _unreachable(consecutive_n=3)
    state = INITIAL_STATE
    state, fired = evaluate_sample(threshold, state, rtt_ms=-1.0, alive=False)
    assert (state.streak, fired) == (1, False)
    state, fired = evaluate_sample(threshold, state, rtt_ms=-1.0, alive=False)
    assert (state.streak, fired) == (2, False)
    state, fired = evaluate_sample(threshold, state, rtt_ms=-1.0, alive=False)
    assert (state.streak, state.in_alarm, fired) == (3, True, True)


def test_unreachable_resets_when_alive_again() -> None:
    # alive=True (erreichbar) ist KEINE Verletzung -> Reset der Serie.
    threshold = _unreachable(consecutive_n=3)
    state, _ = evaluate_sample(threshold, INITIAL_STATE, rtt_ms=-1.0, alive=False)
    state, _ = evaluate_sample(threshold, state, rtt_ms=-1.0, alive=False)
    assert state.streak == 2

    state, fired = evaluate_sample(threshold, state, rtt_ms=20.0, alive=True)
    assert fired is False
    assert state == ThresholdState(streak=0, in_alarm=False)


def test_unreachable_ignores_limit_ms() -> None:
    # limit_ms ist bei UNREACHABLE fachlich irrelevant: alive=False verletzt immer.
    threshold = LatencyThreshold(
        condition=ThresholdCondition.UNREACHABLE,
        limit_ms=99999.0,
        consecutive_n=1,
    )
    _, fired = evaluate_sample(threshold, INITIAL_STATE, rtt_ms=5.0, alive=False)
    assert fired is True


# --- Sentinel-Fall ------------------------------------------------------------


def test_sentinel_not_a_latency_violation() -> None:
    # alive=False mit RTT-Sentinel -1.0 unter LATENCY_ABOVE ist KEINE Latenz-
    # Verletzung (das ist Erreichbarkeit, nicht Latenz) -> kein fired ueber die
    # Latenz-Schiene, kein streak.
    threshold = _latency(limit_ms=100.0, consecutive_n=1)
    state, fired = evaluate_sample(threshold, INITIAL_STATE, rtt_ms=-1.0, alive=False)
    assert fired is False
    assert state == ThresholdState(streak=0, in_alarm=False)


def test_latency_above_not_violated_when_not_alive_even_high_rtt() -> None:
    # Selbst ein hoher rtt_ms zaehlt unter LATENCY_ABOVE nicht, wenn alive=False
    # (der alive-Vorbehalt ist die Schutzschicht, nicht nur der Sentinel-Wert).
    threshold = _latency(limit_ms=100.0, consecutive_n=1)
    _, fired = evaluate_sample(threshold, INITIAL_STATE, rtt_ms=500.0, alive=False)
    assert fired is False


# --- Reinheit / kein In-Place -------------------------------------------------


def test_evaluate_sample_does_not_mutate_input_state() -> None:
    # frozen + dataclasses.replace: der uebergebene Zustand bleibt unveraendert.
    threshold = _latency(limit_ms=100.0, consecutive_n=1)
    original = ThresholdState(streak=0, in_alarm=False)
    new_state, _ = evaluate_sample(threshold, original, rtt_ms=150.0, alive=True)
    assert original == ThresholdState(streak=0, in_alarm=False)
    assert new_state is not original
