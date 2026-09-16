"""Tests fuer die reine Faelligkeits-/is_new-Logik der cve-Domaene (ADR 0037).

Belegt die drei Faelligkeits-Faelle (NEU / PORTS_GEAENDERT / UEBERFAELLIG) + NOT_DUE,
die Reihenfolge der Pruefung, das Abschalten von Fall 3 (Intervall 0), und die
is_new-Fenster-Semantik. Zeitfrei -- ``now``/Intervalle als rohe floats.
"""

from domain.cve.models import HostCheckState
from domain.cve.policy import (
    DEFAULT_NEW_WINDOW_SECONDS,
    DueReason,
    due_reason,
    is_new,
)

HOUR = 3600.0


def _state(last_checked: float, ports: set[int]) -> HostCheckState:
    return HostCheckState(mac="aa", last_checked_ts=last_checked, checked_ports=frozenset(ports))


# ── Fall 1: NEU ──────────────────────────────────────────────────────────────


def test_kein_state_ist_neu() -> None:
    assert due_reason(None, frozenset({22}), now=1000.0, refresh_interval_seconds=24 * HOUR) == (
        DueReason.NEW
    )


# ── Fall 2: PORTS_GEAENDERT ──────────────────────────────────────────────────


def test_anderes_port_set_ist_ports_changed() -> None:
    state = _state(last_checked=1000.0, ports={22, 80})
    assert (
        due_reason(state, frozenset({22, 443}), now=1001.0, refresh_interval_seconds=24 * HOUR)
        == DueReason.PORTS_CHANGED
    )


def test_neu_geoeffneter_port_ist_ports_changed() -> None:
    state = _state(last_checked=1000.0, ports={22})
    assert (
        due_reason(state, frozenset({22, 80}), now=1001.0, refresh_interval_seconds=24 * HOUR)
        == DueReason.PORTS_CHANGED
    )


# ── Fall 3: UEBERFAELLIG ─────────────────────────────────────────────────────


def test_aelter_als_intervall_ist_overdue() -> None:
    state = _state(last_checked=0.0, ports={22})
    # 25h spaeter, Intervall 24h -> ueberfaellig.
    assert (
        due_reason(state, frozenset({22}), now=25 * HOUR, refresh_interval_seconds=24 * HOUR)
        == DueReason.OVERDUE
    )


def test_genau_am_intervall_ist_overdue() -> None:
    state = _state(last_checked=0.0, ports={22})
    assert (
        due_reason(state, frozenset({22}), now=24 * HOUR, refresh_interval_seconds=24 * HOUR)
        == DueReason.OVERDUE
    )


def test_intervall_null_schaltet_overdue_ab() -> None:
    state = _state(last_checked=0.0, ports={22})
    # Selbst 1000h spaeter: Intervall 0 -> Auffrischung AUS -> NOT_DUE (Ports gleich).
    assert (
        due_reason(state, frozenset({22}), now=1000 * HOUR, refresh_interval_seconds=0.0)
        == DueReason.NOT_DUE
    )


# ── NOT_DUE ──────────────────────────────────────────────────────────────────


def test_frisch_geprueft_gleiche_ports_ist_not_due() -> None:
    state = _state(last_checked=1000.0, ports={22, 80})
    assert (
        due_reason(state, frozenset({22, 80}), now=1100.0, refresh_interval_seconds=24 * HOUR)
        == DueReason.NOT_DUE
    )


# ── Reihenfolge: NEU vor allem; PORTS vor OVERDUE ────────────────────────────


def test_ports_changed_schlaegt_overdue() -> None:
    # Sowohl ueberfaellig ALS auch Ports geaendert -> PORTS_CHANGED gewinnt (frueher geprueft).
    state = _state(last_checked=0.0, ports={22})
    assert (
        due_reason(state, frozenset({443}), now=100 * HOUR, refresh_interval_seconds=24 * HOUR)
        == DueReason.PORTS_CHANGED
    )


# ── is_new ───────────────────────────────────────────────────────────────────


def test_is_new_innerhalb_fenster() -> None:
    assert is_new(
        first_seen_ts=1000.0, now=1000.0 + HOUR, window_seconds=DEFAULT_NEW_WINDOW_SECONDS
    )


def test_is_new_ausserhalb_fenster() -> None:
    assert not is_new(first_seen_ts=0.0, now=25 * HOUR, window_seconds=DEFAULT_NEW_WINDOW_SECONDS)


def test_is_new_fenster_null_nie_neu() -> None:
    assert not is_new(first_seen_ts=1000.0, now=1000.0, window_seconds=0.0)


def test_is_new_uhr_sprung_zaehlt_als_neu() -> None:
    # now < first_seen (Uhr-Sprung) -> konservativ neu (Befund nicht verstecken).
    assert is_new(first_seen_ts=1000.0, now=900.0, window_seconds=DEFAULT_NEW_WINDOW_SECONDS)
