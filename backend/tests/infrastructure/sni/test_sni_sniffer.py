"""Tests des SNI-Sniffer-Adapters OHNE echten Sniff/Root.

Wir umgehen den scapy-/psutil-Sniff (der braucht Root + Netz) und pruefen den
Zuordnungs-Pfad direkt: interne rohe Hits + synthetische Socket-Snapshots in den
Adapter setzen und ``observed()`` rufen -> erwartete ``ObservedSni`` mit pid + Delta.
Die Namensaufloesung (psutil) wird ueber den eigenen Prozess belegt. Belegt zudem die
Verfuegbarkeits-/Lifecycle-Stubs ohne laufenden Sniff.
"""

import os

from infrastructure.sni.sni_sniffer import ScapySniSniffer, _RawHit, _resolve_app_name


def test_observed_assigns_nearest_snapshot_and_resolves_name() -> None:
    sniffer = ScapySniSniffer()
    # 1 roher Hit bei ts=100.0 auf 93.184.216.34:443.
    sniffer._raw_hits.append(_RawHit("example.com", "93.184.216.34", 443, 100.0))
    # Zwei Snapshots: der bei 100.05 (50 ms) ist naeher und kennt den Endpunkt mit
    # UNSERER PID -> Treffer + Name unseres Prozesses + Delta 50 ms.
    my_pid = os.getpid()
    sniffer._snapshots.append((100.5, {("93.184.216.34", 443): 99999999}))
    sniffer._snapshots.append((100.05, {("93.184.216.34", 443): my_pid}))

    observed = sniffer.observed()
    assert len(observed) == 1
    obs = observed[0]
    assert obs.hostname == "example.com"
    assert obs.remote_ip == "93.184.216.34"
    assert obs.remote_port == 443
    assert obs.pid == my_pid
    assert obs.app_name == _resolve_app_name(my_pid)  # echter Prozessname (nicht None)
    assert obs.delta_ms == 50


def test_observed_unmatched_hit_has_none_fields() -> None:
    sniffer = ScapySniSniffer()
    sniffer._raw_hits.append(_RawHit("nomatch.io", "9.9.9.9", 443, 100.0))
    sniffer._snapshots.append((100.0, {("1.2.3.4", 443): 1234}))

    obs = sniffer.observed()[0]
    assert obs.app_name is None
    assert obs.pid is None
    assert obs.delta_ms is None


def test_observed_empty_when_no_hits() -> None:
    assert ScapySniSniffer().observed() == []


def test_resolve_app_name_none_pid_returns_none() -> None:
    assert _resolve_app_name(None) is None


def test_resolve_app_name_unknown_pid_returns_none() -> None:
    # Eine sehr hohe PID existiert (mit hoher Wahrscheinlichkeit) nicht -> None,
    # defensiv ueber psutil.Error (kein Crash).
    assert _resolve_app_name(2**31 - 1) is None


def test_is_running_false_without_sniff() -> None:
    assert ScapySniSniffer().is_running() is False


def test_stop_idempotent_without_sniff() -> None:
    # Kein laufender Sniff -> stop() ist ein No-op (kein Crash).
    ScapySniSniffer().stop()


def test_is_available_reflects_scapy() -> None:
    # In der CI ist scapy als feste dep da -> True. Reiner Verfuegbarkeits-Check.
    from infrastructure.capture import _scapy

    assert ScapySniSniffer().is_available() is bool(_scapy.HAS_SCAPY)
