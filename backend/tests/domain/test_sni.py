"""Tests der reinen sni-Domaene: Hostname-Normalisierung + Snapshot-Zuordnung.

Reine Funktionen, kein I/O -- die Zuordnungslogik (``match_snapshot``) ist das
Herzstueck und wird mit synthetischen Snapshots geprueft (1 SNI + passender Snapshot
-> Treffer + Delta), exakt die im Spike gemessene Technik.
"""

from domain.sni import ObservedSni, match_snapshot, normalize_hostname

# ── normalize_hostname ────────────────────────────────────────────────────────


def test_normalize_hostname_trims_and_keeps() -> None:
    assert normalize_hostname("  example.com  ") == "example.com"
    assert normalize_hostname("example.com") == "example.com"


def test_normalize_hostname_empty_or_whitespace_to_none() -> None:
    assert normalize_hostname("") is None
    assert normalize_hostname("   ") is None
    assert normalize_hostname("\t\n") is None


# ── match_snapshot (das Herzstueck) ───────────────────────────────────────────


def test_match_snapshot_nearest_hit_returns_pid_and_delta() -> None:
    # 1 SNI bei ts=100.0; zwei Snapshots, der bei 100.05 (50 ms) ist naeher als der
    # bei 100.5 (500 ms) -- erwartet pid des naechsten + delta 50 ms.
    hit_ts = 100.0
    snapshots = [
        (100.5, {("93.184.216.34", 443): 2222}),
        (100.05, {("93.184.216.34", 443): 1111}),
    ]
    pid, delta_ms = match_snapshot("93.184.216.34", 443, hit_ts, snapshots)
    assert pid == 1111
    assert delta_ms == 50


def test_match_snapshot_no_matching_endpoint_returns_none() -> None:
    snapshots = [(100.0, {("1.2.3.4", 443): 1111})]
    assert match_snapshot("9.9.9.9", 443, 100.0, snapshots) == (None, None)


def test_match_snapshot_empty_snapshots_returns_none() -> None:
    assert match_snapshot("1.2.3.4", 443, 100.0, []) == (None, None)


def test_match_snapshot_endpoint_known_but_pid_none() -> None:
    # rootless-Realitaet: psutil sah den Socket, aber ohne PID -> pid=None, aber ein
    # echtes Delta (der Endpunkt WAR bekannt, nur die PID nicht).
    snapshots = [(100.02, {("1.2.3.4", 443): None})]
    pid, delta_ms = match_snapshot("1.2.3.4", 443, 100.0, snapshots)
    assert pid is None
    assert delta_ms == 20


def test_match_snapshot_port_must_match() -> None:
    # Gleiche IP, anderer Port -> kein Treffer (der Endpunkt ist (ip, port)).
    snapshots = [(100.0, {("1.2.3.4", 8443): 1111})]
    assert match_snapshot("1.2.3.4", 443, 100.0, snapshots) == (None, None)


def test_observed_sni_defaults_are_none() -> None:
    # Die Zuordnungs-Felder sind ohne Match ehrlich None (kein erfundener Wert).
    obs = ObservedSni(hostname="x.io", remote_ip="1.2.3.4", remote_port=443, monotonic_ts=1.0)
    assert obs.app_name is None
    assert obs.pid is None
    assert obs.delta_ms is None
