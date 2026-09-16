"""Unit-Tests der traffic-Domaene -- reine Logik, kein I/O, keine Uhr.

Prueft die Status-Normalisierung (``normalize_status``), die App-Aggregation
(``aggregate_by_app`` -- inkl. der ehrlichen None-Gruppe nicht zuordenbarer
Verbindungen), die Raten-Arithmetik (``compute_rate`` -- Reset- und ``dt<=0``-sicher)
und die Sample-Paarung ueber zwei Messpunkte (``match_samples``). Zeitstempel kommen
als Sample-Feld herein -> rein deterministisch.
"""

from domain.traffic import (
    AppTraffic,
    Connection,
    ConnSample,
    Endpoint,
    _canonical_ip,
    aggregate_by_app,
    compute_rate,
    make_socket_key,
    match_samples,
    normalize_status,
)


def _conn(
    app_name: str | None,
    pid: int | None = None,
    *,
    send_rate_bps: float | None = None,
    recv_rate_bps: float | None = None,
    port: int = 443,
) -> Connection:
    """Baut eine Connection mit sinnvollen Defaults fuer die Aggregations-Tests."""
    return Connection(
        l4="tcp",
        status="established",
        local=Endpoint(ip="10.0.0.1", port=port),
        remote=Endpoint(ip="1.1.1.1", port=443),
        pid=pid,
        app_name=app_name,
        send_rate_bps=send_rate_bps,
        recv_rate_bps=recv_rate_bps,
    )


# ── normalize_status ─────────────────────────────────────────────────────────


def test_normalize_status_known() -> None:
    assert normalize_status("ESTABLISHED") == "established"
    assert normalize_status("LISTEN") == "listen"
    assert normalize_status("NONE") == "none"


def test_normalize_status_unknown_to_other() -> None:
    assert normalize_status("SYN_SENT") == "other"
    assert normalize_status("TIME_WAIT") == "other"
    assert normalize_status("") == "other"


def test_normalize_status_case_insensitive() -> None:
    assert normalize_status("established") == "established"
    assert normalize_status("Listen") == "listen"


# ── aggregate_by_app ─────────────────────────────────────────────────────────


def test_aggregate_groups_multiple_apps() -> None:
    conns = [
        _conn("firefox", pid=10),
        _conn("firefox", pid=10, port=8443),
        _conn("ssh", pid=20),
    ]
    result = aggregate_by_app(conns)
    by_name = {a.app_name: a for a in result}
    assert set(by_name) == {"firefox", "ssh"}
    assert by_name["firefox"].connection_count == 2
    assert by_name["ssh"].connection_count == 1


def test_aggregate_unassigned_into_single_none_group() -> None:
    # Drei Verbindungen ohne app_name (kein PID) -> EINE None-Gruppe, nicht drei
    # einzelne, nicht verworfen.
    conns = [_conn(None), _conn(None), _conn(None)]
    result = aggregate_by_app(conns)
    none_groups = [a for a in result if a.app_name is None]
    assert len(none_groups) == 1
    assert none_groups[0].connection_count == 3
    assert none_groups[0].pids == ()


def test_aggregate_pids_sorted_and_deduped() -> None:
    conns = [_conn("app", pid=30), _conn("app", pid=10), _conn("app", pid=30)]
    result = aggregate_by_app(conns)
    assert result[0].pids == (10, 30)


def test_aggregate_none_group_sorted_last() -> None:
    # None-Gruppe muss ans Ende, benannte Apps davor alphabetisch.
    conns = [_conn(None), _conn("zebra", pid=1), _conn("alpha", pid=2)]
    result = aggregate_by_app(conns)
    assert [a.app_name for a in result] == ["alpha", "zebra", None]


def test_aggregate_rate_sum_none_until_known() -> None:
    # Keine Rate bekannt -> Summe None; eine bekannte -> Summe der bekannten.
    conns_unmeasured = [_conn("app", pid=1), _conn("app", pid=1)]
    assert aggregate_by_app(conns_unmeasured)[0].total_send_rate_bps is None

    conns_partial = [
        _conn("app", pid=1, send_rate_bps=100.0),
        _conn("app", pid=1, send_rate_bps=None),
    ]
    # Eine Rate bekannt (100.0), die unbekannte zaehlt 0 -> Summe 100.0.
    assert aggregate_by_app(conns_partial)[0].total_send_rate_bps == 100.0


def test_aggregate_rate_sum_full() -> None:
    conns = [
        _conn("app", pid=1, send_rate_bps=100.0, recv_rate_bps=10.0),
        _conn("app", pid=1, send_rate_bps=50.0, recv_rate_bps=5.0),
    ]
    app = aggregate_by_app(conns)[0]
    assert app.total_send_rate_bps == 150.0
    assert app.total_recv_rate_bps == 15.0


def test_aggregate_empty() -> None:
    assert aggregate_by_app([]) == []


def test_aggregate_preserves_connection_order_within_group() -> None:
    a = _conn("app", pid=1, port=1)
    b = _conn("app", pid=1, port=2)
    result = aggregate_by_app([a, b])
    assert result[0].connections == (a, b)


def test_aggregate_returns_apptraffic_instances() -> None:
    result = aggregate_by_app([_conn("app", pid=1)])
    assert isinstance(result[0], AppTraffic)


# ── compute_rate ─────────────────────────────────────────────────────────────


def test_compute_rate_normal() -> None:
    prev = ConnSample(key="k", bytes_sent=1000, bytes_received=2000, monotonic_ts=10.0)
    curr = ConnSample(key="k", bytes_sent=3000, bytes_received=2500, monotonic_ts=12.0)
    # dt=2s: sent (3000-1000)/2 = 1000 bps, recv (2500-2000)/2 = 250 bps.
    send_bps, recv_bps = compute_rate(prev, curr)
    assert send_bps == 1000.0
    assert recv_bps == 250.0


def test_compute_rate_dt_zero() -> None:
    prev = ConnSample(key="k", bytes_sent=1000, bytes_received=2000, monotonic_ts=10.0)
    curr = ConnSample(key="k", bytes_sent=3000, bytes_received=4000, monotonic_ts=10.0)
    assert compute_rate(prev, curr) == (0.0, 0.0)


def test_compute_rate_dt_negative() -> None:
    prev = ConnSample(key="k", bytes_sent=1000, bytes_received=2000, monotonic_ts=12.0)
    curr = ConnSample(key="k", bytes_sent=3000, bytes_received=4000, monotonic_ts=10.0)
    assert compute_rate(prev, curr) == (0.0, 0.0)


def test_compute_rate_counter_reset() -> None:
    # curr < prev (Socket geschlossen/neu vergeben) -> 0.0 statt negativer Rate.
    prev = ConnSample(key="k", bytes_sent=5000, bytes_received=5000, monotonic_ts=10.0)
    curr = ConnSample(key="k", bytes_sent=100, bytes_received=200, monotonic_ts=12.0)
    assert compute_rate(prev, curr) == (0.0, 0.0)


def test_compute_rate_reset_one_direction_only() -> None:
    # Sent resettet, received zaehlt normal weiter -> Richtungen unabhaengig.
    prev = ConnSample(key="k", bytes_sent=5000, bytes_received=1000, monotonic_ts=10.0)
    curr = ConnSample(key="k", bytes_sent=100, bytes_received=3000, monotonic_ts=12.0)
    send_bps, recv_bps = compute_rate(prev, curr)
    assert send_bps == 0.0
    assert recv_bps == 1000.0  # (3000-1000)/2


# ── match_samples ────────────────────────────────────────────────────────────


def _sample(key: str) -> ConnSample:
    return ConnSample(key=key, bytes_sent=0, bytes_received=0, monotonic_ts=1.0)


def test_match_samples_common_keys_paired() -> None:
    prev = [_sample("a"), _sample("b")]
    curr = [_sample("a"), _sample("b")]
    pairs = match_samples(prev, curr)
    assert [(p.key, c.key) for p, c in pairs] == [("a", "a"), ("b", "b")]


def test_match_samples_drops_only_in_prev_or_curr() -> None:
    # 'gone' nur in prev, 'new' nur in curr -> beide fallen raus, nur 'shared' bleibt.
    prev = [_sample("shared"), _sample("gone")]
    curr = [_sample("shared"), _sample("new")]
    pairs = match_samples(prev, curr)
    assert [c.key for _, c in pairs] == ["shared"]


def test_match_samples_empty() -> None:
    assert match_samples([], []) == []
    assert match_samples([_sample("a")], []) == []
    assert match_samples([], [_sample("a")]) == []


# ── _canonical_ip ────────────────────────────────────────────────────────────


def test_canonical_ip_ipv4_unchanged() -> None:
    assert _canonical_ip("172.18.1.156") == "172.18.1.156"


def test_canonical_ip_mapped_ss_and_psutil_identical() -> None:
    # DER Kern: ss-Form (mit Klammern) und psutil-Form (ohne) -> identisch.
    ss_form = _canonical_ip("[::ffff:172.18.1.156]")
    psutil_form = _canonical_ip("::ffff:172.18.1.156")
    assert ss_form == psutil_form == "172.18.1.156"


def test_canonical_ip_real_ipv6_bracket_and_plain_identical() -> None:
    assert _canonical_ip("[::1]") == _canonical_ip("::1") == "::1"
    assert _canonical_ip("[2001:db8::1]") == _canonical_ip("2001:db8::1") == "2001:db8::1"


def test_canonical_ip_garbage_returns_raw() -> None:
    # Unparsebares -> roh zurueck (best-effort, nie werfen).
    assert _canonical_ip("nicht-ip") == "nicht-ip"
    assert _canonical_ip("") == ""


# ── make_socket_key ──────────────────────────────────────────────────────────


def test_make_socket_key_ss_and_psutil_same_socket_identical() -> None:
    # DER entscheidende Test: derselbe IPv6-mapped Socket aus ss vs. psutil
    # ergibt denselben key (sonst paaren sie in match_samples nicht).
    ss_key = make_socket_key("tcp", "[::ffff:172.18.1.156]", 3389, "[::ffff:172.18.1.152]", 49946)
    psutil_key = make_socket_key("tcp", "::ffff:172.18.1.156", 3389, "::ffff:172.18.1.152", 49946)
    assert ss_key == psutil_key
    assert ss_key == "tcp:172.18.1.156:3389:172.18.1.152:49946"


def test_make_socket_key_ipv4() -> None:
    assert make_socket_key("tcp", "1.2.3.4", 80, "5.6.7.8", 12345) == "tcp:1.2.3.4:80:5.6.7.8:12345"


def test_make_socket_key_remote_none() -> None:
    # LISTEN o. Ae.: kein Remote -> leere remote-Teile, key bleibt stabil.
    assert make_socket_key("tcp", "0.0.0.0", 22, None, None) == "tcp:0.0.0.0:22::"


def test_make_socket_key_carries_l4_prefix() -> None:
    assert make_socket_key("udp", "1.2.3.4", 53, "5.6.7.8", 53).startswith("udp:")
