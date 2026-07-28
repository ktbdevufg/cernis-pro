"""Tests der traffic-Use-Cases gegen In-Memory-Fakes der Ports.

Kein echtes psutil/sock_diag-Tooling noetig -- wir testen gegen die Protocols. Kern
der Behauptungen: ``ListAppTraffic`` delegiert die Buendelung an die Domaene
(``aggregate_by_app``), ``CheckTrafficPermission`` liefert die ``{ok, error}``-Naht
(verfuegbar/Recht/kein Recht), und ``MeasureThroughput`` rechnet zustandsfrei die
Raten aus zwei uebergebenen Messpunkten. Async via ``asyncio.run`` (Projektmuster,
kein pytest-asyncio).
"""

import asyncio
import contextlib

from application.traffic import (
    CheckTrafficPermission,
    ListAppTraffic,
    MeasureThroughput,
    PollThroughput,
)
from domain.traffic import (
    Connection,
    ConnSample,
    Endpoint,
    TrafficPermissionCause,
    TrafficPermissionResult,
    TrafficPermissionState,
    make_socket_key,
)

# ── In-Memory-Fakes der Ports ────────────────────────────────────────────────


class FakePerProcessTrafficProvider:
    """In-Memory-Implementierung des ``PerProcessTrafficProvider``-Protocols."""

    def __init__(
        self,
        connections: list[Connection] | None = None,
        samples: list[ConnSample] | None = None,
    ) -> None:
        self._connections = connections or []
        self._samples = samples or []
        self.list_connections_calls = 0
        self.sample_throughput_calls = 0

    async def list_connections(self) -> list[Connection]:
        self.list_connections_calls += 1
        return list(self._connections)

    async def sample_throughput(self) -> list[ConnSample]:
        self.sample_throughput_calls += 1
        return list(self._samples)


class SequencedTrafficProvider:
    """Provider, der bei JEDEM ``sample_throughput`` den naechsten Messpunkt liefert.

    Fuer ``PollThroughput``-Tests: tick 1 sieht ``rounds[0]``, tick 2 ``rounds[1]``, ...
    (so lassen sich zwei aufeinanderfolgende Messpunkte mit bekannten Byte-Deltas
    vorgeben). ``list_connections`` wird hier nicht gebraucht -> leer.
    """

    def __init__(self, rounds: list[list[ConnSample]]) -> None:
        self._rounds = rounds
        self._index = 0

    async def list_connections(self) -> list[Connection]:
        return []

    async def sample_throughput(self) -> list[ConnSample]:
        result = self._rounds[self._index] if self._index < len(self._rounds) else []
        self._index += 1
        return result


class FakeTrafficPermission:
    """In-Memory-Implementierung des ``TrafficPermissionPort``-Protocols."""

    def __init__(
        self,
        available: bool = True,
        permission_error: str | None = None,
        state: TrafficPermissionState | None = None,
        cause: TrafficPermissionCause | None = None,
    ) -> None:
        self._available = available
        self._permission_error = permission_error
        # Default: aus dem Text abgeleitet (Text da -> Rechte fehlen). Tests, die
        # den PLATTFORM-Fall pruefen, geben ``state`` ausdruecklich vor.
        self._state = state or (
            TrafficPermissionState.GRANTED
            if permission_error is None
            else TrafficPermissionState.NEEDS_PRIVILEGES
        )
        # Ursache bleibt standardmaessig ``None`` ("keine Ursache") -- nur Tests, die
        # den Ursachen-Durchreichweg pruefen, geben sie ausdruecklich vor (der echte
        # Adapter setzt sie nur im Fehlzustand).
        self._cause = cause

    def is_available(self) -> bool:
        return self._available

    def check_permission(self) -> str | None:
        return self._permission_error

    def permission_state(self) -> TrafficPermissionResult:
        return TrafficPermissionResult(
            state=self._state,
            reason=self._permission_error or "",
            cause=self._cause,
        )


def _conn(app_name: str | None, pid: int | None = None, port: int = 443) -> Connection:
    return Connection(
        l4="tcp",
        status="established",
        local=Endpoint(ip="10.0.0.1", port=port),
        remote=Endpoint(ip="1.1.1.1", port=443),
        pid=pid,
        app_name=app_name,
    )


# ── ListAppTraffic ───────────────────────────────────────────────────────────


def test_list_app_traffic_groups_by_app() -> None:
    fake = FakePerProcessTrafficProvider(
        connections=[
            _conn("firefox", pid=10),
            _conn("firefox", pid=10, port=8443),
            _conn("ssh", pid=20),
            _conn(None),  # rootless nicht zuordenbar -> None-Gruppe
        ]
    )
    result = asyncio.run(ListAppTraffic(fake)())

    by_name = {a.app_name: a for a in result}
    assert set(by_name) == {"firefox", "ssh", None}
    assert by_name["firefox"].connection_count == 2
    assert by_name["ssh"].connection_count == 1
    # ehrliche None-Gruppe (rootless), nicht verworfen
    assert by_name[None].connection_count == 1
    # deterministische Sortierung: None ans Ende
    assert [a.app_name for a in result] == ["firefox", "ssh", None]


def test_list_app_traffic_empty() -> None:
    fake = FakePerProcessTrafficProvider(connections=[])
    result = asyncio.run(ListAppTraffic(fake)())
    assert result == []


def test_list_app_traffic_provider_called_once() -> None:
    fake = FakePerProcessTrafficProvider(connections=[_conn("app", pid=1)])
    asyncio.run(ListAppTraffic(fake)())
    assert fake.list_connections_calls == 1


# ── CheckTrafficPermission ───────────────────────────────────────────────────


def test_check_permission_available_and_allowed() -> None:
    fake = FakeTrafficPermission(available=True, permission_error=None)
    result = CheckTrafficPermission(fake)()
    assert result == {"ok": True, "error": "", "state": "granted", "cause": None}


def test_check_permission_available_but_denied() -> None:
    msg = "Fuer den Durchsatz aller Apps muss CERNIS PRO als Root gestartet werden."
    fake = FakeTrafficPermission(available=True, permission_error=msg)
    result = CheckTrafficPermission(fake)()
    assert result == {
        "ok": False,
        "error": msg,
        "state": "needs_privileges",
        "cause": None,
    }


def test_check_permission_not_available() -> None:
    fake = FakeTrafficPermission(available=False)
    result = CheckTrafficPermission(fake)()
    assert result["ok"] is False
    assert result["error"]  # nicht-leerer Grund
    assert result["state"] == "not_applicable"


def test_check_permission_platform_limit_is_not_a_rights_problem() -> None:
    """Plattformgrenze -> ``not_applicable``, NICHT ``needs_privileges``.

    Die zentrale Unterscheidung dieser Naht: beide Faelle liefern ``ok=False`` mit
    einem Text, sind aber fachlich verschieden (behebbar vs. nicht behebbar). Faellt
    die Trennung je zusammen, kann die Oberflaeche sie nicht mehr auseinanderhalten
    und wuerde auf macOS zu erhoehten Rechten raten, die dort nichts bewirken.
    """
    grund = "Der Durchsatz je Programm laesst sich auf macOS nicht messen."
    fake = FakeTrafficPermission(
        available=True,
        permission_error=grund,
        state=TrafficPermissionState.NOT_APPLICABLE,
    )

    result = CheckTrafficPermission(fake)()

    assert result == {
        "ok": False,
        "error": grund,
        "state": "not_applicable",
        "cause": None,
    }
    assert result["state"] != "needs_privileges"


def test_check_permission_pass_throughs() -> None:
    fake = FakeTrafficPermission(available=True, permission_error="x")
    uc = CheckTrafficPermission(fake)
    assert uc.is_available() is True
    assert uc.check_permission() == "x"


# ── MeasureThroughput (zustandsfrei, kein Port) ──────────────────────────────


def _sample(key: str, sent: int, recv: int, ts: float) -> ConnSample:
    return ConnSample(key=key, bytes_sent=sent, bytes_received=recv, monotonic_ts=ts)


def test_measure_throughput_computes_rates_per_key() -> None:
    prev = [_sample("a", 1000, 2000, 10.0), _sample("b", 0, 0, 10.0)]
    curr = [_sample("a", 3000, 2500, 12.0), _sample("b", 200, 100, 12.0)]
    result = MeasureThroughput()(prev, curr)
    # a: sent (3000-1000)/2=1000, recv (2500-2000)/2=250
    assert result["a"] == (1000.0, 250.0)
    # b: sent 200/2=100, recv 100/2=50
    assert result["b"] == (100.0, 50.0)


def test_measure_throughput_only_paired_keys() -> None:
    prev = [_sample("shared", 0, 0, 10.0), _sample("gone", 0, 0, 10.0)]
    curr = [_sample("shared", 200, 0, 12.0), _sample("new", 999, 0, 12.0)]
    result = MeasureThroughput()(prev, curr)
    # nur 'shared' ist in beiden Messpunkten -> nur dieser key
    assert set(result) == {"shared"}
    assert result["shared"] == (100.0, 0.0)


def test_measure_throughput_empty() -> None:
    assert MeasureThroughput()([], []) == {}
    assert MeasureThroughput()([_sample("a", 0, 0, 1.0)], []) == {}
    assert MeasureThroughput()([], [_sample("a", 0, 0, 1.0)]) == {}


# ── PollThroughput (lebender Use-Case, RunMonitor-Muster) ────────────────────


def test_poll_first_tick_no_rates_yet() -> None:
    # Erster tick: nur ein Messpunkt -> keine Raten (ehrlich leer, nicht 0).
    provider = SequencedTrafficProvider([[_sample("k", 1000, 2000, 10.0)]])
    poll = PollThroughput(provider)
    asyncio.run(poll.tick())
    assert poll.current_rates() == {}


def test_poll_second_tick_computes_rates() -> None:
    # Zwei Messpunkte mit bekannten Byte-Deltas ueber dt=2s -> erwartete bps.
    provider = SequencedTrafficProvider(
        [
            [_sample("k", 1000, 2000, 10.0)],
            [_sample("k", 3000, 2500, 12.0)],
        ]
    )
    poll = PollThroughput(provider)
    asyncio.run(poll.tick())  # prev gesetzt, noch keine Raten
    asyncio.run(poll.tick())  # rechnet gegen prev
    rates = poll.current_rates()
    # sent (3000-1000)/2 = 1000, recv (2500-2000)/2 = 250
    assert rates == {"k": (1000.0, 250.0)}


def test_poll_stop_sets_running_false() -> None:
    poll = PollThroughput(SequencedTrafficProvider([]))
    poll._running = True
    poll.stop()
    assert poll._running is False


def test_poll_current_rates_is_defensive_copy() -> None:
    provider = SequencedTrafficProvider(
        [
            [_sample("k", 0, 0, 10.0)],
            [_sample("k", 100, 0, 12.0)],
        ]
    )
    poll = PollThroughput(provider)
    asyncio.run(poll.tick())
    asyncio.run(poll.tick())
    snapshot = poll.current_rates()
    snapshot["k"] = (999.0, 999.0)  # Mutation am Ergebnis
    snapshot["neu"] = (1.0, 1.0)
    # interner State unberuehrt
    assert poll.current_rates() == {"k": (50.0, 0.0)}


# ── ListAppTraffic mit Raten-Anreicherung ────────────────────────────────────


def _key_of(conn: Connection) -> str:
    return make_socket_key(
        conn.l4,
        conn.local.ip,
        conn.local.port,
        conn.remote.ip if conn.remote else None,
        conn.remote.port if conn.remote else None,
    )


def test_list_app_traffic_enriches_matching_socket() -> None:
    conn = _conn("firefox", pid=10)
    fake = FakePerProcessTrafficProvider(connections=[conn])
    rates = {_key_of(conn): (1234.0, 567.0)}
    result = asyncio.run(ListAppTraffic(fake)(rates))
    app = result[0]
    assert app.connections[0].send_rate_bps == 1234.0
    assert app.connections[0].recv_rate_bps == 567.0


def test_list_app_traffic_no_match_leaves_rates_none() -> None:
    conn = _conn("firefox", pid=10)
    fake = FakePerProcessTrafficProvider(connections=[conn])
    # Map mit einem FREMDEN key -> diese Verbindung bleibt None.
    result = asyncio.run(ListAppTraffic(fake)({"tcp:9.9.9.9:1:8.8.8.8:2": (1.0, 2.0)}))
    assert result[0].connections[0].send_rate_bps is None
    assert result[0].connections[0].recv_rate_bps is None


def test_list_app_traffic_without_rates_is_stage1() -> None:
    # Kein rates-Argument -> unveraendertes Stufe-1-Verhalten (alle Raten None).
    fake = FakePerProcessTrafficProvider(connections=[_conn("firefox", pid=10)])
    result = asyncio.run(ListAppTraffic(fake)())
    assert result[0].connections[0].send_rate_bps is None
    assert result[0].total_send_rate_bps is None


def test_list_app_traffic_aggregates_app_rate_totals() -> None:
    # Zwei Verbindungen derselben App, beide mit Rate -> total_* summiert.
    c1 = _conn("firefox", pid=10, port=1111)
    c2 = _conn("firefox", pid=10, port=2222)
    fake = FakePerProcessTrafficProvider(connections=[c1, c2])
    rates = {_key_of(c1): (100.0, 10.0), _key_of(c2): (50.0, 5.0)}
    result = asyncio.run(ListAppTraffic(fake)(rates))
    app = result[0]
    assert app.total_send_rate_bps == 150.0
    assert app.total_recv_rate_bps == 15.0


# ── Kumulative Byte-Zaehler (Finding 5: bytes_* duerfen nicht null bleiben) ──
# Die Zaehler stehen schon nach dem ERSTEN Messpunkt, die Raten erst nach zwei --
# darum werden sie getrennt hereingereicht und getrennt nachgeschlagen.


def test_list_app_traffic_setzt_byte_zaehler() -> None:
    conn = _conn("firefox", pid=10)
    fake = FakePerProcessTrafficProvider(connections=[conn])
    counters = {_key_of(conn): (98765, 4321)}

    result = asyncio.run(ListAppTraffic(fake)(None, counters))

    assert result[0].connections[0].bytes_sent == 98765
    assert result[0].connections[0].bytes_received == 4321


def test_list_app_traffic_zaehler_ohne_raten() -> None:
    # Nach dem ersten tick: Zaehler da, Raten noch nicht -- beides ehrlich getrennt.
    conn = _conn("firefox", pid=10)
    fake = FakePerProcessTrafficProvider(connections=[conn])

    result = asyncio.run(ListAppTraffic(fake)({}, {_key_of(conn): (500, 200)}))

    assert result[0].connections[0].bytes_sent == 500
    assert result[0].connections[0].send_rate_bps is None


def test_list_app_traffic_raten_und_zaehler_zusammen() -> None:
    conn = _conn("firefox", pid=10)
    fake = FakePerProcessTrafficProvider(connections=[conn])

    result = asyncio.run(
        ListAppTraffic(fake)({_key_of(conn): (12.0, 34.0)}, {_key_of(conn): (500, 200)})
    )

    verbindung = result[0].connections[0]
    assert (verbindung.send_rate_bps, verbindung.recv_rate_bps) == (12.0, 34.0)
    assert (verbindung.bytes_sent, verbindung.bytes_received) == (500, 200)


def test_list_app_traffic_fremder_zaehler_laesst_none() -> None:
    fake = FakePerProcessTrafficProvider(connections=[_conn("firefox", pid=10)])

    result = asyncio.run(ListAppTraffic(fake)(None, {"tcp:9.9.9.9:1:8.8.8.8:2": (1, 2)}))

    assert result[0].connections[0].bytes_sent is None


def test_poll_current_counters_nach_erstem_tick() -> None:
    # Ein einzelner Messpunkt liefert noch keine Rate, aber sehr wohl die Zaehler.
    sample = ConnSample(key="tcp:a", bytes_sent=1000, bytes_received=2000, monotonic_ts=1.0)
    poll = PollThroughput(SequencedTrafficProvider([[sample]]))

    asyncio.run(poll.tick())

    assert poll.current_rates() == {}
    assert poll.current_counters() == {"tcp:a": (1000, 2000)}


def test_poll_current_counters_ist_defensive_kopie() -> None:
    sample = ConnSample(key="tcp:a", bytes_sent=1, bytes_received=2, monotonic_ts=1.0)
    poll = PollThroughput(SequencedTrafficProvider([[sample]]))
    asyncio.run(poll.tick())

    poll.current_counters()["tcp:a"] = (999, 999)

    assert poll.current_counters() == {"tcp:a": (1, 2)}


# ── Messfehler im Poll-Loop: gemerkt, nicht verschluckt (S3) ─────────────────


class FailingTrafficProvider:
    """Provider, dessen ``sample_throughput`` immer scheitert (Werkzeug fehlt)."""

    def __init__(self, message: str = "Werkzeug 'ss' nicht gefunden") -> None:
        self._message = message

    async def list_connections(self) -> list[Connection]:
        return []

    async def sample_throughput(self) -> list[ConnSample]:
        raise RuntimeError(self._message)


def test_poll_tick_reicht_messfehler_durch() -> None:
    # tick selbst schluckt nichts -- sonst fielen die Raten still auf den alten Stand.
    poll = PollThroughput(FailingTrafficProvider())

    try:
        asyncio.run(poll.tick())
    except RuntimeError as exc:
        assert "ss" in str(exc)
    else:
        raise AssertionError("tick haette den Messfehler durchreichen muessen")


def test_poll_run_merkt_fehler_und_laeuft_weiter() -> None:
    """Der Loop stirbt nicht am Messfehler, aber er verschweigt ihn auch nicht."""
    poll = PollThroughput(FailingTrafficProvider(), interval=0.0)

    async def kurz_laufen() -> None:
        task = asyncio.create_task(poll.run())
        await asyncio.sleep(0.05)
        poll.stop()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(kurz_laufen())

    assert poll.last_error() is not None
    assert "ss" in (poll.last_error() or "")
    assert poll.current_rates() == {}


def test_poll_last_error_anfangs_none() -> None:
    poll = PollThroughput(SequencedTrafficProvider([[]]))

    assert poll.last_error() is None


def test_poll_gelungener_tick_loescht_fehler() -> None:
    sample = ConnSample(key="tcp:a", bytes_sent=1, bytes_received=2, monotonic_ts=1.0)
    poll = PollThroughput(SequencedTrafficProvider([[sample]]))
    poll._last_error = "alter Fehler"

    asyncio.run(poll.tick())

    assert poll.last_error() is None


# ── Status-Naht: laufender Messfehler schlaegt auf ok=false durch ────────────


def test_check_permission_messfehler_schlaegt_durch() -> None:
    """Statisch in Ordnung, echter Messlauf scheitert -> ok=false MIT Grund."""
    fake = FakeTrafficPermission(available=True, permission_error=None)

    result = CheckTrafficPermission(fake)("ss endete mit Status 2")

    assert result["ok"] is False
    assert result["error"] == "ss endete mit Status 2"
    assert result["state"] == str(TrafficPermissionState.NEEDS_PRIVILEGES)


def test_check_permission_ohne_messfehler_bleibt_granted() -> None:
    fake = FakeTrafficPermission(available=True, permission_error=None)

    result = CheckTrafficPermission(fake)(None)

    assert result["ok"] is True
    assert result["state"] == str(TrafficPermissionState.GRANTED)


def test_check_permission_messfehler_ueberschreibt_not_applicable_nicht() -> None:
    """Die Plattformgrenze bleibt Plattformgrenze -- sie wird nicht zum Messfehler."""
    fake = FakeTrafficPermission(available=False, permission_error=None)

    result = CheckTrafficPermission(fake)("irgendein Messfehler")

    assert result["state"] == str(TrafficPermissionState.NOT_APPLICABLE)


# ── Ursachen-Naht: cause trennt die zwei Gruende von needs_privileges ─────────


def test_check_permission_messfehler_traegt_ursache_messlauf() -> None:
    """Gescheiterter Messlauf -> ``cause=measurement_failed`` neben unveraendertem Rest.

    Werkzeug fehlt und Messlauf gescheitert liefern denselben ``state`` und beide
    ``ok=False`` mit Text -- nur ``cause`` trennt sie. ``ok``/``error``/``state``
    bleiben dabei in Bedeutung und Schreibweise unveraendert (kein Bruch).
    """
    fake = FakeTrafficPermission(available=True, permission_error=None)

    result = CheckTrafficPermission(fake)("ss endete mit Status 2")

    assert result["ok"] is False
    assert result["error"] == "ss endete mit Status 2"
    assert result["state"] == str(TrafficPermissionState.NEEDS_PRIVILEGES)
    assert result["cause"] == str(TrafficPermissionCause.MEASUREMENT_FAILED)


def test_check_permission_werkzeug_fehlt_reicht_ursache_durch() -> None:
    """Ursache des Adapters (``tool_missing``) erscheint unveraendert in der Wire-Form."""
    grund = "Der Durchsatz je Programm braucht das Werkzeug 'ss' (Paket iproute2)."
    fake = FakeTrafficPermission(
        available=True,
        permission_error=grund,
        cause=TrafficPermissionCause.TOOL_MISSING,
    )

    result = CheckTrafficPermission(fake)()

    assert result == {
        "ok": False,
        "error": grund,
        "state": str(TrafficPermissionState.NEEDS_PRIVILEGES),
        "cause": str(TrafficPermissionCause.TOOL_MISSING),
    }


def test_check_permission_granted_traegt_keine_ursache() -> None:
    """Steht die Sicht, gibt es keine Ursache: ``cause`` ist ``None``, nicht "unbekannt"."""
    fake = FakeTrafficPermission(available=True, permission_error=None)

    result = CheckTrafficPermission(fake)()

    assert result["state"] == str(TrafficPermissionState.GRANTED)
    assert result["cause"] is None


def test_check_permission_not_applicable_traegt_keine_ursache() -> None:
    """Die Plattformgrenze ist keine Ursache im Sinne von ``cause`` -> ``None``.

    ``cause`` beschreibt ausschliesslich, WARUM ``needs_privileges`` gilt; die
    nicht behebbare Plattformgrenze steckt schon vollstaendig im ``state``.
    """
    fake = FakeTrafficPermission(available=False)

    result = CheckTrafficPermission(fake)()

    assert result["state"] == str(TrafficPermissionState.NOT_APPLICABLE)
    assert result["cause"] is None


def test_check_permission_ursachen_sind_maschinell_unterscheidbar() -> None:
    """Beide Ursachen fallen in ``ok``/``error``-Bedeutung zusammen, in ``cause`` nicht.

    Genau das ist der Zweck des Feldes: ohne es muesste die Oberflaeche die zwei
    Faelle aus dem Freitext von ``error`` erraten.
    """
    werkzeug = CheckTrafficPermission(
        FakeTrafficPermission(
            available=True,
            permission_error="Werkzeug fehlt",
            cause=TrafficPermissionCause.TOOL_MISSING,
        )
    )()
    messlauf = CheckTrafficPermission(FakeTrafficPermission(available=True))("Messlauf kaputt")

    assert werkzeug["ok"] is False and messlauf["ok"] is False
    assert werkzeug["state"] == messlauf["state"] == "needs_privileges"
    assert werkzeug["cause"] != messlauf["cause"]
