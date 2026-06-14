"""Tests der sni-Use-Cases gegen einen In-Memory-Fake des ``SniSnifferPort``.

Kein echtes scapy/psutil noetig -- wir testen gegen das Protocol. Kern der
Behauptungen: ``RunSniCapture`` delegiert Lifecycle + Lese-Sicht an den Adapter,
``StartSniCapture`` liefert die ``{ok, error}``-Naht (verfuegbar / Rechte / kein
Recht), ``GetObservedSni`` reicht die Momentaufnahme durch.
"""

from application.sni import GetObservedSni, RunSniCapture, StartSniCapture
from domain.sni import ObservedSni


class FakeSniSniffer:
    """In-Memory-Implementierung des ``SniSnifferPort``-Protocols."""

    def __init__(
        self,
        *,
        available: bool = True,
        permission: str | None = None,
        observed: list[ObservedSni] | None = None,
    ) -> None:
        self._available = available
        self._permission = permission
        self._observed = observed or []
        self._running = False
        self.start_calls: list[str | None] = []
        self.stop_calls = 0

    def start(self, interface: str | None) -> None:
        self.start_calls.append(interface)
        self._running = True

    def stop(self) -> None:
        self.stop_calls += 1
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def observed(self) -> list[ObservedSni]:
        return list(self._observed)

    def check_permission(self) -> str | None:
        return self._permission

    def is_available(self) -> bool:
        return self._available


# ── RunSniCapture ──────────────────────────────────────────────────────────────


def test_run_sni_capture_lifecycle_delegates() -> None:
    fake = FakeSniSniffer()
    run = RunSniCapture(fake)
    assert run.is_running() is False
    run.start("ens33")
    assert fake.start_calls == ["ens33"]
    assert run.is_running() is True
    run.stop()
    assert fake.stop_calls == 1
    assert run.is_running() is False


def test_run_sni_capture_observed_passes_through() -> None:
    obs = [ObservedSni(hostname="x.io", remote_ip="1.2.3.4", remote_port=443, monotonic_ts=1.0)]
    run = RunSniCapture(FakeSniSniffer(observed=obs))
    assert run.observed() == obs


# ── StartSniCapture ({ok, error}-Naht) ───────────────────────────────────────────


def test_start_sni_ok_when_available_and_permitted() -> None:
    start = StartSniCapture(FakeSniSniffer(available=True, permission=None))
    assert start() == {"ok": True, "error": ""}


def test_start_sni_not_available() -> None:
    start = StartSniCapture(FakeSniSniffer(available=False))
    result = start()
    assert result["ok"] is False
    assert "libpcap" in result["error"]


def test_start_sni_no_permission() -> None:
    start = StartSniCapture(FakeSniSniffer(available=True, permission="needs root"))
    assert start() == {"ok": False, "error": "needs root"}


def test_start_sni_exposes_available_and_permission() -> None:
    start = StartSniCapture(FakeSniSniffer(available=True, permission="x"))
    assert start.is_available() is True
    assert start.check_permission() == "x"


# ── GetObservedSni ───────────────────────────────────────────────────────────────


def test_get_observed_sni_returns_snapshot() -> None:
    obs = [
        ObservedSni(
            hostname="a.io",
            remote_ip="1.2.3.4",
            remote_port=443,
            monotonic_ts=1.0,
            app_name="firefox",
            pid=42,
            delta_ms=80,
        )
    ]
    get = GetObservedSni(FakeSniSniffer(observed=obs))
    assert get() == obs
