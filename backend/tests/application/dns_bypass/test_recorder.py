"""Tests des DNS-Bypass-Puffer-Leerpump-Workers (Etappe 4a) gegen eine Fake-Quelle.

Reine application-Schicht: KEIN echter Helfer-Subprozess, KEIN Lifespan-Loop -- jeweils
EIN ``asyncio.run(recorder.tick())`` (Muster ``test_recorder`` aus outbound_log) mit einer
in-memory ``DnsQuerySource``, die vordefinierte Query-dict-Batches nacheinander liefert.
``run()`` wird NICHT ueber einen echten asyncio-sleep-Loop getestet -- nur ``tick()``/
``start()``/``stop()`` direkt. Belegt:

* T1 start mit Fehlertext -> Recorder NICHT aktiv, Text durchgereicht.
* T2 start ok -> aktiv; nach manuellem ``tick()`` sind die gepushten Queries als
  ``RawDnsQuery`` im ``snapshot_queries()`` (``src_ip``/``dst_ip``/``l4`` korrekt,
  fehlendes ``qname`` -> ``""``).
* T3 mehrere ticks akkumulieren (Puffer waechst); ``clear()`` leert.
* T4 ``tick`` ist best-effort: ein werfendes ``poll_queries`` -> kein Wurf, Puffer
  unveraendert.
* T5 ``stop()`` -> nicht mehr aktiv, ``source.stop()`` gerufen.
"""

import asyncio
from typing import Any

from application.dns_bypass import DnsBypassRecorder
from domain.dns_bypass import RawDnsQuery


class _FakeDnsQuerySource:
    """In-memory ``DnsQuerySource``-Fake: liefert vordefinierte Batches nacheinander.

    ``start_error`` konfiguriert das ``start``-Ergebnis (``None`` = ok, sonst Fehlertext).
    ``batches`` ist eine Liste von Query-dict-Batches; jeder ``poll_queries``-Aufruf gibt
    den naechsten Batch zurueck (leer, wenn keiner mehr da ist). ``poll_error``, wenn
    gesetzt, laesst ``poll_queries`` werfen (fuer den best-effort-Test). ``stop_calls``
    zaehlt die ``stop``-Aufrufe.
    """

    def __init__(
        self,
        batches: list[list[dict[str, Any]]] | None = None,
        start_error: str | None = None,
        poll_error: Exception | None = None,
    ) -> None:
        self._batches = list(batches or [])
        self._start_error = start_error
        self._poll_error = poll_error
        self._running = False
        self.stop_calls = 0
        self.started_interface: str | None = None

    def start(self, interface: str | None) -> str | None:
        if self._start_error is not None:
            return self._start_error
        self.started_interface = interface
        self._running = True
        return None

    def poll_queries(self) -> list[dict[str, Any]]:
        if self._poll_error is not None:
            raise self._poll_error
        if not self._batches:
            return []
        return self._batches.pop(0)

    def stop(self) -> None:
        self.stop_calls += 1
        self._running = False

    def is_running(self) -> bool:
        return self._running


def test_start_mit_fehlertext_nicht_aktiv_und_durchgereicht() -> None:
    # T1: start mit Fehlertext -> Recorder NICHT aktiv, Text durchgereicht.
    source = _FakeDnsQuerySource(start_error="DNS-Helfer nicht erreichbar")
    recorder = DnsBypassRecorder(source)

    result = recorder.start("eth0")

    assert result == "DNS-Helfer nicht erreichbar"
    assert recorder.is_active() is False


def test_start_ok_tick_mappt_queries_in_snapshot() -> None:
    # T2: start ok -> aktiv; tick() mappt die gepushten dicts auf RawDnsQuery,
    # fehlendes qname -> "".
    source = _FakeDnsQuerySource(
        batches=[
            [
                {"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "l4": "udp", "qname": "example.com"},
                {"src_ip": "10.0.0.6", "dst_ip": "1.1.1.1", "l4": "tcp"},
            ]
        ]
    )
    recorder = DnsBypassRecorder(source)

    assert recorder.start("eth0") is None
    assert recorder.is_active() is True

    asyncio.run(recorder.tick())

    assert recorder.snapshot_queries() == [
        RawDnsQuery(src_ip="10.0.0.5", dst_ip="8.8.8.8", l4="udp", qname="example.com"),
        RawDnsQuery(src_ip="10.0.0.6", dst_ip="1.1.1.1", l4="tcp", qname=""),
    ]


def test_mehrere_ticks_akkumulieren_und_clear_leert() -> None:
    # T3: mehrere ticks akkumulieren (Puffer waechst); clear() leert.
    source = _FakeDnsQuerySource(
        batches=[
            [{"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "l4": "udp", "qname": "a.example"}],
            [{"src_ip": "10.0.0.6", "dst_ip": "1.1.1.1", "l4": "udp", "qname": "b.example"}],
        ]
    )
    recorder = DnsBypassRecorder(source)
    recorder.start(None)

    asyncio.run(recorder.tick())
    assert len(recorder.snapshot_queries()) == 1
    asyncio.run(recorder.tick())
    assert len(recorder.snapshot_queries()) == 2

    recorder.clear()
    assert recorder.snapshot_queries() == []


def test_tick_ist_best_effort_werfendes_poll_kein_wurf() -> None:
    # T4: tick ist best-effort: eine werfende poll_queries -> kein Wurf, Puffer unveraendert.
    source = _FakeDnsQuerySource(poll_error=RuntimeError("Puffer kaputt"))
    recorder = DnsBypassRecorder(source)
    recorder.start(None)

    asyncio.run(recorder.tick())  # darf NICHT werfen

    assert recorder.snapshot_queries() == []


def test_stop_deaktiviert_und_ruft_source_stop() -> None:
    # T5: stop() -> nicht mehr aktiv, source.stop() gerufen.
    source = _FakeDnsQuerySource()
    recorder = DnsBypassRecorder(source)
    recorder.start(None)
    assert recorder.is_active() is True

    recorder.stop()

    assert recorder.is_active() is False
    assert source.stop_calls == 1
