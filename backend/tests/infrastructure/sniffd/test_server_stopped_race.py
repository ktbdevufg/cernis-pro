"""Test des STOPPED-Race-Fix (Exactly-Once) in ``_Session`` -- ohne echten Sniff/Socket.

ETAPPE 3b TEIL 3: ``_on_pcap_finished`` (prn-Thread, Selbst-Ende) und ``_handle_stop``
(Kommando-Schleife) koennen bei gleichzeitigem Selbst-Ende + STOP beide den Sniffer
non-None sehen und je ein ``STOPPED`` senden. ``_claim_sniffer`` macht das Lesen-und-
Nullen atomar -> GENAU EINER gewinnt -> EXACTLY-ONCE ``STOPPED``.

Hier wird ``_Session`` direkt instanziiert (Socket ist ein Dummy -- ``_send`` ist
ersetzt, sodass kein echtes I/O laeuft), mit einem Fake-Sniffer bestueckt, und beide
Stop-Pfade NEBENLAEUFIG aus vielen Threads gefeuert. Erwartung: ueber alle Laeufe
GENAU EIN ``STOPPED`` pro Session, nie zwei.
"""

import threading
from typing import Any

from infrastructure.sniffd.protocol import MessageType
from infrastructure.sniffd.server import _Session


class _FakeSniffer:
    def stop(self, join: bool = False) -> None:
        pass


def _make_session() -> tuple[_Session, list[Any]]:
    """Baut eine ``_Session`` mit Dummy-conn + Sammel-``_send`` und einem Fake-Sniffer."""
    session = _Session(conn=None)  # type: ignore[arg-type]  # _send ist ersetzt
    sent: list[Any] = []
    lock = threading.Lock()

    def _record(payload: dict[str, Any]) -> None:
        with lock:
            sent.append(payload["type"])

    session._send = _record  # type: ignore[method-assign]
    session._sniffer = _FakeSniffer()
    return session, sent


def test_concurrent_finish_and_stop_send_exactly_one_stopped() -> None:
    # Viele Runden, jede mit beiden Pfaden nebenlaeufig -> nie zwei STOPPED.
    for _ in range(200):
        session, sent = _make_session()
        barrier = threading.Barrier(2)

        # session/barrier als Default-Argumente binden (B023: nicht die Schleifen-
        # Variable einfangen) -- jeder Lauf hat seine eigene Session.
        def _finish(s: _Session = session, b: threading.Barrier = barrier) -> None:
            b.wait()
            s._on_pcap_finished()

        def _stop(s: _Session = session, b: threading.Barrier = barrier) -> None:
            b.wait()
            s._handle_stop()

        t1 = threading.Thread(target=_finish)
        t2 = threading.Thread(target=_stop)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        stopped = [t for t in sent if t == MessageType.STOPPED]
        assert len(stopped) == 1, f"erwartete genau ein STOPPED, bekam {len(stopped)}"


def test_handle_stop_without_sniffer_sends_nothing() -> None:
    # Kein laufender Sniffer -> _handle_stop sendet kein STOPPED (Selbst-Ende war
    # schon durch ODER es lief nie etwas). Exactly-Once bleibt gewahrt.
    session, sent = _make_session()
    session._sniffer = None
    session._handle_stop()
    assert MessageType.STOPPED not in sent


def test_self_finish_alone_sends_one_stopped() -> None:
    # Nur Selbst-Ende, kein gleichzeitiges STOP -> genau ein STOPPED.
    session, sent = _make_session()
    session._on_pcap_finished()
    assert sent.count(MessageType.STOPPED) == 1
    # Zweiter Aufruf (Sniffer schon geclaimt) -> nichts mehr.
    session._on_pcap_finished()
    assert sent.count(MessageType.STOPPED) == 1
