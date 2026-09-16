"""``DnsHelperClient`` -- die DNS-Naht ueber den gemeinsamen Helfer-Client-Kern.

Netzweiter DNS-Umgehungs-Waechter (ADR 0042), unterste Naht: schickt den
``START_DNS``-Befehl, sammelt die ``DNS_QUERY``-Nachrichten ueber den Reader-Thread
in eine thread-sichere ``deque`` (``poll_queries`` leert sie). Strukturell 1:1 wie
``SniHelperClient`` (``infrastructure/sniffd_client/sni_client.py``), nur mit
``START_DNS``/``DNS_QUERY`` statt ``START``/``HIT``.

WICHTIG: Der zugehoerige Sniff im Helfer laeuft mit ``promisc=True`` (netzweiter
Anspruch -- fremde Geraete), NICHT ``promisc=False`` wie SNI/pcap. Das ist bewusst
(ADR 0042) und der einzige Weg, fremden DNS-Traffic ueberhaupt zu sehen.
"""

from collections import deque
from typing import Any

from infrastructure.sniffd.protocol import MessageType
from infrastructure.sniffd_client.base import _BaseSubprocessHelper


class DnsHelperClient(_BaseSubprocessHelper):
    """DNS-Query-Strom ueber einen on-demand gespawnten Helfer-Subprozess.

    Der Reader-Thread liest die ``DNS_QUERY``-Nachrichten in eine thread-sichere
    ``deque`` (Lock); ``poll_queries`` leert sie. ``STOPPED``/``PONG``/``ERROR``
    interessieren den Lese-Pfad nicht -- er zieht nur die Queries.
    """

    def __init__(self) -> None:
        super().__init__()
        self._queries: deque[dict[str, Any]] = deque()

    def start(self, interface: str | None) -> str | None:
        """Spawnt Helfer, connectet, schickt START_DNS. ``None`` bei Erfolg, sonst Text.

        Reihenfolge: Spawn/Connect/Send (gemeinsamer Kern) -> auf STARTED/ERROR warten
        -> Reader-Thread starten. Jeder Fehlschritt raeumt ab (``_cleanup``) und gibt
        einen ehrlichen Fehlertext zurueck -- KEIN Crash, KEINE stille Leer-Erfassung.
        """
        if self.is_running():
            return None  # bereits aktiv -- kein Doppelstart

        self._queries = deque()

        start_msg: dict[str, Any] = {"type": MessageType.START_DNS}
        if interface is not None:
            start_msg["interface"] = interface
        error = self._spawn_connect_send(start_msg, "DNS")
        if error is not None:
            return error

        reply = self._recv_reply_with_timeout()
        if reply is None:
            self._cleanup()
            return "DNS-Helfer beendete die Verbindung vor der START-Antwort"
        reply_type = reply.get("type")
        if reply_type == MessageType.ERROR:
            err = str(reply.get("error", "unbekannter Helfer-Fehler"))
            self._cleanup()
            return err
        if reply_type != MessageType.STARTED:
            self._cleanup()
            return f"DNS-Helfer antwortete unerwartet: {reply_type!r}"

        # Ab hier laeuft der Sniff im Helfer -- Reader-Thread fuer die DNS_QUERY-Nachrichten.
        self._start_reader()
        return None

    def poll_queries(self) -> list[dict[str, Any]]:
        """Leert die interne Query-deque und gibt die rohen Query-dicts zurueck (thread-sicher)."""
        with self._lock:
            queries = list(self._queries)
            self._queries.clear()
        return queries

    def stop(self) -> None:
        """Stoppt Sniff + Helfer (idempotent): STOP best-effort, dann ``_cleanup``."""
        self._send({"type": MessageType.STOP})
        self._cleanup()

    def _handle_message(self, message: dict[str, Any]) -> None:
        """Reader-Hook: nur ``DNS_QUERY``-Nachrichten landen in der deque (ohne ``type``)."""
        if message.get("type") == MessageType.DNS_QUERY:
            query = {k: v for k, v in message.items() if k != "type"}
            with self._lock:
                self._queries.append(query)
