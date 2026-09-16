"""``SniHelperClient`` -- die SNI-Naht ueber den gemeinsamen Helfer-Client-Kern.

Erfuellt strukturell das ``SniffHelperChannel``-Protocol (``infrastructure/sni/
channel.py``): ``start`` / ``poll_hits`` / ``stop`` / ``is_running``. Schickt den
``START``-Befehl, sammelt die ``HIT``-Nachrichten ueber den Reader-Thread in eine
thread-sichere ``deque`` (``poll_hits`` leert sie).

ETAPPE 3b: Bis Etappe 2 lag dieselbe Logik in ``infrastructure/sni/helper_channel.py``
(``SubprocessSniffHelper``). Sie ist hierher gezogen, weil pcap/LLDP denselben Spawn-/
Connect-/Teardown-Kern (``_BaseSubprocessHelper``) brauchen. ``helper_channel.py``
bleibt als duenner Re-Export (``SubprocessSniffHelper = SniHelperClient``), damit die
bestehende SNI-Verdrahtung + die SNI-Tests UNVERAENDERT weiterlaufen.
"""

from collections import deque
from typing import Any

from infrastructure.sniffd.protocol import MessageType
from infrastructure.sniffd_client.base import _BaseSubprocessHelper


class SniHelperClient(_BaseSubprocessHelper):
    """``SniffHelperChannel`` ueber einen on-demand gespawnten Helfer-Subprozess.

    Der Reader-Thread liest die ``HIT``-Nachrichten in eine thread-sichere ``deque``
    (Lock); ``poll_hits`` leert sie. ``STOPPED``/``PONG``/``ERROR`` interessieren den
    Lese-Pfad nicht -- er zieht nur die Hits.
    """

    def __init__(self) -> None:
        super().__init__()
        self._hits: deque[dict[str, Any]] = deque()

    def start(self, interface: str | None) -> str | None:
        """Spawnt Helfer, connectet, schickt START. ``None`` bei Erfolg, sonst Fehlertext.

        Reihenfolge: Spawn/Connect/Send (gemeinsamer Kern) -> auf STARTED/ERROR warten
        -> Reader-Thread starten. Jeder Fehlschritt raeumt ab (``_cleanup``) und gibt
        einen ehrlichen Fehlertext zurueck -- KEIN Crash, KEINE stille Leer-Erfassung.
        """
        if self.is_running():
            return None  # bereits aktiv -- kein Doppelstart

        self._hits = deque()

        start_msg: dict[str, Any] = {"type": MessageType.START}
        if interface is not None:
            start_msg["interface"] = interface
        error = self._spawn_connect_send(start_msg, "SNI")
        if error is not None:
            return error

        reply = self._recv_reply_with_timeout()
        if reply is None:
            self._cleanup()
            return "SNI-Helfer beendete die Verbindung vor der START-Antwort"
        reply_type = reply.get("type")
        if reply_type == MessageType.ERROR:
            err = str(reply.get("error", "unbekannter Helfer-Fehler"))
            self._cleanup()
            return err
        if reply_type != MessageType.STARTED:
            self._cleanup()
            return f"SNI-Helfer antwortete unerwartet: {reply_type!r}"

        # Ab hier laeuft der Sniff im Helfer -- Reader-Thread fuer die HIT-Nachrichten.
        self._start_reader()
        return None

    def poll_hits(self) -> list[dict[str, Any]]:
        """Leert die interne Hit-deque und gibt die rohen Hit-dicts zurueck (thread-sicher)."""
        with self._lock:
            hits = list(self._hits)
            self._hits.clear()
        return hits

    def stop(self) -> None:
        """Stoppt Sniff + Helfer (idempotent): STOP best-effort, dann ``_cleanup``."""
        self._send({"type": MessageType.STOP})
        self._cleanup()

    def _handle_message(self, message: dict[str, Any]) -> None:
        """Reader-Hook: nur ``HIT``-Nachrichten landen in der deque (ohne ``type``)."""
        if message.get("type") == MessageType.HIT:
            hit = {k: v for k, v in message.items() if k != "type"}
            with self._lock:
                self._hits.append(hit)
