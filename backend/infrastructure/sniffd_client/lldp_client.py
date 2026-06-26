"""``LldpHelperClient`` -- einmaliger, zeitbegrenzter LLDP/CDP-Sniff via Helfer.

Schickt ``START_LLDP{interface,duration}`` und wartet blockierend (mit Timeout etwas
groesser als ``duration``) auf die EINE ``NEIGHBORS``-Nachricht des Helfers; gibt die
rohe Nachbar-dict-Liste zurueck und raeumt den Helfer ab. KEIN Dauerstrom, KEIN
Reader-Thread -- es gibt genau eine Antwort, auf die der Aufrufer wartet.

S3-HEILUNG: Spawn-/Connect-/ERROR-Pfad gibt ``[]`` (statt Crash) zurueck; der Adapter
loggt das (wie das Original-``capture`` bei Sniff-Fehler ``[]`` lieferte). Die echte
Rechtepruefung passiert im Helfer ueber die START_LLDP-ERROR-Naht.

Da ``run_lldp_sniff`` im Helfer EINEN Thread aufspinnt und ERST nach Ablauf der
``duration`` die ``NEIGHBORS`` schickt, kann der Helfer auch ein ``ERROR`` (fehlendes
Recht) ODER ein idempotentes ``STARTED`` (bereits laufender Sniff) als erste Antwort
schicken -- beides ergibt hier ``[]`` (keine Nachbarn).
"""

from typing import Any

from infrastructure.sniffd.protocol import MessageType
from infrastructure.sniffd_client.base import _BaseSubprocessHelper

# Reserve auf die ``duration`` obendrauf (Spawn + Alive-Probe ~0.8 s + Sende-/
# Empfangs-Latenz). Der Helfer antwortet erst NACH der ``duration``.
_NEIGHBORS_TIMEOUT_MARGIN_SECS = 5.0


class LldpHelperClient(_BaseSubprocessHelper):
    """Einmal-LLDP/CDP-Client: START_LLDP -> warte auf NEIGHBORS -> list[dict]."""

    def capture(self, interface: str | None, duration: float) -> list[dict[str, Any]]:
        """Spawnt Helfer, schickt START_LLDP, wartet auf NEIGHBORS, gibt die Liste.

        Spawn-/Connect-/Befehls-Fehler -> ``[]`` (S3-frei: keine Nachbarn statt
        Crash). Antwortet der Helfer mit ``NEIGHBORS`` -> dessen Liste; mit ``ERROR``
        (fehlendes Recht) oder unerwartet (z. B. idempotentes ``STARTED``) -> ``[]``.
        Der Helfer wird in jedem Fall abgeraeumt (``_cleanup``).
        """
        start_msg: dict[str, Any] = {
            "type": MessageType.START_LLDP,
            "duration": duration,
        }
        if interface is not None:
            start_msg["interface"] = interface

        error = self._spawn_connect_send(start_msg, "LLDP")
        if error is not None:
            return []

        try:
            timeout = float(duration) + _NEIGHBORS_TIMEOUT_MARGIN_SECS
            reply = self._recv_reply_with_timeout(timeout)
            if reply is None or reply.get("type") != MessageType.NEIGHBORS:
                return []
            neighbors = reply.get("neighbors", [])
            if not isinstance(neighbors, list):
                return []
            return [n for n in neighbors if isinstance(n, dict)]
        except OSError:
            return []
        finally:
            self._cleanup()
