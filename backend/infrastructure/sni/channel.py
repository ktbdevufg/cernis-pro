"""Spawn-Naht des SNI-Adapters: das schmale ``SniffHelperChannel``-Protocol.

Etappe 2 (Privilege-Separation): ``ScapySniSniffer`` faehrt scapy NICHT mehr selbst,
sondern spricht den on-demand gestarteten Helfer (``cernis-sniffd``) ueber AF_UNIX-IPC
an. Damit der Adapter OHNE echten Subprozess testbar bleibt, liegt zwischen Adapter
und Subprozess diese schmale Naht: der Adapter kennt nur das ``SniffHelperChannel``-
Protocol, die echte Implementierung (``SubprocessSniffHelper``) lebt in
``helper_channel.py``, die Tests injizieren einen Fake.

Das Protocol kapselt GENAU das, was der Adapter braucht -- den rohen Sniff-Lifecycle
(start/stop/is_running) plus den Hit-Abruf (poll_hits). Die teure Zuordnung
(psutil-Poller, ``match_snapshot``, Prozessname) bleibt im Adapter; ueber diese Naht
gehen nur die ROHEN Hit-dicts.

KEIN ``@runtime_checkable`` (Muster wie ``ports.sni``): die Vertragspruefung laeuft
statisch ueber mypy und ueber die Verdrahtung (``channel_factory`` im Adapter), nicht
zur Laufzeit per ``isinstance``.
"""

from typing import Any, Protocol


class SniffHelperChannel(Protocol):
    """Schmale Naht zum Sniff-Helfer-Subprozess (rohe Hits, kein Zuordnungs-Wissen)."""

    def start(self, interface: str | None) -> str | None:
        """Startet Helfer + Sniff. ``None`` bei Erfolg, sonst der Fehlertext.

        Spawnt (falls noetig) den Helfer-Prozess, verbindet ueber AF_UNIX und schickt
        die START-Nachricht. Antwortet der Helfer mit STARTED -> ``None`` (Erfolg);
        antwortet er mit ERROR (z. B. fehlendes ``CAP_NET_RAW``, scapy/Geraet kaputt)
        -> der Fehlertext (der Adapter macht daraus die SniError-/Permission-Naht).
        Auch ein gescheiterter Spawn/Connect liefert einen EHRLICHEN Fehlertext (kein
        Crash, S3-frei) -- NIE eine stille Leer-Erfassung.

        ``interface`` ``None`` -> der Helfer ermittelt das Ausgangs-Interface selbst.
        """
        ...

    def poll_hits(self) -> list[dict[str, Any]]:
        """Leert die seit dem letzten Aufruf eingegangenen rohen Hit-dicts und gibt sie.

        Jeder Hit ist die Wire-Form des Helfers:
        ``{hostname, remote_ip, remote_port, monotonic_ts}``. Keine neuen Hits -> ``[]``,
        niemals ``None``. Thread-sicher (der Reader-Thread schreibt, der Adapter-Poller
        liest).
        """
        ...

    def stop(self) -> None:
        """Stoppt Sniff + Helfer (idempotent): STOP senden, Reader/Socket/Subprozess
        beenden, Socket-Verzeichnis entfernen. Kein laufender Helfer -> No-op.
        """
        ...

    def is_running(self) -> bool:
        """``True``, solange der Helfer-Subprozess lebt UND der Reader-Thread aktiv ist."""
        ...
