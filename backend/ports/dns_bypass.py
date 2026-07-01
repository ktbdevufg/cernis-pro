"""Port des DNS-Umgehungs-Waechters: der Vertrag fuer die Query-Quelle (ADR 0042).

Ein schlanker Protocol-Vertrag fuer die Quelle der DNS-Anfragen -- Muster wie die
schlanken Nahtstellen der Nachbar-Domaenen (nur Protocols/Typen, keine Impl).

``ports/`` kennt NUR ``domain.dns_bypass``-Typen + stdlib. KEIN ``modules``- und kein
``infrastructure``-Import (import-linter-Contract "ports kennen hoechstens domain"). Der
Import von ``domain.dns_bypass`` (``RawDnsQuery``) ist erlaubt.

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie blocklist/outbound_log/
monitoring). Die Vertragspruefung laeuft statisch ueber mypy und ueber die Verdrahtung im
Composition Root (``app.py``), nicht zur Laufzeit per ``isinstance``.
"""

from collections.abc import Sequence
from typing import Protocol

from domain.dns_bypass import RawDnsQuery

__all__ = ["DnsQueryProvider"]


class DnsQueryProvider(Protocol):
    """Liefert die aktuell vom Sniffer erkannten DNS-Anfragen (Snapshot).

    Quellen-AGNOSTISCH: gibt ``RawDnsQuery``-Records zurueck (KEIN Fremd-Domaenentyp). Die
    echte Quelle -- der ``DnsHelperClient``-poll (Etappe 1) -- faellt erst im Composition
    Root. Synchron, weil die echte Quelle ein lokaler Snapshot des zuletzt gepollten
    Standes ist.
    """

    def __call__(self) -> Sequence[RawDnsQuery]:
        """Aktuell vom Sniffer erkannte DNS-Anfragen (Snapshot)."""
        ...
