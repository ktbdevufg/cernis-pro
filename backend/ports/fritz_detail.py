"""Port der FritzBox-Detailansicht: Vertrag fuer den read-only Detail-Abruf.

Ein einziger Vertrag (``FritzDetailPort``) neben dem bestehenden
``FritzHostsPort`` (ports/scanning) -- bewusst getrennt: der Hosts-Port liefert
die DHCP-Hostliste fuer den Scan-Merge, dieser Port liefert den vollen
WAN/DSL/WLAN/Log/Portfreigaben-Schnappschuss fuer eine eigene Detailansicht.

``ports/`` kennt NUR ``domain/``-Typen + stdlib (import-linter). Der Import von
``domain.fritz_detail`` ist erlaubt -- verboten ist nur die Gegenrichtung sowie
Importe aus ``infrastructure``/``api``.

KEIN ``@runtime_checkable`` (Muster wie scanning/devices/settings): die
Vertragspruefung laeuft statisch ueber mypy und ueber die Verdrahtung im
Composition Root, nicht zur Laufzeit per ``isinstance``.
"""

from typing import Protocol

from domain.fritz_detail import FritzDetail


class FritzDetailPort(Protocol):
    """Read-only Detail-Schnappschuss einer FRITZ!Box (TR-064) -- optional.

    Liefert ein ``FritzDetail(reachable=False)``, wenn keine FRITZ!Box
    konfiguriert oder erreichbar ist -- "nicht konfiguriert/nicht erreichbar" ist
    ein legitimer Leer-Zustand, KEIN Fehler (ADR 0001: kein stiller unsicherer
    Fallback, aber der Leer-Zustand ist sauber modelliert). FALSCHE Credentials
    sind dagegen ein Fehler: der Adapter wirft dann eine ``FritzAuthError``
    (Muster wie ``FritzHostsPort``, S3-Logik).
    """

    async def get_detail(self) -> FritzDetail:
        """Voller FritzBox-Detailstatus, oder ``FritzDetail(reachable=False)``.

        TR-064 ist blockierend; der Adapter kapselt das ueber ``run_in_executor``,
        die Methode bleibt ``async``. Nicht erreichbar -> ``reachable=False``
        (Leer-Zustand). Auth-Fehler -> ``FritzAuthError`` (kein stilles Leer).
        """
        ...
