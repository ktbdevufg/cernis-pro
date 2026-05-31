"""Adapter fuer ``FritzHostsPort`` -- Wrapper um ``modules.fritzbox.FritzBox``.

``FritzBox.get_hosts`` ist SYNCHRON (blockierender TR-064/SOAP-Aufruf) -- ueber
``run_in_executor`` kapseln, damit der Event-Loop nicht blockiert. Die
Port-Methode bleibt ``async`` (Muster wie smb_info S.4b / nmap S.4c).

Host/User/Passwort werden im KONSTRUKTOR injiziert -- der Adapter baut die
``FritzBox``-Instanz mit genau diesen Werten. Die Verdrahtung (Werte aus den
Settings ziehen) passiert im Composition Root (``app.py``, S.6), nicht hier.

BEWUSST NICHT uebernommen: die ``detect_fritzbox``-Auto-Detection aus dem Altcode.

Sicherheitsbefund (benannt, NICHT reproduziert -- S4-Familie "unsichere Defaults"):

* ``modules.fritzbox.detect_fritzbox`` probiert bei der Suche hartkodierte
  Default-Adressen (``"fritz.box"``, ``"192.168.178.1"``, ``"192.168.1.1"``,
  ``"192.168.0.1"``) und scannt aktiv Port 49000 dieser Ziele. Das ist
  Netzwerk-Probing mit fest verdrahteten Zielen -- gehoert NICHT in einen
  reinen TR-064-Wrapper und wird hier bewusst nicht eingezogen. Der Adapter
  bekommt seine Zieladresse ausschliesslich injiziert. (Kein hartkodiertes
  Passwort im Spiel: ``FritzBox``-Default ist ``user=""``/``password=""``, also
  kein klassisches S4-Credential-Default -- nur die Adress-Defaults sind das
  Finding.)

Fehlerbehandlung -- zwei klar getrennte Faelle (Logik wie ``NmapScanError``, S.4c):

* Box nicht erreichbar / Verbindungsfehler -> ``FritzBox.get_hosts`` faengt das
  im ``_connect``-Pfad ab und liefert ``[]``. Das ist der vertragliche
  "keine/nicht erreichbare Box"-Leer-Zustand (Port: ``[]`` ohne konfigurierte
  Box), KEIN Fehler -- so durchgereicht.
* FALSCHE Credentials -> ``modules.fritzbox._safe_call`` RE-RAISED
  ``FritzAuthorizationError`` (statt sie wie andere Fehler zu ``{}`` zu
  schlucken); aus ``get_hosts`` schlaegt sie durch (der Auth-Fehler faellt beim
  ``GetHostNumberOfEntries`` an, NACH dem ``_connect``-try). Der Adapter faengt
  sie und wirft eine eigene ``FritzAuthError`` MIT ``host``-Bezug
  (diagnostizierbar). KEIN stilles Verschlucken zu ``[]``: falsche Credentials
  sind ein Fehler, NICHT "keine Box" (S3-Logik wie beim nmap-Fix).
"""

import asyncio
from typing import Any

from domain.scanning import DiscoveredHost
from modules.fritzbox import FritzAuthorizationError as _RawFritzAuthError
from modules.fritzbox import FritzBox


class FritzAuthError(Exception):
    """FRITZ!Box-Authentifizierung gescheitert (falsche/fehlende Credentials).

    Uebersetzt ``modules.fritzbox.FritzAuthorizationError`` in einen eigenen
    Domaenen-/Adapter-Fehler MIT ``host``-Bezug. Ersetzt das stille Verschlucken
    zu ``[]``: falsche Credentials sind ein Fehler, NICHT "keine Box" (Logik wie
    ``NmapScanError`` aus S.4c, Finding S3).
    """

    def __init__(self, host: str) -> None:
        self.host = host
        super().__init__(f"FRITZ!Box {host!r}: Authentifizierung gescheitert (Credentials pruefen)")


def _to_domain(raw: Any) -> DiscoveredHost:
    """FritzBox-Host-dict -> ``domain.DiscoveredHost``.

    ``raw`` ist ein ``dict`` aus ``FritzBox.get_hosts`` (``ip``/``mac``/
    ``hostname``/``active``/``interface``). Uebernommen werden ``ip``/``mac``;
    ``source="fritzbox"`` markiert die Herkunft. ``hostname``/``active``/
    ``interface`` haben kein ``DiscoveredHost``-Feld und werden bewusst verworfen
    (die Hostname-Anreicherung passiert spaeter ueber den Resolver/Use-Case).
    """
    return DiscoveredHost(
        ip=str(raw.get("ip", "")),
        mac=str(raw.get("mac", "")),
        source="fritzbox",
    )


class FritzHostsAdapter:
    """Erfuellt das ``FritzHostsPort``-Protocol strukturell (TR-064)."""

    def __init__(self, host: str, user: str = "", password: str = "", port: int = 49000) -> None:
        self._host = host
        self._user = user
        self._password = password
        self._port = port

    async def get_hosts(self) -> list[DiscoveredHost]:
        """Bekannte Hosts der FRITZ!Box, oder ``[]`` ohne erreichbare Box.

        Blockierender TR-064-Aufruf -> ``run_in_executor``. Verbindungsfehler ->
        ``[]`` (vertraglicher Leer-Zustand). Auth-Fehler -> ``FritzAuthError``
        (siehe Modul-Docstring, Finding S3).
        """
        loop = asyncio.get_running_loop()
        try:
            raw_hosts = await loop.run_in_executor(None, self._fetch)
        except _RawFritzAuthError as exc:
            raise FritzAuthError(self._host) from exc
        return [_to_domain(h) for h in raw_hosts]

    def _fetch(self) -> list[Any]:
        """Synchroner TR-064-Aufruf (laeuft im Executor, nicht im Loop-Thread)."""
        box = FritzBox(self._host, port=self._port, user=self._user, password=self._password)
        result: list[Any] = box.get_hosts()
        return result
