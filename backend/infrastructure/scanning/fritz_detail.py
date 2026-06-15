"""Adapter fuer ``FritzDetailPort`` -- Wrapper um ``modules.fritzbox.FritzBox``.

EXAKT das Muster des ``FritzHostsAdapter`` (fritz_hosts.py): die v1-Methoden sind
SYNCHRON (blockierende TR-064/SOAP-Aufrufe) -- ueber ``run_in_executor`` gekapselt,
damit der Event-Loop nicht blockiert. Die Port-Methode bleibt ``async``.

Host/User/Passwort werden im KONSTRUKTOR injiziert; die Verdrahtung (Werte aus den
Settings/dem SecretStore ziehen) passiert im Composition Root (``app.py``).

Wiederverwendete v1-Methoden (modules/fritzbox.py, NICHT veraendert):
``FritzBox.get_status()`` (-> ``FritzStatus``), ``.get_wlan_clients()``,
``.get_log(limit)``, ``.get_port_forwardings()``.

Fehlerbehandlung -- dieselben zwei getrennten Faelle wie fritz_hosts:

* Box nicht erreichbar -> ``get_status`` faengt den Verbindungsfehler selbst ab
  und liefert ``FritzStatus(reachable=False)`` -> daraus ``FritzDetail(
  reachable=False)`` (vertraglicher Leer-Zustand), Rest leer. KEIN Fehler.
* FALSCHE Credentials -> ``modules.fritzbox._safe_call`` re-raised
  ``FritzAuthorizationError`` (aus ``DeviceInfo1/GetInfo`` heraus); der Adapter
  faengt sie und wirft die GEMEINSAME ``FritzAuthError`` (aus ``fritz_hosts``
  importiert -- KEIN zweiter gleichnamiger Typ) MIT ``host``-Bezug.

Die ``_fiber_raw``-Debug-Heuristik aus dem v1-Code wird NICHT angefasst -- gelesen
werden nur die finalen kbps-Felder aus ``FritzStatus``.
"""

import asyncio
from typing import Any

from domain.fritz_detail import (
    FritzDetail,
    FritzDeviceInfo,
    FritzDslStatus,
    FritzLogEntry,
    FritzPortForwarding,
    FritzWanStatus,
    FritzWlanBand,
    FritzWlanClient,
)

# Den GEMEINSAMEN Auth-Fehlertyp aus fritz_hosts wiederverwenden (kein zweiter,
# gleichnamiger Typ) -- der api-Ring/Composition Root faengt genau diesen.
from infrastructure.scanning.fritz_hosts import FritzAuthError
from modules.fritzbox import FritzAuthorizationError as _RawFritzAuthError
from modules.fritzbox import FritzBox

# Wie viele Log-Zeilen die Detailansicht maximal zieht (v1-Default-Niveau).
_LOG_LIMIT = 80


class FritzDetailAdapter:
    """Erfuellt das ``FritzDetailPort``-Protocol strukturell (TR-064, read-only)."""

    def __init__(self, host: str, user: str = "", password: str = "", port: int = 49000) -> None:
        self._host = host
        self._user = user
        self._password = password
        self._port = port

    async def get_detail(self) -> FritzDetail:
        """Voller Detailstatus, oder ``FritzDetail(reachable=False)`` ohne Box.

        Blockierende TR-064-Aufrufe -> ``run_in_executor``. Verbindungsfehler ->
        ``reachable=False`` (Leer-Zustand). Auth-Fehler -> ``FritzAuthError``.
        """
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(None, self._fetch)
        except _RawFritzAuthError as exc:
            raise FritzAuthError(self._host) from exc

    def _fetch(self) -> FritzDetail:
        """Synchroner TR-064-Aufruf + Projektion (laeuft im Executor, nicht im Loop)."""
        box = FritzBox(self._host, port=self._port, user=self._user, password=self._password)
        status = box.get_status()

        # Nicht erreichbar -> Leer-Zustand mit host; Sub-Objekte bleiben Default.
        # (Auth-Fehler schlaegt schon in get_status als FritzAuthorizationError
        # durch und wird in get_detail gefangen -- hier kommt status.reachable=True
        # mit auth_error nur an, wenn get_status den Fehler intern zu auth_error=True
        # gewandelt haette; aktuell re-raised _safe_call, daher robust beides tragen.)
        if not status.reachable:
            return FritzDetail(reachable=False, host=status.host or self._host)

        detail = FritzDetail(
            reachable=True,
            host=status.host or self._host,
            auth_error=status.auth_error,
            device=FritzDeviceInfo(
                model=status.model,
                firmware=status.firmware,
                is_fiber=status.is_fiber,
                total_hosts=status.total_hosts,
            ),
            wan=FritzWanStatus(
                connected=status.wan_connected,
                uptime_secs=status.wan_uptime_secs,
                ip_external=status.wan_ip_external,
                ip_external_v6=status.wan_ip_external_v6,
                upstream_kbps=status.wan_upstream_kbps,
                downstream_kbps=status.wan_downstream_kbps,
                bytes_sent=status.wan_bytes_sent,
                bytes_recv=status.wan_bytes_recv,
            ),
            dsl=FritzDslStatus(
                sync=status.dsl_sync,
                downstream_kbps=status.dsl_downstream_kbps,
                upstream_kbps=status.dsl_upstream_kbps,
                snr_downstream=status.dsl_snr_downstream,
                snr_upstream=status.dsl_snr_upstream,
                attn_downstream=status.dsl_attn_downstream,
                attn_upstream=status.dsl_attn_upstream,
            ),
            wlan_24=FritzWlanBand(
                enabled=bool(status.wlan_24_enabled),
                ssid=status.wlan_24_ssid,
                channel=status.wlan_24_channel,
                clients=status.wlan_24_clients,
            ),
            wlan_5=FritzWlanBand(
                enabled=bool(status.wlan_5_enabled),
                ssid=status.wlan_5_ssid,
                channel=status.wlan_5_channel,
                clients=status.wlan_5_clients,
            ),
            wlan_clients=self._wlan_clients(box),
            log=self._log(box),
            port_forwardings=self._port_forwardings(box),
        )
        return detail

    def _wlan_clients(self, box: Any) -> tuple[FritzWlanClient, ...]:
        """v1-``FritzWlanClient``-Objekte -> domain-``FritzWlanClient`` (Feld fuer Feld)."""
        return tuple(
            FritzWlanClient(
                mac=c.mac,
                ip=c.ip,
                hostname=c.hostname,
                signal_dbm=c.signal_dbm,
                speed_mbps=c.speed_mbps,
                band=c.band,
            )
            for c in box.get_wlan_clients()
        )

    def _log(self, box: Any) -> tuple[FritzLogEntry, ...]:
        """v1-``FritzLogEntry``-Objekte -> domain-``FritzLogEntry``."""
        return tuple(
            FritzLogEntry(id=e.id, timestamp=e.timestamp, message=e.message)
            for e in box.get_log(limit=_LOG_LIMIT)
        )

    def _port_forwardings(self, box: Any) -> tuple[FritzPortForwarding, ...]:
        """v1-Portforwarding-dicts -> domain-``FritzPortForwarding`` (``duration`` verworfen)."""
        return tuple(
            FritzPortForwarding(
                enabled=bool(r.get("enabled", False)),
                description=str(r.get("description", "")),
                protocol=str(r.get("protocol", "")),
                external_port=int(r.get("external_port", 0) or 0),
                internal_ip=str(r.get("internal_ip", "")),
                internal_port=int(r.get("internal_port", 0) or 0),
            )
            for r in box.get_port_forwardings()
        )
