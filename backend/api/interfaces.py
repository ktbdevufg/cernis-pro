"""FastAPI-Router der interfaces-Domaene (v2, I.3), Route ``GET /api/interfaces``.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich den Use-Case aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter und
``domain``-Typen werden hier NICHT importiert -- der Use-Case kommt per
FastAPI-Dependency herein (Verdrahtung im Composition Root ``app.py``), und das
``NetworkInterface`` wird ueber Attribut-Zugriff zu JSON serialisiert (Typ ``Any``,
Muster wie ``api/devices._device_to_dict``).

Loest den fruheren Uebergangs-Endpunkt in ``api/system.py`` ab. Die Wire-Form
bleibt rueckwaertskompatibel (das Frontend laeuft unveraendert): dieselben
Pflichtfelder + die aus ``ipv4``/``ipv4_prefix`` ABGELEITETEN Anzeige-Felder
(``subnet_cidr``/``network``/``broadcast``; ``network_cidr``/``host_count`` traegt
die Domaene). ADDITIV neu: ``is_primary``/``type``/``status`` -- serverseitig
bestimmt (ersetzt das Frontend-Raten).

ENTFALLEN ggue. der Kruecke: ``hw_type``/``hw_icon`` -- das Frontend liest sie
nachweislich nicht (Block 6); Sprache statt Symbole (I.1).
"""

import ipaddress
from typing import Annotated, Any

from fastapi import APIRouter, Depends

from application.interfaces import ListInterfaces

router = APIRouter(prefix="/api", tags=["interfaces"])


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit dem
# echten Use-Case verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler.
def provide_list_interfaces() -> ListInterfaces:
    raise NotImplementedError("ListInterfaces wird in app.py verdrahtet")


def _interface_to_dict(iface: Any) -> dict[str, Any]:
    # iface ist ein domain.NetworkInterface; bewusst als Any behandelt, damit api
    # den domain-Ring nicht importiert (import-linter). None bleibt None (das FE
    # behandelt fehlende Werte). is_primary/type/status sind additiv.
    data: dict[str, Any] = {
        "name": iface.name,
        "ipv4": iface.ipv4,
        "ipv4_prefix": iface.ipv4_prefix,
        "ipv6_link_local": iface.ipv6_link_local,
        "ipv6_global": iface.ipv6_global,
        "mac": iface.mac,
        "gateway": iface.gateway,
        "mtu": iface.mtu,
        "is_up": iface.is_up,
        "is_loopback": iface.is_loopback,
        "network_cidr": iface.network_cidr,
        "host_count": iface.host_count,
        "is_primary": iface.is_primary,
        "type": iface.type,
        "status": iface.status,
    }
    # Ableitbare Anzeige-Felder (Wire-Kompat): subnet_cidr/network/broadcast aus
    # ipv4/ipv4_prefix. network_cidr kommt aus der Domaene -- hier nur die
    # zusaetzlichen Felder, die die Domaene bewusst nicht fuehrt (ableitbare Anzeige).
    if iface.ipv4 and iface.ipv4_prefix is not None:
        data["subnet_cidr"] = f"{iface.ipv4}/{iface.ipv4_prefix}"
        try:
            network = ipaddress.ip_interface(data["subnet_cidr"]).network
            data["network"] = str(network)
            data["broadcast"] = str(network.broadcast_address)
        except ValueError:
            data["network"] = ""
            data["broadcast"] = ""
    return data


@router.get("/interfaces")
async def list_interfaces(
    list_interfaces_uc: Annotated[ListInterfaces, Depends(provide_list_interfaces)],
) -> list[dict[str, Any]]:
    """Netzwerk-Interfaces, fachlich angereichert (``type``/``status``/``is_primary``).

    Liefert die bestehende Wire-Form (``name``/``ipv4``/``ipv4_prefix``/``mac``/
    ``gateway``/``ipv6_link_local``/``mtu``/``host_count``/``network_cidr`` u. a.,
    plus abgeleitete ``subnet_cidr``/``network``/``broadcast``) -- ergaenzt um die
    serverseitige Klassifikation. Loest den Uebergangs-Endpunkt ab.
    """
    interfaces = await list_interfaces_uc()
    return [_interface_to_dict(iface) for iface in interfaces]
