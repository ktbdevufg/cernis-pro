"""Re-Export der SNI-Helfer-Naht -- die Logik lebt seit Etappe 3b in ``sniffd_client``.

ETAPPE 3b (Channel-Naht-Verallgemeinerung): Der gemeinsame Spawn-/Connect-/Teardown-
Kern und die drei Helfer-Clients (SNI/pcap/LLDP) liegen jetzt unter
``infrastructure/sniffd_client/`` -- EINE Heimat statt SNI-spezifischem Duplikat.

Diese Datei bleibt als duenne Re-Export-Schicht erhalten, damit die bestehende
SNI-Verdrahtung (``sni_sniffer.py``) und die SNI-Tests UNVERAENDERT weiterlaufen:
``SubprocessSniffHelper`` ist ein Alias auf ``SniHelperClient`` (verhaltensgleich),
``helper_entry_exists`` / ``_spawn_command`` / ``_is_frozen`` kommen aus dem
gemeinsamen ``sniffd_client.base``.
"""

from infrastructure.sniffd_client.base import (
    _HELPER_BINARY_NAME,
    _is_frozen,
    _spawn_command,
    helper_entry_exists,
)
from infrastructure.sniffd_client.sni_client import SniHelperClient

# Naht-Treue zur Etappe-2-Verdrahtung: ``ScapySniSniffer`` baut per Default eine
# ``SubprocessSniffHelper`` -- der Name bleibt als Alias auf den umbenannten Client.
SubprocessSniffHelper = SniHelperClient

__all__ = [
    "_HELPER_BINARY_NAME",
    "SniHelperClient",
    "SubprocessSniffHelper",
    "_is_frozen",
    "_spawn_command",
    "helper_entry_exists",
]
