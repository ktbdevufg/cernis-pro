"""Use-Cases der interfaces-Domaene.

Orchestrieren die Domaene (``classify_type``/``classify_status``/``select_primary``/
``mark_primary``) + den Port (``InterfaceDiscoveryPort``). Kennen ``domain/`` und
``ports/``, NIEMALS ``infrastructure/`` (maschinell per import-linter erzwungen).
Der Port kommt per Constructor-Injection als Protocol-Typ herein -- nie ein
konkreter Adapter. Kein State ueber Aufrufe, keine Framework-Imports.

Hier wandert die Klassifikation strukturell ins Backend: HEUTE raet das Frontend
(``App.jsx``) das primaere Interface und der Uebergangs-Adapter haengt Icons an.
``ListInterfaces`` macht beides serverseitig und deterministisch -- das Frontend
liest danach nur noch ``type``/``status``/``is_primary``.
"""

from dataclasses import replace

from domain.interfaces import (
    NetworkInterface,
    classify_status,
    classify_type,
    mark_primary,
    select_primary,
)
from ports.interfaces import InterfaceDiscoveryPort


class ListInterfaces:
    """Listet Interfaces, fachlich angereichert + Primary markiert.

    Sequenz: rohe Interfaces ueber den Port holen -> je Interface ``type`` und
    ``status`` ueber die reinen Domaenen-Funktionen setzen -> das primaere
    Interface bestimmen (``select_primary``, deterministisch) und die
    ``is_primary``-Flags konsistent setzen (``mark_primary``). Die
    Eingangsreihenfolge des Adapters bleibt erhalten.

    Leere Discovery -> leere Liste (kein Fehler): ``select_primary`` liefert dann
    ``None``, ``mark_primary`` markiert nichts -- alles ueber I.1-Tests abgedeckt.
    """

    def __init__(self, discovery: InterfaceDiscoveryPort) -> None:
        self._discovery = discovery

    async def __call__(self) -> list[NetworkInterface]:
        raw = await self._discovery.discover()
        enriched = [
            replace(
                iface,
                # Einen vom Adapter bereits klassifizierten Typ (!= unknown, z. B.
                # Windows via IfType) ERHALTEN; nur einen noch unbestimmten Typ
                # (unknown) ueber die namensbasierte classify_type nachbestimmen.
                type=iface.type if iface.type != "unknown" else classify_type(iface.name),
                status=classify_status(iface.is_up, iface.ipv4 is not None),
            )
            for iface in raw
        ]
        primary_name = select_primary(enriched)
        return mark_primary(enriched, primary_name)
