"""Ports der interfaces-Domaene: Vertrag fuer die Interface-Discovery.

Ein Vertrag:

* ``InterfaceDiscoveryPort`` -- liefert die aktuell vorhandenen Netzwerk-
  Interfaces als ROHE ``NetworkInterface``-Objekte. "Roh" heisst: ``name``/
  ``ipv4``/``gateway``/``is_up``/... sind vom Adapter gefuellt, aber die
  fachlichen Felder ``type``/``status``/``is_primary`` traegt der Adapter NICHT --
  die setzt der Use-Case (I.2) ueber die reinen Domaenen-Funktionen
  ``classify_type``/``classify_status``/``select_primary``. So bleibt die
  Klassifikation an EINER Stelle (Domaene), nicht im Adapter dupliziert.

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie settings/devices/
scanning). Die Vertragspruefung laeuft statisch ueber mypy und ueber die
Verdrahtung im Composition Root (``app.py``), nicht zur Laufzeit per ``isinstance``.

``discover`` ist ``async`` (Muster wie die scanning-I/O-Ports): die Discovery ruft
blockierendes System-Tooling (``ip``, ``/sys/class/net``). Der Adapter (I.3)
kapselt das ueber ``run_in_executor``, sodass die Port-Methode ``async`` bleibt --
der Use-Case sieht eine einheitlich asynchrone Schnittstelle.

Import von ``domain`` ist erlaubt -- der import-linter-Contract verbietet nur die
Gegenrichtung (domain -> ports) sowie Importe aus ``infrastructure``/``api``.
"""

from typing import Protocol

from domain.interfaces import NetworkInterface


class InterfaceDiscoveryPort(Protocol):
    """Discovery der aktuell vorhandenen Netzwerk-Interfaces (rohe Felder)."""

    async def discover(self) -> list[NetworkInterface]:
        """Aktuelle Interfaces als rohe ``NetworkInterface``-Liste.

        Roh = ohne die fachlichen Felder ``type``/``status``/``is_primary`` (die
        setzt der Use-Case ueber die Domaenen-Funktionen). Keine Interfaces
        gefunden (z. B. gestubbte Nicht-Linux-Plattform) -> ``[]``, niemals
        ``None`` -- ``[]`` ist der vertragliche Leer-Zustand, kein Fehler.

        Blockierendes System-Tooling im Adapter; ueber ``run_in_executor``
        gekapselt, die Methode bleibt ``async``.
        """
        ...
