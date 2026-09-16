"""Use-Cases der process-Domaene -- Prozess-Sicht (flach/Baum) + Rechte-Naht.

Orchestrieren die reine Domaene (``build_process_tree``) + die Ports
(``ProcessProvider``/``ProcessPermissionPort``). Kennen ``domain/`` und ``ports/``,
NIEMALS ``infrastructure/`` (maschinell per import-linter erzwungen). Ports kommen per
Constructor-Injection als Protocol-Typ herein -- nie ein konkreter Adapter.

Zwei Use-Cases:

* ``ListProcesses`` -- Stufe 1: Prozesse holen, wahlweise flach (``flat``) oder als
  deterministischer Wald (``tree`` ueber ``build_process_tree``). Duenner Lese-Pass-
  Through ueber den Provider.
* ``CheckProcessPermission`` -- die ``{ok, error}``-Rechte-Naht (Muster traffic
  ``CheckTrafficPermission``): ``is_available`` -> ``check_permission`` -> dict. Der
  api-Rand uebersetzt ``ok=False`` spaeter in 403.
"""

from domain.process import ProcessInfo, ProcessNode, build_process_tree
from ports.process import ProcessPermissionPort, ProcessProvider


class ListProcesses:
    """Stufe 1: Prozesse holen, flach oder als deterministischer Wald.

    Duenn (Muster ``ListInterfaces``/``ListAppTraffic``): rohe Prozesse ueber den
    Provider holen; ``flat`` gibt sie unveraendert zurueck, ``tree`` leitet sie durch
    ``build_process_tree`` (ppid-Wald, deterministisch nach pid sortiert). Keine eigene
    Logik ausser dem Aufruf der Domaene. Leere Prozess-Sicht -> ``[]`` bzw. ``()`` (kein
    Fehler).
    """

    def __init__(self, provider: ProcessProvider) -> None:
        self._provider = provider

    async def flat(self) -> list[ProcessInfo]:
        """Stufe 1: flache Prozessliste (duenner Lese-Pass-Through)."""
        return await self._provider.list_processes()

    async def tree(self) -> tuple[ProcessNode, ...]:
        """Prozesse als deterministischer Wald (``domain.build_process_tree``)."""
        processes = await self._provider.list_processes()
        return build_process_tree(processes)


class CheckProcessPermission:
    """Rechte-Naht wie traffic: is_available -> check_permission -> {ok, error}.

    Duenn (Muster traffic ``CheckTrafficPermission`` + capture ``StartCapture``): prueft
    Verfuegbarkeit (Tooling/Plattform da?) und dann die Sicht-Tiefe
    (``check_permission``) ueber den Rechte-Port und gibt die ``{ok, error}``-Form
    zurueck. Der api-Rand uebersetzt ``ok=False`` spaeter in 403.
    """

    def __init__(self, permission: ProcessPermissionPort) -> None:
        self._permission = permission

    def __call__(self) -> dict[str, object]:
        """``{"ok": True, "error": ""}`` bei voller Sicht, sonst ``ok=False`` + Grund.

        ``is_available`` False -> Quelle nicht nutzbar (Plattform/Tooling fehlt).
        Sonst ``check_permission``: ein nicht-leerer Text ist die Rechte-Begruendung
        (z. B. "als Root starten") -> ``ok=False`` (Router uebersetzt das in 403).
        ``None`` -> volle Sicht moeglich.
        """
        if not self._permission.is_available():
            return {
                "ok": False,
                "error": "Die Prozess-Quelle ist auf dieser Plattform nicht verfuegbar.",
            }
        text = self._permission.check_permission()
        return {"ok": text is None, "error": text or ""}

    def is_available(self) -> bool:
        """Reiner Verfuegbarkeits-Check (fuer einen spaeteren ``/available``-Pfad)."""
        return self._permission.is_available()

    def check_permission(self) -> str | None:
        """Rechte-Begruendung oder ``None`` (fuer einen spaeteren ``permission_error``)."""
        return self._permission.check_permission()
