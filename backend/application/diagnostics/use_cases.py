"""Use-Cases der diagnostics-Domaene -- DNS-Aufloesung + traceroute + Rechte-Naht.

Orchestrieren die Ports (``DnsResolver``/``TracerouteRunner``/
``TraceroutePermissionPort``). Kennen ``domain/`` und ``ports/``, NIEMALS
``infrastructure/`` (maschinell per import-linter erzwungen). Ports kommen per
Constructor-Injection als Protocol-Typ herein -- nie ein konkreter Adapter.

Drei Use-Cases (duenn, Muster ``ListProcesses``/``CheckProcessPermission``):

* ``ResolveDns`` -- duenner Lese-Pass-Through ueber den ``DnsResolver``.
* ``RunTraceroute`` -- duenner Pass-Through ueber den ``TracerouteRunner`` (die
  ``privileged``-Wahl reicht der Use-Case unveraendert durch -- bewusste Nutzerwahl).
* ``CheckTraceroutePermission`` -- die ``{ok, error}``-Rechte-Naht (Muster
  ``CheckProcessPermission``): ``is_available`` -> ``check_permission`` -> dict. Hier
  bedeutet ``ok=True``: die privilegierte (genauere) Methode ist verfuegbar; ``ok=False``
  + Text: nur die unprivilegierte (ungenauere) Methode, mit Begruendung.
"""

from collections.abc import Sequence

from domain.diagnostics import DnsRecordType, DnsResult, TracerouteResult
from ports.diagnostics import DnsResolver, TraceroutePermissionPort, TracerouteRunner


class ResolveDns:
    """DNS-Aufloesung: duenner Lese-Pass-Through ueber den ``DnsResolver``.

    Duenn (Muster ``ListProcesses.flat``): die Abfrage ueber den Resolver durchreichen,
    keine eigene Logik. Keine Antwort (leere ``records``) ist KEIN Fehler -- der Resolver
    liefert ein ``DnsResult`` mit leeren ``records``.
    """

    def __init__(self, resolver: DnsResolver) -> None:
        self._resolver = resolver

    async def __call__(self, query: str, types: Sequence[DnsRecordType]) -> DnsResult:
        """Loest ``query`` fuer die angefragten ``types`` auf (duenner Pass-Through)."""
        return await self._resolver.resolve(query, types)


class RunTraceroute:
    """traceroute: duenner Pass-Through ueber den ``TracerouteRunner``.

    Duenn (Muster ``ListProcesses.flat``): die Messung ueber den Runner durchreichen. Die
    ``privileged``-Wahl wird UNVERAENDERT weitergegeben -- bewusste Nutzerwahl, kein
    Default-Raten und keine Selbst-Eskalation (privileged laeuft nur, wenn der Prozess die
    Rechte ohnehin hat; sonst meldet der Runner ehrlich die unprivilegierte Methode).
    """

    def __init__(self, runner: TracerouteRunner) -> None:
        self._runner = runner

    async def __call__(self, target: str, privileged: bool) -> TracerouteResult:
        """Misst den Pfad zu ``target`` (duenner Pass-Through; ``privileged`` durchgereicht)."""
        return await self._runner.run(target, privileged)


class CheckTraceroutePermission:
    """Rechte-Naht wie process: is_available -> check_permission -> {ok, error}.

    Duenn (Muster ``CheckProcessPermission``): prueft Verfuegbarkeit (Binary da?) und dann
    die Methoden-Tiefe (``check_permission``) ueber den Rechte-Port und gibt die
    ``{ok, error}``-Form zurueck. Hier bedeutet ``ok=True``: die privilegierte (genauere)
    Methode ist verfuegbar (Root); ``ok=False`` + Text: nur die unprivilegierte
    (ungenauere) Methode, mit Begruendung. Der api-Rand reicht die Form unveraendert durch.
    """

    def __init__(self, permission: TraceroutePermissionPort) -> None:
        self._permission = permission

    def __call__(self) -> dict[str, object]:
        """``{"ok": True, "error": ""}`` bei moeglicher Root-Methode, sonst ``ok=False`` + Grund.

        ``is_available`` False -> Binary nicht nutzbar (``traceroute`` fehlt). Sonst
        ``check_permission``: ein nicht-leerer Text ist die Begruendung (genauere Methode
        braucht Root) -> ``ok=False`` (nur unprivilegierte Methode). ``None`` -> die
        privilegierte (genauere) Methode ist moeglich.
        """
        if not self._permission.is_available():
            return {
                "ok": False,
                "error": "Das Programm 'traceroute' ist auf dieser Plattform nicht verfuegbar.",
            }
        text = self._permission.check_permission()
        return {"ok": text is None, "error": text or ""}

    def is_available(self) -> bool:
        """Reiner Verfuegbarkeits-Check (fuer einen spaeteren ``/available``-Pfad)."""
        return self._permission.is_available()

    def check_permission(self) -> str | None:
        """Rechte-Begruendung oder ``None`` (fuer einen spaeteren ``permission_error``)."""
        return self._permission.check_permission()
