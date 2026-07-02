"""Best-effort Reverse-DNS (PTR) fuer die Ziel-Resolver-Aufloesung des DNS-Bypass-Berichts.

Streng fehlertolerant und mit HARTEM Timeout: ein haengender PTR-Lookup darf den Aufbau
des DNS-Umgehungs-Berichts / der Live-View NIE blockieren. Jeglicher Fehlschlag (kein
Eintrag, Timeout, Netz-/Resolver-Fehler) liefert ``None`` -- ein fehlender Name ist ein
gueltiger Leer-Zustand, KEIN Fehler (Muster ``ports.resolver.PtrResolverPort`` ->
``""``/``None`` statt zu werfen).

EIGENSTAENDIG (Scope Linux x64, aber ohne Fremd-Bindung): der Lookup laeuft ueber
``socket.gethostbyaddr`` (stdlib), gekapselt in ``run_in_executor`` mit
``asyncio.wait_for`` als hartem Timeout. KEIN ``modules``-Import, KEIN Import aus
``application``/``api`` (Contract "infrastructure kennt nicht application/api").

WARUM Timeout ueber ``wait_for`` statt ``socket.settimeout``: ``gethostbyaddr`` nutzt den
System-Resolver und beachtet den Socket-Default-Timeout NICHT zuverlaessig. Der
blockierende Aufruf laeuft daher im Executor-Thread; ``wait_for`` gibt nach Ablauf des
Timeouts ``None`` zurueck (der Thread laeuft im Hintergrund aus -- best-effort, harmlos).
"""

import asyncio
import socket

# Kurzer, harter Standard-Timeout (Sekunden): der Bericht-/View-Aufbau soll NIE an einem
# haengenden PTR-Lookup kleben. Bewusst < 1s (Auftrag): ein Name ist Beigabe, kein Muss.
_PTR_TIMEOUT_SECS = 0.8


def _lookup_sync(ip: str) -> str | None:
    """Synchroner PTR-Kern (laeuft im Executor-Thread) -- Name oder ``None``.

    ``socket.gethostbyaddr`` liefert ``(hostname, aliaslist, ipaddrlist)``; wir nehmen
    den Haupt-Hostnamen (ohne abschliessenden Punkt, falls vorhanden). Jeglicher Fehler
    (``socket.herror``/``socket.gaierror``/``OSError``) -> ``None`` (gueltiger Leer-Zustand).
    """
    try:
        hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
    except OSError:
        return None
    name = hostname.strip().rstrip(".")
    return name or None


async def reverse_dns_name(ip: str, timeout: float = _PTR_TIMEOUT_SECS) -> str | None:
    """Loest den PTR-Namen zur ``ip`` best-effort mit hartem Timeout -> Name oder ``None``.

    Der blockierende ``gethostbyaddr``-Aufruf laeuft im Executor-Thread (der Event-Loop
    bleibt frei); ``asyncio.wait_for`` erzwingt den Timeout. Timeout ODER jeglicher
    Fehler -> ``None`` (kein Crash, kein Blockieren). Eine leere/ungueltige ``ip`` faellt
    ebenfalls auf ``None`` (der Lookup schlaegt dann fehl).
    """
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _lookup_sync, ip),
            timeout=timeout,
        )
    except TimeoutError:
        # asyncio.wait_for wirft bei Ablauf TimeoutError (ab 3.11 = builtin TimeoutError).
        return None
