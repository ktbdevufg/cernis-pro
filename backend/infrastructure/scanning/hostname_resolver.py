"""Adapter fuer ``HostnameResolverPort`` -- Wrapper um ``modules.resolver``.

Zwei Wege, beide async-Vertrag, aber unterschiedlich gewrappt:

* ``resolve`` -> bevorzugt der injizierte ``PtrResolverPort`` (direkte DNS-Abfrage,
  cache-frei -- umgeht den negativen mDNSResponder-Cache auf macOS, der nach einem
  Scan minutenlang leere Ergebnisse liefert); ohne injizierten Resolver der
  bisherige Weg ``modules.resolve_hostname`` (``socket.gethostbyaddr`` im Executor
  mit Timeout) -- direkt awaiten.
* ``smb_info`` -> ``modules.get_smb_info`` ist SYNCHRON (blockierender
  ``subprocess``-Aufruf von ``nmblookup``) -- ueber ``run_in_executor`` kapseln,
  damit der Event-Loop nicht blockiert. Die Port-Methode bleibt ``async``.

Der ``PtrResolverPort`` wird vom Composition Root injiziert (app.py) -- dieser
Adapter importiert NICHT ``infrastructure.resolver``, er typisiert nur gegen den
Port-Vertrag (Standard-Richtung: infrastructure darf ports kennen).

Altmuster-Befunde (geprueft, beide unkritisch):

* KEINE Injection in ``get_smb_info``: ``nmblookup`` wird mit einer ARGUMENT-LISTE
  (``["nmblookup", "-A", ip]``) und OHNE ``shell=True`` aufgerufen -- ``ip`` ist
  ein Argument, kein interpolierter Shell-String. (Anders als die ``osascript``-
  Faelle S2, die hier nicht beruehrt werden.) Daher unveraendert wrappbar.
* Der ``except Exception: return ""`` / ``("", "")`` des Altcodes ist KEIN
  stiller Sicherheits-Fallback im Sinne von S3: "nicht aufloesbar" ist genau der
  vom Port vorgesehene Leer-Zustand (``""`` bzw. ``("", "")``), kein verdecktes
  Scheitern eines Sicherheitsschritts. Wird daher bewusst beibehalten -- auch fuer
  den PTR-Resolver-Weg (Timeout/Toolfehler -> ``""``, der Scan laeuft weiter).
"""

import asyncio

from modules.resolver import get_smb_info, resolve_hostname
from ports.resolver import PtrResolverPort

# Kurze Wartezeit vor dem EINEN Wiederholungsversuch, wenn die PTR-Antwort leer
# war (der Resolver kann in einem kurzen Loeschfenster stecken, waehrend er seinen
# lokalen Bestand neu schreibt). Konservativ, verlustfrei -- Muster wie
# ``mdns._RETRY_DELAY`` (Commit 6195758).
_PTR_RETRY_DELAY = 1.0


class HostnameResolverAdapter:
    """Erfuellt das ``HostnameResolverPort``-Protocol strukturell."""

    def __init__(self, ptr_resolver: PtrResolverPort | None = None) -> None:
        self._ptr_resolver = ptr_resolver

    async def _ptr_versuch(self, ip: str, timeout: float) -> str:
        """EIN PTR-Versuch ueber den injizierten Resolver -- Fehler/Timeout -> ``""``."""
        assert self._ptr_resolver is not None  # nur aus resolve() im ptr-Zweig gerufen
        try:
            name = await asyncio.wait_for(self._ptr_resolver.resolve_ptr(ip), timeout)
        except Exception:
            # Timeout/fehlendes Tool/Netzfehler -> Leerfall, kein Crash:
            # "nicht aufloesbar" ist der vom Port vorgesehene Leer-Zustand.
            return ""
        # FQDN-Trailing-Dot strippen -- konsistent zum gethostbyaddr-Weg.
        return str(name).rstrip(".")

    async def resolve(self, ip: str, timeout: float) -> str:
        """Reverse-DNS-Name zu ``ip``, oder ``""`` wenn nicht aufloesbar.

        Mit injiziertem ``PtrResolverPort`` laeuft die Abfrage direkt gegen den
        DNS-Server (cache-frei), in ``asyncio.wait_for(..., timeout)`` gekapselt,
        damit der interne Timeout des Resolvers (z.B. 10s ``dig``) NICHT die
        Enrich-Phase bestimmt. Bleibt die erste Antwort LEER (ehrliche
        Leer-Antwort, kein Fehler), wird GENAU EINMAL nach ``_PTR_RETRY_DELAY``
        wiederholt -- der Resolver kann in einem kurzen Loeschfenster stecken.
        Ohne Injektion der bisherige Weg ueber ``modules.resolve_hostname``
        (bereits async, Executor + Timeout intern; OHNE Retry).
        """
        if self._ptr_resolver is not None:
            name = await self._ptr_versuch(ip, timeout)
            if name == "":
                await asyncio.sleep(_PTR_RETRY_DELAY)
                name = await self._ptr_versuch(ip, timeout)
            return name
        # ``str(...)``: ``modules`` ist untypisiert (mypy ``follow_imports=skip``),
        # der Vertrag garantiert hier ``str`` -- der Adapter macht das explizit.
        return str(await resolve_hostname(ip, timeout))

    async def smb_info(self, ip: str) -> tuple[str, str]:
        """SMB-(Name, Domaene) von ``ip``; je ``""`` wenn unbekannt.

        ``modules.get_smb_info`` ist blockierend (``subprocess`` ``nmblookup``);
        ueber ``run_in_executor`` ausgelagert, damit der Event-Loop frei bleibt.
        """
        loop = asyncio.get_running_loop()
        # ``str(...)``: ``modules`` ist untypisiert (mypy ``follow_imports=skip``),
        # der Vertrag garantiert hier ``tuple[str, str]`` -- der Adapter macht das explizit.
        name, domain = await loop.run_in_executor(None, get_smb_info, ip)
        return (str(name), str(domain))
