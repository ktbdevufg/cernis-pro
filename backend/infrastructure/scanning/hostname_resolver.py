"""Adapter fuer ``HostnameResolverPort`` -- Wrapper um ``modules.resolver``.

Zwei Wege, beide async-Vertrag, aber unterschiedlich gewrappt:

* ``resolve`` -> ``modules.resolve_hostname`` ist bereits ``async`` (kapselt
  ``socket.gethostbyaddr`` selbst im Executor mit Timeout) -- direkt awaiten.
* ``smb_info`` -> ``modules.get_smb_info`` ist SYNCHRON (blockierender
  ``subprocess``-Aufruf von ``nmblookup``) -- ueber ``run_in_executor`` kapseln,
  damit der Event-Loop nicht blockiert. Die Port-Methode bleibt ``async``.

Altmuster-Befunde (geprueft, beide unkritisch):

* KEINE Injection in ``get_smb_info``: ``nmblookup`` wird mit einer ARGUMENT-LISTE
  (``["nmblookup", "-A", ip]``) und OHNE ``shell=True`` aufgerufen -- ``ip`` ist
  ein Argument, kein interpolierter Shell-String. (Anders als die ``osascript``-
  Faelle S2, die hier nicht beruehrt werden.) Daher unveraendert wrappbar.
* Der ``except Exception: return ""`` / ``("", "")`` des Altcodes ist KEIN
  stiller Sicherheits-Fallback im Sinne von S3: "nicht aufloesbar" ist genau der
  vom Port vorgesehene Leer-Zustand (``""`` bzw. ``("", "")``), kein verdecktes
  Scheitern eines Sicherheitsschritts. Wird daher bewusst beibehalten.
"""

import asyncio

from modules.resolver import get_smb_info, resolve_hostname


class HostnameResolverAdapter:
    """Erfuellt das ``HostnameResolverPort``-Protocol strukturell."""

    async def resolve(self, ip: str, timeout: float) -> str:
        """Reverse-DNS-Name zu ``ip``, oder ``""`` wenn nicht aufloesbar.

        ``modules.resolve_hostname`` ist bereits async (Executor + Timeout
        intern) -- direkt awaiten.
        """
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
