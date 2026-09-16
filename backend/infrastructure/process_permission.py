"""Linux-Adapter fuer ``ProcessPermissionPort`` (P.3, Rechte-/Sicht-Erkennung).

Erfuellt den ``ProcessPermissionPort`` strukturell: schnelle, synchrone, LOKALE
Pruefung der Sicht-Tiefe -- KEIN externes Tooling, kein Netz-/Loop-I/O (Muster
``infrastructure/traffic_permission.py``).

Rechte-Modell (Vision 4.2/S4/S5): die EIGENEN Prozesse sind IMMER voll lesbar
(``/proc/<pid>/`` des eigenen Users). Die Detailfelder FREMDER Prozesse
(``owner``/``status``/``create_time``/``cmdline``) sieht nur echter Root. "Volle Sicht"
= ``os.geteuid() == 0``. Anders als bei traffic gibt es hier KEINEN CAP_NET_ADMIN-Pfad:
die ``/proc``-Sicht auf fremde Prozesse haengt an echtem Root (euid 0), nicht an einer
Netz-Capability -- darum wird nur ``geteuid`` geprueft.

KEIN stiller Fallback (S3): fehlt die volle Sicht, wird die Luecke handlungsorientiert
benannt (konkreter Befehl), nicht verschwiegen. Der Adapter verschafft sich selbst NIE
Rechte; er stellt nur fest, welche da sind, und benennt den Weg zu mehr.

SCOPE (CLAUDE.md "Nur Linux x64"): ``is_available`` ist auf Nicht-Linux ``False``
(``/proc`` fehlt) -- der Use-Case meldet den Bereich dann ehrlich als nicht verfuegbar,
statt eine Halb-Implementierung vorzutaeuschen.
"""

import os
import sys

# Handlungsorientierter Hinweis bei fehlender voller Sicht (kein nackter "denied"-Text):
# eigene Prozesse funktionieren, fuer fremde Detailfelder wird der Weg konkret benannt.
_NEEDS_ROOT_MESSAGE = (
    "Eigene Prozesse sind vollstaendig sichtbar. Fuer Details fremder Prozesse "
    "(Owner/Status/Kommandozeile) muss CERNIS PRO als Root laufen - starte das "
    "Backend als Root, z.B. 'sudo cernis-backend'."
)


class ProcessPermissionAdapter:
    """Erfuellt das ``ProcessPermissionPort``-Protocol (lokale Rechte-Pruefung, Linux)."""

    def is_available(self) -> bool:
        """``True`` auf Linux (``/proc`` da), sonst ``False``.

        ``/proc`` ist Linux -- auf Nicht-Linux wird der ganze Feature-Bereich ehrlich
        als nicht verfuegbar gemeldet, statt eine Halb-Implementierung vorzutaeuschen
        (CLAUDE.md "Nur Linux x64", Muster ``TrafficPermissionAdapter.is_available``).
        """
        return sys.platform.startswith("linux")

    def check_permission(self) -> str | None:
        """``None`` bei voller Sicht (``geteuid() == 0``), sonst der Root-Hinweis.

        Volle Sicht = echter Root (alle ``/proc/<pid>/``-Detailfelder lesbar). Sonst
        ein handlungsorientierter Hinweis (eigene Prozesse bleiben sichtbar). KEIN
        CAP_NET_ADMIN-Pfad wie bei traffic -- die ``/proc``-Sicht haengt an euid 0.
        """
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return None
        return _NEEDS_ROOT_MESSAGE
