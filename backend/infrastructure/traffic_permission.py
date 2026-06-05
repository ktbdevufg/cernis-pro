"""Linux-Adapter fuer ``TrafficPermissionPort`` (T.3, Rechte-/Sicht-Erkennung).

Erfuellt den ``TrafficPermissionPort`` strukturell: schnelle, synchrone, LOKALE
Pruefung der Sicht-Tiefe -- KEIN externes Tooling, kein Netz-/Loop-I/O (Muster
``infrastructure/capture`` ``check_permission``).

Rechte-Modell (Vision 4.2/S4/S5): Stufe 1 (eigene Verbindungen) laeuft IMMER
rootless. Den Durchsatz ALLER Apps (Stufe 2) sieht nur ein Prozess mit erhoehten
Rechten. "Erhoehte Rechte" = ``os.geteuid() == 0`` ODER ``CAP_NET_ADMIN`` im
effektiven Capability-Set (``CapEff`` in ``/proc/self/status``, Bit 12) -- so
funktioniert das Feature auch, wenn das Backend per Capability statt voller Root
gestartet wurde (minimal-invasiv, direkter Gegenentwurf zu S5).

KEIN stiller Fallback (S3): ist ``/proc/self/status`` nicht lesbar, faellt die
Pruefung auf ``geteuid`` zurueck (dokumentiert) -- das ist die konservativere
Annahme (kein faelschliches "volle Sicht"), kein verschwiegener Fehler. Der Adapter
verschafft sich selbst NIE Rechte; er stellt nur fest, welche da sind, und benennt
den Weg zu mehr (handlungsorientierter Text mit konkretem Befehl).

SCOPE (CLAUDE.md "Nur Linux x64"): ``is_available`` ist auf Nicht-Linux ``False``
(``/proc``/``sock_diag`` fehlen) -- der Use-Case sperrt dann den ganzen Feature-
Bereich, statt eine Halb-Implementierung vorzutaeuschen.
"""

import os
import sys

# CAP_NET_ADMIN ist Capability-Nummer 12 -> Bit 12 (0-basiert) im Capability-Bitset.
_CAP_NET_ADMIN_BIT = 12

# Handlungsorientierter Hinweis bei fehlenden Rechten (kein nackter "denied"-Text):
# Stufe 1 funktioniert, fuer Stufe 2 wird der Weg zu mehr Rechten konkret benannt.
_NEEDS_ROOT_MESSAGE = (
    "Stufe 1 (eigene Verbindungen) ist verfuegbar. Fuer den Durchsatz aller Apps "
    "(Stufe 2) muss CERNIS PRO mit erhoehten Rechten laufen - starte das Backend "
    "als Root, z.B. 'sudo cernis-backend'."
)


def _has_cap_net_admin(cap_eff_hex: str) -> bool:
    """``True``, wenn Bit 12 (CAP_NET_ADMIN) im ``CapEff``-Hexwert gesetzt ist -- rein.

    ``cap_eff_hex`` ist der rohe Wert aus ``/proc/self/status`` (Zeile ``CapEff:``,
    z. B. ``0000003fffffffff``). Ungueltiger/leerer Hex -> ``False`` (defensiv: ein
    nicht parsbarer Wert ist KEIN Nachweis fuer das Recht). Rein: kein I/O.
    """
    try:
        cap_bits = int(cap_eff_hex.strip(), 16)
    except ValueError:
        return False
    return bool(cap_bits & (1 << _CAP_NET_ADMIN_BIT))


def _read_cap_eff() -> str | None:
    """Liest den ``CapEff``-Hexwert aus ``/proc/self/status`` (I/O, Linux).

    Nicht lesbar (Datei fehlt / Permission) -> ``None`` (der Aufrufer faellt dann
    auf ``geteuid`` zurueck -- kein stiller Fallback auf "volle Sicht", S3).
    """
    try:
        with open("/proc/self/status") as status_file:
            for line in status_file:
                if line.startswith("CapEff:"):
                    return line.split(":", 1)[1]
    except OSError:
        return None
    return None


class TrafficPermissionAdapter:
    """Erfuellt das ``TrafficPermissionPort``-Protocol (lokale Rechte-Pruefung, Linux)."""

    def is_available(self) -> bool:
        """``True`` auf Linux (psutil/``/proc`` da), sonst ``False``.

        Stufe 1 (psutil) ist plattformneutral, aber die Stufe-2-Quelle (``sock_diag``,
        ``/proc``) und das Capability-Modell sind Linux -- auf Nicht-Linux wird der
        ganze Feature-Bereich ehrlich als nicht verfuegbar gemeldet, statt eine
        Halb-Implementierung vorzutaeuschen (CLAUDE.md "Nur Linux x64").
        """
        return sys.platform.startswith("linux")

    def check_permission(self) -> str | None:
        """``None`` bei voller Sicht (Root/CAP_NET_ADMIN), sonst der Root-Hinweis.

        Volle Sicht = ``geteuid() == 0`` ODER ``CAP_NET_ADMIN`` im ``CapEff``. Ist
        ``/proc/self/status`` nicht lesbar (``_read_cap_eff`` -> ``None``), zaehlt nur
        ``geteuid`` (konservativer Rueckfall, kein verschwiegener Fehler -- S3).
        """
        if os.geteuid() == 0:
            return None
        cap_eff = _read_cap_eff()
        if cap_eff is not None and _has_cap_net_admin(cap_eff):
            return None
        return _NEEDS_ROOT_MESSAGE
