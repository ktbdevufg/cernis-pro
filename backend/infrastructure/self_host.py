"""Ermittlung des eigenen Hosts (der Rechner, auf dem CERNIS laeuft) ueber psutil.

Ein aktiver Netz-Scan findet den eigenen Host nicht -- er sieht sich selbst nicht.
Damit die eigene IP im Bestand (und darueber im DNS-Umgehungs-Bericht) aufgeloest
wird, ermittelt dieser Adapter das primaere, aktive Nicht-Loopback-Interface:
MAC (``AF_LINK`` / ``AF_PACKET``) + IPv4 (``AF_INET``) je Interface, plus den
Hostnamen ueber ``socket.gethostname()``.

Infrastruktur, NICHT Domaene: die Interface-Ermittlung ist plattformnahe I/O
(``psutil.net_if_addrs`` / ``psutil.net_if_stats``). Die Domaene bleibt framework-
frei; der Bootstrap in ``app.py`` uebersetzt das Ergebnis in ein ``Device``.

STRIKT ausgeschlossen: das Loopback (``lo`` / ``127.0.0.1``) wird NIE als eigener
Host gefuehrt. Best-effort durchgehend: findet sich kein taugliches Interface (oder
wirft psutil), gibt es ``None`` statt eines Absturzes -- der Bootstrap schluckt das.
"""

import ipaddress
import socket
from dataclasses import dataclass

import psutil


@dataclass(frozen=True)
class SelfHost:
    """Die Kenndaten des eigenen Hosts fuer den Bootstrap-Upsert (Wertobjekt).

    ``mac`` und ``ip`` stammen vom primaeren, aktiven Nicht-Loopback-Interface;
    ``hostname`` ist ``socket.gethostname()``. Reine Daten -- die Normalisierung
    der MAC und die Abbildung auf ein ``Device`` liegen beim Aufrufer.
    """

    mac: str
    ip: str
    hostname: str


def _is_loopback_ip(raw: str) -> bool:
    """True, wenn ``raw`` eine Loopback-IPv4 ist (127.0.0.0/8) -- sonst False.

    Ungueltige/leere Eingaben gelten als NICHT-Loopback-tauglich (-> True hier
    wuerde sie faelschlich ausschliessen); ein Parse-Fehler bedeutet aber schlicht
    "keine brauchbare IPv4" und wird vom Aufrufer ohnehin verworfen. Wir melden
    hier nur die eindeutige Loopback-Eigenschaft.
    """
    try:
        return ipaddress.ip_address(raw).is_loopback
    except ValueError:
        return False


def detect_self_host() -> SelfHost | None:
    """Ermittelt den eigenen Host (primaeres aktives Nicht-Loopback-Interface).

    Geht die Interfaces in der von psutil gelieferten (stabilen) Reihenfolge durch
    und nimmt das ERSTE, das (1) laut ``net_if_stats`` aktiv (``isup``) ist,
    (2) NICHT das Loopback ``lo`` ist, (3) eine echte MAC (``AF_LINK`` bzw.
    ``AF_PACKET``) UND (4) eine Nicht-Loopback-IPv4 (``AF_INET``, nicht
    127.0.0.0/8) traegt. Hostname ueber ``socket.gethostname()``.

    best-effort: findet sich kein solches Interface -- oder wirft psutil --, gibt
    es ``None`` (kein Crash). Das Loopback wird STRIKT nie zurueckgegeben.
    """
    try:
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()
    except Exception:
        return None

    hostname = socket.gethostname()
    # psutil liefert AF_LINK plattformuebergreifend fuer die MAC; unter Linux ist
    # das AF_PACKET. Beide akzeptieren, damit der Adapter nicht an einer Konstante
    # klebt (Scope Linux x64, aber ohne Not nicht einengen).
    link_families = {int(psutil.AF_LINK)}
    if hasattr(socket, "AF_PACKET"):
        link_families.add(int(socket.AF_PACKET))

    for name, addrs in if_addrs.items():
        if name == "lo":
            continue
        stats = if_stats.get(name)
        if stats is None or not stats.isup:
            continue

        mac = ""
        ip = ""
        for addr in addrs:
            family = int(addr.family)
            if family in link_families and not mac:
                # psutil ist untypisiert (kein py.typed); address ist Any -> str.
                mac = str(addr.address)
            elif family == int(socket.AF_INET) and not ip:
                candidate = str(addr.address)
                if not _is_loopback_ip(candidate):
                    ip = candidate

        # Nur ein Interface mit ECHTER MAC UND Nicht-Loopback-IPv4 zaehlt als der
        # eigene Host; sonst weiter (ehrliche Abwesenheit, kein Teil-Eintrag).
        if mac and ip:
            return SelfHost(mac=mac, ip=ip, hostname=hostname)

    return None
