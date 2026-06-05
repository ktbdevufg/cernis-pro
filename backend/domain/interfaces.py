"""Domaenenmodell der interfaces-Domaene: Netzwerk-Interface + reine Klassifikation.

Reine Domaenenlogik (stdlib + dataclasses, ADR 0002) -- kein Wissen ueber das
``ip``-Tooling / ``/sys/class/net`` (das ist Infrastruktur, I.3), kein HTTP, keine
Uhr. Alles, was diese Domaene tut, ist deterministische Klassifikation und Auswahl
ueber bereits eingelesene Werte.

Die Domaene hebt drei Entscheidungen aus dem Uebergangs-Adapter
(``infrastructure/interfaces.py``) und dem Frontend (``App.jsx``) in pruefbare,
seiteneffektfreie Funktionen:

* ``classify_type`` -- die Namens-Praefix-Heuristik (heute im Adapter mit
  ``/sys``-Reads vermischt; HIER nur der reine, namensbasierte Teil).
* ``classify_status`` -- ``up``/``down``/``no_ip`` aus zwei Bool-Flags.
* ``select_primary`` -- die Default-Route-Auswahl, die HEUTE das Frontend raet
  (``App.jsx``: erstes mit ``ipv4 && gateway``, sonst ``[0]``). Hier
  deterministisch und testbar, als Name statt Objekt.

DARSTELLUNG bleibt draussen: keine Icons/Emojis (Sprache statt Symbole), kein
``broadcast``/``subnet_cidr``/``network`` -- das sind ableitbare Anzeige-Felder,
die der Adapter/api fuer Wire-Kompatibilitaet behalten (I.3), nicht die Domaene.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Literal

# Fachlicher Interface-Typ. PEP-695-Alias wie im uebrigen domain-Ring
# (settings/scanning/monitoring nutzen ``type X = ...``); als Literal-Union statt
# StrEnum, weil es ein reines Klassifikations-Ergebnis ohne Verhalten ist.
type InterfaceType = Literal["wifi", "ethernet", "loopback", "vpn", "bridge", "virtual", "unknown"]

# Betriebszustand eines Interfaces aus Sicht der Auswahl-Logik.
type InterfaceStatus = Literal["up", "down", "no_ip"]


@dataclass(frozen=True)
class NetworkInterface:
    """Ein Netzwerk-Interface als reines Wertobjekt (frozen, keine Darstellung).

    Spiegelt die heutige Wire-Form (``name``/``ipv4``/``ipv4_prefix``/``mac``/
    ``gateway``/``ipv6_*``/``mtu``/``is_up``/``is_loopback``/``network_cidr``/
    ``host_count``) und ergaenzt die v2-Klassifikationsfelder ``type``/``status``/
    ``is_primary``. ``broadcast``/``subnet_cidr``/``network``/``hw_icon`` sind
    bewusst NICHT enthalten -- ableitbare Anzeige bzw. Darstellung, die der
    Adapter/api fuehrt (I.3).

    Fehlende Werte sind ``None`` (kein Default-Raten in der Domaene): ein
    Interface ohne IPv4 hat ``ipv4=None``/``ipv4_prefix=None``/``network_cidr=None``/
    ``host_count=None``. ``type``/``status`` werden von den Klassifikations-
    Funktionen befuellt; das Aggregat selbst rechnet sie nicht aus (Trennung von
    Datentraeger und Regel).
    """

    name: str
    ipv4: str | None = None
    ipv4_prefix: int | None = None
    ipv6_link_local: str | None = None
    ipv6_global: str | None = None
    mac: str | None = None
    gateway: str | None = None
    mtu: int | None = None
    is_up: bool = True
    is_loopback: bool = False
    network_cidr: str | None = None
    host_count: int | None = None
    type: InterfaceType = "unknown"
    status: InterfaceStatus = "up"
    is_primary: bool = False

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("name darf nicht leer sein")


# Loopback wird NICHT als startswith-Praefix behandelt: ``lo`` ist zu kurz und
# wuerde ``london0``/``loooong`` u. Ae. faelschlich als loopback matchen. Statt-
# dessen das praezise Muster ``lo`` exakt ODER ``lo`` + nur Ziffern (``lo0``/
# ``lo1`` -- BSD/Mehrfach-Loopback).
_LOOPBACK_RE = re.compile(r"lo\d*")

# Praefix -> Typ in Pruef-Reihenfolge. ``lo`` ist hier bewusst NICHT enthalten
# (s. ``_LOOPBACK_RE``). Die uebrigen Praefixe sind als Wortanfaenge real
# eindeutig und ueberschneiden sich nicht (``wl``/``en``/``eth``/``tun``/``tap``/
# ``br``/``docker``/``veth`` sind disjunkt). 1:1 die Heuristik des Uebergangs-
# Adapters (``_hw_info_linux``), aber OHNE die ``/sys``-Reads -- die bleiben
# Infrastruktur (I.3).
_TYPE_PREFIXES: tuple[tuple[tuple[str, ...], InterfaceType], ...] = (
    (("wl",), "wifi"),
    (("eth", "en"), "ethernet"),
    (("tun", "tap"), "vpn"),
    (("br",), "bridge"),
    (("docker", "veth"), "virtual"),
)


def classify_type(name: str) -> InterfaceType:
    """Klassifiziert ein Interface anhand seines NAMENS -- rein, deterministisch.

    Reine Namens-Heuristik (Altcode-treu): ``lo``/``lo0``..->loopback, ``wl``->wifi,
    ``eth``/``en``->ethernet, ``tun``/``tap``->vpn, ``br``->bridge, ``docker``/
    ``veth``->virtual, sonst ``unknown``.

    Loopback ist ein SONDERFALL und wird VOR der Praefix-Tabelle geprueft:
    ``lo`` ist als startswith-Praefix zu kurz und wuerde ``london0``/``loooong``
    o. Ae. faelschlich treffen. Darum das praezise Muster ``_LOOPBACK_RE``
    (``lo`` exakt oder ``lo`` + nur Ziffern). Die uebrigen Typen bleiben
    startswith-Praefixe -- als Wortanfaenge sind sie eindeutig.

    Die ``/sys/class/net``-Vorstufe des Adapters (wireless-Datei, ``type``-Datei
    772/1) ist hier bewusst NICHT abgebildet -- sie ist I/O und gehoert in den
    Infrastruktur-Adapter (I.3). Diese Funktion sieht nur den Namen.

    Rein: kein I/O, kein State, gleiches ``name`` -> gleiches Ergebnis.
    """
    if _LOOPBACK_RE.fullmatch(name):
        return "loopback"
    for prefixes, type_ in _TYPE_PREFIXES:
        if name.startswith(prefixes):
            return type_
    return "unknown"


def classify_status(is_up: bool, has_ipv4: bool) -> InterfaceStatus:
    """Leitet den Betriebszustand aus zwei Flags ab -- rein, deterministisch.

    - ``not is_up`` -> ``down`` (Link nicht aktiv).
    - ``is_up`` aber ``not has_ipv4`` -> ``no_ip`` (aktiv, aber unkonfiguriert).
    - sonst -> ``up`` (aktiv und mit IPv4).

    ``has_ipv4`` ist ein bereits ermitteltes Bool (z. B. ``iface.ipv4 is not
    None``) -- die Domaene parst keine Adressen. Rein: kein I/O, keine Uhr.
    """
    if not is_up:
        return "down"
    if not has_ipv4:
        return "no_ip"
    return "up"


def _is_primary_candidate(iface: NetworkInterface) -> bool:
    """True, wenn ``iface`` als primaeres Interface in Frage kommt.

    Kandidat = aktiv, kein Loopback, mit IPv4 UND Gateway gesetzt. Das ist die
    praezise Fassung des Frontend-Ratens (``App.jsx``: erstes mit
    ``ipv4 && gateway``), ergaenzt um ``is_up`` und ``not is_loopback``.
    """
    return iface.is_up and not iface.is_loopback and bool(iface.ipv4) and bool(iface.gateway)


def select_primary(interfaces: Sequence[NetworkInterface]) -> str | None:
    """Waehlt das primaere Interface (Default-Route) deterministisch -- reine Auswahl.

    Schablone ``select_rules_to_fire`` (alerting): filtert in Eingangsreihenfolge,
    keine Uhr, kein I/O. Kandidat ist, wer aktiv ist, kein Loopback, und ``ipv4``
    UND ``gateway`` gesetzt hat (s. ``_is_primary_candidate``). Bei mehreren
    Kandidaten gewinnt der ERSTE in Eingangsreihenfolge (stabiler Tie-Break) --
    so ersetzt diese Funktion das bisherige Frontend-Raten deterministisch.

    Rueckgabe ist der NAME (str), nicht das Objekt: der Use-Case (I.2) setzt damit
    die ``is_primary``-Flags ueber alle Interfaces, ohne Objektidentitaet
    vergleichen zu muessen (zwei wertgleiche frozen-dataclasses waeren ``==``,
    der Name ist die stabile Identitaet). Kein Kandidat -> ``None``.
    """
    for iface in interfaces:
        if _is_primary_candidate(iface):
            return iface.name
    return None


def mark_primary(
    interfaces: Sequence[NetworkInterface], primary_name: str | None
) -> list[NetworkInterface]:
    """Setzt ``is_primary`` konsistent: genau das Interface ``primary_name`` True.

    Reine Projektion: gibt eine neue Liste zurueck (frozen-dataclasses via
    ``replace``), Eingangsreihenfolge bewahrt. ``primary_name=None`` -> alle
    ``is_primary=False``. Trifft ``primary_name`` keinen Namen, ist ebenfalls
    keines primaer -- ein lautes Hochlaufen waere hier unangebracht, weil der
    Aufrufer ``select_primary`` als Quelle nutzt (dessen Name existiert oder ist
    None). Rein: kein I/O, keine Uhr.
    """
    return [replace(iface, is_primary=(iface.name == primary_name)) for iface in interfaces]
