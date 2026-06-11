"""Domaenenmodell der diagnostics-Domaene: DNS-Aufloesung + traceroute als reine Werte.

Reine Domaenenlogik (stdlib + dataclasses, ADR 0002) -- kein Wissen ueber ``dig``,
``traceroute`` oder Subprocess-Aufrufe (das ist Infrastruktur, ein spaeterer Schnitt),
kein HTTP, KEINE Uhr. Alles, was diese Domaene tut, ist deterministischer Strukturaufbau
ueber bereits eingelesene Rohwerte. Laufzeiten (``rtt_ms``) kommen als FELD herein -- die
Domaene misst nie selbst (testbar, deterministisch).

Vier Wertobjekte + eine reine Funktion:

* ``DnsRecord`` -- ein einzelner DNS-Eintrag (Typ + Wert) als reines Wertobjekt.
* ``DnsResult`` -- das Ergebnis einer Abfrage (Query, angefragte Typen, Eintraege).
  Leere ``records`` heisst "keine Antwort" -- KEIN Fehler (NXDOMAIN/leere Antwort ist
  ein gueltiges Ergebnis, kein Ausnahmefall).
* ``TracerouteHop`` -- ein einzelner Hop. ``address``/``rtt_ms`` sind ehrlich ``None``,
  wenn der Hop nicht antwortet (Timeout / ``*`` in der Ausgabe) -- KEIN erfundener Wert.
* ``TracerouteResult`` -- die Hop-Folge samt Ziel und ob die privilegierte (genauere)
  Methode verwendet wurde.
* ``dedup_records`` -- deterministische Dedup+Sortierung der Eintraege, rein und testbar.

Block 1b (Tool-/Paketmanager-Erkennung) -- reine Daten + zwei reine Funktionen:

* ``TOOL_PACKAGES`` -- die EINZIGE Quelle der Wahrheit, welche System-Tools CERNIS PRO
  verwendet (aktuell ``dig``/``traceroute``) und wie die Pakete je Paketmanager heissen.
  Reine Daten, kein I/O -- die Adapter erkennen NUR, die Registry weiss, was zu erkennen
  ist und wie das fehlende Paket heisst.
* ``ALL_TOOLS`` -- die registrierten Tool-Binaries, deterministisch sortiert.
* ``ToolStatus``/``ToolReport`` -- frozen Wertobjekte fuer den Tool-Bericht. ``manager``
  None = kein bekannter Paketmanager erkannt; ``install_command`` None = nichts fehlt ODER
  kein Manager bekannt (dann ehrlich None, KEIN erfundener Befehl).
* ``build_install_command`` -- bildet fehlende Tools auf ihre Paketnamen fuer DIESEN
  Manager ab und baut den passenden Install-Befehls-TEXT. Ehrliche None-Semantik: kein
  Manager -> None, nichts fehlt -> None, unbekanntes Tool -> uebersprungen (nicht geraten).
  KEINE Selbst-Installation (Sicherheits-Prinzip) -- nur der Befehls-TEXT.
* ``assemble_report`` -- baut den ``ToolReport`` (sortierte Statuses, fehlende ermittelt,
  Install-Befehl ueber ``build_install_command``). Rein, kein I/O.

Block 2a (Banner-Grabbing) -- rein lokales TCP-Klopfen + Lesen der Begruessungszeile,
hier nur die reine Heuristik + das Wertobjekt + die Bereinigung (kein Socket-I/O, das
ist Infrastruktur):

* ``BannerProbe`` -- WIE ein Banner geholt wird: ``"passive"`` (der Dienst gruesst selbst)
  oder ``"http_head"`` (eine minimale HTTP-HEAD-Anfrage senden).
* ``probe_for_port`` -- die EINZIGE Heuristik (rein, deterministisch, mutationsproben-
  tauglich): Klartext-Web-Ports -> ``"http_head"``, alles andere -> ``"passive"``.
  TLS-Ports (443/8443) bewusst NICHT als ``http_head`` -- ein roher Connect dorthin
  spraeche TLS, kein Klartext-HTTP (kein TLS-Handshake in 2a, siehe ADR 0014 Block 2a).
* ``BannerResult`` -- das Ergebnis als frozen Wertobjekt. ``banner`` ehrlich ``None``,
  wenn nichts kam (Timeout/leere Antwort) -- KEIN erfundener Wert. ``state`` benennt das
  Ergebnis ehrlich (ok/no_banner/closed/filtered).
* ``sanitize_banner`` -- bereinigt die rohe Begruessung rein + deterministisch (erste
  Zeile, Steuerzeichen raus, auf Maximallaenge gekuerzt) -- testbar ohne Netz.

DARSTELLUNG bleibt draussen: kein Mensch-lesbares Formatieren, keine Icons -- das fuehrt
api/Frontend. Die Domaene fuehrt nur Werte.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

# Angefragte/gelieferte DNS-Eintragsart. PEP-695-Alias wie im uebrigen domain-Ring
# (process/traffic/interfaces nutzen ``type X = ...``); als Literal-Union statt StrEnum,
# weil es ein reines Kategorie-Etikett ohne Verhalten ist.
type DnsRecordType = Literal["A", "AAAA", "PTR", "MX", "TXT", "NS", "SOA", "CNAME"]

# Bekannter Linux-Paketmanager. PEP-695-Alias wie ``DnsRecordType`` -- ein reines
# Kategorie-Etikett ohne Verhalten (Block 1b). Die Reihenfolge der Literale ist KEINE
# Erkennungs-Reihenfolge -- die legt der Adapter (``LinuxPackageManagerDetector``) fest;
# hier ist es nur die Vertrags-Aufzaehlung der unterstuetzten Manager.
type PackageManager = Literal["apt", "dnf", "yum", "zypper", "pacman"]


@dataclass(frozen=True)
class DnsRecord:
    """Ein einzelner DNS-Eintrag als reines Wertobjekt (frozen).

    ``record_type`` ist die Eintragsart (A/AAAA/PTR/...), ``value`` der rohe Wert, wie
    ihn der Resolver geliefert hat (z. B. eine IP fuer A/AAAA, ein Hostname fuer PTR/NS,
    der TXT-Inhalt). Die Domaene interpretiert den Wert NICHT weiter -- sie fuehrt ihn.
    """

    record_type: DnsRecordType
    value: str


@dataclass(frozen=True)
class DnsResult:
    """Das Ergebnis einer DNS-Abfrage als reines Wertobjekt (frozen).

    ``query`` ist der abgefragte Name (bzw. die Adresse bei PTR), ``requested_types`` die
    vom Nutzer angefragten Eintragsarten (in angefragter Reihenfolge), ``records`` die
    gefundenen Eintraege. ``records`` LEER heisst "keine Antwort" -- das ist KEIN Fehler,
    sondern ein gueltiges Ergebnis (NXDOMAIN, leere Antwort, oder schlicht kein Eintrag
    der angefragten Art). Ein echter Fehler (fehlendes Binary) wird in application/ als
    Exception gefuehrt, nicht als leeres ``records``.
    """

    query: str
    requested_types: tuple[DnsRecordType, ...]
    records: tuple[DnsRecord, ...]


@dataclass(frozen=True)
class TracerouteHop:
    """Ein einzelner traceroute-Hop als reines Wertobjekt (frozen).

    ``hop`` ist die 1-basierte Hop-Nummer (immer vorhanden -- sie kommt aus der Zeilen-
    Position der Ausgabe). ``address`` und ``rtt_ms`` sind ehrlich ``None``, wenn der Hop
    nicht antwortet (Timeout, in der ``traceroute``-Ausgabe als ``*`` dargestellt) --
    KEIN erfundener Wert, KEIN Weglassen des Hops. Ein nicht-antwortender Hop bleibt als
    Luecke (``address=None``, ``rtt_ms=None``) sichtbar.
    """

    hop: int
    address: str | None
    rtt_ms: float | None


@dataclass(frozen=True)
class TracerouteResult:
    """Das Ergebnis eines traceroute als reines Wertobjekt (frozen).

    ``target`` ist das angefragte Ziel, ``privileged`` spiegelt, ob die privilegierte
    (genauere, Root-)Methode verwendet wurde (``True``) oder die unprivilegierte
    (ungenauere) Methode (``False``) -- die ehrliche Auskunft, WIE gemessen wurde.
    ``hops`` ist die Hop-Folge in Reihenfolge (leer = kein Hop ermittelt).
    """

    target: str
    privileged: bool
    hops: tuple[TracerouteHop, ...]


def dedup_records(records: Sequence[DnsRecord]) -> tuple[DnsRecord, ...]:
    """Entfernt doppelte DNS-Eintraege und sortiert deterministisch -- rein, testbar.

    Dedup ueber das Paar ``(record_type, value)``: zwei Eintraege gleichen Typs mit
    gleichem Wert sind derselbe Eintrag (``dig`` kann denselben Wert mehrfach liefern,
    z. B. ueber mehrere Abfragen). Das ERSTE Vorkommen gewinnt die Identitaet, doppelte
    spaetere werden verworfen.

    Deterministisch: das Ergebnis ist aufsteigend nach ``(record_type, value)`` sortiert
    -- gleiche Eingabe (in beliebiger Reihenfolge) -> gleiches Ergebnis. So bleibt die
    Wire-Form stabil, unabhaengig von der Abfrage-/Antwort-Reihenfolge.

    Rein: kein I/O, keine Uhr; gleiche Eingabe -> gleiches Ergebnis.
    """
    seen: set[tuple[str, str]] = set()
    unique: list[DnsRecord] = []
    for record in records:
        key = (record.record_type, record.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(record)
    return tuple(sorted(unique, key=lambda r: (r.record_type, r.value)))


# ── Block 1b: Tool-/Paketmanager-Registry (reine Daten, einzige Quelle der Wahrheit) ──

# Tool-Binary -> (Paketname je PackageManager). Die EINZIGE Quelle der Wahrheit, welche
# System-Tools CERNIS PRO verwendet und wie das nachzuinstallierende Paket pro Manager
# heisst. Reine Daten im domain-Ring -- die Adapter erkennen nur, was hier steht.
#
# ``yum`` mappt bewusst auf dieselben Paketnamen wie ``dnf`` (RHEL-Altsysteme nutzen
# dieselben bind-/traceroute-Pakete). ``dig`` steckt je nach Distro in unterschiedlich
# benannten Paketen (Debian/Ubuntu: ``dnsutils``; RHEL/Fedora/SUSE: ``bind-utils``; Arch:
# ``bind``) -- genau dieser Unterschied ist der Grund fuer diese Registry.
TOOL_PACKAGES: dict[str, dict[PackageManager, str]] = {
    "dig": {
        "apt": "dnsutils",
        "dnf": "bind-utils",
        "yum": "bind-utils",
        "zypper": "bind-utils",
        "pacman": "bind",
    },
    "traceroute": {
        "apt": "traceroute",
        "dnf": "traceroute",
        "yum": "traceroute",
        "zypper": "traceroute",
        "pacman": "traceroute",
    },
}

# Die registrierten Tool-Binaries, deterministisch sortiert (abgeleitet -- KEINE zweite,
# pflegbare Liste, die mit ``TOOL_PACKAGES`` auseinanderlaufen koennte).
ALL_TOOLS: tuple[str, ...] = tuple(sorted(TOOL_PACKAGES.keys()))

# Install-Befehls-Vorlage je Manager. ``{packages}`` wird durch die Space-getrennten
# Paketnamen ersetzt. ``pacman`` nutzt ``-S`` (kein ``install``-Unterkommando) -- darum
# eine Vorlage je Manager statt eines geratenen Einheits-Schemas. Reine Daten, kein Raten.
_INSTALL_TEMPLATES: dict[PackageManager, str] = {
    "apt": "sudo apt install {packages}",
    "dnf": "sudo dnf install {packages}",
    "yum": "sudo yum install {packages}",
    "zypper": "sudo zypper install {packages}",
    "pacman": "sudo pacman -S {packages}",
}


@dataclass(frozen=True)
class ToolStatus:
    """Verfuegbarkeit EINES Tool-Binaries als reines Wertobjekt (frozen).

    ``name`` ist der Binary-Name (z. B. ``dig``), ``available`` ob es nutzbar ist. Die
    Pruefung selbst macht der Adapter (which-basiert) -- die Domaene fuehrt nur den Wert.
    """

    name: str
    available: bool


@dataclass(frozen=True)
class ToolReport:
    """Der Tool-Bericht als reines Wertobjekt (frozen).

    ``manager`` ist der erkannte Paketmanager oder ``None`` (kein bekannter erkannt).
    ``statuses`` ist die Verfuegbarkeit je angefragtem Tool (deterministisch sortiert).
    ``install_command`` ist der fertige Install-Befehls-TEXT oder ``None`` -- ``None``
    heisst ENTWEDER "nichts fehlt" ODER "kein Manager bekannt" (dann ehrlich ``None``,
    KEIN erfundener Befehl). NUR der Text wird gefuehrt -- KEINE Selbst-Installation
    (Sicherheits-Prinzip): die Domaene fuehrt aus, baut aber nie aus, was zu tun waere.
    """

    manager: PackageManager | None
    statuses: tuple[ToolStatus, ...]
    install_command: str | None


def build_install_command(
    manager: PackageManager | None, missing_tools: Sequence[str]
) -> str | None:
    """Baut den Install-Befehls-TEXT fuer die fehlenden Tools -- rein, deterministisch.

    Ehrliche None-Semantik (kein Raten):

    * ``manager`` ``None`` -> ``None`` (ohne bekannten Manager kein erfundener Befehl).
    * keine fehlenden Tools -> ``None`` (es gibt nichts zu installieren).
    * sonst: jedes fehlende Tool auf seinen Paketnamen fuer DIESEN ``manager`` abbilden
      (ueber ``TOOL_PACKAGES``), deterministisch sortiert + dedupliziert, und ueber die
      Manager-Vorlage zusammensetzen (``apt/dnf/yum/zypper`` -> ``install``, ``pacman`` ->
      ``-S``). Ein unbekanntes Tool (nicht in ``TOOL_PACKAGES``) wird defensiv
      uebersprungen, NICHT erfunden -- bleiben dann keine Pakete uebrig, ist das Ergebnis
      ``None`` (kein leerer Befehl).

    Rein: kein I/O, keine Uhr; gleiche Eingabe -> gleiches Ergebnis (voll testbar). NUR der
    Befehls-TEXT wird geliefert -- KEINE Ausfuehrung (Sicherheits-Prinzip).
    """
    if manager is None:
        return None
    packages: set[str] = set()
    for tool in missing_tools:
        mapping = TOOL_PACKAGES.get(tool)
        if mapping is None:
            continue  # unbekanntes Tool -- nicht erfinden, defensiv ueberspringen
        packages.add(mapping[manager])
    if not packages:
        return None  # nichts (Bekanntes) fehlt -> kein erfundener Befehl
    joined = " ".join(sorted(packages))
    return _INSTALL_TEMPLATES[manager].format(packages=joined)


def assemble_report(
    manager: PackageManager | None,
    tool_availability: Mapping[str, bool],
    requested_tools: Sequence[str],
) -> ToolReport:
    """Baut den ``ToolReport`` aus Manager + Verfuegbarkeits-Mapping -- rein, kein I/O.

    Fuer jedes Tool in ``requested_tools`` wird ein ``ToolStatus`` aus
    ``tool_availability`` gebaut (fehlt der Eintrag, gilt das Tool defensiv als nicht
    verfuegbar -- ``False``). Die Statuses werden deterministisch nach ``name`` sortiert.
    Die FEHLENDEN Tools (``available`` False) gehen in ``build_install_command``, das den
    Install-Befehls-TEXT baut (oder ehrlich ``None`` liefert). Rein: kein I/O, keine Uhr.
    """
    statuses = tuple(
        sorted(
            (
                ToolStatus(name=tool, available=tool_availability.get(tool, False))
                for tool in requested_tools
            ),
            key=lambda s: s.name,
        )
    )
    missing = [status.name for status in statuses if not status.available]
    install_command = build_install_command(manager, missing)
    return ToolReport(manager=manager, statuses=statuses, install_command=install_command)


# ── Block 2a: Banner-Grabbing (reine Heuristik + Wertobjekt + Bereinigung) ─────

# WIE ein Banner geholt wird. PEP-695-Alias wie ``DnsRecordType``/``PackageManager`` -- ein
# reines Kategorie-Etikett ohne Verhalten. ``passive`` = nach dem Connect kurz lauschen
# (der Dienst gruesst selbst, z. B. SSH/SMTP/FTP). ``http_head`` = eine minimale HTTP-HEAD-
# Anfrage senden und die Statuszeile + den ``Server``-Header als Banner lesen.
type BannerProbe = Literal["passive", "http_head"]

# Klartext-HTTP-Web-Ports, die per minimaler HTTP-HEAD-Anfrage gegruesst werden. BEWUSST
# OHNE die TLS-Ports {443, 8443}: ein roher TCP-Connect dorthin spricht TLS, kein Klartext-
# HTTP -- eine HEAD-Anfrage gaebe Muell. In 2a wird KEIN TLS-Handshake gesprochen (Scope-
# Grenze, ADR 0014 Block 2a); TLS-Ports fallen daher in ``passive`` und gruessen bei rohem
# Connect nicht -> ehrlich ``no_banner``. Reine Daten -- die einzige Heuristik-Quelle.
_HTTP_HEAD_PORTS: frozenset[int] = frozenset({80, 8080, 8000, 8008})

# Maximale Bannerlaenge nach der Bereinigung. Ein Banner ist eine kurze Begruessung/ein
# Server-Header -- mehr ist fuer ein Diagnose-Werkzeug Laerm und ein Risiko (uferlose
# Antwort eines boesartigen Diensts). 512 Zeichen sind grosszuegig fuer reale Banner.
_MAX_BANNER_LEN = 512


def probe_for_port(port: int) -> BannerProbe:
    """Bestimmt die Banner-Methode fuer ``port`` -- rein, deterministisch, testbar.

    Klartext-Web-Ports ({80, 8080, 8000, 8008}) -> ``"http_head"`` (eine minimale
    HTTP-HEAD-Anfrage senden); alle anderen Ports -> ``"passive"`` (kurz lauschen, der
    Dienst gruesst selbst). Die TLS-Ports {443, 8443} sind BEWUSST NICHT in der
    http_head-Menge: ein roher Connect dorthin spraeche TLS, kein Klartext-HTTP -- in 2a
    wird kein TLS-Handshake gesprochen (Scope-Grenze), darum gelten sie als ``passive``
    und gruessen bei rohem Connect nicht (ehrlich ``no_banner`` im Adapter).

    Das ist die EINZIGE Heuristik der Banner-Domaene -- rein, kein I/O, keine Uhr; gleiche
    Eingabe -> gleiches Ergebnis (mutationsproben-tauglich).
    """
    if port in _HTTP_HEAD_PORTS:
        return "http_head"
    return "passive"


@dataclass(frozen=True)
class BannerResult:
    """Das Ergebnis eines Banner-Grabs als reines Wertobjekt (frozen).

    ``target``/``port`` sind das angeklopfte Ziel, ``probe`` die verwendete Methode
    (``passive``/``http_head`` -- die ehrliche Auskunft, WIE geholt wurde). ``banner`` ist
    die gelesene Begruessungszeile bzw. der Server-Header, ehrlich ``None``, wenn nichts
    Lesbares kam (Timeout, leere Antwort) -- KEIN erfundener Wert. ``state`` benennt das
    Ergebnis: ``"ok"`` = Banner gelesen; ``"no_banner"`` = verbunden, aber keine lesbare
    Antwort; ``"closed"`` = aktiv abgewiesen (ConnectionRefused); ``"filtered"`` = Timeout/
    unerreichbar. ``banner`` ist NUR bei ``"ok"`` nicht-``None``.
    """

    target: str
    port: int
    probe: BannerProbe
    banner: str | None
    state: Literal["ok", "no_banner", "closed", "filtered"]


def sanitize_banner(raw: str) -> str:
    """Bereinigt eine rohe Banner-Antwort -- rein, deterministisch, testbar.

    Drei Schritte, in dieser Reihenfolge:

    1. **Erste Zeile**: ein Banner ist eine Begruessungszeile -- alles ab dem ersten
       Zeilenumbruch (``\\r``/``\\n``) faellt weg.
    2. **Steuerzeichen raus**: nicht-druckbare Zeichen (``\\x00``-Bereich, Steuerzeichen)
       werden entfernt -- ein Banner ist Text, kein Byte-Strom; fuehrende/folgende
       Leerzeichen werden getrimmt.
    3. **Laengenbegrenzung**: auf ``_MAX_BANNER_LEN`` (512) Zeichen gekuerzt -- eine
       uferlose Antwort wird begrenzt (Diagnose-Werkzeug, kein Byte-Sammler).

    Rein: kein I/O, keine Uhr; gleiche Eingabe -> gleiches Ergebnis. Leere Eingabe (oder
    eine, die nach der Bereinigung leer ist) -> leerer String (der Adapter entscheidet
    daraus die ``no_banner``-Semantik).
    """
    first_line = raw.splitlines()[0] if raw.splitlines() else ""
    # Nur druckbare Zeichen behalten (Steuerzeichen wie \t,\x00,\x1b raus); dann trimmen.
    printable = "".join(ch for ch in first_line if ch.isprintable())
    return printable.strip()[:_MAX_BANNER_LEN]
