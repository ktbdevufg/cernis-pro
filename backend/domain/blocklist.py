"""Domaenenmodell der blocklist-Domaene: Abgleich von Aussenkontakten gegen Blocklists.

Reine Domaenenlogik (stdlib only, ADR 0002 -- kein Pydantic, kein Netz, keine Uhr).
CERNIS bewertet NICHT selbst -- die Einordnung gehoert der jeweiligen Liste; diese
Datei definiert nur das Vokabular (StrEnums), die unveraenderlichen Datentraeger
(``frozen`` dataclasses, Muster ``domain/scheduler/models.py``) und die reinen,
zeitfreien Funktionen, die einen Aussenkontakt gegen extern gepflegte Listen pruefbar
machen.

Muster konsequent aus der Nachbarschaft: ``StrEnum``-Einzelwerte wie
``domain/maintenance.py`` (der Wire-Wert ist der String), ``frozen`` dataclasses wie
``domain/scheduler/models.py``. Die Heuristiken (``detect_license_hint``) verweigern
NICHTS -- sie sind nur ein freundlicher Hinweis an den Nutzer.
"""

import ipaddress
from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "DEFAULT_SOURCES",
    "BlocklistFormat",
    "BlocklistGroup",
    "BlocklistMatch",
    "BlocklistSource",
    "BlocklistStatus",
    "ContactMatchResult",
    "MatchStrictness",
    "SourceOrigin",
    "detect_license_hint",
    "domain_suffix_candidates",
    "ip_in_cidr",
    "normalize_domain",
    "strictness_allows",
]


# ── Vokabular (StrEnums) ──────────────────────────────────────────────────────


class BlocklistGroup(StrEnum):
    """Die fachliche Gruppe einer Blocklist -- WAS die Liste klassifiziert.

    ``TRACKER_ADS`` umfasst Tracker und Werbung, ``THREAT`` umfasst Bedrohungen
    (Malware/Botnet/Abuse). ``DOH`` klassifiziert bekannte DoH-Anbieter (DNS-over-HTTPS):
    deren Nutzung umgeht den Heim-DNS und wird vom netzweiten Waechter direkt abgefragt
    (s. ``strictness_allows``). Der Wert ist direkt log-/wire-tauglich (``StrEnum``).
    """

    TRACKER_ADS = "tracker_ads"
    THREAT = "threat"
    DOH = "doh"


class BlocklistFormat(StrEnum):
    """Die Parser-Formatfamilie einer Blocklist-Quelle.

    Bestimmt, wie der spaetere Lade-/Parse-Schritt (Application/Infrastructure) die rohe
    Quelle in Domain- bzw. IP-Eintraege zerlegt -- die Domaene parst hier NICHTS, sie
    benennt nur die Familie:

    * ``HOSTS``       -- klassisches Hosts-Format (``0.0.0.0 domain`` / ``127.0.0.1 domain``).
    * ``ADBLOCK``     -- Adblock-Syntax (``||domain^``).
    * ``DOMAIN_LIST`` -- eine Domain pro Zeile, plain.
    * ``IP_LIST``     -- eine IP oder CIDR pro Zeile.
    * ``CSV_DOMAIN``  -- CSV, Domain in einer Spalte.
    * ``CSV_IP``      -- CSV, IP in einer Spalte.
    """

    HOSTS = "hosts"
    ADBLOCK = "adblock"
    DOMAIN_LIST = "domain_list"
    IP_LIST = "ip_list"
    CSV_DOMAIN = "csv_domain"
    CSV_IP = "csv_ip"


class BlocklistStatus(StrEnum):
    """Lade-Zustand einer Quelle (zuletzt bekannter Stand).

    ``NEVER`` -- noch nie geladen; ``OK`` -- zuletzt erfolgreich geladen und geparst;
    ``BROKEN`` -- Download oder Parse fehlgeschlagen.
    """

    NEVER = "never"
    OK = "ok"
    BROKEN = "broken"


class SourceOrigin(StrEnum):
    """Herkunft einer Quelle -- WOHER die Listen-Definition stammt.

    ``BUILTIN`` -- mitgelieferte Werksquelle; ``USER_URL`` -- vom Nutzer per URL
    hinzugefuegt; ``UPLOAD`` -- vom Nutzer hochgeladene Datei (keine Refresh-URL,
    ``url`` ist dann ``None``).
    """

    BUILTIN = "builtin"
    USER_URL = "user_url"
    UPLOAD = "upload"


class MatchStrictness(StrEnum):
    """Anzeige-Strenge: WELCHE Treffer dem Nutzer ueberhaupt gezeigt werden.

    Reine Stufen-Semantik (siehe ``strictness_allows``):

    * ``CRITICAL_ONLY`` -- nur ``THREAT``-Treffer zeigen.
    * ``RECOMMENDED``   -- ``THREAT`` + ``TRACKER_ADS`` (Default).
    * ``ALL``           -- alle Treffer (inkl. reiner Werbung).

    Die Gruppen-Feinschalter (pro Gruppe an/aus) liegen NICHT hier in der Domaene --
    sie sind Settings-/Application-Belang. Die Domaene definiert nur die Stufen.
    """

    CRITICAL_ONLY = "critical_only"
    RECOMMENDED = "recommended"
    ALL = "all"


# ── Datentraeger (frozen) ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class BlocklistSource:
    """Definition EINER Blocklist-Quelle (unveraenderlicher Datentraeger).

    Beschreibt eine extern gepflegte Liste samt Herkunft, Lizenz und zuletzt bekanntem
    Lade-Zustand. ``url`` ist ``None`` bei ``UPLOAD`` (keine Refresh-URL). ``license``
    ist ein freier Bezeichner-String (z. B. ``"MIT"``/``"CC0"``/``"unknown"``).
    ``last_fetched_ts`` ist Unix-ts oder ``None`` (noch nie geladen); ``entry_count``
    die Zahl geparster Eintraege oder ``None`` (unbekannt). Zeit als roher ``float`` --
    die Domaene haelt keine Uhr.

    * ``id``                   -- stabile slug-id (z. B. ``"stevenblack_hosts"``).
    * ``name``                 -- Anzeigename.
    * ``group``                -- fachliche Gruppe (``BlocklistGroup``).
    * ``fmt``                  -- Parser-Formatfamilie (``BlocklistFormat``).
    * ``origin``               -- Herkunft (``SourceOrigin``).
    * ``url``                  -- Bezugs-URL oder ``None`` (bei ``UPLOAD``).
    * ``license``              -- Lizenz-Bezeichner.
    * ``attribution_required`` -- ob die Lizenz Namensnennung verlangt.
    * ``enabled``              -- ob die Quelle aktiv abgeglichen wird.
    * ``last_fetched_ts``      -- Unix-ts des letzten Ladens oder ``None``.
    * ``status``               -- zuletzt bekannter Lade-Zustand (``BlocklistStatus``).
    * ``entry_count``          -- Zahl geparster Eintraege oder ``None``.
    """

    id: str
    name: str
    group: BlocklistGroup
    fmt: BlocklistFormat
    origin: SourceOrigin
    url: str | None
    license: str
    attribution_required: bool
    enabled: bool
    last_fetched_ts: float | None
    status: BlocklistStatus
    entry_count: int | None


@dataclass(frozen=True)
class BlocklistMatch:
    """EIN Treffer eines Aussenkontakts gegen genau eine Quelle (Datentraeger).

    Traegt die Quelle (``source_id``/``source_name``/``group``) und den konkreten Wert,
    auf den getroffen wurde (``matched_on`` -- die Domain oder die IP/CIDR). Die
    Einordnung gehoert der Liste: ``group`` ist die Gruppe der TREFFENDEN Quelle, kein
    eigenes CERNIS-Urteil.
    """

    source_id: str
    source_name: str
    group: BlocklistGroup
    matched_on: str


@dataclass(frozen=True)
class ContactMatchResult:
    """Das gebuendelte Ergebnis fuer EINEN Aussenkontakt (Datentraeger).

    Haelt den geprueften Kontakt (``remote_ip`` + optionaler ``hostname``) und die Menge
    der Treffer (``matches`` als unveraenderliches Tuple). Leeres Tuple = kein Treffer
    (der Kontakt steht auf keiner aktiven Liste).
    """

    remote_ip: str
    hostname: str | None
    matches: tuple[BlocklistMatch, ...]


# ── Reine Funktionen (zeitfrei, netzfrei, testbar) ────────────────────────────


def normalize_domain(raw: str) -> str | None:
    """Normalisiert einen rohen Domain-String -> kleingeschriebene, www-freie Domain.

    Trimmt Leerraum, lowercased, entfernt ein fuehrendes ``www.`` und einen
    Trailing-Dot. Gibt ``None`` bei leerer oder offensichtlich ungueltiger Eingabe
    (kein Punkt enthalten, oder enthaelt Leerraum/Schraegstrich). KEIN Netz, KEIN DNS --
    rein lexikalisch.
    """
    host = raw.strip().lower()
    if not host:
        return None
    host = host.rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host:
        return None
    # Offensichtlich ungueltig: kein Punkt (keine echte Domain), oder enthaelt
    # Trenner/Leerraum, die in einer Domain nichts zu suchen haben.
    if "." not in host:
        return None
    if any(ch.isspace() for ch in host) or "/" in host:
        return None
    return host


def domain_suffix_candidates(host: str) -> tuple[str, ...]:
    """Liefert ``host`` plus alle Eltern-Domains fuer Suffix-Matching gegen Domain-Listen.

    ``sub.example.com`` -> ``("sub.example.com", "example.com", "com")``. Das Ergebnis
    ist lowercased und www-frei (fuehrendes ``www.`` wird wie in ``normalize_domain``
    entfernt). So kann der Aufrufer mit EINEM Set-Lookup pruefen, ob irgendeine
    Eltern-Domain auf einer Domain-Liste steht. Leere/punktlose Eingabe liefert das
    bereinigte Einzel-Element bzw. ein leeres Tuple bei ganz leerer Eingabe.
    """
    cleaned = host.strip().lower().rstrip(".")
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]
    if not cleaned:
        return ()
    labels = cleaned.split(".")
    # Jede Suffix-Variante: ganzer Host, dann jeweils das fuehrende Label abschneiden.
    return tuple(".".join(labels[i:]) for i in range(len(labels)))


def strictness_allows(group: BlocklistGroup, strictness: MatchStrictness) -> bool:
    """Reine Stufen-Semantik: darf ein Treffer dieser ``group`` bei ``strictness`` erscheinen?

    * ``CRITICAL_ONLY`` -> nur ``THREAT`` ist ``True``.
    * ``RECOMMENDED``   -> ``THREAT`` und ``TRACKER_ADS`` sind ``True``.
    * ``ALL``           -> immer ``True``.

    KEINE Gruppen-Feinschalter (pro Gruppe an/aus) -- die liegen in Settings/Application.

    BEWUSST: ``DOH`` laeuft NICHT ueber die Anzeige-Strenge. Die Strenge-Stufen gehoeren
    den Aussenkontakten (Tracker/Threat); DoH ist eine eigene Achse. Der netzweite
    Waechter fragt die DoH-Gruppe DIREKT ab (steht das Ziel in einer aktiven DOH-Quelle?),
    unabhaengig von dieser Anzeige-Strenge. Ein ``DOH``-Treffer wird hier folglich mit
    ``False`` beantwortet -- das ist KORREKT und Absicht, kein fehlender Zweig.
    """
    if strictness is MatchStrictness.ALL:
        return True
    if strictness is MatchStrictness.RECOMMENDED:
        return group in (BlocklistGroup.THREAT, BlocklistGroup.TRACKER_ADS)
    # CRITICAL_ONLY
    return group is BlocklistGroup.THREAT


def ip_in_cidr(ip: str, cidr: str) -> bool:
    """Prueft per ``ipaddress`` (stdlib), ob ``ip`` in ``cidr`` liegt.

    Akzeptiert ``cidr`` ohne ``/`` (plain IP) als ``/32`` (IPv4) bzw. ``/128`` (IPv6).
    Ungueltige Eingaben (keine IP, falsche Familie, Muell) liefern ``False`` -- KEIN
    Werfen, KEIN stiller Erfolg. Rein lexikalisch/rechnerisch, kein Netz.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return False
    # Familien-Mismatch (IPv4 gegen IPv6-Netz oder umgekehrt) ist kein Treffer.
    if addr.version != network.version:
        return False
    return addr in network


def detect_license_hint(url: str) -> str | None:
    """Kleine Heuristik: schaetzt anhand des URL-Hosts einen Lizenz-HINWEIS oder ``None``.

    Prueft den Host der ``url`` gegen eine eingebaute Tabelle bekannter
    copyleft-/attribution-pflichtiger Quellen (Substring-Treffer im Host) und gibt einen
    HINWEIS-String zurueck. Dient NUR dem freundlichen Hinweis an den Nutzer
    (Attribution/Share-Alike beachten) -- die Funktion verweigert NICHTS, sie urteilt
    nicht. Reine Funktion, kein Netz.
    """
    # Substring im Host -> Lizenz-Hinweis. Bewusst klein und wartbar gehalten.
    table: tuple[tuple[str, str], ...] = (
        ("easylist", "GPL-2.0-or-later / CC-BY-SA-3.0"),
        ("adguard", "GPL-3.0 / CC-BY-SA"),
        ("disconnect", "GPL-3.0"),
        ("fanboy", "CC-BY-SA-3.0"),
    )
    lowered = url.strip().lower()
    # Host aus der URL ziehen, ohne urllib-Vollparse: nach optionalem Schema bis zum
    # ersten Pfad-/Port-Trenner. Faellt bei schemalosen Eingaben auf den Gesamtstring
    # zurueck (Substring-Suche bleibt korrekt).
    rest = lowered.split("://", 1)[-1]
    host = rest.split("/", 1)[0].split(":", 1)[0]
    for needle, hint in table:
        if needle in host:
            return hint
    return None


# ── Werksliste ────────────────────────────────────────────────────────────────

# Mitgelieferte Werksquellen. Vorausgewaehlte (``enabled=True``) sind bewusst
# lizenzrobust (permissiv / public domain); die Copyleft-Quellen sind mitgeliefert,
# aber DEAKTIVIERT (erst nach Lizenzklaerung durch den Nutzer aktivieren). Alle:
# ``origin=BUILTIN``, ``last_fetched_ts=None``, ``status=NEVER``, ``entry_count=None``.
DEFAULT_SOURCES: tuple[BlocklistSource, ...] = (
    BlocklistSource(
        id="stevenblack_hosts",
        name="StevenBlack Unified Hosts",
        group=BlocklistGroup.TRACKER_ADS,
        fmt=BlocklistFormat.HOSTS,
        origin=SourceOrigin.BUILTIN,
        url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        license="MIT",
        attribution_required=False,
        enabled=True,
        last_fetched_ts=None,
        status=BlocklistStatus.NEVER,
        entry_count=None,
    ),
    BlocklistSource(
        id="oisd_small",
        name="OISD Small",
        group=BlocklistGroup.TRACKER_ADS,
        fmt=BlocklistFormat.DOMAIN_LIST,
        origin=SourceOrigin.BUILTIN,
        url="https://small.oisd.nl/domainswild2",
        license="custom-free",
        attribution_required=True,
        enabled=True,
        last_fetched_ts=None,
        status=BlocklistStatus.NEVER,
        entry_count=None,
    ),
    BlocklistSource(
        id="urlhaus",
        name="URLhaus (abuse.ch)",
        group=BlocklistGroup.THREAT,
        # Das urlhaus-hostfile ist HOSTS-Format (0.0.0.0 domain) -> fmt HOSTS.
        fmt=BlocklistFormat.HOSTS,
        origin=SourceOrigin.BUILTIN,
        url="https://urlhaus.abuse.ch/downloads/hostfile/",
        license="CC0",
        attribution_required=False,
        enabled=True,
        last_fetched_ts=None,
        status=BlocklistStatus.NEVER,
        entry_count=None,
    ),
    BlocklistSource(
        id="feodo_ipblocklist",
        name="Feodo Tracker IP Blocklist (abuse.ch)",
        group=BlocklistGroup.THREAT,
        fmt=BlocklistFormat.IP_LIST,
        origin=SourceOrigin.BUILTIN,
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        license="CC0",
        attribution_required=False,
        enabled=True,
        last_fetched_ts=None,
        status=BlocklistStatus.NEVER,
        entry_count=None,
    ),
    # FireHOL Level 1 fuehrt bewusst private/reservierte Bogon-Netze (127/8,
    # 192.168/16, 10/8) und wuerde eigene Infrastruktur als "Bedrohung" treffen --
    # im Heim-/SOHO-Alltag praktisch nur Reibung statt echter Treffer. Feodo deckt
    # aktive Threat-IPs ohne Bogon-Reibung ab. Daher mitgeliefert, aber AUS.
    BlocklistSource(
        id="firehol_level1",
        name="FireHOL Level 1",
        group=BlocklistGroup.THREAT,
        fmt=BlocklistFormat.IP_LIST,
        origin=SourceOrigin.BUILTIN,
        url=(
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/"
            "firehol_level1.netset"
        ),
        license="MIT",
        attribution_required=False,
        enabled=False,
        last_fetched_ts=None,
        status=BlocklistStatus.NEVER,
        entry_count=None,
    ),
    # ── Mitgeliefert, aber DEAKTIVIERT (Copyleft -- erst nach Lizenzklaerung) ──
    BlocklistSource(
        id="easylist",
        name="EasyList",
        group=BlocklistGroup.TRACKER_ADS,
        fmt=BlocklistFormat.ADBLOCK,
        origin=SourceOrigin.BUILTIN,
        url="https://easylist.to/easylist/easylist.txt",
        license="GPL-2.0-or-later / CC-BY-SA-3.0",
        attribution_required=True,
        enabled=False,
        last_fetched_ts=None,
        status=BlocklistStatus.NEVER,
        entry_count=None,
    ),
    BlocklistSource(
        id="easyprivacy",
        name="EasyPrivacy",
        group=BlocklistGroup.TRACKER_ADS,
        fmt=BlocklistFormat.ADBLOCK,
        origin=SourceOrigin.BUILTIN,
        url="https://easylist.to/easylist/easyprivacy.txt",
        license="GPL-2.0-or-later / CC-BY-SA-3.0",
        attribution_required=True,
        enabled=False,
        last_fetched_ts=None,
        status=BlocklistStatus.NEVER,
        entry_count=None,
    ),
    # ── DoH-Anbieter (kuratierte Eigen-Zusammenstellung) ──────────────────────
    # Kuratierte, klartext, permissive (CC0) Eigen-Zusammenstellung bekannter
    # oeffentlicher DoH-Endpunkte -- durch den Nutzer erweiterbar. Der KLARTEXT-Inhalt
    # ist MITGELIEFERT (application/blocklist/doh_builtin.py), darum ``url=None`` wie bei
    # UPLOAD: keine Refresh-URL; der Bootstrap laedt den eingebauten Inhalt direkt.
    BlocklistSource(
        id="doh_providers_ip",
        name="Bekannte DoH-Anbieter (IP)",
        group=BlocklistGroup.DOH,
        fmt=BlocklistFormat.IP_LIST,
        origin=SourceOrigin.BUILTIN,
        url=None,
        license="CC0",
        attribution_required=False,
        enabled=True,
        last_fetched_ts=None,
        status=BlocklistStatus.NEVER,
        entry_count=None,
    ),
    BlocklistSource(
        id="doh_providers_domain",
        name="Bekannte DoH-Anbieter (Domain)",
        group=BlocklistGroup.DOH,
        fmt=BlocklistFormat.DOMAIN_LIST,
        origin=SourceOrigin.BUILTIN,
        url=None,
        license="CC0",
        attribution_required=False,
        enabled=True,
        last_fetched_ts=None,
        status=BlocklistStatus.NEVER,
        entry_count=None,
    ),
)
