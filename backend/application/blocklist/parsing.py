"""Reine Parser je ``BlocklistFormat`` -- zeitfrei, netzfrei, einzeln testbar.

Zerlegt den rohen Listentext einer Quelle in normalisierte ``(domains, ip_cidrs)``.
Kennt NUR ``domain.blocklist`` (die reine Normalisierung ``normalize_domain`` + die
Format-Enum) und stdlib (``csv``/``ipaddress``) -- keine Ports, kein Netz, keine Uhr.
So bleibt der Application-Ring testbar, ohne echte Quellen zu laden.

DISPATCH: ``parse_blocklist`` waehlt anhand der Formatfamilie die kleine, einzeln
testbare ``_parse_*``-Funktion. Jede liefert ``(domains, ip_cidrs)`` bereits
DEDUPLIZIERT bei STABILER Reihenfolge (``dict.fromkeys``) -- Kommentare/Leerzeilen
werden ignoriert.

ENTWURFSREGEL HOSTS: die Sentinel-Praefixe ``0.0.0.0``/``127.0.0.1``/``::`` sind KEINE
Threat-IPs -- sie werden verworfen; aus einer HOSTS-Zeile bleibt nur die Domain.
"""

import csv
import ipaddress

from domain.blocklist import BlocklistFormat, normalize_domain

__all__ = ["parse_blocklist"]

# HOSTS-Sentinels: nur Bind-Adressen, KEINE echten Threat-IPs -> verwerfen.
_HOSTS_SENTINELS: frozenset[str] = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1"})


def parse_blocklist(fmt: BlocklistFormat, raw_text: str) -> tuple[list[str], list[str]]:
    """Zerlegt ``raw_text`` je nach ``fmt`` in ``(domains, ip_cidrs)`` (normalisiert/dedupliziert).

    Dispatcht auf die kleine ``_parse_*``-Funktion der jeweiligen Formatfamilie. Das
    Ergebnis ist je Liste stabil sortiert nach Erstauftreten und dublettenfrei. Eine
    Formatfamilie, die nur Domains kennt, liefert ``ip_cidrs == []`` und umgekehrt.
    """
    if fmt is BlocklistFormat.HOSTS:
        return _parse_hosts(raw_text), []
    if fmt is BlocklistFormat.DOMAIN_LIST:
        return _parse_domain_list(raw_text), []
    if fmt is BlocklistFormat.ADBLOCK:
        return _parse_adblock(raw_text), []
    if fmt is BlocklistFormat.IP_LIST:
        return [], _parse_ip_list(raw_text)
    if fmt is BlocklistFormat.CSV_DOMAIN:
        return _parse_csv_domain(raw_text), []
    # CSV_IP -- der letzte Fall der StrEnum.
    return [], _parse_csv_ip(raw_text)


# ── Hilfen ────────────────────────────────────────────────────────────────────


def _dedupe(values: list[str]) -> list[str]:
    """Entfernt Dubletten bei STABILER Reihenfolge (Erstauftreten, ``dict.fromkeys``)."""
    return list(dict.fromkeys(values))


def _significant_lines(raw_text: str) -> list[str]:
    """Liefert die getrimmten, nicht-leeren, nicht-kommentierten Zeilen (``#``/``!``).

    Reine Zeilen-Vorfilterung fuer die zeilenbasierten Formate: Leerzeilen und
    voll-Kommentarzeilen (``#`` oder ``!`` als erstes Zeichen) fallen weg. Inline-
    Kommentare bleiben erhalten -- die schneidet der jeweilige Parser formatgerecht ab.
    """
    lines = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped[0] in ("#", "!"):
            continue
        lines.append(stripped)
    return lines


def _valid_ip_cidr(token: str) -> str | None:
    """Prueft per ``ipaddress`` (stdlib), ob ``token`` eine IP oder ein CIDR ist.

    Liefert die kanonische Schreibweise (``str`` des ``ip_address``/``ip_network``,
    ``strict=False`` -> Host-Bits in Netzen toleriert) oder ``None`` bei Unsinn. Eine
    nackte IP bleibt eine nackte IP (kein ``/32``-Anhang) -- der Lookup im Repo deckt
    beide Schreibweisen ab.
    """
    candidate = token.strip()
    if not candidate:
        return None
    if "/" in candidate:
        try:
            return str(ipaddress.ip_network(candidate, strict=False))
        except ValueError:
            return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


# ── Format-Parser (klein, einzeln testbar) ────────────────────────────────────


def _parse_hosts(raw_text: str) -> list[str]:
    """HOSTS-Format: ``0.0.0.0 domain`` / ``127.0.0.1 domain`` -> nur die Domain.

    Splittet jede Zeile in Whitespace-Token; das erste Token ist die Bind-Adresse
    (Sentinel -> verwerfen), die uebrigen sind Hostnamen. Jeder Hostname laeuft durch
    ``normalize_domain``; ungueltige fallen weg. Die Sentinel-IPs selbst werden NIE als
    IP-Eintrag aufgenommen.
    """
    domains: list[str] = []
    for line in _significant_lines(raw_text):
        # Inline-Kommentar nach '#' abschneiden (manche Hosts-Dateien haben welche).
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = line.split()
        # Erstes Token ist die Bind-Adresse; nur wenn sie ein bekanntes Sentinel ist,
        # gelten die Folge-Token als Hostnamen. Sonst die ganze Zeile als Hostnamen
        # deuten (manche Listen fuehren die Domain ohne fuehrende IP).
        host_tokens = tokens[1:] if tokens and tokens[0] in _HOSTS_SENTINELS else tokens
        for token in host_tokens:
            if token in _HOSTS_SENTINELS:
                continue
            normalized = normalize_domain(token)
            if normalized is not None:
                domains.append(normalized)
    return _dedupe(domains)


def _parse_domain_list(raw_text: str) -> list[str]:
    """DOMAIN_LIST: eine Domain (oder Wildcard ``*.x.y``) pro Zeile -> Domain.

    Strippt ein fuehrendes ``*.`` (Wildcard) und fuehrt den Rest durch
    ``normalize_domain``. Inline-Kommentare (``#``) werden abgeschnitten.
    """
    domains: list[str] = []
    for line in _significant_lines(raw_text):
        token = line.split("#", 1)[0].strip()
        if token.startswith("*."):
            token = token[2:]
        normalized = normalize_domain(token)
        if normalized is not None:
            domains.append(normalized)
    return _dedupe(domains)


def _parse_adblock(raw_text: str) -> list[str]:
    """ADBLOCK: ``||domain^`` -> Domain. Nicht-Domain-Regeln werden uebersprungen.

    Beruecksichtigt nur die einfache Netzwerk-Hosts-Regel ``||domain^``: Element-Hide-
    Regeln (``##``/``#@#``), Ausnahme-Regeln (``@@``) und alles ohne fuehrendes ``||``
    werden ignoriert (keine echte Domain-Sperre fuer den Aussenkontakt-Abgleich). Die
    Domain steht zwischen ``||`` und dem ersten ``^``/``/``/``$``/Zeilenende; Optionen
    nach ``$`` fallen weg. Ergebnis ueber ``normalize_domain``.
    """
    domains: list[str] = []
    for line in _significant_lines(raw_text):
        # Ausnahme- und Element-Hide-Regeln tragen keinen Sperr-Host fuer uns.
        if line.startswith("@@") or "##" in line or "#@#" in line:
            continue
        if not line.startswith("||"):
            continue
        rest = line[2:]
        # Domain endet am ersten Trenner: '^' (Adblock-Anker), Pfad '/', Optionen '$'.
        for sep in ("^", "/", "$"):
            idx = rest.find(sep)
            if idx != -1:
                rest = rest[:idx]
        normalized = normalize_domain(rest)
        if normalized is not None:
            domains.append(normalized)
    return _dedupe(domains)


def _parse_ip_list(raw_text: str) -> list[str]:
    """IP_LIST: eine IP oder CIDR pro Zeile -> gueltige IP/CIDR.

    Inline-Kommentar nach ``#`` oder ``;`` abschneiden; die Gueltigkeit prueft
    ``ipaddress`` (ungueltige Zeilen werden uebersprungen).
    """
    ip_cidrs: list[str] = []
    for line in _significant_lines(raw_text):
        token = line.split("#", 1)[0].split(";", 1)[0].strip()
        valid = _valid_ip_cidr(token)
        if valid is not None:
            ip_cidrs.append(valid)
    return _dedupe(ip_cidrs)


def _csv_rows(raw_text: str) -> list[list[str]]:
    """Liest ``raw_text`` als CSV (stdlib) -> Liste der Zeilen-Zellen (Kommentare raus).

    Voll-Kommentarzeilen (``#``) werden vor dem CSV-Parse entfernt; leere Zeilen fallen
    weg. Der ``csv``-Reader uebernimmt das Quoting korrekt.
    """
    payload = "\n".join(
        line for line in raw_text.splitlines() if line.strip() and not line.strip().startswith("#")
    )
    return [row for row in csv.reader(payload.splitlines()) if row]


def _parse_csv_domain(raw_text: str) -> list[str]:
    """CSV_DOMAIN: erste plausible Domain-Spalte je Zeile (Header tolerant uebersprungen).

    Probiert je Zeile die Zellen von links durch und nimmt die erste, die
    ``normalize_domain`` akzeptiert. Eine Header-Zeile (keine Zelle ist eine gueltige
    Domain) fuehrt zu keinem Eintrag und faellt damit von selbst heraus.
    """
    domains: list[str] = []
    for row in _csv_rows(raw_text):
        for cell in row:
            normalized = normalize_domain(cell.strip())
            if normalized is not None:
                domains.append(normalized)
                break
    return _dedupe(domains)


def _parse_csv_ip(raw_text: str) -> list[str]:
    """CSV_IP: erste plausible IP/CIDR-Spalte je Zeile (Header tolerant uebersprungen).

    Probiert je Zeile die Zellen von links durch und nimmt die erste, die ``ipaddress``
    als IP/CIDR akzeptiert. Eine Header-Zeile (keine gueltige Zelle) faellt heraus.
    """
    ip_cidrs: list[str] = []
    for row in _csv_rows(raw_text):
        for cell in row:
            valid = _valid_ip_cidr(cell.strip())
            if valid is not None:
                ip_cidrs.append(valid)
                break
    return _dedupe(ip_cidrs)
