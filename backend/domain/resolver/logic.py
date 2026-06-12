"""Reine Funktionen der resolver-Domaene -- kein I/O, voll unit-testbar.

Hier liegt die wertneutrale Logik, die aus Rohfakten ABGELEITETE Aussagen macht,
OHNE selbst Daten abzurufen: die Anti-Spoof-Bestaetigung des PTR, das Aufspueren von
Laender-Widerspruechen, die Feststellung (nicht Bewertung) eines self-signed-Zerts und
der lokale Port->Dienst-Hinweis. Alles stdlib-rein -- die Quell-Adapter liefern die
Rohdaten, diese Funktionen ordnen sie ein.
"""

from collections.abc import Sequence

# Lokale Lookup-Tabelle gaengiger Ports -> Dienst-Hinweis. Reine Daten im domain-Ring:
# ein HINWEIS, keine Garantie ueber den tatsaechlich laufenden Dienst.
_SERVICE_HINTS: dict[int, str] = {
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    443: "https",
    3389: "rdp",
    8443: "https-alt",
}

# Gaengige DynDNS-Suffixe: ein PTR-Name ODER TLS-CN, der auf eines dieser Suffixe
# endet, deutet auf einen DynDNS-Anbieter (die Gegenstelle ist ein Heim-/SoHo-
# Anschluss mit wechselnder IP hinter einem festen Namen). Reine Daten im
# domain-Ring: ein HINWEIS aus dem NAMEN, kein Lookup (kein DNSDB-Adapter, A1/Frage-2-B).
_DYNDNS_SUFFIXES: tuple[str, ...] = (
    "dyndns.org",
    "no-ip.com",
    "ddns.net",
    "dyn.com",
    "spdns.de",
    "myfritz.net",
    "dynv6.net",
    "duckdns.org",
)


def confirm_forward(forward_ips: Sequence[str], target_ip: str) -> bool:
    """Anti-Spoof: bestaetigt den PTR-Namen nur bei Vorwaerts-Rueckbezug.

    Gibt ``True`` nur zurueck, wenn ``target_ip`` in den Vorwaerts-Aufloesungen des
    PTR-Namens (``forward_ips``) enthalten ist -- der klassische Forward-Confirmed-
    Reverse-DNS-Abgleich. Ein PTR-Name, dessen Vorwaerts-Aufloesung NICHT auf die
    Ziel-IP zeigt, ist nicht bestaetigt (moegliches Spoofing) -> ``False``.
    """
    return target_ip in forward_ips


def flag_country_conflict(rdap_net: str | None, org_address: str | None, geodb: str | None) -> bool:
    """``True``, wenn sich mindestens zwei bekannte Laenderquellen widersprechen.

    Verglichen werden die NICHT-``None``-Werte, normalisiert ueber Grossschreibung und
    umgebenden Whitespace (damit "DE" und " de " als gleich gelten). Eine einzige
    bekannte Quelle (oder gar keine) kann sich nicht widersprechen -> ``False``. Reines
    AUFZEIGEN eines Widerspruchs, KEINE Aufloesung -- welche Quelle "recht" hat,
    entscheidet die resolver-Domaene bewusst nicht.
    """
    known = [value.strip().upper() for value in (rdap_net, org_address, geodb) if value is not None]
    return len(set(known)) > 1


def detect_self_signed(subject_cn: str | None, issuer: str | None) -> bool | None:
    """Stellt fest, ob ein Zertifikat selbst-signiert aussieht -- Feststellung, nicht Urteil.

    ``True`` wenn ``subject_cn`` und ``issuer`` beide vorhanden und gleich sind, sonst
    ``False``; ``None`` wenn eines der Daten fehlt (unbestimmbar). Bewusst eine reine
    FESTSTELLUNG (subject == issuer), KEINE Bewertung der Sicherheit -- ein
    selbst-signiertes Zertifikat ist nicht per se "schlecht"; das Einordnen bleibt
    spaeteren Ringen/Regeln ueberlassen.
    """
    if subject_cn is None or issuer is None:
        return None
    return subject_cn == issuer


def derive_dyndns(ptr_name: str | None, tls_subject_cn: str | None) -> str | None:
    """Erkennt einen DynDNS-Namen aus PTR-Name ODER TLS-CN -- rein, kein Lookup.

    Prueft beide Kandidaten (PTR zuerst, dann TLS-CN) gegen die Tabelle gaengiger
    DynDNS-Suffixe (``_DYNDNS_SUFFIXES``). Der erste Kandidat, der auf eines der
    Suffixe endet, wird (normalisiert: Whitespace und ein abschliessender Punkt
    entfernt, kleingeschrieben) zurueckgegeben. Kein Treffer / beide ``None`` /
    leere Eingaben -> ``None``. ABLEITUNG aus dem NAMEN, kein passives DNS (A1/
    Frage-2-B: kein DNSDB-Adapter) -- ein HINWEIS, dass die Gegenstelle ein
    DynDNS-Anschluss ist, keine Garantie.
    """
    for candidate in (ptr_name, tls_subject_cn):
        if not candidate:
            continue
        normalized = candidate.strip().rstrip(".").lower()
        if not normalized:
            continue
        for suffix in _DYNDNS_SUFFIXES:
            if normalized == suffix or normalized.endswith("." + suffix):
                return normalized
    return None


def service_hint_for_port(port: int | None) -> str | None:
    """Lokaler Port->Dienst-Hinweis aus einer festen Tabelle gaengiger Ports.

    Liefert den hinterlegten Hinweis (z. B. 443 -> "https") oder ``None`` fuer einen
    unbekannten bzw. fehlenden Port. Reine Daten im domain-Ring -- ein HINWEIS, keine
    Aussage ueber den tatsaechlich laufenden Dienst.
    """
    if port is None:
        return None
    return _SERVICE_HINTS.get(port)
