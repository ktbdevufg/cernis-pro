"""resolver-Adapter (Teilschritt 2c): RdapClient -- RIR-toleranter RDAP-Lookup.

Erfuellt ``ports.resolver.RdapClientPort`` strukturell: holt per HTTPS die RDAP-IP-Antwort
einer Gegenstelle und parst sie zu ``domain.resolver.RdapRawFacts``. Quelle ist
``rdap.org`` als RIR-toleranter Einstieg -- ``https://rdap.org/ip/<ip>`` leitet per
Redirect zur zustaendigen Registry (RIPE/ARIN/APNIC/LACNIC/AFRINIC); daher
``follow_redirects=True``.

httpx-Muster aus ``infrastructure.diagnostics_linux.HttpxReachabilityProvider`` uebernommen:
``httpx.AsyncClient`` mit festem ``Timeout``, HTTPS-Cert-Pflicht (KEIN ``verify=False``),
injizierbarer ``transport`` NUR fuer Tests (``httpx.MockTransport`` ersetzt das Netz, ohne
die Cert-/Timeout-Naht zu verbiegen). httpx ist vorhandene Dependency.

STRENG FEHLERTOLERANT laut Port-Vertrag: bei JEGLICHEM Fehlschlag (Timeout, HTTP-
Fehlerstatus, Netzfehler, ungueltiges/leeres JSON, Parse-Fehler, beliebige Exception) ->
leerer ``RdapRawFacts()`` (alle Felder ``None``). NIE werfen.

RIR-Strukturen variieren stark -- das gesamte Parsen lebt in reinen, testbaren Helfern
AUSSERHALB der Klasse, die mit unvollstaendigen/fehlerhaften dicts klarkommen und ``None``
statt einer Exception liefern. Die Klasse orchestriert nur HTTP + Helfer.

``asn``/``asn_org`` bleiben BEWUSST ``None``: die Origin-ASN steht nicht zuverlaessig im
RDAP-IP-Objekt; ASN kommt spaeter aus der Geo-DB (2d), NICHT aus RDAP geraten.

EIGENSTAENDIG (independence-Contract): KEIN ``modules``-Import, KEIN Import aus
``application``/``api`` (Contract "infrastructure kennt nicht application/api").
"""

from typing import Any

import httpx

from domain.resolver import RdapRawFacts

# Festes Timeout fuer den RDAP-Aufruf -- ein haengender RIR-Dienst darf den Request nicht
# unbegrenzt blockieren. Bewusst grosszuegiger als der cpnetcheck-Connect: RDAP-Server
# (samt Redirect zur Registry) koennen langsamer antworten.
_RDAP_TIMEOUT_SECS = 8.0

# rdap.org als RIR-toleranter Einstieg: leitet per Redirect zur zustaendigen Registry.
_RDAP_BASE_URL = "https://rdap.org/ip/"


def _jcard_field(vcard_array: Any, field_name: str) -> str | None:
    """Liefert den Wert eines jCard-Eintrags (z. B. ``fn``/``email``) -- rein, kein I/O.

    Eine RDAP-Entity traegt optional ``vcardArray``:
    ``["vcard", [ ["version",{},"text","4.0"], ["fn",{},"text","ACME"], ... ]]``.
    Jeder Eintrag ist ``[name, params, typ, wert]``; gesucht wird der erste Eintrag mit
    passendem ``name``, dessen Wert zurueckkommt. Tolerant gegen fehlende/teilweise
    Strukturen (kein ``vcardArray``, falsche Laenge, falsche Typen) -> ``None`` statt
    Exception. Rein: kein I/O.
    """
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    entries = vcard_array[1]
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        if entry[0] == field_name:
            value = entry[3]
            return str(value) if value not in (None, "") else None
    return None


def _walk_entities(entities: Any, role: str) -> dict[str, Any] | None:
    """Findet REKURSIV die erste Entity mit ``role`` in ihrem ``roles``-Array -- rein.

    Steigt in verschachtelte ``entities`` ab (RIR-Unterschied: die abuse-Entity kann eine
    Ebene tiefer unter der Org-Entity haengen). Tiefensuche: zuerst die Entity selbst, dann
    ihre Kinder. Tolerant gegen fehlende Keys / falsche Typen (kein ``roles``, kein
    ``entities``, Nicht-Listen) -> ``None`` statt Exception. Rein: kein I/O.
    """
    if not isinstance(entities, list):
        return None
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles")
        if isinstance(roles, list) and role in roles:
            return entity
        nested = _walk_entities(entity.get("entities"), role)
        if nested is not None:
            return nested
    return None


def _extract_org(rdap_json: dict[str, Any]) -> str | None:
    """Liefert den Org-Anzeigenamen -- ``fn`` aus dem jCard, sonst ``handle``, sonst ``None``.

    Sucht die erste Organisations-Entity ueber die Rolle ``registrant``, ersatzweise
    ``administrative``. Anzeigename ist der jCard-``fn``-Eintrag; fehlt er, der entity-
    ``handle``. Keine passende Entity -> ``None``. Rein: kein I/O.
    """
    entities = rdap_json.get("entities")
    entity = _walk_entities(entities, "registrant") or _walk_entities(entities, "administrative")
    if entity is None:
        return None
    name = _jcard_field(entity.get("vcardArray"), "fn")
    if name is not None:
        return name
    handle = entity.get("handle")
    return str(handle) if handle not in (None, "") else None


def _extract_abuse(rdap_json: dict[str, Any]) -> str | None:
    """Liefert die Abuse-Email aus der Entity mit Rolle ``abuse`` -- rekursiv, rein.

    Die abuse-Entity kann eine Ebene tiefer in verschachtelten ``entities`` liegen (RIR-
    abhaengig) -> rekursiver Walk. Aus ihrem jCard kommt der ``email``-Eintrag; fehlt er
    oder fehlt die Entity -> ``None``. Rein: kein I/O.
    """
    entity = _walk_entities(rdap_json.get("entities"), "abuse")
    if entity is None:
        return None
    return _jcard_field(entity.get("vcardArray"), "email")


def _extract_netname(rdap_json: dict[str, Any]) -> str | None:
    """Liefert das ``name``-Feld des IP-Netz-Objekts (Netname), sonst ``None`` -- rein."""
    name = rdap_json.get("name")
    return str(name) if name not in (None, "") else None


def _extract_net_range(rdap_json: dict[str, Any]) -> str | None:
    """Liefert den Adressbereich -- ``start - end``, sonst ``cidr0_cidrs``, sonst ``handle``.

    Bevorzugt ``startAddress``/``endAddress`` als ``"start - end"``. Fehlt eines, faellt es
    auf ``cidr0_cidrs`` zurueck (Liste von ``{v4prefix|v6prefix, length}`` -> ``"prefix/len"``,
    erster Eintrag), sonst auf ``handle``. Nichts davon vorhanden -> ``None``. Rein: kein I/O.
    """
    start = rdap_json.get("startAddress")
    end = rdap_json.get("endAddress")
    if start not in (None, "") and end not in (None, ""):
        return f"{start} - {end}"

    cidrs = rdap_json.get("cidr0_cidrs")
    if isinstance(cidrs, list):
        for cidr in cidrs:
            if not isinstance(cidr, dict):
                continue
            prefix = cidr.get("v4prefix", cidr.get("v6prefix"))
            length = cidr.get("length")
            if prefix not in (None, "") and length is not None:
                return f"{prefix}/{length}"

    handle = rdap_json.get("handle")
    return str(handle) if handle not in (None, "") else None


def _extract_country(rdap_json: dict[str, Any]) -> str | None:
    """Liefert das ``country``-Feld der IP-Antwort, sonst ``None`` -- rein, kein I/O.

    BEWUSST nur Durchreichen: RDAP-Land ist RIR-abhaengig oft leer -> ``None``. Das Land
    kommt spaeter primaer aus der Geo-DB (2d); hier wird nur weitergegeben, was RDAP gibt.
    """
    country = rdap_json.get("country")
    return str(country) if country not in (None, "") else None


def _parse_rdap(rdap_json: dict[str, Any]) -> RdapRawFacts:
    """Baut ``RdapRawFacts`` aus der RDAP-IP-Antwort -- rein, ueber die Helfer, kein I/O.

    ``asn``/``asn_org`` bleiben BEWUSST ``None`` (Origin-ASN nicht zuverlaessig im RDAP-IP-
    Objekt; kommt aus der Geo-DB 2d, NICHT aus RDAP geraten). Jedes Feld kommt ehrlich aus
    seinem Helfer -- fehlend/unklar -> ``None``. Rein: kein I/O.
    """
    return RdapRawFacts(
        org=_extract_org(rdap_json),
        netname=_extract_netname(rdap_json),
        net_range=_extract_net_range(rdap_json),
        asn=None,  # bewusst None: Origin-ASN nicht zuverlaessig im RDAP-IP-Objekt (-> Geo-DB)
        asn_org=None,  # bewusst None: ASN-Org kommt aus der Geo-DB (2d), nicht aus RDAP geraten
        abuse_contact=_extract_abuse(rdap_json),
        country=_extract_country(rdap_json),
    )


class RdapClient:
    """Erfuellt das ``RdapClientPort``-Protocol -- RIR-toleranter RDAP-Lookup (httpx).

    ``transport`` ist NUR fuer Tests gedacht (``httpx.MockTransport``): ist es ``None``
    (Produktiv-Default, wie ``RdapClient()`` in app.py), baut der Adapter einen echten
    Client OHNE ``verify``-Abschaltung (HTTPS-Cert-Pflicht) und mit ``follow_redirects=True``
    (rdap.org leitet zur zustaendigen Registry). Ein injizierter Transport ersetzt das Netz
    im Test, ohne die Cert-/Timeout-/Redirect-Naht zu verbiegen.
    """

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport

    async def lookup(self, ip: str) -> RdapRawFacts:
        """Liefert die RDAP-Rohfakten zur ``ip`` (leerer ``RdapRawFacts`` wenn nichts).

        Async Netz-I/O ueber httpx. STRENG fehlertolerant laut Port-Vertrag: JEDER
        Fehlschlag (Timeout, HTTP-Fehlerstatus >=400, Netzfehler, ungueltiges/leeres JSON,
        Parse-Fehler, beliebige Exception) -> leerer ``RdapRawFacts()``; NIE werfen.
        """
        try:
            payload = await self._fetch(ip)
        except Exception:
            # Port-Vertrag: bei JEGLICHEM Fehlschlag still leerer RdapRawFacts (kein
            # Werfen) -- Timeout/Netzfehler/HTTP-Fehler/kaputtes JSON/beliebige Exception.
            return RdapRawFacts()
        if not isinstance(payload, dict):
            # Antwort ist kein JSON-Objekt (z. B. Liste/null) -> nichts verwertbar.
            return RdapRawFacts()
        return _parse_rdap(payload)

    async def _fetch(self, ip: str) -> Any:
        """Fuehrt EINEN HTTPS-RDAP-Aufruf aus und liefert den geparsten JSON-Body.

        ``transport=None`` -> echter Client (HTTPS-Cert-Pflicht, kein verify-Disable);
        ein injizierter MockTransport (nur Tests) ersetzt das Netz, ohne die Naht zu
        verbiegen. ``follow_redirects=True``: rdap.org leitet zum zustaendigen RIR. Ein
        Fehlerstatus (>=400) wird ueber ``raise_for_status`` zum ``httpx.HTTPError``; den
        faengt ``lookup`` zentral ab. Kaputtes JSON -> ``ValueError`` (ebenfalls dort).
        """
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(_RDAP_TIMEOUT_SECS),
            transport=self._transport,
            follow_redirects=True,
        ) as client:
            response = await client.get(
                f"{_RDAP_BASE_URL}{ip}",
                headers={"Accept": "application/rdap+json, application/json"},
            )
        response.raise_for_status()
        return response.json()
