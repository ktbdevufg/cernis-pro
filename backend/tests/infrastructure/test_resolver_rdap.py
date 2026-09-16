"""Tests des resolver-Rdap-Adapters -- reine Helfer + gemockter httpx-Pfad, kein Netz.

Kein echter RDAP-Aufruf: die reinen Helfer (``_jcard_field``/``_walk_entities``/
``_extract_*``) werden direkt gegen zwei REALISTISCHE, unterschiedlich strukturierte
RDAP-IP-Antworten geprueft -- eine RIPE-artige (gesetztes ``country`` + verschachtelte
abuse-Entity) und eine ARIN-artige (leeres ``country`` + abuse eine Ebene tiefer). Der
Adapter-Kern ``lookup`` laeuft gegen einen ``httpx.MockTransport`` (Mock-Muster wie der
``HttpxReachabilityProvider``-Test in ``test_diagnostics_linux.py``). Geprueft wird die
strenge Fehlertoleranz des Port-Vertrags: jeder Fehlschlag -> leerer ``RdapRawFacts()``.
"""

import asyncio

import httpx

from domain.resolver import RdapRawFacts
from infrastructure.resolver.rdap import (
    RdapClient,
    _extract_abuse,
    _extract_country,
    _extract_net_range,
    _extract_netname,
    _extract_org,
    _jcard_field,
    _walk_entities,
)

# ── Zwei realistische, unterschiedlich strukturierte RDAP-IP-Antworten ─────────

# RIPE-artig: gesetztes country, startAddress/endAddress, und die abuse-Entity haengt
# VERSCHACHTELT unter der registrant-Org-Entity (RIR-typisch).
_RIPE_RESPONSE = {
    "handle": "193.0.0.0 - 193.0.23.255",
    "name": "RIPE-NCC",
    "startAddress": "193.0.0.0",
    "endAddress": "193.0.23.255",
    "country": "NL",
    "entities": [
        {
            "handle": "ORG-RIEN1-RIPE",
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Reseaux IP Europeens Network Coordination Centre"],
                ],
            ],
            "entities": [
                {
                    "handle": "ABUSE-RIPE",
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "RIPE NCC Abuse"],
                            ["email", {}, "text", "abuse@ripe.example"],
                        ],
                    ],
                }
            ],
        }
    ],
}

# ARIN-artig: country FEHLT (leer -> None), Bereich nur als cidr0_cidrs, registrant-Org
# OHNE fn (-> handle als Org), und die abuse-Entity liegt eine Ebene tiefer unter der
# administrative-Entity.
_ARIN_RESPONSE = {
    "handle": "NET-104-16-0-0-1",
    "name": "CLOUDFLARENET",
    "cidr0_cidrs": [{"v4prefix": "104.16.0.0", "length": 12}],
    "entities": [
        {
            "handle": "CLOUD14",
            "roles": ["registrant", "administrative"],
            # KEIN vcardArray -> Org faellt auf den handle zurueck.
            "entities": [
                {
                    "handle": "ABUSE2916-ARIN",
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Abuse"],
                            ["email", {}, "text", "abuse@cloudflare.example"],
                        ],
                    ],
                }
            ],
        }
    ],
}


# ── jCard-Helfer (_jcard_field) ───────────────────────────────────────────────


def test_jcard_field_reads_fn_and_email() -> None:
    vcard = _RIPE_RESPONSE["entities"][0]["entities"][0]["vcardArray"]  # type: ignore[index]
    assert _jcard_field(vcard, "fn") == "RIPE NCC Abuse"
    assert _jcard_field(vcard, "email") == "abuse@ripe.example"


def test_jcard_field_missing_vcard_is_none() -> None:
    # Fehlendes/leeres vcardArray -> None, keine Exception.
    assert _jcard_field(None, "fn") is None
    assert _jcard_field([], "fn") is None
    assert _jcard_field(["vcard"], "fn") is None


def test_jcard_field_partial_jcard_only_present_fields() -> None:
    # Teilweises jCard: nur fn vorhanden -> email ist None, fn kommt.
    partial = ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Nur Name"]]]
    assert _jcard_field(partial, "fn") == "Nur Name"
    assert _jcard_field(partial, "email") is None


def test_jcard_field_tolerates_malformed_entries() -> None:
    # Kaputte Eintraege (zu kurz, falscher Typ) werden uebersprungen, nicht geworfen.
    broken = ["vcard", [["fn"], "nonsense", ["email", {}, "text", "ok@example"]]]
    assert _jcard_field(broken, "email") == "ok@example"
    assert _jcard_field(broken, "fn") is None


# ── Rekursiver Entity-Walk (_walk_entities) ────────────────────────────────────


def test_walk_entities_finds_role_at_top_level() -> None:
    entities = _RIPE_RESPONSE["entities"]
    found = _walk_entities(entities, "registrant")
    assert found is not None and found["handle"] == "ORG-RIEN1-RIPE"


def test_walk_entities_descends_into_nested_for_abuse() -> None:
    # abuse haengt eine Ebene tiefer -> rekursiver Abstieg noetig.
    found = _walk_entities(_RIPE_RESPONSE["entities"], "abuse")
    assert found is not None and found["handle"] == "ABUSE-RIPE"


def test_walk_entities_missing_keys_is_none() -> None:
    assert _walk_entities(None, "abuse") is None
    assert _walk_entities([{"handle": "x"}], "abuse") is None  # keine roles
    assert _walk_entities("nonsense", "abuse") is None  # Nicht-Liste -> None


# ── Feld-Extraktoren gegen die beiden Antworten ────────────────────────────────


def test_extract_org_prefers_fn_from_jcard() -> None:
    assert _extract_org(_RIPE_RESPONSE) == ("Reseaux IP Europeens Network Coordination Centre")


def test_extract_org_falls_back_to_handle_without_fn() -> None:
    # ARIN-Org-Entity hat kein vcardArray -> handle als Anzeigename.
    assert _extract_org(_ARIN_RESPONSE) == "CLOUD14"


def test_extract_abuse_via_recursive_walk_both_layouts() -> None:
    assert _extract_abuse(_RIPE_RESPONSE) == "abuse@ripe.example"
    # abuse liegt unter der administrative-Entity -> rekursiver Walk.
    assert _extract_abuse(_ARIN_RESPONSE) == "abuse@cloudflare.example"


def test_extract_netname_reads_name_field() -> None:
    assert _extract_netname(_RIPE_RESPONSE) == "RIPE-NCC"
    assert _extract_netname(_ARIN_RESPONSE) == "CLOUDFLARENET"


def test_extract_net_range_start_end_then_cidr() -> None:
    # RIPE: start - end.
    assert _extract_net_range(_RIPE_RESPONSE) == "193.0.0.0 - 193.0.23.255"
    # ARIN: kein start/end -> cidr0_cidrs.
    assert _extract_net_range(_ARIN_RESPONSE) == "104.16.0.0/12"


def test_extract_net_range_falls_back_to_handle() -> None:
    # Weder start/end noch cidrs -> handle.
    only_handle = {"handle": "NET-HANDLE-ONLY"}
    assert _extract_net_range(only_handle) == "NET-HANDLE-ONLY"
    assert _extract_net_range({}) is None


def test_extract_country_set_vs_empty() -> None:
    # RIPE: country gesetzt; ARIN: country fehlt -> bewusst None (kommt spaeter aus Geo-DB).
    assert _extract_country(_RIPE_RESPONSE) == "NL"
    assert _extract_country(_ARIN_RESPONSE) is None


# ── lookup() gegen httpx.MockTransport (kein Netz) ─────────────────────────────


def _client_with(handler: object) -> RdapClient:
    # MockTransport ersetzt das Netz -- KEINE echten Aufrufe. Der Client baut den
    # AsyncClient mit diesem Transport (Cert-/Redirect-Naht bleibt unberuehrt).
    return RdapClient(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]


def test_lookup_valid_response_fills_facts_and_keeps_asn_none() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["accept"] = request.headers.get("Accept")
        return httpx.Response(200, json=_RIPE_RESPONSE)

    client = _client_with(handler)
    facts = asyncio.run(client.lookup("193.0.6.139"))

    assert facts.org == "Reseaux IP Europeens Network Coordination Centre"
    assert facts.netname == "RIPE-NCC"
    assert facts.net_range == "193.0.0.0 - 193.0.23.255"
    assert facts.abuse_contact == "abuse@ripe.example"
    assert facts.country == "NL"
    # asn/asn_org bleiben BEWUSST None (kommen aus der Geo-DB 2d, nicht aus RDAP).
    assert facts.asn is None
    assert facts.asn_org is None
    # Korrekte rdap.org-URL + RDAP-Accept-Header.
    assert seen["url"] == "https://rdap.org/ip/193.0.6.139"
    assert "application/rdap+json" in str(seen["accept"])


def test_lookup_arin_like_empty_country_is_none() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ARIN_RESPONSE)

    facts = asyncio.run(_client_with(handler).lookup("104.16.0.1"))
    assert facts.org == "CLOUD14"
    assert facts.net_range == "104.16.0.0/12"
    assert facts.abuse_contact == "abuse@cloudflare.example"
    assert facts.country is None  # leer -> None, kein Fehler
    assert facts.asn is None and facts.asn_org is None


def test_lookup_timeout_returns_empty_facts() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out", request=request)

    facts = asyncio.run(_client_with(handler).lookup("203.0.113.1"))
    assert facts == RdapRawFacts()


def test_lookup_http_404_returns_empty_facts() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"errorCode": 404})

    facts = asyncio.run(_client_with(handler).lookup("203.0.113.2"))
    assert facts == RdapRawFacts()


def test_lookup_http_500_returns_empty_facts() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    facts = asyncio.run(_client_with(handler).lookup("203.0.113.3"))
    assert facts == RdapRawFacts()


def test_lookup_broken_json_returns_empty_facts() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # 200, aber kein gueltiges JSON -> Parse-Fehler -> leerer RdapRawFacts.
        return httpx.Response(200, content=b"<html>not json</html>")

    facts = asyncio.run(_client_with(handler).lookup("203.0.113.4"))
    assert facts == RdapRawFacts()


def test_lookup_non_object_json_returns_empty_facts() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # Gueltiges JSON, aber kein Objekt (Liste) -> nichts verwertbar -> leer.
        return httpx.Response(200, json=[1, 2, 3])

    facts = asyncio.run(_client_with(handler).lookup("203.0.113.5"))
    assert facts == RdapRawFacts()
