"""Geteilte ``EnrichedHost`` <-> dict/JSON-Serialisierung der scanning-Adapter.

Herausgezogen aus ``scan_history.py``, weil mehrere Adapter denselben verlustfreien
Rekonstruktor brauchen (``scan_history`` fuer den DB-Round-trip, ``ipv6_enrichment``
fuer den dict-Round-trip um den Altcode ``enrich_with_ipv6``). So greift kein
Adapter mehr in den privaten Teil eines anderen.

Die (De-)Serialisierung ist VERLUSTFREI, inkl. der verschachtelten ``PortInfo`` /
``MdnsService`` / ``SsdpService`` und der ``tuple``-Felder (JSON-Listen werden beim
Lesen wieder zu ``tuple`` normalisiert -- ``MdnsService.properties`` sogar als
``tuple[tuple[str, str], ...]``, ``ipv6_all`` als ``tuple[str, ...]``).

KEIN ``modules``-Import -- reine domain-zu-dict-Mechanik; die ADR-0007-Ausnahme
wird hier nicht gebraucht.
"""

import json
from dataclasses import asdict
from typing import Any

from domain.scanning import (
    EnrichedHost,
    MdnsService,
    PortInfo,
    SsdpService,
)


class CorruptScanError(Exception):
    """Ein zu deserialisierender Host-Blob ist kein gueltiges JSON-Objekt.

    Ersetzt den stillen ``or "[]"``-Rueckfall des Altcodes: ein kaputter Blob ist
    ein Fehler MIT ``scan_id``-Bezug (Muster wie ``CorruptDeviceError``). Dazu
    zaehlt auch ein formfremdes verschachteltes Feld (z. B. ``mDNS``-properties als
    flache String-Liste statt ``[key, value]``-Paaren).
    """

    def __init__(self, scan_id: int, raw_value: str) -> None:
        self.scan_id = scan_id
        self.raw_value = raw_value
        super().__init__(
            f"Scan {scan_id}: result_json ist kein gueltiges JSON-Array: {raw_value!r}"
        )


def host_to_dict(host: EnrichedHost) -> dict[str, Any]:
    """EnrichedHost -> JSON-taugliches dict (tuples werden zu Listen)."""
    return asdict(host)


def _str_pairs(scan_id: int, raw: Any) -> tuple[tuple[str, str], ...]:
    """JSON-Liste von [key, value]-Paaren -> tuple[tuple[str, str], ...].

    Formfremdes ``properties`` (z. B. eine flache String-Liste aus altem
    Bestandsdatensatz statt [key, value]-Paaren) wird als benannter
    ``CorruptScanError`` (mit ``scan_id``-Bezug) gemeldet -- NICHT als nackter
    ``ValueError``, und NICHT still repariert (kein Datenverlust). Vervollstaendigt
    die S3-Linie ("kein stiller Fallback") an dieser Stelle.
    """
    pairs: list[tuple[str, str]] = []
    try:
        items = list(raw)
    except TypeError as exc:
        raise CorruptScanError(scan_id, json.dumps(raw)) from exc
    for item in items:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            k, v = item
            pairs.append((str(k), str(v)))
        else:
            raise CorruptScanError(scan_id, json.dumps(raw))
    return tuple(pairs)


def dict_to_host(scan_id: int, data: Any) -> EnrichedHost:
    """JSON-dict -> EnrichedHost, verschachtelte Typen + tuples rekonstruiert."""
    if not isinstance(data, dict):
        raise CorruptScanError(scan_id, json.dumps(data))
    ports = tuple(PortInfo(**p) for p in data.get("ports", ()))
    mdns = tuple(
        MdnsService(
            name=m.get("name", ""),
            type=m.get("type", ""),
            port=m.get("port", 0),
            hostname=m.get("hostname", ""),
            is_ndi=m.get("is_ndi", False),
            properties=_str_pairs(scan_id, m.get("properties", ())),
            ip=m.get("ip", ""),
        )
        for m in data.get("mdns_services", ())
    )
    ssdp = tuple(SsdpService(**s) for s in data.get("ssdp_services", ()))
    return EnrichedHost(
        ip=data["ip"],
        mac=data["mac"],
        vendor=data.get("vendor", ""),
        rtt_ms=data.get("rtt_ms"),
        hostname=data.get("hostname", ""),
        smb_name=data.get("smb_name", ""),
        smb_domain=data.get("smb_domain", ""),
        ipv6=data.get("ipv6", ""),
        ipv6_all=tuple(data.get("ipv6_all", ())),
        os_guess=data.get("os_guess", ""),
        os_accuracy=data.get("os_accuracy", 0),
        scan_method=data.get("scan_method", "socket"),
        ports=ports,
        mdns_services=mdns,
        ssdp_services=ssdp,
        is_ndi=data.get("is_ndi", False),
        is_unknown=data.get("is_unknown", False),
        category=data.get("category", ""),
        label=data.get("label", ""),
        tags=tuple(data.get("tags", ())),
        notes=data.get("notes", ""),
        # Default "ping": alte DB-Blobs (vor S.7f) haben kein source-Feld -- ein
        # damals gespeicherter Host war ein Ping-Host. host_to_dict nimmt source
        # ueber asdict automatisch mit; hier der explizite Pull beim Lesen.
        source=data.get("source", "ping"),
    )
