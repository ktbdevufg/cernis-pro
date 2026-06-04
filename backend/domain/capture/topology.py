"""Reine Topologie-Logik der capture-Domaene -- I/O-frei, deterministisch.

``topology_graph`` baut aus LLDP/CDP-Nachbarn + Scan-Hosts einen Knoten-/Kanten-
Graphen. Node/Edge bleiben bewusst untyped ``dict`` (KEINE Records): der
Konsument-Endpunkt ``/api/lldp/topology`` ist tot, eine Record-Modellierung waere
verhaltensloser Ballast fuer einen toten Pfad.

GEHEILT gegenueber dem Altcode: der Altcode haengte an JEDE Nachbar-Node eine
Kante zum Ziel ``"local"`` -- einem Knoten, der NIE als Node existierte (dangling
edge). Diese tote Stelle faellt weg; es entstehen nur Kanten zwischen tatsaechlich
vorhandenen Knoten. Die Dedup ueber ``seen_ids`` bleibt 1:1.
"""


def topology_graph(
    neighbors: list[dict[str, str]], hosts: list[dict[str, str]]
) -> dict[str, list[dict[str, str]]]:
    """Baut ``{nodes, edges}`` aus LLDP/CDP-Nachbarn und Scan-Hosts.

    Hosts werden als ``host``-Knoten aufgenommen (id = ``mac`` oder ``ip``),
    Nachbarn als ``switch``/``network``-Knoten (id = ``chassis_id`` oder
    ``source_mac``). Ein bereits gesehener oder leerer ``id`` wird uebersprungen.
    Es entstehen KEINE dangling edges (kein ``"local"``-Ziel) -- erst ein echter
    Topologie-Endpunkt wuerde Kanten zwischen vorhandenen Knoten definieren.
    """
    nodes: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    seen_ids: set[str] = set()

    # Bekannte Hosts als Knoten aufnehmen.
    for h in hosts:
        node_id = h.get("mac") or h.get("ip")
        if not node_id or node_id in seen_ids:
            continue
        seen_ids.add(node_id)
        nodes.append(
            {
                "id": node_id,
                "ip": h.get("ip", ""),
                "mac": h.get("mac", ""),
                "hostname": h.get("hostname", ""),
                "vendor": h.get("vendor", ""),
                "type": "host",
            }
        )

    # LLDP/CDP-Nachbarn als Switch-/Netzwerk-Knoten aufnehmen.
    for n in neighbors:
        node_id = n.get("chassis_id") or n.get("source_mac")
        if not node_id or node_id in seen_ids:
            continue
        seen_ids.add(node_id)
        nodes.append(
            {
                "id": node_id,
                "mac": n.get("source_mac", ""),
                "hostname": n.get("system_name", ""),
                "description": n.get("system_desc", "")[:60],
                "port": n.get("port_id", ""),
                "type": "switch" if "switch" in n.get("system_desc", "").lower() else "network",
                "protocol": n.get("protocol", "LLDP"),
            }
        )

    return {"nodes": nodes, "edges": edges}


def neighbor_age(now: float, last_seen: float, ttl: int) -> tuple[int, bool]:
    """Alter (Sekunden) und Ablauf-Status eines Nachbarn.

    Verhaltensgleich zum Altcode-``get_neighbors``: ``age_secs = int(now -
    last_seen)``, ``expired = (now - last_seen) > ttl``. ``now`` wird hereingereicht
    (kein ``time``-Import in der Domaene).
    """
    delta = now - last_seen
    return int(delta), delta > ttl
