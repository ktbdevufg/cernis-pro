"""Reine Topologie-Logik der capture-Domaene -- I/O-frei, deterministisch.

``topology_graph`` baut aus LLDP/CDP-Nachbarn + Scan-Hosts einen reinen Knoten-
Graphen OHNE Kanten (Altstand, regressionssicher belassen). ``radial_topology``
ist der neue Gateway-zentrierte Graph MIT Kanten (measured/assumed) hinter dem
``/api/topology``-Endpunkt (siehe ADR 0035). Node/Edge bleiben bewusst untyped
``dict`` (KEINE Records): die Wire-Form baut der api-Rand, eine Record-
Modellierung in der Domaene waere verhaltensloser Ballast.

GEHEILT gegenueber dem Altcode: der Altcode haengte an JEDE Nachbar-Node eine
Kante zum Ziel ``"local"`` -- einem Knoten, der NIE als Node existierte (dangling
edge). Diese tote Stelle faellt weg; in beiden Funktionen entstehen nur Kanten
zwischen tatsaechlich vorhandenen Knoten. Die Dedup ueber ``seen_ids`` bleibt 1:1.
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


def radial_topology(
    neighbors: list[dict[str, str]],
    hosts: list[dict[str, str]],
    gateway_ip: str,
) -> dict[str, list[dict[str, str]]]:
    """Baut den radialen Heimnetz-Graphen: Gateway im Zentrum, Geraete ringsum.

    Kantenmodell "beides kombiniert":

    * **measured** -- fuer jeden LLDP/CDP-Nachbarn eine Kante vom Host, der diesen
      Nachbarn gemessen hat (Match ueber ``source_mac`` == Host-``mac``), zum
      Nachbar-Knoten. Findet sich kein passender Host, haengt die Kante am Gateway
      (der Messpunkt ist das lokale Geraet -- naeherungsweise das Zentrum). So hat
      JEDE measured-Kante zwei existierende Endpunkte (keine dangling edges).
    * **assumed** -- fuer jeden Host OHNE gemessenen Nachbar-Pfad eine
      Sternkante ``host -> gateway`` (Fallback). Das Gateway selbst und Hosts, die
      bereits eine measured-Kante tragen, bekommen KEINE assumed-Kante.

    Gateway-Erkennung: der Host-Knoten, dessen ``ip`` gleich ``gateway_ip`` ist,
    wird als ``type: "gateway"`` markiert (statt ``host``) und ist das Zentrum.
    Ist ``gateway_ip`` leer oder trifft keinen Host, entsteht KEIN Gateway-Zentrum
    -- dann gibt es auch keine assumed-Kanten (ehrlicher Leerzustand statt
    Sternkanten ins Leere).

    Reine, I/O-freie, deterministische Funktion. Reihenfolge bleibt stabil:
    Knoten in Eingabe-Reihenfolge (Hosts vor Nachbarn), Kanten measured vor
    assumed. Dedup ueber ``seen_ids`` (Knoten) bzw. ``seen_edges`` (Kanten).
    """
    nodes: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    seen_ids: set[str] = set()

    # Host-Knoten aufnehmen; den Gateway-Host als Zentrum markieren.
    gateway_id = ""
    # mac (lowercase) -> node_id, um measured-Kanten dem Quell-Host zuzuordnen.
    host_id_by_mac: dict[str, str] = {}
    for h in hosts:
        node_id = h.get("mac") or h.get("ip")
        if not node_id or node_id in seen_ids:
            continue
        seen_ids.add(node_id)
        is_gateway = bool(gateway_ip) and h.get("ip", "") == gateway_ip and not gateway_id
        if is_gateway:
            gateway_id = node_id
        mac = h.get("mac", "")
        if mac:
            host_id_by_mac[mac.lower()] = node_id
        nodes.append(
            {
                "id": node_id,
                "ip": h.get("ip", ""),
                "mac": mac,
                "hostname": h.get("hostname", ""),
                "vendor": h.get("vendor", ""),
                "type": "gateway" if is_gateway else "host",
            }
        )

    # LLDP/CDP-Nachbarn als Switch-/Netzwerk-Knoten + measured-Kanten.
    # measured_hosts: Host-ids, die einen gemessenen Pfad tragen (keine assumed-Kante).
    measured_hosts: set[str] = set()
    for n in neighbors:
        node_id = n.get("chassis_id") or n.get("source_mac")
        if not node_id:
            continue
        if node_id not in seen_ids:
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
        # Quell-Host der Messung: der Host mit passender mac, sonst das Gateway.
        source_mac = n.get("source_mac", "")
        source = host_id_by_mac.get(source_mac.lower(), gateway_id)
        if not source or source == node_id:
            continue
        measured_hosts.add(source)
        edges.append({"source": source, "target": node_id, "kind": "measured"})

    # assumed-Sternkanten: jeder Host ohne measured-Pfad -> Gateway.
    if gateway_id:
        for node in nodes:
            if node["type"] != "host":
                continue
            if node["id"] in measured_hosts:
                continue
            edges.append({"source": node["id"], "target": gateway_id, "kind": "assumed"})

    # Dedup gleicher Kanten (source+target+kind), Reihenfolge erhalten.
    seen_edges: set[tuple[str, str, str]] = set()
    deduped: list[dict[str, str]] = []
    for e in edges:
        key = (e["source"], e["target"], e["kind"])
        if key in seen_edges:
            continue
        seen_edges.add(key)
        deduped.append(e)

    return {"nodes": nodes, "edges": deduped}


def neighbor_age(now: float, last_seen: float, ttl: int) -> tuple[int, bool]:
    """Alter (Sekunden) und Ablauf-Status eines Nachbarn.

    Verhaltensgleich zum Altcode-``get_neighbors``: ``age_secs = int(now -
    last_seen)``, ``expired = (now - last_seen) > ttl``. ``now`` wird hereingereicht
    (kein ``time``-Import in der Domaene).
    """
    delta = now - last_seen
    return int(delta), delta > ttl
