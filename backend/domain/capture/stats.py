"""Reine Statistik-Logik der capture-Domaene -- I/O-frei, deterministisch.

``time`` wird NICHT importiert: ``stats_to_view`` bekommt ``now`` hereingereicht
(der Altcode rief ``time.time()`` mitten in ``CaptureStats.to_dict`` -- die
Zeitquelle ist Aufrufer-/Adapter-Sache, nicht Domaenenlogik). Alle Funktionen
geben NEUE Werte zurueck und mutieren ihre Eingaben nicht (frozen-treu).
"""

from domain.capture.models import CaptureStats, PacketSummary


def apply_packet(stats: CaptureStats, ps: PacketSummary) -> CaptureStats:
    """Schreibt ein Paket in die Statistik fort -- liefert eine NEUE ``CaptureStats``.

    Verhaltensgleich zum Altcode-``_update_stats``: ``total_packets`` +1,
    ``total_bytes`` += ``length``, ``protocols`` je Protokoll (leer -> ``"Other"``)
    +1, ``top_talkers`` summiert Bytes je Quell-IP (nur wenn ``src_ip`` gesetzt),
    ``top_ports`` zaehlt je Ziel-Port (nur wenn ``dst_port`` gesetzt, Schluessel
    als ``str``). Die dict-Felder werden kopiert, nicht in-place veraendert.
    """
    protocols = dict(stats.protocols)
    proto = ps.protocol or "Other"
    protocols[proto] = protocols.get(proto, 0) + 1

    top_talkers = dict(stats.top_talkers)
    if ps.src_ip:
        top_talkers[ps.src_ip] = top_talkers.get(ps.src_ip, 0) + ps.length

    top_ports = dict(stats.top_ports)
    if ps.dst_port:
        port_key = str(ps.dst_port)
        top_ports[port_key] = top_ports.get(port_key, 0) + 1

    return CaptureStats(
        total_packets=stats.total_packets + 1,
        total_bytes=stats.total_bytes + ps.length,
        protocols=protocols,
        top_talkers=top_talkers,
        top_ports=top_ports,
        start_time=stats.start_time,
    )


def stats_to_view(stats: CaptureStats, now: float) -> dict[str, object]:
    """Sortierte, gekappte Sicht der Statistik fuer die REST-Antwort.

    Verhaltensgleich zum Altcode-``CaptureStats.to_dict``: ``duration_secs`` aus
    ``now - start_time`` (auf 0.1 gerundet), ``protocols`` absteigend nach Anzahl,
    ``top_talkers`` absteigend nach Bytes auf die Top-10, ``top_ports`` absteigend
    nach Anzahl auf die Top-20 gekappt.
    """
    return {
        "total_packets": stats.total_packets,
        "total_bytes": stats.total_bytes,
        "duration_secs": round(now - stats.start_time, 1),
        "protocols": dict(sorted(stats.protocols.items(), key=lambda x: x[1], reverse=True)),
        "top_talkers": dict(
            sorted(stats.top_talkers.items(), key=lambda x: x[1], reverse=True)[:10]
        ),
        "top_ports": dict(sorted(stats.top_ports.items(), key=lambda x: x[1], reverse=True)[:20]),
    }


def ring_trim(
    packets: list[PacketSummary], cap: int = 10000, keep: int = 5000
) -> list[PacketSummary]:
    """Ringpuffer-Regel: ueber ``cap`` Eintraegen auf die letzten ``keep`` kuerzen.

    Verhaltensgleich zum Altcode-``_handle_packet`` (``if len > 10000: [-5000:]``).
    Unter dem Limit kommt die Liste unveraendert (als neue Liste) zurueck.
    """
    if len(packets) > cap:
        return packets[-keep:]
    return list(packets)
