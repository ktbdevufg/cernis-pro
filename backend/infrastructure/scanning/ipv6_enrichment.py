"""Adapter fuer ``Ipv6EnrichmentPort`` -- Wrapper um ``modules.ipv6.enrich_with_ipv6``.

``enrich_with_ipv6`` ist SYNCHRON (blockierende NDP-Tabellen-Abfrage via
``subprocess`` ``ip -6 neigh`` o.ae.) -- ueber ``run_in_executor`` kapseln, damit
der Event-Loop nicht blockiert. Die Port-Methode bleibt ``async`` (Muster wie
``smb_info`` in S.4b / nmap in S.4c).

``enrich_with_ipv6`` arbeitet dict-basiert und reichert IN-PLACE an: es matcht
ueber das ``mac``-Feld gegen die NDP-Tabelle und setzt bei Treffer ``ipv6`` (die
beste Adresse: global > ULA > link-local) und ``ipv6_all`` (alle gefundenen).
Hosts OHNE MAC-Match bekommen KEINE ``ipv6``-Keys -- daher beim Rueckmapping
``.get(..., default)``, kein KeyError.

Mapping-Strategie (verlustfrei in beide Richtungen, S.4e-Modell-Vorbau):

* ``EnrichedHost`` -> ``dict`` via ``asdict`` (ALLE Felder, inkl. der bereits
  vorhandenen ``ipv6``/``ipv6_all``) -- so geht beim dict-Round-trip kein
  bestehendes Feld verloren.
* ``enrich_with_ipv6`` reichert die dicts an (nur ``ipv6``/``ipv6_all`` dazu).
* ``dict`` -> ``EnrichedHost`` ueber die GETEILTE Serialisierung aus
  ``_serialization.dict_to_host`` (derselbe verlustfreie Rekonstruktor, den auch
  der ScanHistory-Adapter nutzt) -- die verschachtelten
  ``PortInfo``/``MdnsService``/``SsdpService`` und alle ``tuple``-Felder (jetzt
  inkl. ``ipv6_all``) werden korrekt zurueckgebaut. ``ipv6_all`` (Liste aus
  ``modules``) wird dort zu ``tuple`` normalisiert.

Wir geben einen ``scan_id``-Platzhalter (``-1``) an ``dict_to_host``: er dient
dort nur dem Fehlerbezug eines ``CorruptScanError`` -- die Daten stammen hier aus
unseren eigenen ``asdict``-dicts, sind also nie korrupt; der Platzhalter wird in
der Praxis nie in eine Exception einfliessen.

Sicherheits-/Altmuster-Befund (geprueft, hier akzeptabel):

* ``enrich_with_ipv6`` ruft kein Binary direkt; ``get_ndp_table`` nutzt
  ``subprocess.run([...])`` mit ARGUMENT-LISTE ohne ``shell=True`` -- keine
  Injection (≠ S2). Der ``except Exception: pass`` in ``get_ndp_table`` liefert
  bei Fehler eine leere NDP-Tabelle -> die Hosts kommen unveraendert (ohne IPv6)
  zurueck. Das ist KEIN verdecktes Scheitern: "keine NDP-Eintraege" ist der vom
  Port vorgesehene Zustand ("Keine IPv6-Daten -> Hosts unveraendert"), best-effort
  Anreicherung wie mDNS/SSDP. Daher KEIN Exception-Umbau.
"""

import asyncio
from collections.abc import Sequence
from dataclasses import asdict
from typing import Any

from domain.scanning import EnrichedHost
from infrastructure.scanning._serialization import dict_to_host
from modules.ipv6 import enrich_with_ipv6


class Ipv6EnrichmentAdapter:
    """Erfuellt das ``Ipv6EnrichmentPort``-Protocol strukturell."""

    async def enrich(self, hosts: Sequence[EnrichedHost]) -> list[EnrichedHost]:
        """Reichert die Hosts um IPv6 an (gleiche Anzahl, gleiche Reihenfolge).

        ``enrich_with_ipv6`` ist blockierend -> ``run_in_executor``. Keine
        IPv6-Daten verfuegbar -> die Hosts kommen unveraendert zurueck (siehe
        Modul-Docstring: best-effort, kein verdecktes Scheitern).
        """
        raw_dicts: list[dict[str, Any]] = [asdict(h) for h in hosts]

        loop = asyncio.get_running_loop()
        enriched_dicts = await loop.run_in_executor(None, enrich_with_ipv6, raw_dicts)

        # ``-1``: scan_id-Platzhalter (nur Fehlerbezug; unsere asdict-dicts sind nie korrupt).
        return [dict_to_host(-1, d) for d in enriched_dicts]
