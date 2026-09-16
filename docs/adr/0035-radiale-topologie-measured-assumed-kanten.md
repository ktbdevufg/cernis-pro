# 0035 — Radiale Topologie: Gateway-Zentrum, measured/assumed-Kanten

## Status

Akzeptiert

## Kontext

Die "Beobachten"-Ansicht bekommt eine Topologie-Funktion: das lokale Heimnetz als
radialer Graph — Gateway im Zentrum, Geräte ringsum. Es musste entschieden werden,
**woher die Kanten kommen** und wie der frühere, tote Topologie-Pfad behandelt wird.

Befund am Code:

- `domain/capture/topology.py::topology_graph` baute bereits Knoten (Scan-Hosts +
  LLDP/CDP-Nachbarn), **bewusst aber keine Kanten** (Kommentar: "erst ein echter
  Topologie-Endpunkt würde Kanten definieren"). Es heilte zugleich einen Altcode-Bug:
  der Altcode hängte an jede Nachbar-Node eine Kante zum Ziel `"local"` — einem
  Knoten, der nie existierte (dangling edge).
- Der frühere Endpunkt `/api/lldp/topology` war **tot** — nur noch ein Wort in einem
  Kommentar in `api/capture.py`, bewusst nicht vom C.0-Characterization-Contract
  festgenagelt.
- Gemessene Nachbarschaft liefert `GET /api/lldp/neighbors` (LLDP/CDP). Für viele
  Heimnetz-Hosts gibt es **gar keine** LLDP-Nachbarschaft (Consumer-Geräte sprechen
  kein LLDP), aber sie hängen faktisch sternförmig am Gateway.
- Die Gateway-IP kennt die `interfaces`-Domäne (primäres Interface, Feld `gateway`).
  Scan-Hosts (mac/ip/hostname/vendor) liegen als persistierter Bestand im
  `device_repository` (`domain.devices`).

## Entscheidung

### Kantenmodell "beides kombiniert"

Eine neue reine Domänen-Funktion `radial_topology(neighbors, hosts, gateway_ip)`
(neben dem unangetasteten `topology_graph`, das regressionssicher bleibt) erzeugt
zwei Kantenarten:

- **measured** (`kind: "measured"`) — für jeden gemessenen LLDP/CDP-Nachbarn eine
  durchgezogene Kante vom messenden Host (Match `source_mac` == Host-`mac`) zum
  Nachbar-Knoten. Findet sich kein passender Host, hängt die Kante am Gateway (der
  Messpunkt ist das lokale Gerät) — so hat **jede** measured-Kante zwei existierende
  Endpunkte, der `"local"`-dangling-edge-Bug kehrt nicht zurück.
- **assumed** (`kind: "assumed"`) — für jeden Host **ohne** gemessenen Pfad eine
  gestrichelte Sternkante `host → gateway` (Fallback). Hosts mit measured-Kante und
  das Gateway selbst bekommen keine assumed-Kante.

Begründung "beides kombiniert" statt nur eines: Reine LLDP-Topologie wäre für ein
Heimnetz fast leer (kaum LLDP-Geräte) — unehrlich nutzlos. Reines Stern-Modell würde
die real gemessene Switch-/Bridge-Struktur verschweigen. Die Kombination zeigt
gemessenes Wissen als harte Linie und macht die Annahme als gestrichelte Linie
**sichtbar als Annahme** — kein stiller Fallback, der Messung vortäuscht.

### Gateway-Zentrum

Der Host-Knoten, dessen `ip` gleich `gateway_ip` ist, wird `type: "gateway"` (statt
`host`) und ist optisch das Zentrum. Trifft `gateway_ip` keinen Host oder ist leer,
entsteht **kein** Zentrum und es gibt **keine** assumed-Kanten — ehrlicher
Leerzustand statt Sternkanten ins Leere (Finding S3: keine stillen Fallbacks).

### Tote Stelle ersetzt, nicht reaktiviert

`/api/lldp/topology` (Altcode mit dangling edges) wird **nicht** wiederbelebt,
sondern durch den sauber neu gebauten `GET /api/topology` ersetzt. Begründung: Der
Altpfad war an einen kaputten Knoten-Graphen gekoppelt; ein Reaktivieren hätte den
Bug mitgeschleppt. Der neue Endpunkt baut auf der bereits geheilten Knoten-Logik auf.

### Architektur-Naht (5-Ring)

- **domain** (`radial_topology`): rein, I/O-frei, deterministisch, framework-frei
  (stdlib + dicts, kein Pydantic), independence-Contract gewahrt — kein Import in
  fremde Domänen.
- **application** (`BuildTopology`): kennt **keine** Fremd-Domäne und kein
  `infrastructure`. Die Quer-Domänen-Daten (Scan-Hosts, Gateway-IP) kommen über drei
  schlanke Provider-Callables herein (Muster `application.export.ScanProvider`), die
  der Composition Root projiziert. Gibt rohe `{nodes, edges}` zurück.
- **api** (`GET /api/topology`): baut die Wire-Form am Rand (`_topology_node_to_dict`
  + Edge-Projektion), keine `.to_dict()` in der Domäne.
- **app.py** (Regel 5): verdrahtet die Provider — Hosts aus `device_repository`,
  Nachbarn aus `GetLldpNeighbors`, Gateway-IP aus `ListInterfaces` (primäres
  Interface). Der Gateway-Provider ist async (Interface-Discovery ist echtes I/O),
  darum ist `BuildTopology.__call__` und der Endpunkt async.

## Konsequenzen

- Ohne Scan-Lauf oder LLDP-Capture ist der Graph ehrlich leer; das Frontend zeigt
  einen ehrlichen Leerzustand ("Scan ausführen / LLDP-Capture nötig").
- Gemessene LLDP-Nachbarschaft braucht Root (Raw-Socket). Der Endpunkt liefert
  trotzdem den Stern-Fallback ohne LLDP-Daten — kein Self-Escalate, keine 403 auf
  dem Lesepfad. Live-LLDP-Capture bleibt ein separater, root-pflichtiger Schritt.
- `topology_graph` bleibt unverändert (alte Tests grün); `radial_topology` ist voll
  unit-getestet (leer, nur Gateway, Hosts ohne Nachbarn, gemischt measured/assumed,
  Nachbar ohne passenden Host → Gateway, kein Gateway → keine assumed-Kanten, Dedup).
