# ADR 0018 — FritzBox-Detailansicht als eigener read-only Port/Adapter

- **Status:** Akzeptiert
- **Datum:** 2026-06-15
- **Phase:** Quer-Feature nach Stabilisierung des Bestands (eigener `fritz_detail`-Strang, neben der scanning-Domäne)
- **Bezug:** ADR 0007 (scanning-Adapter dürfen `modules/` importieren — gilt für diesen Adapter direkt mit); `ports/scanning.FritzHostsPort` + `infrastructure/scanning/fritz_hosts.py` (Vorbild-Muster); CLAUDE.md (Importregeln, 5 Ringe); ADR 0001 (kein stiller unsicherer Fallback, Auth-Fehler ist ein Fehler)

## Kontext

Das Frontend braucht eine reichhaltige FRITZ!Box-Detailansicht: WAN/Fiber/DSL-Status, beide WLAN-Bänder (2.4 + 5 GHz), Geräte-Info (Modell/Firmware/Fiber/Host-Anzahl), die aktiven WLAN-Clients, das Ereignisprotokoll und die Portfreigaben. Bisher kennt v2 die FRITZ!Box nur über `FritzHostsPort` — der liefert ausschließlich die DHCP-Hostliste für den Scan-Merge (S.7c), nicht den vollen Status.

Die nötigen TR-064-Abrufe existieren bereits erprobt im v1-Code (`modules/fritzbox.py`): `FritzBox.get_status()` (→ `FritzStatus`), `.get_wlan_clients()`, `.get_log(limit)`, `.get_port_forwardings()`. Diesen Code zeilenweise in `infrastructure/` zu reimplementieren wäre dieselbe Wegwerf-Arbeit, die ADR 0007 für die ganze systemnahe Schicht vermeidet — und `modules/fritzbox.py` ist die Quelle der Wahrheit für die korrekte TR-064-/Digest-Auth-Behandlung über alle FritzOS-/Modell-Varianten.

Die Frage war also nicht *ob* der v1-Code wiederverwendet wird, sondern *wie* er sauber in die 5-Ringe-Architektur eingehängt wird, ohne `FritzHostsPort` zu überladen (zwei sehr unterschiedliche Rückgabe-Formen an einem Port wäre eine künstliche Kopplung).

## Entscheidung

Ein **eigener, getrennter Port/Adapter** `fritz_detail`, parallel zu `FritzHostsPort` — nicht eine Erweiterung des Hosts-Ports.

- **Ring 1 — `domain/fritz_detail.py`:** eigene `frozen`-Wertobjekte (`FritzWanStatus`, `FritzDslStatus`, `FritzWlanBand`, `FritzDeviceInfo`, `FritzWlanClient`, `FritzLogEntry`, `FritzPortForwarding`) und das Aggregat `FritzDetail`. Reine stdlib/dataclasses, kein TR-064-/HTTP-/Uhr-Wissen (ADR 0002). Alle Unter-Objekte haben Leer-Defaults → `FritzDetail(reachable=False)` ist ohne Pflichtfelder baubar.
- **Ring 2 — `ports/fritz_detail.py`:** `FritzDetailPort` mit `async def get_detail() -> FritzDetail`. „Nicht konfiguriert/nicht erreichbar" ist der vertragliche Leer-Zustand (`reachable=False`), **kein** Fehler — genau wie `FritzHostsPort` → `[]`.
- **Ring 3 — `application/fritz_detail/`:** `GetFritzDetail` mit Constructor-Injection des Ports, reine Delegation. **Kein** eigener Auth-Fehlertyp (siehe unten).
- **Ring 4 — `infrastructure/scanning/fritz_detail.py`:** `FritzDetailAdapter`, exakt das `fritz_hosts`-Muster (synchroner TR-064-Aufruf über `run_in_executor`, Konstruktor-Injektion von host/user/password/port). Projiziert die v1-`FritzStatus`-/-Objekte/-dicts feldweise auf die domain-Typen.
- **Ring 5 — `api/fritz.py`:** neuer Router `prefix="/api/fritz"`, `GET /detail`. Vollständige Wire-Projektion (`_detail_to_dict`, `detail` als `Any` → kein domain-Import im api-Ring, tuple→list, Sub-Objekte verschachtelt).
- **Composition Root (`app.py`):** `GetFritzDetail` → `FritzDetailAdapter` wird **pro Request** frisch mit den aktuellen Credentials gebaut (host/user aus dem Settings-Repository, Passwort als Klartext direkt aus dem SecretStore — Muster wie `_build_run_network_scan`), per `dependency_overrides` verdrahtet. **Nicht gecacht.**

**Auth-Fehler-Typ wiederverwenden, nicht doppeln:** Der einzige fachliche Fehler ist der FritzBox-Auth-Fehler. Der Adapter wirft dafür die **bestehende** `infrastructure.scanning.fritz_hosts.FritzAuthError` (kein zweiter, gleichnamiger Typ). Der api-Ring importiert diesen infrastructure-Typ direkt — import-linter-konform exakt so, wie es `ws_scan`/scanning für `FritzAuthError`/`NmapScanError` bereits halten (die Fritz-/Scan-Auth-Fehlerbehandlung ist die etablierte Ausnahme zur „api → nur application"-Regel; `allow_indirect_imports` + der scharfe direkte-Import-Block greifen hier nicht, weil der Auth-Fehlertyp bewusst aus infrastructure kommt). Eine `application/fritz_detail/errors.py` existiert nur als leerer Aufhänger (`FritzDetailApplicationError`), damit das Paket-Muster konsistent bleibt.

**Modules-Bezug:** `FritzDetailAdapter` liegt in `infrastructure.scanning` und darf `modules/` importieren — bereits von der `infrastructure.scanning.** -> modules`-Ausnahme aus ADR 0007 abgedeckt, ohne Änderung an den Contracts.

## HTTP-Semantik

- **`reachable: false`** (Box nicht konfiguriert/nicht erreichbar) → **200** mit `reachable: false` im Body. Das ist ein legitimer Leer-Zustand, kein Fehler — das Frontend rendert eine „keine Box"-Ansicht, ohne einen HTTP-Fehler behandeln zu müssen.
- **Falsche Credentials (`FritzAuthError`)** → **502 Bad Gateway** mit klarer Meldung („FRITZ!Box-Authentifizierung gescheitert (Credentials prüfen)."). Das Upstream-Gerät lehnt die Anmeldung ab — aus Sicht unseres Dienstes ein Gateway-Problem, kein 4xx-Client-Fehler unserer eigenen API. Bewusst **nicht** best-effort verschluckt (anders als der Scan-Merge in `_FritzHostsWiring`): der Detail-Endpunkt ist ein expliziter Lese-Pfad, ein verschluckter Auth-Fehler wäre hier ein stiller Fallback (ADR 0001 / Finding S3).

## Konsequenzen

**Positiv**
- Saubere Trennung: `FritzHostsPort` (DHCP-Liste für den Scan-Merge) und `FritzDetailPort` (voller Status für die Detailansicht) bleiben je sortenrein; kein überladener Port mit zwei unzusammenhängenden Rückgabe-Formen.
- Keine Wegwerf-Reimplementierung der TR-064-Schicht; der erprobte v1-Code wird hinter einem stabilen Port wiederverwendet (`modules/fritzbox.py` **unverändert**).
- Eigene domain-Typen + Wire-Projektion im api-Ring → keine Domänen-Kopplung, der api-Ring importiert `domain` nicht.
- Credentials pro Request frisch → Einstellungsänderung wirkt ohne App-Neustart.

**Kosten / Restfenster**
- Wie bei `fritz_hosts` bleibt die Alt/Neu-Grenze an `infrastructure.scanning` (modules-Bezug, ADR 0007, temporär bis zur möglichen systemnahen Reimplementierung).
- Der Adapter macht beim erreichbaren Pfad mehrere blockierende TR-064-Roundtrips (`get_status` + clients + log + forwardings) in einem Executor-Call — bewusst nicht gecacht, weil die Detailansicht ein frischer Schnappschuss sein soll. Bei langsamer Box kann der Request dauern; das ist akzeptiert (read-only, vom Nutzer angefordert).
