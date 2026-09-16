# ADR 0017 — sni-Domäne: angefragte Hostnamen (TLS-SNI) passiv erfassen und dem Prozess zuordnen

- **Status:** Akzeptiert
- **Datum:** 2026-06-14
- **Phase:** Grüne Wiese (Quer-Feature nach interfaces (0009) + traffic (0010) + process (0011) + analysis (0012/0013) + diagnostics (0014) + resolver (0015/0016))
- **Bezug:** ADR 0016 (resolver: PTR zeigt bei AWS/CloudFront nur den **Hoster**, nicht den echten Namen — genau die Lücke, die SNI schließt); ADR 0010 (traffic: psutil-`net_connections`-Naht, rootless-Realität pid=None); die capture-Domäne (`PacketSnifferPort`/`ScapyPacketSniffer`, geteiltes `_scapy`) — bewusst **nicht** integriert (Begründung unten); ADR 0002 (domain bleibt framework-frei, keine Uhr); ADR 0001 (keine stillen Fallbacks, Finding S3); pyproject.toml (`independence`-Contract über alle `domain.*`-Subpakete)

## Kontext

Die Verkehrsliste (traffic) zeigt pro Verbindung eine Gegenstellen-IP und — über den Batch-PTR-Endpunkt (ADR 0016) — deren reverse-DNS-Namen. Bei modernen Diensten hinter AWS/CloudFront/Fastly/Akamai liefert PTR aber nur den **Hoster** (`server-…​.cloudfront.net`, `…​.compute.amazonaws.com`), nicht den **echten** Domainnamen, den die App tatsächlich angefragt hat. Damit lässt sich die Verkehrsliste nicht sinnvoll nach Domains bündeln — „App → Server-IP" bleibt, „App → **Domain** → Server" fehlt.

Der **Server Name Indication** (SNI) im TLS-ClientHello trägt genau diesen echten Namen — und zwar **unverschlüsselt** im Klartext (vor dem verschlüsselten Teil des Handshakes). Er lässt sich **passiv** mitlesen, ohne irgendetwas zu entschlüsseln, und der verursachende Prozess lässt sich über dieselbe Socket→PID-Tabelle zuordnen, die CERNIS für traffic ohnehin nutzt.

Ein **Wegwerf-Spike** (`spike_sni.py`, außerhalb des Repos) hat das empirisch belegt: **60 SNIs erfasst, 93 % einem Prozess zugeordnet, Zuordnungs-Delta median 177 ms**. Der Spike hat zugleich drei Fallen aufgedeckt, die das Design hier auflöst:

1. **scapy-TLS-Dissektor untauglich.** scapy 2.7 erkennt über `scapy.layers.tls` **0** ClientHellos, obwohl `tcpdump` sie sehr wohl zeigt. Und `bytes(pkt[TCP].payload)` reserialisiert dissektiert — die Bytes weichen vom Draht ab → 0 Treffer. Funktioniert hat **nur** der layer-unabhängige Roh-Zugriff `bytes(pkt[TCP])[dataofs*4:]` plus **manuelles** Byte-Parsing.
2. **GIL-Aushungern.** Schwere Arbeit (psutil-Namensauflösung) im scapy-prn-Callback hat den libpcap-Lesepfad ausgehungert → „0 TCP-Pakete". Der prn **muss** billig sein; die Socket-Snapshots gehören in einen **eigenen** Thread, die Namensauflösung **nach** den Sniff.
3. **Interface als String, nie als `conf.iface`-Objekt.** Auf der VM ist scapys Interface-DB leer (`conf.iface == None`); `sniff(iface=None)` liefert 0 Pakete, der explizite String-Aufruf (`iface="ens33"`) liefert Pakete.

## Entscheidung

1. **Eigene Domäne `sni`, NICHT in capture integriert.** Der capture-Parser (`ScapyPacketSniffer._parse_packet`) liest den **TCP-Payload nicht** (er klassifiziert nur über Ports/Flags) und nutzt genau den Layer-Zugriff (`pkt[TCP].payload`), der für das ClientHello **untauglich** ist. capture in eine zweite Betriebsart („gib mir auch den SNI") zu zwingen, hieße seinen erprobten Strom-/Broadcast-Pfad umzubauen — Risiko ohne Gewinn. Darum eine **eigene, schlanke Domäne** mit eigenem Adapter. **capture wird nicht angefasst.**

2. **Erprobte Spike-Technik produktiv übernommen** (Technik, nicht Stil):
   - **Payload layer-unabhängig:** `raw = bytes(pkt[TCP])[dataofs*4:]` (nicht `bytes(payload)`).
   - **ClientHello manuell aus den Rohbytes** (`parse_sni` — **reine Funktion ohne scapy-Abhängigkeit**, gut testbar): TLS-Record `0x16` → Handshake `0x01` → ServerName-Extension `0x0000` → Hostname, mit robuster Längen-/Offset-Prüfung. Jede Störung (abgeschnitten/fragmentiert, ServerHello, kein SNI) → `None`, nie ein Crash.
   - **Billiger prn:** der Sniff-Callback parst nur + hängt einen rohen Hit an. **Keine** psutil-Arbeit im Callback.
   - **Eigener Poller-Thread:** periodische `(ip,port)→pid`-Snapshots (0.5 s), entkoppelt vom Sniff-Thread; nur die billige Tabelle, **kein** Name. Die psutil-Naht ist **deckungsgleich** mit `infrastructure/traffic_linux.py` (`net_connections(kind="inet")`, defensive Namensauflösung `except psutil.Error → None`).
   - **Interface als String** über `_pick_iface` (conf.iface → Default-Route → `/sys/class/net`).

3. **Passiv / MANUELL / nur-Speicher.** Der Sniff ist **rein lesend** (keine Pakete injiziert) und startet **ausschließlich** über `POST /api/sni/start` — **kein** Autostart (anders als monitor/poll, die einen cfg-AUTO-Schalter haben). Die erfassten SNIs leben **nur im Arbeitsspeicher** in einem Ringpuffer (`deque(maxlen=5000)`); **kein SQLite**. Begründung **Datenschutz:** die SNI-Historie ist sensibel (welche App welche Domain wann angefragt hat) — sie soll den Prozess nicht überleben.

4. **Root-pflichtig mit ehrlicher 403.** Der Raw-Socket-Sniff braucht `CAP_NET_RAW`/Root. Die `StartSniCapture`-`{ok,error}`-Naht prüft **vor** dem Start (`is_available` + `check_permission`, Muster `StartCapture`); ein Permission-Fehler wird zur **403** mit konkretem Fix-Hinweis (`sudo setcap cap_net_raw+eip …`) — **kein stiller Leer-Fallback** (S3). Ein echter Start-Fehler des Adapters (toter Sniffer-Thread/Gerät/scapy) wirft `SniError`, die der Composition Root auf **503** mappt (Muster `DiagnosticsToolMissing`/`ResolverToolMissing`).

5. **Geteiltes `_scapy`, nicht dupliziert.** Die scapy-Symbole (`HAS_SCAPY`/`AsyncSniffer`/`TCP`/`IP`/`IPv6`) kommen aus `infrastructure.capture._scapy` (geteilte Infrastruktur — der Cache-Dir-Fix + die breite Probe leben dort an einer Stelle). `_scapy` wird **nicht** verändert. Kein import-linter-Contract verbietet diesen infra-internen Quergriff: die Contracts sind **schicht-**, nicht domänen-intern (`infrastructure → nicht application/api`), und der `independence`-Contract gilt **nur** für `domain.*`. Geprüft: `lint-imports` bleibt grün.

6. **Aggregat statt Strom über fünf Ringe.** Anders als `PacketSnifferPort` (Dauer-Capture als async-**Strom**) ist `SniSnifferPort` ein **Aggregat**: der Adapter hält die rohen Hits + die Snapshots intern (zwei Hintergrund-Threads) und liefert die zugeordnete Momentaufnahme auf Abruf (`observed()`) — **kein** async-Strom, **kein** Callback-Geflecht im Use-Case.
   - **domain/sni.py** — `ObservedSni` (frozen) + zwei reine Funktionen: `normalize_hostname` (leer → `None`) und `match_snapshot` (zeitnächster passender Snapshot → `(pid, delta_ms)`). Keine Uhr — `monotonic_ts` kommt als Feld herein (Muster `domain.traffic.ConnSample`).
   - **ports/sni.py** — `SniSnifferPort` (start/stop/is_running/observed/check_permission/is_available), synchron, **kein** `@runtime_checkable`.
   - **infrastructure/sni/** — `sni_sniffer.py` (Parser + Lifecycle + Poller + Zuordnung) und `errors.py` (`SniError`).
   - **application/sni/** — `RunSniCapture` (Lifecycle), `StartSniCapture` (`{ok,error}`-Prüfung → 403), `GetObservedSni` (Lese-Sicht). Kennt nur domain + ports.
   - **api/sni.py** — `POST /sni/start` (403 bei ok=false), `POST /sni/stop` (idempotent), `GET /sni/status` (`{running,count,available,permission_error}`), `GET /sni/observed` (Wire-dicts mit `age_secs`). Wire-Projektion am Rand (Attribut-Zugriff, Typ `Any`).

7. **Ringpuffer im Adapter, nicht im Use-Case.** Die rohen Hits **und** die periodischen Socket-Snapshots werden aus den beiden Hintergrund-Threads des Adapters beschrieben, und die Zuordnung braucht **beide** zusammen. Ein `deque(maxlen=…)` am thread-lokalen Schreib-Ort (Adapter) ist der natürliche Ringpuffer; ihn in den Use-Case zu heben hieße, der Use-Case müsste in die laufenden Adapter-Threads hineingreifen — mehr Naht, kein Gewinn. `RunSniCapture` hält darum **keinen** eigenen State außer dem Adapter (anders als `RunCapture`, dessen `run()`-Loop über einen async-Strom iteriert und Stats/Ringpuffer selbst fortschreibt — hier gibt es keinen Strom).

8. **Kein asyncio-Task, Teardown über `stop()`.** Der Sniff läuft in den beiden Adapter-**Threads**, nicht in einer Coroutine — es gibt also **keinen** `asyncio.Task` (anders als der capture-/poll-Loop). Der Start-Callable legt den `RunSniCapture`-Use-Case auf `app.state`; der lifespan-Shutdown stoppt + joint die Threads über `RunSniCapture.stop()` (idempotent), falls ein Sniff lief. Der `start`-Endpunkt bleibt dennoch `async` (Muster `traffic/poll/start`), damit die Naht zu einem späteren task-basierten Pfad offen bleibt.

## Konsequenzen

**Positiv**
- **App → Domain → Server** wird möglich: der echte angefragte Name (SNI) steht neben der IP, dort wo PTR nur den Hoster zeigt — die Lücke aus ADR 0016 ist geschlossen.
- **Erprobt, nicht geraten:** die Technik ist im Spike real gemessen (60 SNIs, 93 % zugeordnet, Delta median 177 ms); die drei Spike-Fallen (scapy-Dissektor, GIL-Aushungern, iface-String) sind im Design adressiert.
- **Datenschutzbewusst:** passiv, manuell, nur-Speicher (kein SQLite) — die sensible SNI-Historie überlebt den Prozess nicht.
- **Sauber gekapselt:** der Parser ist eine reine Funktion (ohne scapy testbar), die Zuordnung eine reine Domänen-Funktion (mit synthetischen Snapshots testbar) — ein späterer Sprachwechsel der systemnahen Schicht bleibt ein lokaler Eingriff im Adapter.
- **capture unberührt:** kein Risiko am erprobten Capture-/Broadcast-Pfad.

**Kosten / Grenzen (nicht verlieren)**
- **Root-pflichtig:** ohne `CAP_NET_RAW`/Root gibt es eine ehrliche 403 — der echte Sniff-Lauf zur Verifikation läuft separat (nicht Teil des Backend-Auftrags; kein `sudo` in der CI, die Permission wird über den Fake-Port abgefangen).
- **Kein TCP-Reassembly:** ein über mehrere Segmente fragmentierter ClientHello wird still übersprungen (`None`) — in der Praxis liefert der nächste frische Verbindungsaufbau i. d. R. einen unfragmentierten ClientHello (der Spike-Trichter bestätigt das). Reassembly wäre ein späterer Anbau.
- **Zuordnung ist best-effort:** rootless sieht psutil fremde Sockets ohne PID (`pid=None`, ehrliche Lücke); kurzlebige Verbindungen können zwischen Snapshot-Ticks durchrutschen (Delta-Mass macht das sichtbar). Die 93 % aus dem Spike sind ein guter, kein perfekter Wert.
- **Nur-Speicher heißt flüchtig:** ein Neustart verliert die Historie (bewusst — Datenschutz). Wer Persistenz will, müsste die Datenschutz-Frage neu stellen.
- **Frontend offen:** dieser Auftrag baut nur das Backend. Die Anbindung der Verkehrsliste an die SNI-Daten (App → Domain → Server-Bündelung) folgt separat.
- **Kein neuer import-linter-Contract außer der `independence`-Zeile** — `domain.sni` reiht sich in den bestehenden Contract ein (importiert keine andere `domain`-Subdomäne); der infra-interne Quergriff auf `infrastructure.capture._scapy` ist von den schicht-basierten Contracts gedeckt.
