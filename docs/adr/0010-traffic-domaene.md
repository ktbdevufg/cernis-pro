# ADR 0010 — traffic-Domäne: Per-App-Netzwerk-Monitoring (Stufe 1+2)

- **Status:** Akzeptiert
- **Datum:** 2026-06-05
- **Phase:** Grüne Wiese (zweite neue Domäne nach interfaces), Schritte T.1–T.5
- **Bezug:** `vision_features_202605.md` §4.2 (Per-App-Traffic Stufe 1+2, Rechte-Modell), §6.1 (eigener Rechte-Port), Findings S4/S5 (erhöhte Rechte); ADR 0009 (interfaces als „Krücke → Domäne über fünf Ringe"-Muster); capture-Domäne (Rechte-Port-Vorbild `check_permission`); CLAUDE.md (pragmatisch hexagonal, „keine stillen Fallbacks", Finding S3)

## Kontext

Per-App-Netzwerk-Monitoring ist das **Kernfeature** der Produkt-These (Vision §2: „Per-App-Traffic = Mündigkeit"): sichtbar machen, welche App wohin spricht und mit wieviel Durchsatz. Es ist die erste neue Domäne mit echter, lohnender Domänenlogik — und zugleich die erste, die in die Rechte-Zone der Findings S4/S5 reicht.

Vision §4.2 schneidet das Feature bewusst in Stufen:

- **Stufe 1 — Verbindungen (rootless):** welche App welche Verbindung offen hat. Ohne Root nur die **eigenen** Prozesse zuordenbar.
- **Stufe 2 — Durchsatz:** grobe Rate rein/raus aus Sekunden-Polling der kumulativen Socket-Byte-Zähler (Methode wie `nethogs`).
- **Stufe 3 — eBPF:** bewusst **zurückgestellt** (kernelversionsabhängig, eigenes Projekt).

Erhöhte Rechte sind die S4/S5-Zone: das Rechte-Modell muss **minimal, lokalisiert, sichtbar** sein — nicht die GUI privilegieren, kein Selbst-Privileg, ein direkter Gegenentwurf zur Pcap-Anleitung von Finding S5.

Faktencheck der Linux-Quellen (gegen das reale System geprüft):

- `psutil.net_connections` sieht Verbindungen **inkl. PID rootless**, aber nur die eigenen Prozesse (fremde erscheinen mit `pid=None`) — die ehrliche „benötigt Root"-Lücke.
- `/proc/net/tcp` hat **keine** kumulativen Byte-Zähler (nur Momentan-Queues).
- `ss -i` / `sock_diag` ist die **einzige** Byte-Zähler-Quelle (`bytes_sent`/`bytes_received`).
- iproute2-6.1.0 hat **kein JSON** (`-j`/`-J` sind `invalid option`); `socket.NETLINK_SOCK_DIAG` fehlt im Python-Build; `pyroute2` ist nicht installiert.

## Entscheidung

1. **Vollwertige traffic-Domäne über alle fünf Ringe** nach dem interfaces-Muster (ADR 0009). `domain/traffic.py`: frozen `Connection`/`AppTraffic`/`Endpoint`/`ConnSample` + reine Funktionen (`normalize_status`, `aggregate_by_app`, `compute_rate`, `match_samples`, `make_socket_key`), kein I/O, keine Uhr (Zeitstempel als `ConnSample`-Feld).

2. **Zwei Datenquellen hinter EINEM Port** `PerProcessTrafficProvider`: psutil für Stufe 1 (`list_connections`), `ss -tin` für Stufe 2 (`sample_throughput`). eBPF (Stufe 3) bleibt ein möglicher späterer **zweiter Adapter hinter demselben Port** — kein Umbau.

3. **ss-Text-Parsing statt pyroute2/raw-Netlink:** kein neuer Dependency (minimal-invasiv), eine reine, gegen echtes ss-Format getestete `parse_ss_output`-Funktion. Nur **TCP** — UDP hat keine kumulativen Byte-Zähler.

4. **Kanonischer Socket-key** (`make_socket_key` + `_canonical_ip`, stdlib `ipaddress`): vereinheitlicht die ss-Adressform (`[::ffff:x]`) und die psutil-Form (`::ffff:x`), löst IPv4-mapped IPv6 auf. Ohne das würden gemappte/IPv6-Sockets bei der Raten-Paarung (`match_samples`) nicht zusammenfinden. `Endpoint.ip` bleibt die **rohe Anzeige-IP**; der kanonische key ist reines **Paarungs-Detail** (kein `key`-Feld an `Connection`).

5. **Eigener Rechte-Port** `TrafficPermissionPort` (Vision §6.1) nach capture-Muster: `check_permission() -> str | None`. Volle Sicht (Durchsatz aller Apps) nur bei `geteuid() == 0` **ODER** `CAP_NET_ADMIN` (`CapEff` Bit 12). Sonst ein handlungsorientierter Text, der zum **Selbst-als-Root-Starten anleitet** (konkreter Befehl) — das Backend eskaliert **NICHT** selbst (kein Selbst-Privileg, S4/S5-konform). Kein stiller Fallback (S3): ist `/proc/self/status` nicht lesbar, fällt die Prüfung auf `geteuid` zurück, **nie** auf „volle Sicht".

6. **Stufe 2 (Durchsatz-Messung) braucht selbst KEIN Root:** `ss -tin` liest die Byte-Zähler rootless. Die Root-Frage betrifft allein die **PID/App-Zuordnung** (Stufe 1) der fremden Prozesse — der Durchsatz wird auch rootless gemessen, nur eben den nicht zuordenbaren Sockets (None-Gruppe) zugeschrieben.

7. **Polling-Zustand AUTO und MANUELL** (Nutzer-Wahl): `PollThroughput`-Use-Case (RunMonitor-Muster — `tick`/`run`/`stop`/`current_rates`, interner State über die Zeit, kein Modul-Global). **MANUELL** = on-demand via `POST /api/traffic/poll/start|stop` (capture-Muster, Default, sparsam — nur bei offenem View). **AUTO** = lifespan-Dauer-Poll hinter dem Flag `CERNIS_TRAFFIC_POLL_AUTO` (nur mit `bootstrap_on_startup`), Intervall `CERNIS_TRAFFIC_POLL_INTERVAL` (der Vision-„Regler"). Beide nutzen denselben `app.state`-Singleton; Doppelstart-Schutz via `task.done()`.

8. **Zweistufige Grundeinheit:** `AppTraffic` (App-Übersicht) mit eingebetteten `Connection` (einen Klick tiefer) — Vision „Überblick → Detail". Nicht zuordenbare Verbindungen (rootless, ohne PID) kommen in **EINE** ehrliche `app_name=None`-Gruppe, nicht verworfen und nicht je einzeln.

9. **State-Kombination im Composition Root:** `poll.current_rates()` wird per Runner-Callable mit `ListAppTraffic(rates)` verheiratet (`_monitor_status`-Muster). `ListAppTraffic` bleibt portrein (`rates` als optionales Argument); die Laufzeit-Singleton-Kombination kennt nur `app.py`. Der geteilte `PsutilTrafficAdapter`-Singleton (`lru_cache`) stellt sicher, dass Poller und Leser dieselbe Quelle nutzen.

## Konsequenzen

**Positiv**
- Das Kernfeature der Vision ist live (Per-App-Durchsatz, rootless + Root), die Domänenlogik ist testbar und liegt an **einer** Stelle, die fünf Ringe sind sauber (8/8 import-Contracts kept).
- Der Quellenwechsel (eBPF/pyroute2) bleibt später ein **lokaler** Eingriff hinter dem Port — kein Umbau des Rests.
- Das Rechte-Modell ist S4/S5-konform: kein Selbst-Privileg, sichtbare Rechte, nur der Backend-Prozess wird privilegiert (nicht die GUI).
- **Ehrliche Darstellung:** nicht zuordenbare Verbindungen bleiben sichtbar (None-Gruppe), Raten sind `None` bis gemessen (kein erfundener Wert) und `0.0` bei einem gemessenen, aber verkehrslosen Socket — der Unterschied „nicht gemessen" vs. „null Durchsatz" bleibt erhalten.

**Kosten / Verhaltensänderung / Grenzen**
- **ss-Text-Parsing ist quellformat-abhängig** (iproute2). Bricht eine Distribution das Format, braucht es den zweiten Adapter. Bewusst in Kauf genommen gegen den pyroute2-Dependency (minimal-invasiv schlägt formstabil).
- **Nur TCP-Durchsatz** — UDP hat keine kumulativen Zähler, taucht in Stufe 1 (Verbindungsliste) auf, aber ohne Rate.
- **Erste Rate erst nach dem zweiten tick** (ein Intervall Verzögerung) — bauartbedingt, weil eine Rate die Differenz zweier Messpunkte ist.
- **Die Poll-Endpunkte müssen `async` sein:** ein synchroner Endpunkt + `asyncio.create_task` wirft `RuntimeError: no running event loop` im Starlette-Threadpool (beim Laufzeit-Smoke gefangen und behoben). **NACHZÜGLER:** capture's `pcap_start` trägt denselben latenten `sync + create_task`-Bug (sein Test überschreibt den Runner mit einem Fake, der echte Pfad wird nie sync getriggert) — noch nicht verifiziert/behoben, eigener Scope.
