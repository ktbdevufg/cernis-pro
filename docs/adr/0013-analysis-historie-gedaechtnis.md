# ADR 0013 — analysis-Historie: das erste Gedächtnis (neuer Host „seit deinem letzten Scan")

- **Status:** Akzeptiert
- **Datum:** 2026-06-10
- **Phase:** Grüne Wiese — analysis-Folgeschnitt C (Historie), nach A (editierbare Regeln, A.1/A.2) und B (hosts-Quelle + host-Regel `host_remote_access_port`). Vorbereitet in C.1 (Repository + Domänen-Feld `ObservedHost.is_known` + Regel `new_host_seen`), verdrahtet in C.2 (beide Nähte im Composition Root).
- **Bezug:** `vision_features_202605.md` (host-Auffälligkeiten — „neues Gerät im Netzwerk"); ADR 0012 (analysis-Domäne — Regeln als Daten, rechte-bewusste Schärfung als Vorbild für „Faktum im Snapshot", §7 „keine Historie in Runde 1" wird hier abgelöst); B (hosts-Quelle: jüngster Scan als dritte Datenquelle, ausfallsicher); C.1-Commit (`SqliteHostHistoryRepository` + `ObservedHost.is_known` + Regel `new_host_seen`, Repository noch nicht verdrahtet).

## Kontext

Bisher sind **alle** analysis-Regeln **zustandslos**: sie arbeiten ausschließlich auf dem **aktuellen** Snapshot, ohne Gedächtnis (ADR 0012 §7 hat das bewusst so festgelegt). Die Beobachtung „**erstmals** neuer Host im Netz" durchbricht das — sie braucht **Verlauf**: „neu = noch nie gesehen" ist nur entscheidbar, wenn etwas die bisher gesehenen Hosts erinnert.

Das ist **qualitativ neu** und darf die reine, deterministische Engine **nicht** zustandsbehaftet machen. Die Spannung: analysis braucht ein Gedächtnis, der Domänen-Kern soll aber rein bleiben (kein I/O, keine Persistenz, testbar an einer Stelle — der Hexagonal-Rechtfertigungsgrund aus ADR 0012 §6.2).

## Entscheidung

1. **GEDÄCHTNIS ALS SNAPSHOT-FAKTUM.** Die Engine wertet nur ein `bool` — `ObservedHost.is_known` —, **genau wie** `full_process_visibility` beim Tarnverdacht (ADR 0012 / AN.3-fix-2). Die Domäne kennt **keine** Persistenz; das „schon gesehen?" kommt fertig berechnet als Faktum in den Snapshot. Default `True` („im Zweifel bekannt") — ein unbekannter Historie-Zustand schlägt **nicht** fälschlich als neuer Host an (kein Falsch-Alarm). Die Regel `new_host_seen` feuert genau dann, wenn `is_known == False` (und die `ip` nicht leer ist).

2. **MECHANIK IN INFRASTRUKTUR + COMPOSITION ROOT.** `SqliteHostHistoryRepository` (Tabelle `analysis_known_hosts`, MAC als `PRIMARY KEY`, `first_seen`-Zeitstempel) hält das Gedächtnis. Lese- und Schreib-Pfad sind **getrennt** (`known_macs` / `is_known` vs. `record_seen`). Die beiden Nähte, die das Repository an Scan und analysis koppeln, leben **ausschließlich im Composition Root** (`ws_scan.py` und `_analyze_snapshot` in `app.py` — beide von den import-linter-Contracts ausgenommen). Kein Eingriff in `domain`/`application`/`ports`.

3. **IDENTITÄT = MAC, nicht IP.** Die MAC ist die stabile Geräte-Kennung; IPs wechseln per DHCP, ein IP-Wechsel ist kein neues Gerät. Hosts **ohne** MAC gelten als **bekannt** (`is_known` True, werden nicht in die Historie geschrieben) — ein Host ohne stabile Identität wäre als „neu" nur Rauschen. Das ist **dieselbe Linie** wie `ws_scan._record_host` (devices-Projektion überspringt MAC-lose Hosts).

4. **SCAN SCHREIBT, ANALYSIS LIEST (Variante 2).** Zwei **getrennte, unabhängige** Nähte:
   - **Schreib-Naht** am Scan-Abschluss: `ws_scan` trägt pro `HostEnriched`-Event die MAC per `record_seen` in die Historie ein — **neben** der bestehenden devices-Projektion, **best-effort** (ein Fehler wird gefangen + geloggt als `record_seen_host_failed`, der Scan läuft weiter; mit Log **kein** stiller S3-Fallback).
   - **Lese-Naht** in `_analyze_snapshot`: die hosts-Projektion holt die bekannten MACs **einmal** (`known_macs`, Bulk) und füllt `is_known` je Host. **Reiner Lesevorgang** — `GET /api/analysis` hat **keinen** Schreib-Seiteneffekt (sauberes API-Design: ein GET mutiert nicht).

   Mentales Modell für den Nutzer: „neuer Host **seit deinem letzten Scan**".

5. **BASELINE — kein lauter Fehlstart.** Der erste Scan trägt **alle** gefundenen Hosts in die Historie ein → beim nächsten analysis-Lesen sind alle bekannt → die Regel `new_host_seen` meldet beim ersten Scan **nichts**. „Neu" feuert ab dem **zweiten** Scan für echte Neuzugänge. Das ergibt sich **automatisch** aus der Trennung (Scan schreibt, analysis liest danach) — **keine** Sonderbehandlung des ersten Scans nötig. Bewusst rauschfrei: ein frisch installiertes CERNIS würde sonst beim ersten Scan das ganze Netz als „neu" anschwärzen.

6. **AUSFALLSICHERHEIT bleibt (aus B).** Ein korrupter jüngster Scan lässt die hosts-Projektion (und damit auch `new_host_seen`) aus, **ohne** den Lageüberblick (traffic/process) zu fällen — `scan_history.get()` wirft weiterhin laut, wer den Scan gezielt abruft; nur die interpretierende Projektion überspringt die unlesbare Host-Quelle (mit Warn-Log).

## Konsequenzen

**Positiv**
- **Engine bleibt rein und deterministisch trotz Gedächtnis:** sie wertet nur `is_known` (bool) — dieselbe Faktum-im-Snapshot-Technik wie der Rechte-Kontext (`full_process_visibility`). Ein **wiederverwendbares Muster** für künftige historieabhängige Regeln.
- **Sauberer GET:** `/api/analysis` liest nur, schreibt nie — die Historie wird allein am Scan gepflegt.
- **Rauschfreie Baseline:** kein lauter Fehlstart, „neu" bedeutet wirklich „seit deinem letzten Scan dazugekommen".
- **Best-effort-Symmetrie:** die Schreib-Naht ist genau so abgesichert wie die devices-Projektion — ein DB-Problem killt die Scan-Anzeige nicht, bleibt aber sichtbar (Log).

**Offen / später**
- **Weitere Historie-Regeln auf derselben Infrastruktur:** „neues Verbindungsziel", „neuer Prozess" — rauschanfälliger (mehr Fluktuation), kommen als eigene Schnitte.
- **Alterung / Vergessen** alter Historie-Einträge (z. B. ein lange abwesendes Gerät wieder als „neu" werten).
- **Historie in der GUI** sichtbar und rücksetzbar machen (inkl. „Host-Daten aus letztem Scan nicht lesbar" für den korrupten-Scan-Fall).

Strang dieses ADR (echte Commits): B (hosts-Quelle + `host_remote_access_port` + ausfallsichere Projektion), Serializer-Fix (`3536c7d`, formfremde mDNS-properties als `CorruptScanError`), C.1 (`SqliteHostHistoryRepository` + `ObservedHost.is_known` + Regel `new_host_seen`, Repository noch unverdrahtet), C.2 (beide Nähte im Composition Root verdrahtet — Scan schreibt, analysis liest). `domain.analysis` steht seit AN.1 im `independence`-Contract (`pyproject.toml`); `is_known` ändert daran nichts (bleibt ein nacktes bool).
