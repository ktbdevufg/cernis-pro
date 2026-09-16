# ADR 0012 — analysis-Domäne: die interpretierende Schicht (Regeln als Daten, wertneutral)

- **Status:** Akzeptiert
- **Datum:** 2026-06-10
- **Phase:** Grüne Wiese (vierte neue Domäne nach interfaces (0009) + traffic (0010) + process (0011)), Schritte AN.1–AN.4 — vorbereitet durch P.5 (exe_path als Datenquelle), nachgeschärft in AN.3-fix/-fix-2 (im Bau gefundene Schärfungen).
- **Bezug:** `vision_features_202605.md` §4.4 (interpretierende Schicht — „zeigen + einordnen, nicht urteilen"; kein Verkehr ohne bewussten Klick), §6.2 (analysis rechtfertigt die Hexagonal-Entscheidung — reiner, fast I/O-freier Domänen-Kern), §6.3 (Regeln als Daten), §6.4 (Hilfe-URL ist Infrastruktur); ADR 0011 (process als Datenquelle, `exe_path`-Erweiterung P.5); ADR 0010 (Adapter-/Rechte-Port-Vorbild); ADR 0002 (domain bleibt framework-frei); CLAUDE.md (keine stillen Fallbacks, Finding S3)

## Kontext

analysis ist das **interpretierende Herzstück** des Rewrites — die Schicht über den datenliefernden Schwester-Domänen. Sie konsumiert deren Sicht (traffic + process; scanning/hosts ist vorbereitet, aber in Runde 1 ungenutzt) und produziert **wertneutrale Beobachtungen mit Hilfe-Kontext**: „das fällt auf, hier kannst du nachlesen" — nicht „das ist gefährlich".

Die zentrale Spannung: analysis **braucht** Fremd-Domänen-Daten, **darf** aber per `independence`-Contract (CI-erzwungen seit AN.1, vgl. ADR 0011 zur Lückenschließung) **keine andere `domain`-Subdomäne importieren**. Eine Domäne, die über `traffic`/`process` urteilt, ohne sie zu kennen — das ist der Knoten, den dieses ADR auflöst.

§6.2 der Vision macht analysis explizit zum **Rechtfertigungsgrund für die Hexagonal-Architektur**: gerade weil diese Schicht reine Rechenlogik über fremde Daten ist, zahlt sich der I/O-freie Kern aus (testbar an einer Stelle, agent-freundlich, ohne Mock-Last).

## Entscheidung

1. **ENTKOPPLUNG über eigene Eingabe-Typen.** analysis definiert in `domain/analysis/models.py` **eigene schlanke** Wertobjekte — `ObservedConnection` / `ObservedProcess` / `ObservedHost` und den bündelnden `Snapshot` — statt `domain.traffic.Connection` / `domain.process.ProcessInfo` / `domain.scanning.EnrichedHost` zu importieren. Jeder Typ trägt nur die Felder, die Regeln brauchen. Die **Projektion** aus den echten Fremd-Objekten in diese Sicht lebt im **Composition Root (`app.py`, `_analyze_snapshot`)**, NICHT in einem Use-Case oder Adapter — exakt das Muster der bestehenden Fremd-Domänen-Nähte (`_list_app_traffic` / `_list_processes` / `_build_run_network_scan`): Fremd-Domänen-Kopplung gehört in die Verdrahtung. So bleibt die Domäne rein und der `independence`-Contract **kept**.

2. **REGELN ALS DATEN (Vision §6.3).** `Rule` ist ein frozen Datenobjekt: ein deklaratives `kind`-Feld plus Parameter (`path_prefixes`, `ports`, `threshold`) — die Bedingung steckt **nicht** als Lambda in der Regel. `engine.evaluate` ist der **einzige** Ort mit Auswertungslogik und interpretiert das `kind` per `match`-Dispatch. Folge: eine neue **konkrete** Regel ist genau ein neuer Eintrag in `DEFAULT_RULES` (oder eine zur Laufzeit übergebene Regel) — **keine** Code-Verzweigung. Eine neue **Regel-ART** ist genau ein neuer Dispatch-Zweig; mypy-strict erzwingt die Exhaustiveness des `match` über die `RuleKind`-Union, also **kein** `case _`-Fallback (ein unbekanntes `kind` läuft laut auf, kein stiller Rückfall — S3).

3. **REGELQUELLE HINTER PORT.** `RuleProvider` (`ports/analysis.py`, synchron, reiner In-Memory-Lookup) ist die Quelle der Regeln; der erste Adapter `BuiltinRuleProvider` liefert schlicht `DEFAULT_RULES`. Ein späterer Datei-/DB-Adapter (benutzer-editierbare Regeln) tritt hinter **denselben** Port, **ohne** die Domäne anzufassen — dasselbe Muster wie der spätere eBPF-Adapter hinter den traffic-Ports. In Runde 1 sind die Defaults bewusst **eingebaut, nicht benutzer-editierbar**. Eine leere Regelliste (`()`) ist ein gültiger Zustand (keine Regeln → keine Beobachtungen), kein Fehler.

4. **HILFE-URL IST INFRASTRUKTUR (Vision §6.4).** Eine `Observation` trägt nur einen `help_kind` (stabiler `Literal`-Schlüssel), **keine** URL. Der `HelpLinkResolver`-Port löst `help_kind → URL`; der erste Adapter `StaticHelpLinkResolver` hält eine **lokale** Lookup-Tabelle auf langlebige, allgemein anerkannte Ziele (Wikipedia), bewusst keine projekteigene Domain. Rein lokal, **kein** Netz-I/O: der Resolver **liefert** die URL, er **ruft** sie nicht ab (Vision §4.4 — kein Verkehr ohne bewussten Klick; Privacy der Links bleibt ein Phase-4-Audit-Punkt). Ein unbekannter `help_kind` → `""` (legitimer Leer-Zustand, kein Fehler).

5. **ROTE LINIE „nicht urteilen".** `Severity` hat bewusst nur **zwei neutrale** Stufen — `info` (reine Einordnung) und `notable` („fällt auf") — **kein** `gefährlich`/`sicher`. Der Severity-Rang (`_SEVERITY_RANK`, `notable` vor `info`) ist **nur** eine stabile Sortier-Ordnung für deterministische Ausgabe, keine Wertung.

6. **RECHTE-BLINDE vs. RECHTE-BEWUSSTE Regeln** (im Bau gefunden, AN.3-fix/-fix-2). Echte Kernel-Threads (`kind == "kernel"`, in der Projektion aus `domain.process.classify_kind` gefüllt) sind aus der Prozess-Auffälligkeit **ausgeschlossen** — ihr fehlender `exe_path`/leeres `cmdline` ist Natur, kein Verhalten (sonst Anschwärzen von Harmlosem, Vision-rote-Linie). Der Tarnverdacht `process_masquerade` ist **rechte-bewusst**: leeres `cmdline` trifft **immer** (`info`, in beiden Rechte-Modi verlässlich); ein fehlender `exe_path` (None) trifft **nur unter voller Prozess-Sicht (Root)** und dann **notable** — Root *darf* jeden Pfad lesen, fehlt er trotzdem, ist das ein echtes, stärkeres Signal (z. B. gelöschtes Binary). Rootless ist ein fehlender Pfad **mehrdeutig** (evtl. nur fehlende Leserechte) → kein Treffer für diesen Fall. Der Rechte-Status kommt als `bool` (`Snapshot.full_process_visibility`, Default `False` — „im Zweifel rootless") in den Snapshot — die Domäne bleibt **entkoppelt** (kennt keinen Permission-Port); die Composition Root leitet das `bool` aus dem bestehenden `CheckProcessPermission` (über `ProcessPermissionAdapter`) ab, nicht aus einem direkten `geteuid`.

7. **KEINE PERSISTENZ / HISTORIE in Runde 1.** Regeln arbeiten ausschließlich auf dem **aktuellen** Snapshot. „Host/Prozess spricht **erstmals** mit neuem Ziel" (braucht Verlauf) und die scanning-/hosts-Quelle sind bewusst auf spätere, **eigene** Schnitte verschoben — kein totes Feld auf Vorrat: `Snapshot.hosts` bleibt definiert, aber in der Projektion **unbefüllt** (keine der drei Start-Regeln nutzt es).

## Konsequenzen

**Positiv**
- **Reine, testbare Domäne** (fast I/O-frei): Modelle, Regeln und `evaluate` sind an **einer** Stelle prüfbar, ohne Mock-Last — analysis **rechtfertigt** damit die Hexagonal-Entscheidung in der Praxis (Findings A1/A6, Vision §6.2). Die fünf Ringe sind sauber, der `independence`-Contract trotz Fremd-Daten-Bedarf kept.
- **Beobachtungen in beiden Rechte-Modi vertrauenswürdig:** rootless wird das mehrdeutige „kein Pfad"-Signal zurückgehalten, Root liefert das stärkere; kein Anschwärzen von Harmlosem (Vision-rote-Linie gewahrt).
- **Erweiterung über Daten statt Code:** eine neue konkrete Regel ist ein `DEFAULT_RULES`-Eintrag; eine neue Regelquelle ein zweiter Adapter hinter `RuleProvider`; eine neue Hilfe-URL ein Tabelleneintrag im Resolver — der Domänen-Kern bleibt jeweils unberührt.

**Offen / später**
- **Benutzer-editierbare Regeln** via Datei-/DB-Adapter hinter dem bestehenden `RuleProvider`-Port (Runde 1 bewusst nur eingebaute Defaults).
- **hosts-/scanning-Quelle** als eigener Schnitt + erste host-Regel (`Snapshot.hosts` steht bereit, ist aber noch unbefüllt — kein totes Feld auf Vorrat).
- **Historie** für „erstmals neues Ziel" (braucht Persistenz, in Runde 1 bewusst keine).
- **Stärkeres kein-Pfad-Signal** liefert der Root-Kontext bereits jetzt; rootless bleibt zurückhaltend.
- **Privacy der Hilfe-Links** (der Resolver liefert lokal, ruft nichts ab) bleibt ein **Phase-4-Audit-Punkt**.

Strang dieses ADR (echte Commits): AN.1 (`3171c6d`, analysis-domain: Snapshot, Regeln-als-Daten, RuleEngine), AN.2 (`2f07856`, analysis-ports + AnalyzeSnapshot-Use-Case), P.5 (`4f4fd23`, process um `exe_path` erweitert — Datenquelle für analysis), AN.3 (`4be473e`, end-to-end verdrahtet: Adapter, `/api/analysis`, Snapshot-Projektion), AN.3-fix (`bd5271a`, Kernel-Threads raus, Userland-Tarnverdacht zeigen), AN.3-fix-2 (`6c466a2`, Tarnverdacht rechte-bewusst: kein-Pfad nur unter Root). `domain.analysis` steht seit AN.1 im `independence`-Contract (`pyproject.toml`).
