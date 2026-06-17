# ADR 0029 — host_detail-Frame: analysis_severity (Auffälligkeits-Bewertung, Achse B) als eigenes Feld

- **Status:** Akzeptiert
- **Datum:** 2026-06-17
- **Phase:** Grüne Wiese — Quer-Feature nach Stabilisierung des Bestands. Erweitert die WS-getriebene Scan-Tabelle (`host_detail`-Frame) um ein Bewertungs-Signal, verdrahtet ausschließlich im Composition Root (`app.py` + `ws_scan.py`).
- **Bezug:** Konzept §4 (Achse A vs. Achse B); ADR 0026 (host_detail-`new_ports` — Achse A, Port-History, identisches best-effort-/Default-/Loop-Muster); ADR 0019/0020 (host_detail-Baseline-Anreicherung, `baseline_known`-Timing); ADR 0023/0027/0028 (Provider-Stack: Composite→Configured→Filtered, konfigurierbare Regeln, `/rules/all`-Ungefiltertheit); ADR 0013 (Lese-/Schreib-Naht der Host-Historie).

## Kontext

Das `host_detail`-Frame trägt seit ADR 0026 `new_ports` — das **wertneutrale** Faktum „seit dem letzten Scan ist Port Y neu offen" (**Achse A**, Port-History, kein Urteil, selbsterledigend). Was fehlt, ist das **bewertende** Gegenstück:

> **Achse B (Auffälligkeit):** Die höchste Auffälligkeits-Bewertung des Hosts gegen die **konfigurierten** Regeln — `"critical"` | `"notable"` | `null`.

Achse A und Achse B sind **strikt getrennt**: Achse A beschreibt eine Differenz (was ist seit dem letzten Scan dazugekommen?), Achse B ein Urteil über den **aktuellen** Portstand (welche offenen Ports sind nach den Regeln auffällig?). Ein Host kann neue Ports OHNE Auffälligkeit haben (harmloser neuer Port) und Auffälligkeit OHNE neue Ports (ein seit jeher offener Backdoor-Port). Deshalb zwei **unabhängige** Frame-Felder.

Die Bewertungs-Engine existiert bereits: `AnalyzeSnapshot` (synchron, dünn) über `evaluate` (rein) und dem Provider-Stack Composite→Configured→Filtered (ADR 0023/0027). Bisher wurde sie nur im REST-Pfad `GET /api/analysis` (`_analyze_snapshot`) genutzt — gegen die **DB-Historie** des jüngsten Scans. Die WS-getriebene Scan-Tabelle braucht die Bewertung jedoch **live**, pro angereichertem Host, während der Scan läuft.

Bei der Analyse fielen zwei bestehende Doppelungen im Composition Root auf, die diese Erweiterung sonst ein drittes Mal kopiert hätte:
- Der Provider-Stack Composite→Configured(→Filtered) lag **zweimal** inline: in `_analyze_snapshot` MIT Filter (Engine sieht nur aktive Regeln), im `/rules/all`-Runner OHNE Filter (die UI muss deaktivierte Regeln weiter sehen, um sie wieder einschaltbar zu machen, ADR 0028).
- Die Projektion `EnrichedHost → ObservedHost` lag inline im `_analyze_snapshot`.

## Entscheidung

1. **PROVIDER-STACK + PROJEKTION ALS FREIE FUNKTIONEN — SINGLE SOURCE.** Die beiden inline duplizierten Bausteine werden in `app.py` extrahiert, bevor sie ein drittes Mal entstehen:
   - `_build_configured_provider(rules, settings) -> _ConfiguredRuleProvider` — die Kette Composite→Configured. Genutzt vom `/rules/all`-Runner (UNGEFILTERT — semantisch wie bisher).
   - `_build_filtered_provider(rules, settings) -> _FilteredRuleProvider` — derselbe Stack + Filter obendrauf. Genutzt von `_analyze_snapshot` (REST) UND der neuen WS-Severity-Verdrahtung (Engine-Pfad).
   - `_observed_host(host, is_known) -> ObservedHost` — die Projektion (Felder ip/hostname/vendor/open_ports/is_known; `open_ports` = Portnummern mit `state == "open"`). Genutzt von der Bulk-Schleife in `_analyze_snapshot` UND vom Einzel-Host-Pfad.

   Beide alten Inline-Stellen rufen jetzt diese Funktionen — **kein Verhaltenswechsel**, nur eine Quelle. Die Unterscheidung gefiltert vs. ungefiltert bleibt exakt erhalten (Test belegt sie).

2. **EINZEL-HOST-BEWERTUNG: `_severity_for_host(host, is_known, analyze) -> Severity | None`** (freie Funktion in `app.py`). Sie baut einen **Ein-Host-`Snapshot`** (`hosts=(_observed_host(host, is_known),)`, `connections=()`, `processes=()`, `full_process_visibility` auf dem Snapshot-Default `False` — der Host-Pfad hängt nicht an der Prozess-Sicht), lässt die injizierte `AnalyzeSnapshot` darüber laufen und nimmt:
   - nur die **Host-Beobachtungen** (`observation.kind.startswith("host_")` — die Host-`RuleKind`-Werte `host_remote_port`/`host_new`/`host_port_count` aus `domain/analysis/rules.py`),
   - die **höchste** Severity via `_SEVERITY_RANK` aus `domain.analysis.engine` (importiert, nicht lokal gespiegelt — kleinster Rang = stärkste Severity gewinnt),
   - `"info"` wird **NICHT** als Auffälligkeit gewertet → bei nur info-/keinen Host-Befunden: `None`. Nur `"critical"`/`"notable"` sind Achse-B-Signale.

   Hosts ohne `ip` werden übersprungen (`None`) — kein bewertbares Subjekt, konsistent mit der Engine.

3. **LIVE-HOST, NICHT DB-HISTORIE.** Bewertet wird der **live** `event.host` (`EnrichedHost`), nicht der abgeschlossene Scan aus der DB. Deshalb wird `_analyze_snapshot` **nicht** wiederverwendet (das liest den jüngsten gespeicherten Scan). Zwei Snapshot-Quellen teilen sich bewusst nur **Provider + Projektion** (Single Source), nicht den Daten-Lesepfad: REST = DB-Historie (Bulk), WS = Live-Host (einzeln).

4. **ANREICHERUNG IM WS-LOOP, INJIZIERTE CALLABLE.** `ws_scan.py` baut **keine** analysis-Projektion und **keinen** Provider selbst. `make_ws_scan` bekommt eine sechste Factory `severity_factory: SeverityFactory` (analog `IsKnownFactory`), die pro Verbindung ein Callable `(EnrichedHost, bool) -> Severity | None` liefert. In `app.py` gebaut: eine `AnalyzeSnapshot`-Instanz mit dem **gefilterten** Provider (`_build_filtered_provider`) + `StaticHelpLinkResolver`, einmal instanziiert, geschlossen in `lambda host, known: _severity_for_host(host, known, analyze)`. Die Verdrahtung bleibt im Composition Root.

5. **`is_known`-EINGABE = `baseline_known`.** Die Engine-Eingabe `is_known` ist der im Loop schon **vor `record_seen`** gelesene `baseline_known` (ADR 0019). Kein zusätzlicher Vorzustand-Read für Achse B nötig — Severity bewertet den aktuellen Portstand, nicht die Differenz; `baseline_known` wird nur für die `host_new`-Regel durchgereicht.

6. **UNABHÄNGIG VON KURATIERUNG.** `frame["analysis_severity"]` wird **außerhalb** des `if kuratiert is not None:`-Blocks gesetzt — Achse B braucht keine Kuratierung (auch ein brandneuer, nie gespeicherter Host kann auffällige Ports haben). Damit ist Achse B disjunkt von der `new_ports`/`is_changed`-Logik (Achse A), die an einem devices-Vorzustand hängt.

7. **DEFAULT im Frame-Schema = `None`.** `_host_detail_frame` setzt `analysis_severity: None` zu den Default-Keys (jetzt **26 Keys** statt 25 — der Docstring-Kommentar wird entsprechend angepasst). So ist das Feld **immer** im Frame vorhanden, auch wenn die Anreicherung übersprungen wird. `_host_detail_frame` bleibt eine reine Projektion ohne I/O; die Bewertung braucht die injizierte Callable und gehört in den Loop.

8. **BEST-EFFORT, KEIN SCAN-ABBRUCH.** Die Anreicherung läuft über `_severity_safe` (analog `_is_known_safe`): wirft das Severity-Callable, wird der Fehler gefangen, als Warnung geloggt (`host_analysis_severity_failed`) und `None` zurückgegeben — „im Zweifel keine Auffälligkeit". Ein Bewertungsfehler darf die Scan-Anzeige nicht fällen; mit Warn-Log kein stiller S3-Fallback.

## Konsequenzen

- Das `host_detail`-Frame trägt **+1 Feld** (`analysis_severity`, 25 → 26 Keys). Das Frontend kann Achse A (`new_ports`, neutral) und Achse B (`analysis_severity`, bewertend) unabhängig darstellen.
- **Zwei Snapshot-Quellen** teilen sich Provider-Stack + Projektion: REST (`_analyze_snapshot`, DB-Historie, Bulk) und WS (`_severity_for_host`, Live-Host, einzeln). Eine Änderung an Provider oder Projektion wirkt auf beide — gewollt (Single Source).
- Die beiden zuvor inline duplizierten Provider-Stellen sind eliminiert; `_build_configured_provider`/`_build_filtered_provider` sind die einzige Quelle. Die gefiltert/ungefiltert-Semantik (Engine vs. UI) bleibt unverändert und ist testabgesichert.
- `make_ws_scan` hat eine sechste Factory (`severity_factory`); alle Aufrufer (`app.py` + Tests) sind angepasst.
- `_severity_for_host`/`_observed_host`/`_severity_safe` sind direkt unit-testbar (freie Funktionen, kein WS-/DB-Setup nötig).

## Nicht Teil dieser Entscheidung

- **Achse A (`new_ports`, `is_changed`, `is_known`) bleibt unberührt** — keine Änderung an Port-History oder Historie-Logik.
- **Kein Acknowledge / keine Severity-Historie** — `analysis_severity` ist ein flüchtiges Frame-Faktum des aktuellen Scans, wie `new_ports` selbsterledigend (der Folgescan bewertet neu).
- **Keine zweite Provider-Kopie** — die freien Factory-Funktionen sind die einzige Quelle.
