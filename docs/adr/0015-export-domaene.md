# ADR 0015 — export-Domäne: Berichte als CSV / JSON / PDF (Block 1: Scan · Block 2: Analyse-Befunde)

- **Status:** Akzeptiert
- **Datum:** 2026-06-11
- **Phase:** Grüne Wiese (erste Export-/Berichts-Schicht, Quer-Feature, nach interfaces (0009) + traffic (0010) + process (0011) + analysis (0012/0013) + diagnostics (0014))
- **Bezug:** ADR 0012/0013 (analysis als Vorbild der `Observed*`-Projektion im Composition Root — kein Domäne-zu-Domäne-Import); ADR 0011/0014 (Fünf-Ringe-Muster, Port + Adapter für das systemnahe/render-nahe I/O); ADR 0002 (domain bleibt framework-frei); ADR 0001 (keine stillen Fallbacks, Finding S3); pyproject.toml (`independence`-Contract über alle `domain.*`-Subpakete)

## Kontext

Die export-Domäne ist die erste **Berichts-Schicht** des Rewrites: ein **Quer-Feature**, das einen bereits gespeicherten Scan in ein teilbares/druckbares Format gießt. In v1 hing der Export am `lastScanId`; v2 macht die Quelle explizit — ein gespeicherter Scan wird **per `scan_id`** aus der ScanHistory geholt und in drei Formaten ausgegeben.

Faktencheck der Quelle (gegen das reale System geprüft):

- Die Scan-Daten liegen als `domain.scanning.ScanRecord` (mit `EnrichedHost`-Tupel) in der ScanHistory; der Lesepfad ist der bestehende `GetScanDetail` (`scan_id` → `ScanRecord | None`).
- `EnrichedHost` trägt die Kernfelder (ip/mac/vendor/hostname/os_guess/category/label/tags/source/rtt_ms/os_accuracy) **und** verschachtelte Listen (`ports`, `mdns_services`, `ssdp_services`).
- `PortInfo` trägt `port`/`state`/`service`, **kein** Protokoll-Feld — der socket-/nmap-Scan ist TCP.

Drei wiederkehrende Spannungen, die dieses ADR auflöst:

1. **Domänen-Kopplung.** Ein „fauler" `from domain.scanning import ScanRecord` in `domain.export` wäre ein Domäne-zu-Domäne-Import — genau das, was der `independence`-Contract verbietet (Muster analysis, das stattdessen eigene `Observed*`-Typen + eine Projektion im Composition Root nutzt).
2. **Was heißt „vollständig" je Format?** CSV, JSON und PDF haben unterschiedliche, gegenläufige Stärken — eine einheitliche Spaltenmenge wäre für alle drei die falsche.
3. **Wo lebt das Rendern?** PDF-Rendern (reportlab) ist Infrastruktur; CSV/JSON-String-Erzeugung ist reine stdlib.

## Entscheidung

1. **Vollwertige export-Domäne über alle fünf Ringe** nach dem diagnostics/analysis-Muster. `domain/export.py`: frozen `ExportablePort`/`ExportableHost`/`ExportableScan` (die **eigenen** Eingabe-Typen) + `PdfReportModel`, Alias `ExportFormat` (`Literal["csv","json","pdf"]`), reine Funktionen `to_json`/`to_csv`/`build_pdf_model` + Helfer `format_ports`/`format_tags` — kein I/O außer stdlib-`csv`/`json`-**String**-Erzeugung, keine Uhr.

2. **KEINE Domäne-zu-Domäne-Kopplung — eigene `Exportable*`-Typen + Projektion im Composition Root** (Muster analysis' `Observed*`). `domain.export` importiert **NICHT** `domain.scanning`; die Projektion `ScanRecord`/`EnrichedHost` → `ExportableScan`/`ExportableHost` lebt in `app.py` (`_project_scan_to_exportable`, per Attribut-Zugriff). Der Use-Case `ExportScan` kennt nur ein schlankes `scan_provider`-Callable (`Callable[[int], ExportableScan | None]`) + den `ReportRenderer` + `domain.export` — kein scanning-Import. `domain.export` kommt in den `independence`-Contract (pyproject.toml) analog `domain.diagnostics`.

3. **Format-gerechte Vollständigkeit** (Best Practice, kein Spaltenwähler im ersten Wurf):
   - **JSON = alles:** verlustfrei der komplette `ExportableScan` (alle Host-Felder, verschachtelt: ports als Objekt-Liste, mdns/ssdp als String-Listen). `sort_keys=True`, `indent=2`, `ensure_ascii=False` — **deterministisch + reproduzierbar**.
   - **CSV = Tabelle:** flache Kernfelder, eine Zeile pro Host, **definierte Spalten-Reihenfolge** (`ip,mac,vendor,hostname,os_guess,category,label,open_ports,tags,source`). `open_ports`/`tags` zusammengefasst (`"22/tcp,80/tcp"` / `"a;b"`), Escaping über das stdlib-`csv`-Modul. Verschachteltes (mdns/ssdp-Detail) ist **bewusst weggelassen** (in einer flachen Tabelle nicht sauber abbildbar — das führt JSON).
   - **PDF = Bericht:** lesbar, druckbar, **kein Logo**. Kopf (Titel „CERNIS PRO — Scan-Bericht", `scanned_at`, `cidr`, `host_count`) + Tabelle der Kernfelder (`ip,mac,vendor,hostname,os_guess,category,open_ports`).

4. **Reine Serialisierung + PDF-MODELL in domain, reportlab-Rendern in infrastructure.** `build_pdf_model` liefert ein **reines** `PdfReportModel` (Kopf-Felder + `columns`/`rows` als reine Daten) — so bleibt die Layout-/Spaltenwahl **testbar** (mutationsproben-tauglich), ohne reportlab im domain-Ring. Der `ReportRenderer`-Port (synchron — reportlab ist CPU-/Render-Arbeit, kein Netz-I/O) wird vom `ReportlabRenderer` erfüllt (`SimpleDocTemplate` + `Table` + Kopf-Paragraphs → `BytesIO` → bytes). CSV/JSON brauchen **keinen** Port (reine domain-Funktionen).

5. **`ExportResult` als schlanke application-Struktur** (`content: bytes`, `media_type: str`, `filename: str`). `media_type`/`filename` sind transport-nah (HTTP-Download) → application, nicht domain. `filename = cernis-scan-<scan_id>.<ext>`, `media_type` ∈ `text/csv` | `application/json` | `application/pdf`.

6. **`scan_id` nicht gefunden → ehrlicher 404, kein leerer Export** (ADR 0001). Der `scan_provider` liefert `None` (Scan-ID gibt es nicht) → der Use-Case wirft `application.export.ScanNotFoundError`; ein globaler `exception_handler` im Composition Root mappt auf **404** (Muster `DeviceNotFoundError` / der diagnostics-Rechte-Naht — das Mapping sitzt am Composition Root). Ungültiges `format` → FastAPI 422 (Pflicht-`Literal`-Query-Param).

## Konsequenzen

**Positiv**
- Die Serialisierung (CSV-Spalten, JSON-Struktur, PDF-Modell) liegt **rein im domain-Ring**, mutationsproben-getestet; das reportlab-Rendern ist in **einem** Adapter gekapselt (Sprach-Wechsel bleibt lokal, Vision 5.2).
- **Keine Domäne-zu-Domäne-Kopplung:** `domain.export` ist unabhängig (independence-Contract), die scanning→export-Projektion lebt in der Verdrahtung — exakt das analysis-Vorbild.
- **Format-gerecht statt einheitlich-falsch:** JSON verlustfrei, CSV als Tabelle, PDF als Bericht — kein Spaltenwähler nötig (Best Practice im ersten Wurf).
- **Deterministisch/reproduzierbar:** sortierte JSON-Keys, feste CSV-Spalten, stabile Listen-Reihenfolge — gleicher Scan → gleicher Export.

**Kosten / Grenzen**
- **mdns/ssdp im CSV bewusst weggelassen** — die flache Tabelle bildet Verschachteltes nicht sauber ab; wer das Detail braucht, nimmt JSON.
- **`PortInfo` ohne Protokoll-Feld:** die Projektion setzt `protocol="tcp"` (die reale Scan-Annahme) — bei einem späteren UDP-Scan ist das hier nachzuziehen.
- **Abhängigkeit von reportlab:** bereits Dependency; das Rendern selbst ist an die reportlab-API gebunden (im einen Adapter gekapselt, ohne echtes I/O über das `%PDF`-Magic testbar).
- **Kein neuer import-linter-Contract außer der `independence`-Zeile** — `domain.export` reiht sich in den bestehenden Contract ein; der Use-Case importiert `domain.export` + `ports.export` (beides `application → domain`/`ports`, erlaubt), die Projektion sitzt am Composition Root (kein application↔application-Import, kein scanning-Import in domain.export).

**Anschluss (spätere Blöcke)**
- Weitere Exportquellen (Analyse-Befunde, Diagnose-Ergebnisse) hängen sich später als **eigene Schnitte** an dasselbe Muster: je Quelle eine Projektion im Composition Root auf `Exportable*`-/eigene Modelle, dieselben format-gerechten Serialisierer, derselbe Renderer-Port.

## Block 2: Analyse-Befunde (CSV / JSON / PDF)

Zweite Datenquelle der export-Domäne: die **aktuellen Analyse-Befunde**. Sie folgt exakt dem Block-1-Muster (eigene `Exportable*`-Typen + Projektion im Composition Root, format-gerechte Serialisierer, derselbe Renderer-Port) — mit drei bewussten Unterschieden, die sich aus der Natur der Quelle ergeben.

1. **Kein gespeicherter Stand → kein `analysis_id`, frischer Snapshot, async.** Anders als der Scan (mit gespeicherter `scan_id`) hat die Analyse **keinen** gespeicherten Stand: `GET /api/analysis` baut den Snapshot bei **jedem** Aufruf frisch aus traffic + process + jüngstem Scan (`_analyze_snapshot`). Der Analyse-Export nutzt **genau diesen Pfad** → er exportiert „die Analyse von jetzt", konsistent mit der Analyse-Ansicht. Daraus folgt:
   - **Kein `analysis_id`-Pfadparameter.** Die Route ist `GET /api/export/analysis?format=csv|json|pdf` (kein `/{id}`).
   - **Kein `NotFound`-Fall.** Die Analyse wird immer frisch erzeugt, sie kann nicht „fehlen" — es gibt kein `ScanNotFound`-Äquivalent (Auftrag: keinen künstlichen Fehlerfall erfinden). Schlägt der Snapshot-Bau selbst fehl, propagiert das sauber.
   - **`ExportAnalysis` ist async** (anders als der synchrone `ExportScan`): der `analysis_provider` ist ein `Callable[[], Awaitable[ExportableAnalysis]]`, das der Use-Case awaited; die Route `export_analysis` ist `async def`. Das Serialisieren/Rendern selbst bleibt synchron (reine Funktionen bzw. CPU-Rendern).

2. **`domain.export` bleibt analysis-frei (independence).** `domain.export` importiert **nicht** `domain.analysis`. Eigene schlanke `ExportableFinding` (`rule_id`/`severity`/`title`/`detail`/`subject`/`help_kind`/`help_url`) + `ExportableAnalysis` (`generated_at`/`findings`/`finding_count`). `severity` ist bewusst **`str`** (Werte `"info"`/`"notable"`), **kein** Import von `domain.analysis.Severity`. Die Projektion `ResolvedObservation → ExportableFinding` lebt im Composition Root (`_project_analysis_to_exportable`, Muster `_project_scan_to_exportable`) und reuse't `_analyze_snapshot` (keine zweite Snapshot-Projektion).

3. **`generated_at` als Feld — die Domäne fragt keine Uhr.** `generated_at` (ISO, **wann** der Export erzeugt wurde) kommt als **Feld** in `ExportableAnalysis` herein; der Composition Root füllt es über die **eine Zeitquelle** (`SystemClock`, UTC, `.isoformat()`) direkt bei der Projektion. Der Use-Case braucht darum **keine** eigene Uhr (symmetrisch zu `ExportScan`, der nur einen Provider kennt) — ADR 0002/0001 (keine Uhr im domain-/use-case-Kern).

4. **`PdfReportModel` generalisiert (Verbesserung des Block-1-Modells).** In Block 1 trug `PdfReportModel` fest die **scan-spezifischen** Kopf-Felder `scanned_at`/`cidr`/`host_count`, und der `ReportlabRenderer` rendert dafür **hartkodierte** Labels (`Scan-Zeitpunkt`/`Gescanntes Netz`/`Geräteanzahl`). Das war ein fälschlich scan-spezifisches Berichts-Modell. Block 2 nutzt **dasselbe** Modell mit einem anderen Kopf — darum trägt `PdfReportModel` jetzt **generische** `meta: tuple[tuple[str, str], ...]` (Label/Wert-Paare); der Renderer iteriert nur über sie (keine hartkodierten Labels mehr). `build_pdf_model` (Scan) liefert seinen Kopf semantisch identisch als Paare `[("Scan-Zeitpunkt", …), ("Gescanntes Netz", …), ("Geräteanzahl", …)]` — **Ausgabe unverändert**, nur generisch. `build_analysis_pdf_model` liefert `[("Erzeugt am", generated_at), ("Anzahl Befunde", finding_count)]`. **Eine bewusste Verbesserung** (kein zweites Modell, keine Renderer-Verzweigung); berührt `domain.export.PdfReportModel`, `infrastructure.export_pdf` und die betroffenen Block-1-Tests (prüfen jetzt `meta` statt der Einzelfelder).

5. **Format-gerechte Vollständigkeit (wie Block 1, befund-gerecht).**
   - **JSON = alles:** verlustfrei die komplette `ExportableAnalysis` (`generated_at`/`finding_count` + alle Befund-Felder inkl. `rule_id`/`help_kind`/`help_url`). `sort_keys`/`indent=2`/`ensure_ascii=False` — deterministisch.
   - **CSV = Tabelle:** eine Zeile pro Befund, **definierte Spalten-Reihenfolge** `severity,title,subject,detail,rule_id,help_kind,help_url` (severity zuerst — wonach man zuerst schaut — dann der lesbare Text, dann die technischen Schlüssel). **Keine** erzwungene Sortierung: die Befund-Reihenfolge bleibt die von `AnalyzeSnapshot` (bereits deterministisch sortiert). Escaping über das stdlib-`csv`-Modul.
   - **PDF = lesbarer Bericht:** Kopf (Titel „CERNIS PRO — Analyse-Bericht", `Erzeugt am`, `Anzahl Befunde`) + Tabelle **reduziert** auf `severity,title,subject,detail`. `rule_id`/`help_kind`/`help_url` sind **bewusst nicht** in der PDF-Tabelle (zu breit/technisch für einen lesbaren Bericht — sie bleiben verlustfrei in CSV/JSON). `detail` wird für die Zellenbreite über den reinen Helfer `_truncate` auf 120 Zeichen gekürzt (nur im PDF; CSV/JSON führen das volle `detail`).

6. **Dateiname mit Zeitstempel.** `filename = cernis-analysis-<YYYYMMDD-HHMMSS>.<ext>` (kompakt aus `generated_at`) — ein Zeitstempel ist hier nützlich, da es (anders als beim Scan) **keine** `analysis_id` gibt; mehrere Exporte bleiben unterscheidbar. `media_type` wie Block 1 (`text/csv` | `application/json` | `application/pdf`).

**Unverändert wiederverwendet (nicht dupliziert):** `ExportResult` (application), der `ReportRenderer`-Port + `ReportlabRenderer` (kein neuer Port nötig — dasselbe `PdfReportModel`), der `independence`-Contract (kein neuer import-linter-Contract — `domain.export` reiht sich weiter ein; `domain.export` importiert **nicht** `domain.analysis`, die Projektion sitzt am Composition Root).
