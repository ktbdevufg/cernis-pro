# ADR 0019 — host_detail-Frame: Baseline-Anreicherung im Composition Root

- **Status:** Akzeptiert
- **Datum:** 2026-06-15
- **Phase:** Grüne Wiese — Quer-Feature nach Stabilisierung des Bestands. Naht zwischen `scanning` (Event-Strom), `devices` (kuratierte Stammdaten) und `analysis`-Historie (Gedächtnis), verdrahtet ausschließlich im Composition Root (`ws_scan.py` / `app.py`).
- **Bezug:** ADR 0013 (analysis-Historie — `record_seen`/`is_known`, Baseline `new_host_seen`, MAC-Identität, Leere-MAC-Linie); S.7d (devices-Projektion im WS-Handler, best-effort); ADR 0006 (devices↔scanning-Schichtung).

## Kontext

Das `host_detail`-Frame entstand bisher als **reine Projektion des frischen Scans** (`EnrichedHost` -> Frame). Zwei Probleme folgten daraus:

1. **Kuratierte Felder gehen verloren.** `label`/`tags`/`notes` pflegt der Nutzer in der devices-DB (`UpdateDeviceMeta`). Der frische Scan trägt sie leer — das Frame zeigte folglich leere kuratierte Felder, obwohl in der DB Notizen stehen. Geräte­notizen überlebten keinen neuen Scan in der Live-Anzeige.

2. **`is_known` war kein verlässliches Faktum.** Das „neu/bekannt"-Gedächtnis lebt in der Host-Historie (`SqliteHostHistoryRepository`, ADR 0013), aber das `host_detail`-Frame trug es nicht. „Neu im Netz" war nur über den separaten `GET /api/analysis`-Pfad sichtbar, nicht direkt am Scan-Frame.

Beide Datenquellen existieren bereits und sind im Composition Root schon verdrahtet: `GetDevice` (kuratiert) und `record_seen`/`is_known` der Host-Historie (Gedächtnis). Es fehlte allein die **Anreicherung** des Frames aus diesen Quellen.

## Entscheidung

1. **ANREICHERUNG AUSSCHLIESSLICH IM COMPOSITION ROOT.** Die Naht liegt in `ws_scan.py` (Loop) + `app.py` (Verdrahtung) — **nicht** in `application/scanning`. `scanning` bleibt eine reine Funktion `ScanConfig -> Event-Strom` und importiert weiterhin **weder** `devices` **noch** `analysis`. Begründung wie bei der devices-Projektion (S.7d): der Composition Root darf alle Domänen, hier kommen `scanning` + `devices` + `analysis`-Historie ohnehin zusammen, und die Schreib-Pfade (`record_host`/`record_seen`) sitzen bereits hier. Die Lese-Pfade dazuzustellen ist die natürliche Erweiterung derselben Naht, ohne eine `scanning -> devices`/`scanning -> analysis`-Kopplung einzuführen.

2. **TIMING — `is_known` VOR `record_seen` lesen.** Pro `HostEnriched`-Event ist die Reihenfolge zwingend:
   1. `baseline_known = is_known(mac)` — der **Vorzustand** der Historie, **VOR** dem Schreiben.
   2. `record_host(...)` (devices-DB) und `record_seen(...)` (Historie) — wie bisher.
   3. Frame bauen, mit `baseline_known` und den kuratierten Feldern anreichern, senden.

   Würde `is_known` **nach** `record_seen` gelesen, wäre jeder Host sofort „bekannt" (er wurde ja gerade eingetragen). Das Lesen des Vorzustands ist der Kern: ein Host, der im selben Scan erstmals gesehen wird, ist im Frame `is_known=false`.

3. **`is_known`-DEFAULT im Frame-Schema = True.** `_host_detail_frame` setzt `is_known: True` als Default („bekannt, sofern nicht anders angereichert"). Der Loop überschreibt ihn mit `baseline_known`. So ist `is_known` **immer** im Frame vorhanden (definiertes Schema), auch wenn die Anreicherung mal übersprungen wird. `_host_detail_frame` selbst macht **keinen** Historie-Zugriff — es bleibt eine reine Projektion ohne I/O; das Gedächtnis braucht der Loop.

4. **KURATIERTE FELDER: die devices-DB ist die Wahrheit.** Liegt ein gespeichertes Gerät vor, **überschreiben** dessen `label`/`tags`/`notes` die leeren Scan-Defaults im Frame. Quelle ist `GetDevice` (liefert `DeviceWithHistory`, kuratierte Felder auf `.device`). Kein gespeichertes Gerät (`DeviceNotFoundError`) -> die Scan-Defaults bleiben.

5. **MAC-LOSE / NICHT ERMITTELBARE HOSTS GELTEN ALS BEKANNT.** Leere MAC -> `is_known` True (kein Rauschen, gewollt — konsistent mit ADR 0013 und der devices-Projektion) und keine Kuratierung. Ein Host ohne stabile Identität ist nie „neu".

6. **BEST-EFFORT, KEIN SCAN-ABBRUCH.** Beide Lese-Pfade sind reine Lesevorgänge und gegen Fehler abgesichert (gleiche Linie wie die Schreib-Nähte):
   - `_is_known_safe`: Callable wirft -> Warn-Log (`host_is_known_failed`) + `True` (im Zweifel „bekannt", lieber kein falsches „neu").
   - `_lese_kuratierung`: `DeviceNotFoundError` -> `None` (keine Kuratierung, kein Fehler). Jeder andere Fehler -> Warn-Log (`host_get_device_failed`) + `None`.

   Mit Warn-Log ist es **kein** stiller S3-Fallback. Ein DB-Problem killt die Scan-Anzeige nicht.

7. **NUR `host_detail` wird angereichert.** `host_found`-Frames bleiben unverändert — sie haben keine kuratierten Felder und kein verlässliches `is_known`; erst `host_detail` trägt die Baseline. Der Frontend-Mapper liest `is_known` ausschließlich aus `host_detail`.

## Konsequenzen

**Positiv**
- **Notizen überleben einen Scan in der Live-Anzeige:** das Frame zeigt die gepflegten `label`/`tags`/`notes` aus der DB, nicht die leeren Scan-Defaults.
- **„neu/bekannt" am Scan-Frame:** `is_known` ist ein echtes Faktum aus dem Historie-Vorzustand, direkt am `host_detail` — ohne separaten `/api/analysis`-Abruf.
- **Schichtung bleibt sauber:** `scanning` kennt weiterhin weder `devices` noch `analysis`; die Naht sitzt dort, wo die Schreib-Pfade schon sitzen (Composition Root).
- **Best-effort-Symmetrie:** die Lese-Nähte sind genau so abgesichert wie die Schreib-Nähte — Fehler bleiben sichtbar (Log), brechen aber nichts ab.
- **Definiertes Frame-Schema:** `is_known` ist immer vorhanden (Default True), auch ohne Anreicherung.

**Offen / später**
- **`is_known` auch an `host_found`** (heute bewusst nicht — kein verlässlicher Vorzustand zum frühen Zeitpunkt).
- **`category` ebenfalls aus der devices-DB anreichern** (heute trägt das Frame die Scan-`category`; kuratierte Kategorie wäre derselbe Mechanismus, ist aber ein eigener Schnitt).
- **Bulk-Lesen** statt N einzelner `is_known`/`get_device`-Aufrufe (Muster `known_macs`), falls die Per-Host-Reads sich als Engpass zeigen.
