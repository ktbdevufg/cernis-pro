# ADR 0031 — Acknowledge: append-only Audit-Log, port-genaue Quittierung von Achse-B-Befunden

- **Status:** Akzeptiert
- **Datum:** 2026-06-17
- **Phase:** Grüne Wiese — Quer-Feature nach Stabilisierung des Bestands (Schnitt 8a, Backend). Erweitert die WS-getriebene Scan-Tabelle (`host_detail`-Frame) und den `analysis`-Router um das Quittieren, verdrahtet ausschließlich im Composition Root (`app.py` + `ws_scan.py`) plus ein neues `infrastructure`-Repo.
- **Bezug:** ADR 0029 (host_detail-`analysis_severity` — Achse B, Host-Maximum) + ADR 0030 (host_detail-`flagged_ports` — getroffene Ports je Stufe; beide Felder werden vom Acknowledge gefiltert; das kombinierte `_build_axis_b`-Callable + `_axis_b_safe`-Wrapper + Single-Source-Muster werden direkt erweitert); ADR 0013 (`analysis_host_history_db.py` — Vorbild für das injizierte SQLite-Repo, append-only/abgeleiteter Status statt zweitem Statusspeicher); ADR 0025/0027 (die portbasierten `host_remote_port`-Default-Regeln, deren Treffer quittierbar werden).

## Kontext

Seit ADR 0029/0030 trägt das `host_detail`-Frame zwei Achse-B-Felder: `analysis_severity` (Host-Maximum, die Pille) und `flagged_ports` (die schuldigen offenen Ports je Stufe, die Port-Böppel-Färbung). Beide sind ein **Urteil über den aktuellen Portstand** — sie bewerten bei jedem Scan neu.

Was fehlt (Konzept §6): der Nutzer kann einen Befund nicht **quittieren**. Ein bewusst betriebener Dienst (z. B. RDP auf einem Admin-Host, ein offener 3306 auf dem DB-Server) bleibt sonst bei jedem Scan rot/orange — das Signal nutzt sich ab. Quittieren soll die Bewertung dauerhaft wegnehmen, ohne den Port zu verstecken.

**Produktentscheidungen (Karl, fest):**

- **Granularität pro (MAC, Port).** Port 3306 quittiert betrifft NUR 3306; ein neuer auffälliger Port (z. B. 6379) am selben Host löst weiter aus.
- **Rücknehmbar.** Ein Un-Acknowledge stellt den Befund wieder scharf. **Kein Löschen** — append-only Log (jeder ack/unack ist eine neue Zeile, die History bleibt vollständig).
- **Wirkt NUR auf die Bewertung.** Ein quittierter Port bleibt offen und wird im Frame-Feld `ports` weiter geführt — er trägt nur nicht mehr zu `analysis_severity`/`flagged_ports` bei.

## Entscheidung

1. **APPEND-ONLY LOG, STATUS ALS ABLEITUNG.** Neue Tabelle `analysis_acknowledgements` (`id INTEGER PK AUTOINCREMENT, mac TEXT, port INTEGER, severity TEXT, action TEXT CHECK(action IN ('ack','unack')), created_at TEXT DEFAULT datetime('now')`). `record(mac, port, severity, action)` schreibt **immer eine neue Zeile** — nie Update/Delete. Der effektive Status eines `(mac, port)` ist eine **reine Ableitung**: quittiert ist genau der Port, dessen **jüngster** Eintrag (`max(id)` je `(mac, port)`) `action == 'ack'` ist; ein späteres `unack` hebt das auf. **Eine Wahrheit, kein zweiter Statusspeicher** (gleiche Linie wie `analysis_host_history_db.py`, ADR 0013).

2. **NEUES REPO `SqliteAcknowledgementRepository`** (`infrastructure/analysis_acknowledgements_db.py`), Vorbild **exakt** `analysis_host_history_db.py`: injizierter `db_path`, `_ensure_schema` im `__init__`, `@contextmanager _connect` mit Transaktion + garantiertem `close`, `CREATE TABLE IF NOT EXISTS`, kein `modules`-Import. Lese-Pfad `acknowledged_ports(mac) -> set[int]` (effizient per `max(id)`-Subquery, nicht die ganze History in Python); leere MAC → leere Menge. **Kein Audit-Listing** in 8a (YAGNI).

3. **FILTER REDUZIERT NUR DEN BEWERTETEN PORTSTAND — NICHT DIE GENERISCHE PROJEKTION.** `_observed_host` bleibt unverändert (die eine, generische „offen"-Projektion). Stattdessen bekommen `_severity_for_host` und `_flagged_ports_for_host` einen zusätzlichen Parameter `acked: frozenset[int]` (Default leer → Bestandsaufrufer unverändert) und ziehen `acked` vom bewerteten Portstand ab, **bevor** Severity/flagged_ports gebildet werden:
   - `_flagged_ports_for_host`: `open_ports = {... state=="open"} - acked`.
   - `_severity_for_host`: der projizierte `ObservedHost.open_ports` wird per `dataclasses.replace` um `acked` reduziert, dann läuft die Engine.

   Beide ziehen `acked` vom **selben** „offen"-Stand ab — die Konsistenz-Invariante (0030) hält auf dem reduzierten Stand weiter.

4. **SINGLE SOURCE: `acked` ALS PARAMETER DURCHGEREICHT, EINMAL JE HOST GEHOLT.** Die WS-Verdrahtung `_build_axis_b` schließt zusätzlich das `acknowledged_ports`-Callable des neuen Repos ein (späte Namensauflösung wie `host_history_repository`). Das kombinierte Callable holt `acked = acknowledged_ports(host.mac)` **einmal** je Host und nutzt es doppelt: (a) Severity + flagged_ports auf dem reduzierten Stand bilden, (b) als sortierte Liste zurückreichen. Die acked-Logik lebt **komplett in der Closure** — geringste Kopplung; `ws_scan` braucht keine zweite Factory.

5. **DRITTES FRAME-FELD `acknowledged_ports`.** Das Callable liefert ein **Tripel** `(severity, flagged, acked_list)`. `_axis_b_safe` wird entsprechend zu `(str | None, dict, list[int])` erweitert (ein `try/except` deckt alle drei ab; Fehler → `(None, leere Form, [])`). `_host_detail_frame` setzt `acknowledged_ports: []` zu den Default-Keys (jetzt **28 Keys** statt 27). Das Feld macht dem Panel (8b) sichtbar, welche Ports quittiert sind (zum Wieder-Scharfstellen).

6. **NEUER ENDPUNKT `POST /api/analysis/acknowledge`.** Body `{mac, port (1–65535), severity ("critical"|"notable"), action ("ack"|"unack")}` — `port` per `Field`-Constraint, `severity`/`action` als `Literal` (Müll → 422, kein stiller Fallback, S3). Der api-Ring bleibt repo-frei: ein Composition-Root-Runner (`_acknowledge`, per `Depends`/Override) reicht `record(...)` durch (Muster `_delete_user_rule`). Erfolg → 200 `{"ok": true}`. **Kein GET/Listing** in 8a (YAGNI).

## Konsequenzen

- Das `host_detail`-Frame trägt **+1 Feld** (`acknowledged_ports`, 27 → 28 Keys). Quittierte Ports bleiben in `ports` offen geführt, fallen aber aus `analysis_severity`/`flagged_ports` heraus.
- **Neue Tabelle als History-Keim.** Das append-only Log hält die vollständige ack/unack-History; eine Auswertung (Audit-Listing) ist bewusst kein Thema für 2.0.
- **Neuer Endpunkt** + neuer Composition-Root-Runner + neue lru_cache-Repo-Factory (`acknowledgement_repository`, teilt die `cernis.db`).
- `_build_axis_b`-Callable wird von Paar auf **Tripel** erweitert; `_axis_b_safe` + alle Aufrufer (Tests) angepasst. Die Signatur `(host, known)` bleibt — `acked` wird innen geholt.
- `SqliteAcknowledgementRepository` und die `acked`-Reduktion in `_severity_for_host`/`_flagged_ports_for_host` sind direkt unit-testbar (freie Funktionen / tmp_path-DB).

## Nicht Teil dieser Entscheidung

- **Kein Frontend** — die Detail-Panel-Buttons (quittieren/zurücknehmen) sind Schnitt 8b.
- **Kein Löschen von Audit-Zeilen** — append-only; der effektive Status ist immer der jüngste Eintrag.
- **Quittierte Ports werden NICHT aus dem `ports`-Frame-Feld entfernt** — nur aus der Bewertung. Die Single-Source-„offen"-Projektion (`_observed_host`) bleibt generisch.
- **Kein Audit-Listing / GET-Endpunkt** (YAGNI; 8a braucht nur `acknowledged_ports` + `record`).
- **Granularität ist port-genau, nicht host-genau** — kein „ganzen Host quittieren".
