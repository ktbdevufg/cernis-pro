# CERNIS PRO — Pre-Release Planung 2026-05

**Stand:** 2026-05-27
**Projekt:** CERNIS PRO (LAN-Scanner Desktop-App)
**Repository:** `ktbdevufg/cernis-pro` (Branch `dev`)
**Arbeitsumgebung:** Ubuntu x64 VM `ubultsvm`, `/home/kbach/Dokumente/Github-Repos/Cernis-Pro`
**Status v1.0.0:** Auf 5 Plattformen gebaut (Win ARM64, Win x64, macOS ARM64, Linux deb/AppImage, Fedora RPM)
**Ziel:** Vollständiger Backend-Rewrite zu v2.0.0 mit Hexagonal-Architektur, Tests, Doku und Security-Audit
**Begleitdokument:** `vision_features_202605.md` (Produktvision, Qualitätsanspruch, neue Features, Technologie-Entscheidung). Dieses Dokument hier ist der **Plan/Prozess**, das Begleitdokument die **Vision/Features**. Beide gehören ins Projekt-Wissen.

---

## 1. Anlass für den Rewrite

Externer Review eines Principal Master Entwicklers hat gravierende Mängel in zwei Dimensionen aufgezeigt:

1. **Code-Qualität und Architektur** — schwer wartbar, Regelverstöße, Agent-feindlich
2. **Sicherheit** — kritische Lücken in Auth, CORS, Secret-Handling, Plattform-Code

Die Entscheidung lautet: **kein Patchen, sondern strukturierter Rewrite des Backends.** Frontend und Tauri-Shell bleiben in Phase 1–4 weitgehend unangetastet.

Übergeordneter Anspruch (siehe `vision_features_202605.md`, Abschnitt 0): CERNIS PRO soll nicht nur funktionieren, sondern ein **Best-Effort-Best-Practice-Vorzeigeprojekt** werden — Code-Qualität, Architektur und Doku auf einem Niveau, vor dem erfahrene Principals den Hut ziehen.

---

## 2. Findings aus dem externen Review

### 2.1 Architektur- und Qualitätsmängel (Principal Developer)

| # | Finding | Befund |
|---|---|---|
| A1 | Monolithische `main.py` | 2009 Zeilen — würde einem menschlichen Entwickler "um die Ohren gehauen" |
| A2 | SQLite-Zugriffe verstreut | Mehrere Module greifen direkt auf SQLite zu, kein zentrales Persistence-Layer |
| A3 | State über Modulebenen verteilt | Modul-globaler State, unklare Lebenszyklen, schwer testbar |
| A4 | Keinerlei Test-Code | Kein einziger Unit-, Integration-, Smoke- oder E2E-Test |
| A5 | Mac-App startet nicht | Vermutung: nicht für Apple Silicon kompiliert oder Quarantine-Issue |
| A6 | Agent-feindlich | Bei wachsendem Code verhaspeln sich Coding-Agents im überfüllten Kontextfenster → Spaghetti-Code, Bugs |

### 2.2 Sicherheitsmängel (Security-Review, Teil 1)

| # | Severity | Bereich | Befund |
|---|---|---|---|
| S1 | **Critical** | API/Auth | `CORSMiddleware allow_origins=["*"]` global, **keine Auth** auf sensiblen Endpunkten (Pip-Install, Capture, Agent-Mgmt, Settings, WebSockets). Jede Webseite kann das Backend ansprechen |
| S2 | **High** | macOS-Notifications | AppleScript-Injection via `osascript` über Alert-Namen / Monitor-Labels (`alerting.py:143`, `monitor.py:185`, `main.py:1044`, `main.py:385`) |
| S3 | **High** | Settings/Secrets | `GET /api/settings` liefert Klartext-Secrets (Shodan API Key); Crypto-Helper fällt still auf Base64 oder Plaintext zurück (`crypto.py:41`, `:65`) |
| S4 | Medium | Remote-Agent | Default `0.0.0.0` + Shared-Secret `changeme` + permissives CORS (`agent.py:258–261`, `:187`) |
| S5 | Medium | Pcap-Anleitung | Empfiehlt `/dev/bpf*` world-accessible (macOS) und `cap_net_raw` auf gesamte Backend-Binary (Linux) — schwächt Host-Sicherheit |
| S6 | **High** | Frontend/Static | Path-Traversal im SPA-Catch-all: `main.py:1991–1999` baut den Dateipfad aus user-kontrolliertem `full_path` zusammen (`os.path.join(_FRONTEND_DIR, full_path)` + `isfile` + `FileResponse`) ohne Containment-Prüfung. Mit (URL-kodiertem) `../` ausbruchbar; in Kombination mit S1 (Wildcard-CORS, keine Auth) von jeder Webseite/`curl` exfiltrierbar → effektiv **High**. Im Rewrite (P2.1c) gefunden. **In v2 gelöst** (app.py: `StaticFiles`, kein manuelles Pfad-Join — ADR 0005); im sterbenden `main.py` bewusst **nicht** gepatcht (stirbt mit Einstiegspunkt-Wechsel P2.3) |

> **Hinweis:** S1–S5 stammen aus dem externen Security-Review (Teil 1); S6 wurde im Rewrite (P2.1c) gefunden. Weitere Findings (Teile 2+) werden im Audit der Phase 4 systematisch erhoben.

Die vollständige Adressierung jedes Findings (was die neue Architektur konkret dagegen tut) ist in `vision_features_202605.md`, Abschnitt 1, tabellarisch dokumentiert.

---

## 3. Festgehaltene Entscheidungen

- **Architektur:** Pragmatische Hexagonal-Architektur (Ports & Adapters), drei Ringe statt fünf — nach Empfehlung des Principal. `main.py`/`app.py` nur Bootstrap; Router kennen nur Use-Cases; Use-Cases kennen Interfaces (Ports); Infrastruktur implementiert diese Interfaces.
- **Architekturregeln maschinell erzwungen:** `import-linter`.
- **Python-Standards:** PEP 8, Type-Hints durchgängig, `ruff` + `mypy`, `pytest`, Pydantic für Modelle, `pydantic-settings`, `structlog`.
- **Tests (Variante C → für v2 verschärft):** Characterization Tests vor jeder Feature-Migration; kritische Pfade mit Tests, UI-nahe Pfade manuell. **Neu für v2:** keine Änderung ohne grünen Test-Lauf in CI.
- **Scope während Rewrite:** Linux x64 first; andere Plattformen via Ports gestubbt; plattformübergreifend geplant, aber nur auf Ubuntu getestet während Migration.
- **API-Verträge:** dürfen brechen (mit Frontend-Anpassung).
- **Versionierung:** `v1.0.0-final` taggen, dann Branch `rewrite/v2` von `dev`.
- **DB:** leere DB beim ersten Start akzeptabel.
- **Agent-Disziplin:** pro Session ein Use-Case; Architektur erzwingt kleine Module.
- **Technologie (siehe `vision_features_202605.md`, Abschnitt 5):** bestehender Stack (Tauri v2 + React/Vite + Python) wird weiterentwickelt; systemnahe Adapter so gekapselt, dass ein späterer Sprachwechsel ein lokaler, ungefährlicher Eingriff bleibt. Entscheidung getroffen (Claude als Entwickler), nicht offen.

---

## 4. Zielarchitektur

```
backend/
  api/              # FastAPI-Router. Kennt nur application/. KEIN infrastructure/.
  application/      # Use-Cases. Kennt domain/ und ports/. NICHT infrastructure/.
  domain/           # Reine Domänenmodelle/-logik. Nur domain/ + stdlib.
  ports/            # Interfaces (Verträge), die application/ nutzt.
  infrastructure/   # Implementiert ports/. Kennt domain/-Modelle.
  app.py            # Composition Root: verdrahtet ports/ <-> infrastructure/, Middleware, DI.
```

**Importregeln (per `import-linter` erzwungen):**
1. `domain/` darf nur `domain/` und Standard-Library importieren
2. `application/` darf `domain/` und `ports/` importieren, **nicht** `infrastructure/`
3. `infrastructure/` implementiert `ports/`-Interfaces, kennt `domain/`-Modelle
4. `api/` ruft nur `application/`, kennt **kein** `infrastructure/`
5. Verdrahtung zwischen `ports/` und `infrastructure/` passiert **ausschließlich** in `app.py`

**Geplante Domänen (inkl. neuer Features aus dem Brainstorming):**
`scanning`, `devices`, `monitoring`, `alerting`, `security`, `capture`, `agent`, `settings` (Bestand) + `traffic`, `process`, `analysis` (neu — siehe `vision_features_202605.md`, Abschnitt 6).

---

## 5. Phasenplan

### Phase 0 — Ist-Analyse (offen, wartet auf `data/`-Freigabe)
**Ziel:** Vollständiges Bild des aktuellen Backend-Codes als Grundlage für die Migration.
**Deliverables:** Modul-Inventar (Datei: Zeilen, Zweck, Abhängigkeiten); Domänen-Karte (inkl. neuer Domänen `traffic`/`process`/`analysis`); SQLite-Zugriffspunkte (alle Stellen/Tabellen); State-Karte (Globals, Singletons, Caches); API-Inventar (alle Endpunkte mit Auth-Status, alle WebSockets); Risiko-Bewertung pro Domäne; Migrations-Reihenfolge mit Begründung.
**Inputs vorhanden:** `backend/` (~700 KB echter Code in `main.py` + `modules/`).
**Inputs ausstehend:** Schema der `data/`-SQLite-DB (auf Freigabe wartend); `frontend/` + `src-tauri/` (später bei Bedarf).

### Phase 1 — Skelett (abgeschlossen)
**Ziel:** Neue Architektur steht, ein Use-Case durchgezogen, CI grün.
**Deliverables:** Verzeichnisstruktur (Abschnitt 4); `app.py` mit DI-Container + Middleware; Pre-commit (Ruff, mypy, pytest); `import-linter`-Regeln aktiv; GitHub Actions (Linter + Tests + Build); ein vollständig migriertes Referenz-Feature: **`settings`** (klein, gut isolierbar); `pyproject.toml` als alleinige Config; `requirements.txt` → Lock-Datei (uv oder pip-tools).

**Status:** Abgeschlossen. Die `settings`-Domäne ist vollständig durch alle Ringe migriert (`domain` → `ports` → `infrastructure` → `application` → `api`, verdrahtet in `app.py`, per TestClient end-to-end grün) und dient als **Referenz-Implementierung des Strangler-Musters** für alle weiteren Domänen-Migrationen.

**Tatsächlich gefahrene Sub-Schritte** (Granularität von Schritt 6 — bislang nur in Chat/Memory festgehalten, hier dauerhaft dokumentiert):
- **6a** — ADR-Setup (0001 Secret-Handling, 0002 domain framework-frei)
- **6b** — Domain: `settings` als reine dataclasses + Redaction-Policy
- **6c** — Ports: `SettingsRepository` + `SecretStore` als `typing.Protocol`
- **6d.1** — Infrastructure: `SqliteSettingsRepository` (SQLite-Adapter)
- **6d.2** — Infrastructure: `KeyringSecretStore` (OS-Keystore via `keyring`/libsecret)
- **6e** — Application: Use-Cases `GetSettings` / `UpdateSetting` / `UpdateSecret`
- **6f** — API-Router + Verdrahtung in `app.py` (Composition Root)

### Phase 2 — Strangler-Fig-Migration
**Vorgehen pro Feature:** (1) Characterization-Tests gegen aktuelles Verhalten; (2) Tests gegen alten Code grün; (3) Feature in neue Struktur migrieren (Use-Case + Ports + Adapter); (4) Tests gegen neuen Code grün; (5) alter Code gelöscht; (6) Commit, CI grün, weiter.

**Strategie (siehe ADR 0004):** Phase 2 migriert **Domäne für Domäne** (settings ✓ → `devices` → `scanning` → `monitoring` → `alerting` → `capture` → `agent` → Hilfsmodule), jeweils im bei `settings` etablierten Muster (Characterization → `domain` → `ports` → `infrastructure` → `application` → `api` → Verdrahtung in `app.py`). Mit **jeder** migrierten Domäne **schrumpft der Altcode** in `main.py`.

**Einstiegspunkt-Wechsel `main.py` → `app.py` kommt ans ENDE von Phase 2** (wenn genug/alle Domänen migriert sind), **nicht** an den Anfang. Dann ist er ein kleiner Schritt (Spec/Tauri auf einen `app:app`-Runner umstellen, `CERNIS_BOOTSTRAP_ON_STARTUP=true`), kein Monolith-Mount.

**Ausdrücklich verworfen — Monolith-Mount (früher als „Weg 1"/„P2.2" erwogen):** `main.py` als **einen** `APIRouter` nach `app.py` zu mounten, um `app.py` früh produktiv zu machen. Begründung der Ablehnung: zieht den gesamten Altcode-Blob inkl. `modules/` in den Composition Root, hält den Monolithen am Stück am Leben (statt ihn pro Domäne zu verkleinern) und birgt konkrete Risiken (Wiedereinführung des S6-Traversal-Catch-alls, Settings-Routen-Kollision mit dem v2-Router). Das widerspricht dem Strangler-Prinzip und dem Vorzeige-Anspruch.

**Klarstellung zu P2.1 (erledigt, bleibt gültig):** Die in P2.1 gebaute Vorbereitung — `app.py` als Lifespan-Owner (`bootstrap_on_startup`-Flag, Commit `a7a3063`) und als traversal-sicherer Frontend-Serving-Owner (Commit `e6211e1`, ADR 0005) — war **richtig** und nötig: sie ist die Voraussetzung dafür, dass `app.py` beim späteren Einstiegspunkt-Wechsel übernehmen kann. Nur die ursprüngliche Schlussfolgerung „also jetzt umschalten" war falsch und ist hiermit korrigiert.

**Nächster konkreter Schritt:** Migration der Domäne `devices` (scanning folgt als zweite — siehe ADR 0006).

**Reihenfolge (vorläufig, in Phase 0 finalisiert):** `settings` (in Phase 1) → `devices` → `scanning` → `monitoring` → `alerting` → `security` → `capture` → `agent` → Hilfsmodule (resolver, fritzbox, mdns, ssdp, snmp, …) (devices vor scanning, weil scanning in die devices-Domäne schreibt — `update_device_from_scan` — und liest — `get_known_devices`; Migration in Abhängigkeitsrichtung vermeidet eine Wegwerf-Übergangskopplung auf devices-Altcode, siehe ADR 0006). Neue Domänen (`traffic`, `process`, `analysis`) werden nach Stabilisierung des Bestands eingeplant.

### Phase 3 — Doku-Finalisierung
**Deliverables:** `README.md`; `docs/ARCHITECTURE.md`; `docs/CODING_STANDARDS.md`; `docs/CONTRIBUTING.md`; `docs/adr/` (ein ADR pro größerer Entscheidung); OpenAPI via FastAPI; Setup-Guide; Build-Guide pro Plattform (Stand v1.0.0 mitnehmen). **Hinweis:** Doku entsteht parallel mit jedem Modul, nicht erst hier — Phase 3 ist Finalisierung, nicht Beginn.

### Phase 4 — Security-Audit
**Deliverables:** Audit-Bericht (alle Findings mit Severity, Reproduktion, Empfehlung); Masterplan (Reihenfolge, Aufwand, Abhängigkeiten); Status der bekannten Findings S1–S6 (gelöst/offen/verschoben); Threat-Model; Defense-in-Depth (Logging, Rate-Limiting, Input-Validation). **Anschließend:** Fixes nach Masterplan mit Test-Abdeckung. Audit läuft gegen **stabilen** Code, nicht gegen ein bewegliches Ziel. Zusätzlicher Audit-Punkt: Privacy der `analysis`-Links (siehe `vision_features_202605.md`, 4.4).

### Phase 5 — Frontend-Refactoring (optional, später)
**Trigger:** wenn Backend-Rewrite stabil ist und Frontend-Pflege spürbar wehtut. Knüpft an das UI-Designprinzip an (`vision_features_202605.md`, Abschnitt 3).

---

## 6. Offene Punkte / nächste Schritte

### 6.1 Auf Freigabe wartend
- [ ] Darf das `data/`-Verzeichnis (SQLite-DBs) für Schema-Analyse herangezogen werden? (Nur Schema, keine Inhalte.) Betrifft jetzt auch die Speicherung von Traffic-Historie.

### 6.2 Direkt anstehend (nach Freigabe)
- [ ] Phase 0 starten: vollständige Ist-Analyse des Backends
- [ ] Lieferung der Ist-Analyse als strukturiertes Dokument
- [ ] Diskussion der Migrations-Reihenfolge (inkl. Einordnung der neuen Domänen)

### 6.3 Vor Phase 1
- [ ] `v1.0.0-final` taggen auf `main` und `dev`
- [ ] Branch `rewrite/v2` von `dev` abzweigen
- [ ] `pre_release_202605.md` und `vision_features_202605.md` ins Repo unter `docs/` einchecken

### 6.4 Beobachtungen aus Stichprobe (Bestand)
- `main.py` = 2009 Zeilen (bestätigt Finding A1)
- `cernis_cli.py` und `main.py` haben Permissions `-rw-------` statt `0644` — im Rewrite korrigieren, in Coding-Standards festschreiben
- Für künftige Upload-Archive: `tar`-Excludes mit `./pfad`-Notation (sonst landen `build/`/`dist/` im Archiv)
- `frontend/` und `src-tauri/` fehlen bewusst, werden später nachgeladen

---

## 7. Working Rules

Die Regeln gelten je nach Werkzeug unterschiedlich. Diese Aufteilung ist verbindlich —
fruehere Fassungen fuehrten die Regeln pauschal als "fuer die gesamte Arbeit" und verleiteten
dazu, Chat-spezifische Mechanik (vim, Datei-Downloads) faelschlich auf Claude Code anzuwenden.

### 7.1 Gelten nur fuer Claude Chat (Planung/Analyse)
Begruendung: Claude Chat hat keinen direkten Dateizugriff auf die Maschine; er liefert fertige
Artefakte zum Selbst-Einsetzen.
- Editor: vim
- Vollstaendige Dateien als Download bereitstellen — keine manuellen Zeilen-Edits anweisen
- Snapshots als Download, wenn das Kontextlimit erreicht wird

### 7.2 Gelten ueberall (Chat und Claude Code)
- Sprache: Deutsch
- Vollstaendige absolute Pfade in allen Befehlen
- Shell-Typ und Rechtelevel bei jedem Befehl angeben (z. B. *bash (User)*, *bash (root)*, *PowerShell (Admin)*)
- Aenderungen einzeln, in definierter Reihenfolge — kein Trial-and-Error
- Situation vollstaendig verstehen, bevor Aenderungen vorgenommen werden
- Keine Aenderung ohne gruenen Test-Lauf in CI (neu fuer v2)
- Vollstaendige lokale Gate-Kette vor jedem Commit fahren: ruff format --check, ruff check, lint-imports, mypy (ohne Pfad-Argument), pytest
- Push erst nach Karls Abnahme jedes Sub-Schritts, dann sofort
- Veroeffentlichte Commits nicht per amend/force umschreiben — separater Fix-Commit

### 7.3 Gelten fuer Claude Code (Ausfuehrung)
Begruendung: Claude Code editiert direkt im Repo, zeigt Diffs, Karl nimmt ab.
- Claude Chat liefert eine Spezifikation (was, welche Signaturen, welche Architektur-
  Entscheidung dahinter) — keine Editor-Mechanik wie "mit vim anlegen"
- Claude Code schreibt die Datei selbst und zeigt das Diff
- Nach jedem Sub-Schritt: STOP mit Commit-Hash, geaenderten Dateien und Gate-Ergebnissen,
  warten auf Karls Abnahme

### 7.4 Strikte Werkzeug-Trennung
- Planung/Analyse -> Claude Chat. Ausfuehrung -> Claude Code. Strikt getrennt.
- Beide sind getrennte Instanzen ohne automatischen Austausch. Claude Code kennt nur, was in
  CLAUDE.md steht oder ihm direkt gesagt wird. Nach einer CC-Session bringt Karl den Stand
  (git log/diff) zurueck in den Chat.

---

## 8. Risiken und Annahmen

### Annahmen
- API-Verträge dürfen brechen (mit Frontend-Anpassung)
- Leere DB beim ersten Start ist akzeptabel
- Plattform-Fokus während Rewrite: ausschließlich Linux x64
- Kein Termindruck — Qualität vor Geschwindigkeit

### Risiken
| Risiko | Wahrscheinlichkeit | Auswirkung | Gegenmaßnahme |
|---|---|---|---|
| Charakterisierungs-Tests übersehen Verhalten | mittel | mittel | Manuelle Verifikation pro Feature ergänzen |
| Migration eines Features zieht versteckte Abhängigkeiten | hoch | mittel | In Phase 0 Abhängigkeiten kartieren; Reihenfolge danach wählen |
| `data/`-DB-Schema unzureichend dokumentiert | mittel | gering | Schema in Phase 0 extrahieren; danach neu definieren |
| Coding-Agent verliert Kontext bei großen Refactorings | hoch | mittel | Architektur erzwingt kleine Module; pro Session ein Use-Case |
| macOS-Startproblem (A5) ist Code-Ursache, nicht Build | mittel | mittel | In Phase 0 Build-Logs prüfen; ggf. in Phase 2 als Feature |
| Spätere Sprachwahl systemnaher Adapter | gering | gering | Hinter Port gekapselt → lokaler Eingriff, kein Neubau (siehe Vision-Doc 5.2) |

---

## 9. Stakeholder & Rollen

- **Karl Bach** — Owner; entscheidet **was** das Produkt können soll und für wen (Produktvision, Features, UX). Kein Entwickler — Technologie-Entscheidungen sind an Claude delegiert.
- **Principal Master Developer** (extern) — Review-Quelle, Architektur-Empfehlung
- **Claude (chat)** — Planung, Analyse, Dokumentation, Code-Review, Snapshots; entscheidet **womit** gebaut wird (technische Verantwortung)
- **Claude Code** — Ausführende Code-Änderungen in Sessions; folgt diesem Plan und den Working Rules

---

**Dokument-Status:** lebend. Wird nach Phase 0 mit der Ist-Analyse erweitert und nach jeder Phase aktualisiert.
