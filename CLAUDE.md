# CLAUDE.md — Arbeitsanweisungen für Claude Code

**Projekt:** CERNIS PRO 2.0 — Backend-Rewrite
**Repo:** `ktbdevufg/cernis-pro`
**Diese Datei wird von Claude Code beim Start automatisch gelesen. Sie ist verbindlich.**

---

## Wer entscheidet was

- **Karl Bach** ist Owner, **kein Entwickler**. Er entscheidet *was* das Produkt können soll und für wen (Produktvision, Features, UX).
- **Technische Entscheidungen** (Sprache, Tooling, Architektur-Details) sind an Claude delegiert. Karl nicht mit Technologie-Grundsatzfragen behelligen.
- **Planung/Analyse** passiert in Claude Chat, **Ausführung** in Claude Code — strikt getrennt. Claude Code führt diesen Plan aus, erfindet ihn nicht neu.

---

## Verbindliche Projektdokumente (im Repo unter `docs/`)

Vor jeder Session lesen — sie sind die Quelle der Wahrheit:

1. `docs/pre_release_202605.md` — Plan/Prozess: Findings, Zielarchitektur, 5-Phasen-Plan, Importregeln.
2. `docs/vision_features_202605.md` — Vision/Features: Produkt-These, neue Domänen, Technologie-Entscheidung, Adressierung aller Findings.
3. `docs/phase0_ist_analyse.md` — Ist-Zustand des Backends: Modul-Inventar, Domänen-Karte, 15 Tabellen, Migrations-Reihenfolge.
4. `docs/CERNIS_PRO_snapshot.json` — Build-Gedächtnis (plattformspezifische Build-Lektionen v1.0).

---

## Working Rules (nicht verhandelbar)

- **Sprache: Deutsch** — Code-Kommentare, Commits, Kommunikation.
- **Editor: vim.**
- **Vollständige absolute Pfade** in allen Befehlen.
- **Shell-Typ und Rechtelevel** bei jedem Befehl angeben (z. B. *bash (User)*, *bash (root)*).
- **Vollständige Dateien** liefern/ändern, keine zeilenweisen manuellen Edit-Instruktionen an den Nutzer.
- **Kein Trial-and-Error.** Erst die Situation vollständig verstehen, dann handeln. Lieber zweimal nachdenken als Schnellschuss.
- **Änderungen einzeln, in definierter Reihenfolge** — kein paralleles Vorgehen.
- **Pro Session ein Use-Case.** Die Architektur erzwingt kleine Module; nicht mehrere Features gleichzeitig anfassen.
- **Keine Änderung ohne grünen Test-Lauf in CI.** (Neu für v2, hart.)

---

## Architektur (pragmatisch hexagonal, 3 Ringe)

```
backend/
  api/              # FastAPI-Router. Kennt nur application/. KEIN infrastructure/.
  application/      # Use-Cases. Kennt domain/ und ports/. NICHT infrastructure/.
  domain/           # Reine Domänenlogik. Nur domain/ + stdlib.
  ports/            # Interfaces (Verträge), die application/ nutzt.
  infrastructure/   # Implementiert ports/. Kennt domain/-Modelle.
  app.py            # Composition Root: verdrahtet ports/ <-> infrastructure/, DI, Middleware.
```

**Importregeln (per `import-linter` maschinell erzwungen):**
1. `domain/` → nur `domain/` + stdlib.
2. `application/` → `domain/` + `ports/`, **nicht** `infrastructure/`.
3. `infrastructure/` → implementiert `ports/`, kennt `domain/`-Modelle.
4. `api/` → ruft nur `application/`, kennt **kein** `infrastructure/`.
5. Verdrahtung `ports/` <-> `infrastructure/` **ausschließlich** in `app.py`.

---

## Standards & Tooling

- PEP 8, Type-Hints durchgängig.
- `ruff` (Lint/Format) + `mypy` (strict).
- `pytest` für Tests; Characterization Tests **vor** jeder Feature-Migration.
- Pydantic für Modelle, `pydantic-settings` für Konfiguration.
- `structlog` für Logging.
- `pyproject.toml` als alleinige Config (kein verstreutes setup.cfg etc.).
- Lock-Datei statt loser `requirements.txt` (uv oder pip-tools).
- **Keine stillen Fallbacks.** Ein Fehlschlag ist ein Fehler, nicht ein leiser Rückfall auf unsicheres Verhalten (siehe Finding S3).
- **Pre-commit-Hooks werden nicht automatisch in `.git/hooks/` installiert** — Aktivierung durch Entwickler mit `uv run pre-commit install`. Begründung: vorhersehbarer Commit-Flow für Coding-Agents. Die CI (`.github/workflows/ci.yml`) erzwingt dieselben Gates ohnehin verbindlich.

---

## Migrations-Vorgehen (Strangler Fig, pro Feature)

1. Characterization-Tests gegen aktuelles Verhalten schreiben.
2. Tests gegen alten Code grün.
3. Feature in neue Struktur migrieren (Use-Case + Ports + Adapter).
4. Tests gegen neuen Code grün.
5. Alten Code löschen.
6. Commit, CI grün, weiter.

**Reihenfolge** (aus `phase0_ist_analyse.md`, Abschnitt 7):
`settings` → `scanning` → `devices` → `monitoring` → `alerting` → `security` → `capture` → `agent` → Hilfsmodule.
Neue Domänen (`traffic`, `process`, `analysis`) erst nach Stabilisierung des Bestands.

---

## Scope während des Rewrites

- **Nur Linux x64.** Andere Plattformen via Ports gestubbt, nicht implementiert.
- **API-Verträge dürfen brechen** (Frontend wird angepasst).
- **Leere DB beim ersten Start** ist akzeptabel.
- Plattformspezifische, systemnahe Adapter (sock_diag, /proc) so kapseln, dass ein späterer Sprachwechsel ein lokaler Eingriff bleibt — aber **nicht jetzt** wechseln.

---

## Git-Konventionen

- GitHub-User: `ktbdevufg`. SSH-Key: `id_github` (ed25519).
- Branches: `main` + `dev` (Bestand). Rewrite läuft auf **`rewrite/v2`** (von `dev` abgezweigt).
- Entwicklung auf `rewrite/v2`; Merge nach `dev`/`main` nur bei Meilensteinen.
- Nach jeder Session prüfen: `git log --oneline origin/rewrite/v2..HEAD`.
- Commits auf Deutsch, im Imperativ, mit Präfix (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
