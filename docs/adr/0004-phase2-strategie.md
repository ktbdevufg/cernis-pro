# ADR 0004 — Phase-2-Strategie: Domänen-Migration vor Einstiegspunkt-Wechsel (Monolith-Mount verworfen)

- **Status:** Akzeptiert
- **Datum:** 2026-05-28
- **Phase:** Phase 2 (Strangler-Fig-Migration), Strategie-Festlegung
- **Bezug:** `pre_release_202605.md` §5 (Phasenplan), §7 (Strangler-Vorgehen); P2.1 (app.py als Lifespan-/Serving-Owner, Commits `a7a3063`/`e6211e1`, ADR 0005); Findings S1, S6

## Kontext

Phase 2 sollte laut früher Formulierung „mit dem Einstiegspunkt-Wechsel `main.py` → `app.py` beginnen". Die Vorklärung dazu ergab: `main.py` hat **keine** `APIRouter` — alle **104 Routen** hängen direkt an der `app`-Instanz (`@app.get/post/...`), dazu die CORS-Middleware, das `/assets`-Mount, der Frontend-Catch-all und `uvicorn.run` am `app`-Objekt.

Ein **früher** Einstiegspunkt-Wechsel erzwingt damit eines von zwei Übeln:

1. **Monolith-Mount** („Weg 1"): `main.py` minimal-invasiv auf einen `APIRouter` umstellen und in `app.py` via `include_router` mounten. Das zieht den **gesamten Altcode-Blob inkl. `modules/`** in den Composition Root, hält den Monolithen am Stück am Leben (statt ihn pro Domäne zu verkleinern) und birgt konkrete Risiken:
   - **Wiedereinführung von S6** — der Traversal-Catch-all (`main.py:1991–1999`) käme über den Router zurück in v2, obwohl er in P2.1c gerade entfernt wurde.
   - **Settings-Routen-Kollision** — die Alt-Endpunkte (`/api/settings` GET/PUT/PATCH, `/shodan-key`) kollidieren mit dem bereits migrierten v2-`settings_router`.
2. Oder der Wechsel ist schlicht nicht sauber möglich, ohne `main.py` größer umzubauen.

Beides widerspricht dem Strangler-Prinzip (Altcode **schrumpfen**, nicht am Stück umhängen) und dem Vorzeige-Anspruch.

## Entscheidung

**Sauberer Weg: Domäne für Domäne migrieren; der Einstiegspunkt-Wechsel kommt ans ENDE von Phase 2.**

- Phase 2 migriert `scanning` → `monitoring` → `alerting` → `capture` → `agent` → Hilfsmodule, jeweils im bei `settings` etablierten Muster (Characterization → `domain` → `ports` → `infrastructure` → `application` → `api` → Verdrahtung in `app.py`). Mit jeder Domäne schrumpft der Altcode in `main.py`.
- Der Einstiegspunkt-Wechsel `main.py` → `app.py` erfolgt am **Ende** von Phase 2 (genug/alle Domänen migriert) und ist dann ein kleiner Schritt: PyInstaller-Spec/Tauri auf einen `app:app`-Runner umstellen (Binary `cernis-backend`/Port 8765 bleiben), `CERNIS_BOOTSTRAP_ON_STARTUP=true` setzen.
- **Monolith-Mount verworfen.** Kein `app.py → main.router`.

## Konsequenzen

**Positiv**
- Keine Architektur-Rückschritte: kein Altcode-Blob und kein `modules/`-Import im Composition Root.
- Strangler-Prinzip gewahrt — der Altcode verkleinert sich messbar pro Domäne.
- Keine Wiedereinführung von S6, keine Settings-Routen-Kollision.

**Preis (ehrlich benannt)**
- **S1** (Wildcard-CORS) und **S6** (Traversal im `main.py`-Catch-all) **bleiben im Altcode bestehen**, bis der Einstiegspunkt-Wechsel am Ende von Phase 2 `main.py` außer Betrieb nimmt. Das Risiko ist **unverändert gegenüber v1.0.0** (das Backend bindet an `127.0.0.1`, gleiche Exposition wie bisher) — wir verschlechtern nichts, sondern verschieben den Fix bewusst ans Phasenende, statt ihn durch einen Architektur-Rückschritt vorzuziehen. Für das **Phase-4-Audit** sind S1/S6 als **bewusst aufgeschoben** (nicht übersehen) zu führen.

**P2.1 bleibt gültige Vorbereitung**
- `app.py` als Lifespan-Owner (`bootstrap_on_startup`-Flag) und traversal-sicherer Frontend-Serving-Owner (ADR 0005) war richtig und nötig — es ist die Voraussetzung für den späteren Wechsel. Nur die Schlussfolgerung „also jetzt umschalten" war falsch und ist mit diesem ADR korrigiert.
