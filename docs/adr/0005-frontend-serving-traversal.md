# ADR 0005 — Frontend-Serving in app.py traversal-sicher; Altcode-Lücke (S6) bewusst nicht gepatcht

- **Status:** Akzeptiert
- **Datum:** 2026-05-28
- **Phase:** Phase 2, Schritt P2.1c (Umzug des Frontend-Servings main.py → app.py)
- **Bezug:** Finding S6 (`pre_release_202605.md` §2.2), S1 (Wildcard-CORS), P2.1b (Bootstrap-Owner app.py), Einstiegspunkt-Wechsel P2.3

## Kontext

Der SPA-Catch-all des Altcodes (`main.py:1991–1999`) baut den auszuliefernden Dateipfad aus user-kontrolliertem Input zusammen:

```python
file_path = os.path.join(_FRONTEND_DIR, full_path)   # full_path = URL-Pfad
if os.path.isfile(file_path):
    return FileResponse(file_path)
```

Es gibt **keine** Containment-Prüfung (kein `realpath`+`startswith(_FRONTEND_DIR)`). Mit (URL-kodiertem) `../` lässt sich aus dem Frontend-Verzeichnis ausbrechen (`/%2e%2e/%2e%2e/…/etc/passwd`); `os.path.isfile` folgt dem aufgelösten Pfad, `FileResponse` liefert die Datei. Das `startswith(("api/","ws/"))` filtert nur API/WS, nicht Traversal.

**Severity-Einschätzung:** isoliert eine lokale Path-Traversal-Leseprimitive. In Kombination mit **S1** (`allow_origins=["*"]`, keine Auth) kann jede beliebige Webseite (oder `curl`) das lokal gebundene Backend ansprechen und Dateien außerhalb des Frontend-Verzeichnisses exfiltrieren → **effektiv High**. Das `/assets`-Serving (Starlette `StaticFiles`) ist hingegen sicher; die Lücke sitzt ausschließlich im manuellen Pfad-Join des Catch-alls.

Der Befund entstand bei der Vorklärung zu P2.1c (Umzug des Servings nach app.py).

## Entscheidung

1. **v2 baut die Lücke gar nicht erst ein.** Das Frontend-Serving in `app.py` läuft ausschließlich über Starlettes `StaticFiles` (containt von Haus aus gegen Traversal). Eine schmale Subklasse `_SpaStaticFiles` ergänzt den SPA-Fallback: existierende Dateien liefert `StaticFiles` aus, unbekannte Nicht-`api/`/`ws/`-Pfade fallen auf `index.html` (fixer Pfad) zurück. **Keine Zeile konkateniert user-Input in einen Dateipfad.**
2. **Injizierbarer Pfad (Env-Seam):** `CERNIS_FRONTEND_DIR` / `AppConfig.frontend_dir` hat Vorrang; fehlt er, dieselbe Suchreihenfolge wie der Altcode. Kein Frontend gefunden → API-only (kein Serving-Mount).
3. **Route-Reihenfolge:** Der `"/"`-Mount wird als **letztes** in `create_app` registriert, nach allen API-Routern — sonst verschluckt er deren Routen.
4. **`main.py` wird NICHT gepatcht.** Der Altcode ist sterbend: mit dem Einstiegspunkt-Wechsel (P2.3) wird `app.py` produktiv und `main.py`/sein Catch-all verschwinden. Ein Patch am Altcode wäre Wegwerf-Arbeit und widerspricht der Strangler-Linie (Altcode nicht anfassen, ersetzen).

## Konsequenzen

**Positiv**
- v2-Serving ist traversal-sicher per Konstruktion (kein manuelles Pfad-Join), bewiesen durch eine Sicherheits-Regression in `tests/api/test_frontend_serving.py` (Sentinel-Datei außerhalb des Frontend-Dirs ist über keinen `../`-/URL-kodierten Pfad abrufbar).
- Der Env-Seam macht das Serving testbar (tmp-Frontend) — was beim import-zeit-verdrahteten Altcode nicht ging (vgl. P2.1a, zurückgestellte Charakterisierung).

**Risiko / Restfenster**
- Solange `main.py` produktiv ist (bis P2.3), besteht die Traversal-Lücke **im Altcode** weiter. Mitigation: lokal gebundenes Backend (`127.0.0.1`); echter Hebel ist erst die Kombination mit S1. Bewusst akzeptiertes, befristetes Fenster.
- Im **Phase-4-Audit** ist S6 als „in v2 gelöst, im Altcode bis P2.3 offen" zu führen; nach dem Einstiegspunkt-Wechsel ist S6 abgeschlossen.
