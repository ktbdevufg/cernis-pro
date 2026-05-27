"""Composition Root von CERNIS PRO 2.0.

Einziger Ort, an dem alle Ringe zusammenkommen: verdrahtet ``ports/`` <->
``infrastructure/`` (Dependency Injection), konfiguriert Middleware und baut die
FastAPI-App. Bewusst von den Architektur-Regeln ausgenommen (darf alle Ringe
importieren) -- deshalb nicht Teil der import-linter-Vertraege.

Platzhalter (Schritt 2). Wird in Schritt 3 mit Lifespan-Kontext, Middleware und
DI-Verdrahtung gefuellt -- Lifespan statt ``@app.on_event`` (siehe
docs/migration_notes.md, fastapi/starlette).
"""
