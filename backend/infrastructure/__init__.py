"""Infrastructure: konkrete Adapter, die ``ports/`` implementieren.

Hier liegt die technische Anbindung (SQLite, OS-Keystore, externe Dienste).
Darf ``ports/`` und ``domain/`` (Modelle) kennen. Verdrahtet wird sie mit den
Ports ausschliesslich im Composition Root (``app.py``), nie direkt von
``application/`` oder ``api/`` aus.
"""
