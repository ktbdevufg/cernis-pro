"""Application: Use-Cases (Anwendungsfaelle).

Orchestrieren Domaenenlogik ueber Ports. Duerfen ``domain/`` und ``ports/``
importieren, aber **nicht** ``infrastructure/`` oder ``api/``. Kennen also nur
Vertraege, nie konkrete Adapter.
"""
