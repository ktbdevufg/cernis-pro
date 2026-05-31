"""Ports: Schnittstellen (Vertraege), die ``application/`` nutzt.

Definieren abstrakte Vertraege (z. B. Repositories, Secret-Store). Duerfen
hoechstens ``domain/`` kennen (fuer Typen in den Signaturen), nie Application,
Infrastructure oder API. Implementiert werden sie in ``infrastructure/``.
"""
