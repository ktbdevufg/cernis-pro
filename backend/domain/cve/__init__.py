"""Domaene ``cve`` -- CVE-Schwachstellen-Monitoring ueber den bekannten Geraete-Bestand.

Eigenstaendige Domaene (ADR 0037), NICHT an ``security`` angebaut: ``security`` ist
Momentaufnahme-Inspektion (ARP/TLS/Creds eines Scans), ``cve`` ist ein persistenter,
zeitgesteuerter Belang ueber den BESTAND -- per-Host-Pruefstand, Drip-Worker,
quittierbare Befunde. Andere Lebensdauer, andere Identitaet, eigenes Modell.

Framework-frei (ADR 0002): nur stdlib + dataclasses, KEIN pydantic/fastapi/structlog.
Zeitfrei im Verhalten -- ``now``/Intervalle werden als rohe ``float``-Sekunden HEREIN-
gereicht (der Persistenz-/Use-Case-Rand haelt die Uhr), die Domaene rechnet nur.
"""

from domain.cve.models import (
    CveFindingRecord,
    HostCheckState,
)
from domain.cve.policy import (
    DEFAULT_NEW_WINDOW_SECONDS,
    DEFAULT_REFRESH_INTERVAL_HOURS,
    DueReason,
    due_reason,
    is_new,
)

__all__ = [
    "DEFAULT_NEW_WINDOW_SECONDS",
    "DEFAULT_REFRESH_INTERVAL_HOURS",
    "CveFindingRecord",
    "DueReason",
    "HostCheckState",
    "due_reason",
    "is_new",
]
