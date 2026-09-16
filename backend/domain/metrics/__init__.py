"""metrics-Querschnitt: Aggregat-Modelle + reine Export-Format-Funktionen.

Ein LESE-/AGGREGAT-Querschnitt ueber mehrere Quell-Domaenen (devices, rtt_history,
sla_samples, scan_history), KEINE Fach-Domaene. Haelt nur eigene schmale Typen +
stdlib -- kein Import anderer ``domain``-Pakete (s. ``models``-Modul-Kommentar zur
Schnitt-Disziplin).
"""

from domain.metrics.format import (
    to_homeassistant,
    to_influxdb,
    to_prometheus,
)
from domain.metrics.models import (
    MetricsSnapshot,
    RttPoint,
    SlaPoint,
)

__all__ = [
    "MetricsSnapshot",
    "RttPoint",
    "SlaPoint",
    "to_homeassistant",
    "to_influxdb",
    "to_prometheus",
]
