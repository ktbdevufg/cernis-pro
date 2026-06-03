"""Infrastruktur des metrics-Querschnitts: der SQLite-Lese-Adapter (M.8).

Eigenes Paket (nicht ``infrastructure/monitoring/``), konsistent zum ``domain/metrics``-
und ``ports/metrics``-Schnitt: metrics ist ein Lese-/Aggregat-Querschnitt ueber
mehrere Quell-Tabellen, KEIN monitoring-Adapter. Es unter ``monitoring`` zu legen
mischte Domaenen-fremde Aggregate (devices/scan/sla) in das monitoring-Paket -- genau
die Vermischung, die der independence-Contract (domain-Ring) verbietet; hier im
infrastructure-Ring per Paket-Schnitt vermieden.
"""

from infrastructure.metrics.metrics_reader import SqliteMetricsReader

__all__ = ["SqliteMetricsReader"]
