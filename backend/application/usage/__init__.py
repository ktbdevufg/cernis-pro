"""Application-Ring der usage-Zaehlung (Nutzungs-Ranking des Schnellzugriffs).

Zwei duenne Use-Cases ueber dem ``ports.usage.UsageStatsRepository``-Port:
``RecordFeatureUsage`` (zaehlt eine Funktions-Oeffnung) und ``GetTopFeatures`` (liefert
die Rangliste). Kennt NUR ``ports.usage`` -- NIE ``infrastructure``/``modules`` (import-
linter) und KEINE Fremd-Domaene. Die echte Verdrahtung (Repo-Instanz, db_path) faellt
erst der Composition Root (app.py, Regel 5).
"""

from application.usage.use_cases import GetTopFeatures, RecordFeatureUsage

__all__ = [
    "GetTopFeatures",
    "RecordFeatureUsage",
]
