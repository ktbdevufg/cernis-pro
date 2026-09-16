"""Settings-Keys + Defaults der blocklist-Domaene (KEINE neue Settings-Domaene).

Die blocklist-Funktion legt KEINE eigene Settings-Domaene an -- sie nutzt den
bestehenden Key-Value-``SettingsRepository`` (Muster ``cve``-Settings). Hier liegen
nur die Key-Konstanten + Defaults, damit Application-Ring und Composition Root
DIESELBEN Namen/Defaults teilen (eine Quelle der Wahrheit, kein verstreuter Magie-
String). Das tatsaechliche Lesen/Schreiben passiert defensiv im Composition Root
(``app.py``, Helfer analog ``_read_cve_int_setting``) bzw. ueber schmale Endpunkte.
"""

__all__ = [
    "DEFAULT_GROUP_THREAT_ENABLED",
    "DEFAULT_GROUP_TRACKER_ADS_ENABLED",
    "DEFAULT_REFRESH_DAYS",
    "DEFAULT_STRICTNESS",
    "SETTING_GROUP_THREAT",
    "SETTING_GROUP_TRACKER_ADS",
    "SETTING_REFRESH_DAYS",
    "SETTING_STRICTNESS",
]

# Anzeige-Strenge (Wire-Wert von ``MatchStrictness``; Default "recommended").
SETTING_STRICTNESS = "blocklist_strictness"
DEFAULT_STRICTNESS = "recommended"

# Auto-Refresh-Intervall in Tagen (Faelligkeit ueber last_fetched_ts, Muster cve).
SETTING_REFRESH_DAYS = "blocklist_refresh_interval_days"
DEFAULT_REFRESH_DAYS = 7

# Gruppen-Feinschalter (pro Gruppe an/aus) -- Settings-/Application-Belang, NICHT
# Domaene (s. domain/blocklist.py: die Domaene kennt nur die Strenge-Stufen).
SETTING_GROUP_TRACKER_ADS = "blocklist_group_tracker_ads_enabled"
DEFAULT_GROUP_TRACKER_ADS_ENABLED = True

SETTING_GROUP_THREAT = "blocklist_group_threat_enabled"
DEFAULT_GROUP_THREAT_ENABLED = True
