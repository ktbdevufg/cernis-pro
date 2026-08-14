"""Application-Ring der maintenance-Domaene -- die zwei Stufen der Daten-Loeschung.

Kennt ``ports/``, NIE ``infrastructure/`` oder ``modules/`` (import-linter). Alle
Repositories/Cleaner kommen als Ports/Protocols per Constructor-Injection herein.
``ResetScanData`` (Stufe 1) und ``FactoryReset`` (Stufe 2) orchestrieren nur die
``clear_all``-Methoden der jeweiligen Ports -- keine eigene Persistenz.

DANEBEN das Aufraeumen nach Netz (S88-P3, ``netz_aufraeumen.py``):
``GruppiereGeraeteNachNetz`` rechnet die /24-Gruppen aus dem Bestand aus,
``EntferneGeraeteMenge`` loescht eine MENGE von Geraeten samt aller
MAC-gebundenen Nebendaten in EINER Transaktion (eigener Port
``DevicePurgeRepository`` -- die ``clear_all``-Bausteine oben taugen dafuer
nicht, sie kennen keinen MAC-Filter).
"""

from application.maintenance.netz_aufraeumen import (
    OHNE_IP,
    EntferneGeraeteMenge,
    GruppiereGeraeteNachNetz,
    NetzGruppe,
)
from application.maintenance.use_cases import (
    AnalysisAckCleaner,
    DeleteSelectedData,
    FactoryReset,
    KnownHostsCleaner,
    ResetScanData,
)

__all__ = [
    "OHNE_IP",
    "AnalysisAckCleaner",
    "DeleteSelectedData",
    "EntferneGeraeteMenge",
    "FactoryReset",
    "GruppiereGeraeteNachNetz",
    "KnownHostsCleaner",
    "NetzGruppe",
    "ResetScanData",
]
