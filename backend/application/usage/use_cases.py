"""Use-Cases der usage-Zaehlung -- Funktions-Oeffnung zaehlen + Rangliste holen.

Zwei duenne Use-Cases (Muster ``AddUserRules`` / ``ListUserRules``): sie orchestrieren
nichts ausser dem ``ports.usage.UsageStatsRepository``-Port -- keine Eigenlogik. Kennt NUR
``ports/`` (hier gibt es keine ``domain.usage``-Logik -- ein Zaehler traegt keine
Domaenen-Regel), NIEMALS ``infrastructure/`` (maschinell per import-linter erzwungen). Der
Port kommt per Constructor-Injection als Protocol-Typ herein -- nie ein konkreter Adapter.

Synchron: der Store ist ein lokaler SQLite-Zugriff ohne Loop-/Netz-I/O -- ehrlich kein
``async``.
"""

from ports.usage import UsageRecord, UsageStatsRepository


class RecordFeatureUsage:
    """Zaehlt EINE Funktions-Oeffnung -- duenner Pass-Through an ``increment``.

    Der ``feature_id`` kommt vom Frontend (stabiler Schluessel, z. B. ``"observe:scan"``);
    der Use-Case reicht ihn unveraendert an den Store durch. KEINE Validierung gegen eine
    feste Liste -- offen fuer neue Funktionen ohne Backend-Aenderung (Entscheidung im Port).
    """

    def __init__(self, repo: UsageStatsRepository) -> None:
        self._repo = repo

    def __call__(self, feature_id: str) -> None:
        self._repo.increment(feature_id)


class GetTopFeatures:
    """Liefert die ``limit`` meistgeoeffneten Funktionen -- duenner Pass-Through an ``top``.

    Reihenfolge/Tiebreaker (count DESC, last_used DESC) liegen im Adapter; dieser Use-Case
    reicht nur den Wunsch-Umfang durch. Leerer Stand -> ``[]`` (gueltiger Zustand).
    """

    def __init__(self, repo: UsageStatsRepository) -> None:
        self._repo = repo

    def __call__(self, limit: int = 5) -> list[UsageRecord]:
        return self._repo.top(limit)
