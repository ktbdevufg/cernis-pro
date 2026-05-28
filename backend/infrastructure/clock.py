"""System-Adapter fuer den ``Clock``-Port.

``SystemClock.now()`` liefert timezone-aware UTC und ist damit die strukturelle
Loesung der UTC/lokal-Inkonsistenz des Altcodes (Schema-Default ``datetime('now')``
in UTC vs. ``datetime.now()`` in lokaler Zeit): in v2 gibt es genau EINE
Zeitquelle, und sie ist eindeutig UTC.
"""

from datetime import UTC, datetime


class SystemClock:
    """Erfuellt das ``Clock``-Protocol strukturell (Systemuhr, UTC)."""

    def now(self) -> datetime:
        return datetime.now(UTC)
