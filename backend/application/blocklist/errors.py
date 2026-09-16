"""Application-Exceptions der blocklist-Domaene.

Eigene Vokabular-/Ablauf-Fehler des Application-Rings (Muster
``application/outbound_log/errors.py``). Der api-Rand faengt sie und mappt sie auf
HTTP (422 fuer Vokabular-Hebung, s. ``UnknownStrictnessError``); ``BlocklistFetchError``
ist ein interner Lade-Befund, den ``RefreshSource`` selbst verarbeitet (status BROKEN),
nicht ein nach aussen geworfener HTTP-Fehler.

Kennt NUR stdlib -- keine ``infrastructure``/``api``-Imports (import-linter:
``application kennt nicht infrastructure/api``).
"""

__all__ = [
    "BlocklistError",
    "BlocklistFetchError",
    "UnknownStrictnessError",
]


class BlocklistError(Exception):
    """Basisklasse aller blocklist-Application-Fehler.

    Der api-Rand faengt diese Basisklasse (bzw. das stdlib-``ValueError`` der
    Enum-Hebung) und mappt sie auf 422 -- ein nicht zum Vokabular passender
    Gruppen-/Format-/Strenge-Wert ist ein Wire-Fehler des Aufrufers, kein 500.
    """


class BlocklistFetchError(BlocklistError):
    """Der Download einer Quelle ist fehlgeschlagen (Netz/HTTP/leerer Body).

    Wird von der Fetcher-Naht (``BlocklistFetcher``-Protocol, echte Impl in
    ``infrastructure``) ueber den Use-Case ausgeloest: der ``RefreshSource``-Use-Case
    faengt die rohe Lade-Exception der Infrastruktur breit (``Exception``) und uebersetzt
    sie in diesen sprechenden Fehler bzw. verarbeitet sie direkt zu status BROKEN. KEIN
    Werfen nach aussen im Refresh-Pfad -- der BROKEN-Status ist der ehrliche Befund.
    """


class UnknownStrictnessError(BlocklistError):
    """Ein unbekannter Strenge-Wert wurde ueber die Wire-Grenze hereingereicht.

    Die Hebung roher Wire-Strings in ``MatchStrictness`` passiert autoritativ im
    Application-Ring (``strictness_from_wire``); ein nicht zum Vokabular passender Wert
    wirft diesen Fehler, den der api-Rand auf 422 mappt (kein stiller Fallback, S3).
    """
