"""Application-Exceptions der dns_trust-Use-Cases (DNS-Server-Vertrauensmodell).

Eigenstaendige Fehlerklassen OHNE HTTP-/Transport-Details -- das Mapping auf
Statuscodes passiert in ``api/`` (Muster ``application/devices/errors.py`` und
``application/outbound_log/errors.py``). Beide erben ueber eine gemeinsame Basis
direkt von ``Exception`` (NICHT von ``ValueError``): der api-Rand kann genau diese
Fehler fangen, ohne einen unrelated ``ValueError`` mitzunehmen -- der bleibt dort
weiter dem echten Vokabular-/Wertfehler vorbehalten (422).

Beide Faelle bezeichnen einen bisher STILLEN Nichtvollzug: der Schreibpfad meldete
Erfolg, ohne etwas zu schreiben. Das ist derselbe Mangel, den ``DeviceNotFoundError``
fuer ``update_device_meta`` bereits benennt ("war dort ein stiller No-op auf
unbekannte MAC ... v2 macht das explizit"). Kein stiller Fallback (Finding S3).
"""

__all__ = [
    "DnsTrustApplicationError",
    "DnsTrustServerNotConfirmedError",
    "DnsTrustServerNotFoundError",
]


class DnsTrustApplicationError(Exception):
    """Basis fuer Fehler der dns_trust-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""


class DnsTrustServerNotFoundError(DnsTrustApplicationError):
    """Zu dieser ``ip`` ist gar kein DNS-Server erfasst.

    Geworfen von ``SetDnsServerTrust``, wenn ``DnsTrustRepository.get`` ``None``
    liefert. Zuvor war das ein stiller No-Op: ``repo.set_trust`` betraf 0 Zeilen,
    die Schnittstelle meldete trotzdem Erfolg -- der Nutzer traf eine Entscheidung,
    die folgenlos blieb. Der api-Rand mappt ihn auf 404 (Muster
    ``DeviceNotFoundError``). Traegt die ``ip`` im Bezug.

    Das ANLEGEN eines unbekannten Servers ist bewusst NICHT Teil dieses Weges --
    erfasst werden Server ueber ``SyncDnsTrustServer`` aus beobachtetem Verkehr.
    """

    def __init__(self, ip: str) -> None:
        self.ip = ip
        super().__init__(f"Kein DNS-Server zur Adresse {ip!r} erfasst")


class DnsTrustServerNotConfirmedError(DnsTrustApplicationError):
    """Der Server ist weder ``TRUSTED`` noch traegt er bereits einen Rang.

    Geworfen von ``SetDnsServerRank``, wenn die ``ip`` nicht in der betroffenen
    Menge liegt (trusted ODER ``expected_rank > 0``). Die Einschraenkung ist
    FACHLICH GEWOLLT und bleibt: der Rang ist die erwartete Prioritaet INNERHALB
    der erwarteten Menge (``TrustedDnsServerIps``) -- fuer einen nicht bestaetigten
    Server hat er keine Wirkung. Zuvor fiel der Wunsch still weg (die ``ip`` stand
    nicht in ``gewuenscht``, es wurde nichts geschrieben, die Schnittstelle meldete
    Erfolg). Der api-Rand mappt ihn auf 409 (Zustand laesst die Aktion nicht zu,
    Muster ``InvalidRecordingTransition``). Traegt die ``ip`` im Bezug.
    """

    def __init__(self, ip: str) -> None:
        self.ip = ip
        super().__init__(f"Der DNS-Server {ip!r} ist nicht bestaetigt und traegt keinen Rang")
