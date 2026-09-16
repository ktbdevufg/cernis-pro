"""Domaenenmodell der Capture-Rechte: Zustand, Einrichtung und Widerruf.

Reine Domaenenlogik (stdlib, ADR 0002) -- kein Wissen ueber Persistenz, HTTP oder
die konkrete Plattform-Mechanik (BPF-Geraete, LaunchDaemon, osascript). Beschrieben
wird nur das FACHLICHE Vokabular: ist der rohe Mitschnitt zugaenglich, und wie ist
ein Einrichtungsversuch ausgegangen.

Der Kern ist die Dreiteilung des Ergebnisses (S3, kein stiller Fallback): Erfolg,
ABBRUCH DURCH DEN NUTZER und Fehlschlag sind DREI unterscheidbare Zustaende, nicht
zwei. Ein Abbruch ist ausdruecklich KEIN Fehler -- der Nutzer hat sich legitim
entschieden, die Systemabfrage nicht zu bestaetigen; die Oberflaeche soll dafuer
keine Fehleroptik zeigen und die Einrichtung jederzeit nachholbar lassen.

Dieselbe Dreiteilung gilt fuer den WIDERRUF (Etappe 3): er nimmt die Einrichtung
zurueck und kann ebenso gelingen, abgebrochen werden oder fehlschlagen. Er hat
einen EIGENEN Ergebnis-Enum, damit keine unmoeglichen Zustaende darstellbar sind
(siehe ``CaptureAccessRevokeOutcome``).

Muster ``StrEnum`` wie ``domain/maintenance.py``/``domain/outbound_log.py`` -- der
Wire-Wert ist der jeweilige String.
"""

from dataclasses import dataclass
from enum import StrEnum


class CaptureAccessState(StrEnum):
    """Zustand des rohen Mitschnitt-Zugriffs (die Status-Frage).

    ``GRANTED`` -- der Zugriff steht (auf macOS: die BPF-Geraete sind fuer den
    aktuellen Nutzer lesbar); die Sniff-Familie laeuft ohne weitere Einrichtung.
    ``MISSING`` -- der Zugriff fehlt und laesst sich auf dieser Plattform einrichten.
    ``NOT_APPLICABLE`` -- auf dieser Plattform gibt es diese Einrichtung nicht (Linux
    loest das ueber ``setcap`` im Postinstall). Das ist ein ehrlicher eigener Zustand,
    KEIN Fehler und kein vorgetaeuschtes ``GRANTED``.
    """

    GRANTED = "granted"
    MISSING = "missing"
    NOT_APPLICABLE = "not_applicable"


class CaptureAccessOutcome(StrEnum):
    """Ausgang eines Einrichtungsversuchs -- die S3-Dreiteilung.

    ``GRANTED`` -- eingerichtet, der Zugriff steht jetzt.
    ``CANCELLED`` -- der Nutzer hat die Systemabfrage abgebrochen. Ein eigener
    Zustand, ausdruecklich KEIN Fehler.
    ``FAILED`` -- der Versuch ist fehlgeschlagen; der Grund wird benannt, nicht
    verschwiegen.
    ``NOT_APPLICABLE`` -- auf dieser Plattform nicht zutreffend (siehe
    ``CaptureAccessState.NOT_APPLICABLE``).
    """

    GRANTED = "granted"
    CANCELLED = "cancelled"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class CaptureAccessRevokeOutcome(StrEnum):
    """Ausgang eines Widerrufsversuchs -- dieselbe S3-Dreiteilung, andere Werte.

    ``REVOKED`` -- widerrufen; die Einrichtung ist (ganz oder fuer diesen Nutzer)
    zurueckgenommen.
    ``CANCELLED`` -- der Nutzer hat die Systemabfrage abgebrochen. Ein eigener
    Zustand, ausdruecklich KEIN Fehler.
    ``FAILED`` -- der Versuch ist fehlgeschlagen; der Grund wird benannt.
    ``NOT_APPLICABLE`` -- auf dieser Plattform nicht zutreffend.

    BEWUSST EIN EIGENER ENUM statt einer Wiederverwendung von
    ``CaptureAccessOutcome``: dessen ``GRANTED`` ergibt beim Widerruf keinen Sinn,
    und ein gemeinsamer Enum wuerde unmoegliche Zustaende erlauben -- ein Widerruf
    koennte dann typkorrekt "granted" melden und eine Einrichtung "revoked". Zwei
    getrennte Enums machen genau die Werte moeglich, die es fachlich gibt.
    """

    REVOKED = "revoked"
    CANCELLED = "cancelled"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class CaptureAccessStatus:
    """Der Status-Befund: Zustand + optionale Begruendung + Gruppenmitglieder.

    ``detail`` traegt bei ``MISSING``/``NOT_APPLICABLE`` den ehrlichen Klartext-Grund
    (z. B. den Rechte-Hinweis der Sniff-Probe oder "auf dieser Plattform nicht
    noetig"). Bei ``GRANTED`` ist ``detail`` leer -- es gibt nichts zu erklaeren.

    ``members`` sind die Login-Namen der Mitglieder der Capture-Gruppe; leer, wenn
    die Gruppe nicht existiert oder die Plattform sie nicht kennt. Das Feld dient
    ALLEIN dazu, dem Nutzer VOR einem Widerruf ehrlich zu zeigen, wer sonst noch
    betroffen waere: die Geraete und der Systemdienst sind SYSTEMWEITE Ressourcen,
    die sich alle Konten der Maschine teilen. Es ist ausdruecklich KEIN Vorgriff auf
    die geplante Mehrbenutzerfaehigkeit der Anwendung, sondern die korrekte
    Behandlung einer geteilten Betriebssystem-Ressource.

    ``tuple`` statt ``list``, weil die dataclass ``frozen`` ist -- eine Liste waere
    trotz ``frozen`` von aussen veraenderbar.
    """

    state: CaptureAccessState
    detail: str = ""
    members: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CaptureAccessResult:
    """Das Ergebnis eines Einrichtungsversuchs: Ausgang + optionale Begruendung.

    ``reason`` ist bei ``FAILED`` der verstaendliche Grund (S3: benannt, nicht
    verschluckt) und bei ``NOT_APPLICABLE`` die ehrliche Einordnung. Bei ``GRANTED``
    und ``CANCELLED`` bleibt ``reason`` leer: Erfolg braucht keine Begruendung, und
    ein Abbruch ist kein Fehler, der erklaert werden muesste.
    """

    outcome: CaptureAccessOutcome
    reason: str = ""


@dataclass(frozen=True, slots=True)
class CaptureAccessRevokeResult:
    """Das Ergebnis eines Widerrufsversuchs: Ausgang + optionale Begruendung.

    ``reason`` ist bei ``FAILED`` der verstaendliche Grund (S3: benannt, nicht
    verschluckt) und bei ``NOT_APPLICABLE`` die ehrliche Einordnung. Bei ``REVOKED``
    und ``CANCELLED`` bleibt ``reason`` leer -- Erfolg braucht keine Begruendung, und
    ein Abbruch ist kein Fehler, der erklaert werden muesste.
    """

    outcome: CaptureAccessRevokeOutcome
    reason: str = ""
