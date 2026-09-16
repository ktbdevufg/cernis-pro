"""Application-Exceptions der outbound_log-Use-Cases (Aussenkontakte-Aufzeichnung).

Eigenstaendige Fehlerklassen OHNE HTTP-/Transport-Details -- das Mapping auf
Statuscodes bzw. Wire-Frames passiert in ``api/`` (E3b/E4). Beide erben direkt von
``Exception`` (NICHT von ``ValueError`` -- analog ``InvalidRecordingTransition`` der
Domaene und ``LoggingTaskNotFound``/``LoggingTaskConflict`` der monitoring-Schicht):
der api-Rand kann genau diese Fehler fangen, ohne einen unrelated ``ValueError``
mitzunehmen.

KONFLIKT-Semantik bewusst SIMPLER als beim RTT-Logging: eine Aussenkontakte-
Aufzeichnung bezieht sich auf DIESEN Host (nicht auf ein Ziel) -- es gibt KEINE
``target_id``. Pro Host darf darum HOECHSTENS EINE Aufzeichnung gleichzeitig
``ACTIVE`` sein (zwei parallele Snapshot-Worker waeren sinnlos/doppelt). Der
Konflikt traegt nur die ``running_id`` der bereits aktiven Aufzeichnung.
"""


class RecordingNotFound(Exception):
    """Eine Aufzeichnungs-Definition mit dieser ``id`` existiert nicht.

    Geworfen von den Lifecycle-/Lese-Use-Cases (Start/Pause/Resume/Stop/Get), wenn
    ``OutboundRecordingRepository.get`` ``None`` liefert. Der api-Rand (E3b) mappt
    ihn auf 404. Traegt die gesuchte ``recording_id`` im Bezug, damit der Fehler ohne
    Kontext-Rekonstruktion sprechend ist (Muster ``LoggingTaskNotFound``).
    """

    def __init__(self, recording_id: str) -> None:
        super().__init__(f"Aussenkontakte-Aufzeichnung {recording_id!r} nicht gefunden")
        self.recording_id = recording_id


class RecordingConflict(Exception):
    """Es laeuft bereits eine andere Aufzeichnung im Zustand ``ACTIVE`` (Host-Regel).

    Pro Host darf HOECHSTENS EINE Aufzeichnung gleichzeitig ``ACTIVE`` sein (global,
    KEIN ``target_id``-Bezug -- anders als ``LoggingTaskConflict``). Geworfen beim
    Start (``StartOutboundRecording``) und beim Fortsetzen aus Pause
    (``ResumeOutboundRecording``), wenn ``_find_active_recording`` eine bereits aktive
    Aufzeichnung findet. Der api-Rand (E3b) mappt ihn auf 409. Traegt die
    ``running_id`` der bereits aktiven Aufzeichnung im Bezug.
    """

    def __init__(self, running_id: str) -> None:
        super().__init__(
            f"Es laeuft bereits die Aufzeichnung {running_id!r} (host-weit nur eine aktiv)"
        )
        self.running_id = running_id


class RecordingNameTaken(Exception):
    """Der (getrimmte) Aufzeichnungs-NAME ist bereits von einer ANDEREN Aufzeichnung belegt.

    Ein ``label`` darf host-weit nicht doppelt vergeben werden -- verglichen wird
    GETRIMMT + CASE-SENSITIV (``"test3"`` und ``"test3 "`` gelten als gleich, ``"test3"``
    und ``"Test3"`` sind erlaubt). Die Belegung ist ZUSTANDSUNABHAENGIG: solange eine
    Aufzeichnung existiert (auch ``FINISHED``), ist ihr Name belegt -- erst das Loeschen
    gibt ihn frei. Geworfen beim Anlegen (``CreateOutboundRecording``) und beim Umbenennen
    (``EditOutboundRecording``), wenn ``_name_taken`` einen Treffer findet. Der api-Rand
    (E4) mappt ihn auf 409. Traegt den kollidierenden (rohen) ``label`` im Bezug.
    """

    def __init__(self, label: str) -> None:
        super().__init__(f"Der Aufzeichnungs-Name {label!r} ist bereits vergeben")
        self.label = label
