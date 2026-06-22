"""Reine Domaenenlogik der scheduler-Domaene: Faelligkeit eines Fensters (stdlib, zeitfrei).

Hier wohnt die Frage, die der Worker pro Tick je Job stellt: "soll dieser Job JETZT
laufen?". Die Antwort ergibt sich allein aus dem Zeitplan (``DailyWindow``) + dem
Zustand (``JobState``) -- NIE aus dem Aufgaben-Inhalt (die Domaene kennt ihn nicht).

Alles zeitfrei: Die Domaene erzeugt KEINE Uhr. ``now_epoch`` (UTC-Sekunden), ``now_minute``
(lokale Wanduhr-Minute seit Mitternacht) und ``weekday`` (0=Montag..6=Sonntag) werden vom
Aufrufer hereingereicht -- so bleibt die Tages-Rechnung zeitzonenfrei (siehe ``models``).
"""

from domain.scheduler.models import DailyWindow, JobState, ScheduledJob

__all__ = ["is_active_job", "is_expired", "is_within_window"]


def is_within_window(
    window: DailyWindow, *, now_epoch: float, now_minute: int, weekday: int
) -> bool:
    """Liegt der angegebene Moment IM Tagesfenster? -- True genau dann, wenn ALLE gelten:

    1. Gesamtzeitraum: ``now_epoch >= window.from_epoch`` UND (``window.until_epoch == 0.0``
       -> unbegrenzt, ODER ``now_epoch <= window.until_epoch``). ``until_epoch == 0.0``
       ist der "kein Ende"-Leerzustand (S3).
    2. Wochentag: ``window.weekdays`` ist leer (-> jeder Tag zaehlt) ODER ``weekday`` ist
       darin enthalten.
    3. Tagesfenster: ``window.start_minute <= now_minute < window.end_minute`` (halb-offen,
       Beginn inklusiv, Ende exklusiv).

    Reine Funktion: keine Uhr, keine I/O.
    """
    in_overall_period = now_epoch >= window.from_epoch and (
        window.until_epoch == 0.0 or now_epoch <= window.until_epoch
    )
    on_weekday = not window.weekdays or weekday in window.weekdays
    in_day_window = window.start_minute <= now_minute < window.end_minute
    return in_overall_period and on_weekday and in_day_window


def is_expired(window: DailyWindow, *, now_epoch: float) -> bool:
    """Ist der Gesamtzeitraum des Fensters ABGELAUFEN?

    True, wenn ``window.until_epoch != 0.0`` (es gibt ueberhaupt ein Ende) UND
    ``now_epoch > window.until_epoch``. ``until_epoch == 0.0`` (unbegrenzt) laeuft NIE ab.
    Der Worker setzt abgelaufene Jobs spaeter auf ``JobState.FINISHED``.
    """
    return window.until_epoch != 0.0 and now_epoch > window.until_epoch


def is_active_job(job: ScheduledJob, *, now_epoch: float, now_minute: int, weekday: int) -> bool:
    """Soll dieser Job JETZT laufen? -- die Frage des Workers pro Tick je Job.

    True genau dann, wenn ALLE gelten (Pruefreihenfolge deterministisch):

    1. ``job.state == JobState.ACTIVE`` (``PAUSED``/``FINISHED`` laufen nie).
    2. NICHT ``is_expired(job.window, now_epoch=...)`` (Gesamtzeitraum nicht abgelaufen).
    3. ``is_within_window(job.window, ...)`` (im Tagesfenster + am richtigen Wochentag).

    Reine Funktion: keine Uhr, keine I/O.
    """
    return (
        job.state == JobState.ACTIVE
        and not is_expired(job.window, now_epoch=now_epoch)
        and is_within_window(
            job.window, now_epoch=now_epoch, now_minute=now_minute, weekday=weekday
        )
    )
