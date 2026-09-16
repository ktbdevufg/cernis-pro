"""Schedule-Format-Parsing der monitoring-Domaene -- reine Logik (stdlib, ADR 0002).

Der EINZIGE reine-Logik-Anteil des scheduler-Belangs: das Parsen des Schedule-
Strings (``"interval:30m"`` / ``"cron:0 2 * * *"``) in eine strukturierte
``ScheduleSpec``. Verhaltensgleich aus ``modules/scheduler._parse_trigger``
portiert, ABER getrennt vom APScheduler-Objekt-Bau: ``parse_schedule`` liefert nur
die Spec, der M.6-Adapter (Schritt 2) baut daraus das ``IntervalTrigger`` /
``CronTrigger``. So bleibt die Format-Logik stdlib-rein + isoliert testbar, und nur
die Trigger-Objekt-Erzeugung ist APScheduler-spezifisch.

``ScheduleSpec`` ist eine PEP-695-Union (kein Basisklassen-Hierarchie): so prueft
mypy ein ``match`` ueber die Spec-Varianten via ``assert_never`` auf
Vollstaendigkeit -- analog ``ScanEvent`` (S.2). Die Felder spiegeln die
APScheduler-Trigger-Argumente, die ``_parse_trigger`` setzt.

S3-FIX (bewusste v2-Abweichung, KEIN stiller Fallback): Der Altcode hatte ZWEI
Fehlermodi fuer einen kaputten String -- (1) stiller ``IntervalTrigger(hours=24)``-
Fallback bei Formatfehlern (leerer String, falsches Suffix, ungueltige Cron-
Feldzahl) und (2) ein ungefangener ``ValueError`` bei nicht-numerischem Wert
(``"interval:abcm"`` -> ``int("abc")``), den das ``_register_job``-``except: print``
verschluckte. Beide sind verdeckte Fehler -- besonders der 24h-Fallback (ein
Tippfehler erzeugt klammheimlich ein voellig anderes Intervall, ohne dass der User
es je merkt). v2 vereinheitlicht: JEDER unparsbare String wirft
``ScheduleParseError``. Der Aufrufer (M.6 ``ManageSchedules``) behandelt das
best-effort (Schedule-Zeile entsteht, aber kein Job + Warn-Log) -- sichtbar, nie
still.

ZUSAETZLICHE BEWUSSTE v2-ABWEICHUNG (``interval:0m`` / negativ): siehe den
``value <= 0``-Kommentar in ``_parse_interval`` -- der Altcode machte daraus ein
1-Sekunden-Dauerfeuer bzw. ein undefiniertes negatives Intervall; v2 lehnt es ab.
Kein M.1-Charakterisierer deckt diesen Pfad (``_parse_trigger`` lief nur im
ungetesteten ``_register_job``), also KEINE Contract-Abweichung zu einem Test.
"""

from dataclasses import dataclass


class ScheduleParseError(Exception):
    """Ein Schedule-String ist nicht parsbar (kaputtes Format ODER ungueltiger Wert).

    EIGENSTAENDIG (erbt NICHT von ``ValueError``): so kann der best-effort-Fang in
    ``ManageSchedules`` (M.6 Schritt 2) ihn GEZIELT fangen, ohne dass ein
    versehentliches ``except ValueError`` ihn -- oder umgekehrt einen unrelated
    ``ValueError`` (z. B. aus dem APScheduler-Trigger-Bau) -- mitfaengt. Die
    Exception-Hierarchie macht den Zu-breit-Fang strukturell unmoeglich, statt ihn
    nur per Disziplin zu vermeiden.

    Der ``int()``-``ValueError`` bei nicht-numerischem Intervallwert wird in
    ``_parse_interval`` via ``raise ... from exc`` in diesen Fehler umgewandelt --
    nach aussen kommt also IMMER nur ``ScheduleParseError`` (die Kausalkette bleibt
    ueber ``__cause__`` erhalten). Der Altcode fiel hier still auf 24h zurueck bzw.
    warf einen rohen ``ValueError``; v2 wirft EINEN benannten Fehler mit dem
    verursachenden String im Bezug.
    """

    def __init__(self, schedule: str) -> None:
        super().__init__(f"Unparsbarer Schedule-String: {schedule!r}")
        self.schedule = schedule


@dataclass(frozen=True)
class IntervalSpec:
    """Intervall-Trigger: alle ``value`` Zeiteinheiten ``unit``.

    ``unit`` ist eines von ``"minutes" | "hours" | "days"`` -- exakt die
    APScheduler-``IntervalTrigger``-Argumentnamen, die ``_parse_trigger`` aus dem
    ``m``/``h``/``d``-Suffix ableitet. ``value`` ist die geparste positive Zahl.
    """

    unit: str
    value: int


@dataclass(frozen=True)
class CronSpec:
    """Cron-Trigger: die fuenf Standard-Cron-Felder (Minute, Stunde, Tag, Monat, Wochentag).

    Die Feldwerte bleiben Strings (``"0"``, ``"*/6"``, ``"*"`` ...) -- genau wie
    ``_parse_trigger`` sie ungeparst an ``CronTrigger`` durchreicht (APScheduler
    interpretiert die Cron-Syntax selbst).
    """

    minute: str
    hour: str
    day: str
    month: str
    day_of_week: str


# PEP-695-Union: ein ``match`` ueber die Varianten ist mit ``assert_never``
# exhaustiv pruefbar (der Adapter in Schritt 2 konsumiert die Spec so).
type ScheduleSpec = IntervalSpec | CronSpec

# Suffix -> APScheduler-IntervalTrigger-Einheit (Altcode _parse_trigger).
_INTERVAL_UNITS = {"m": "minutes", "h": "hours", "d": "days"}
_CRON_FIELD_COUNT = 5


def parse_schedule(schedule: str) -> ScheduleSpec:
    """Parst einen Schedule-String in eine ``ScheduleSpec`` oder wirft ``ScheduleParseError``.

    Akzeptierte Formate (Altcode-treu):
      * ``"interval:<n><m|h|d>"`` -- z. B. ``"interval:30m"``, ``"interval:6h"``,
        ``"interval:1d"``. ``<n>`` muss eine positive ganze Zahl sein.
      * ``"cron:<min> <hour> <day> <month> <dow>"`` -- genau fuenf Felder, z. B.
        ``"cron:0 2 * * *"``.

    JEDER andere String (leer, falsches Praefix, fehlendes/falsches Suffix, nicht-
    numerischer Intervallwert, falsche Cron-Feldzahl) wirft ``ScheduleParseError``
    -- KEIN stiller 24h-Fallback (S3-Fix, siehe Modul-Docstring).
    """
    if schedule.startswith("interval:"):
        return _parse_interval(schedule[len("interval:") :], schedule)
    if schedule.startswith("cron:"):
        return _parse_cron(schedule[len("cron:") :], schedule)
    raise ScheduleParseError(schedule)


def _parse_interval(spec: str, original: str) -> IntervalSpec:
    if not spec:
        raise ScheduleParseError(original)
    suffix = spec[-1]
    unit = _INTERVAL_UNITS.get(suffix)
    if unit is None:
        # Kein/ falsches Einheiten-Suffix (z. B. ``interval:30`` ohne m/h/d).
        raise ScheduleParseError(original)
    raw_value = spec[:-1]
    try:
        value = int(raw_value)
    except ValueError as exc:
        # Nicht-numerischer Wert (Altcode: roher ValueError in _register_job).
        raise ScheduleParseError(original) from exc
    if value <= 0:
        # BEWUSSTE v2-ABWEICHUNG vom Altcode (kein Charakterisierer deckt diesen
        # Pfad -- _parse_trigger lief nur im ungetesteten _register_job): Der Altcode
        # baute aus ``interval:0m`` ein ``IntervalTrigger(minutes=0)``, das
        # APScheduler klaglos zu einem 1-SEKUNDEN-Dauerfeuer macht (empirisch
        # belegt: interval[0:00:01]); negative Werte ergaben ein undefiniertes
        # negatives Intervall. Beides ist kein sinnvoller Scan-Schedule -- ein
        # Sekundentakt-Scan haemmert das Netz. v2 lehnt ``value <= 0`` daher ab
        # (ScheduleParseError) statt das gefaehrliche Dauerfeuer-Verhalten zu
        # zementieren. Bewusst markiert (nicht als "Ergaenzung" getarnt).
        raise ScheduleParseError(original)
    return IntervalSpec(unit=unit, value=value)


def _parse_cron(expr: str, original: str) -> CronSpec:
    parts = expr.split()
    if len(parts) != _CRON_FIELD_COUNT:
        # Falsche Feldzahl (Altcode: stiller 24h-Fallback).
        raise ScheduleParseError(original)
    minute, hour, day, month, day_of_week = parts
    return CronSpec(minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week)
