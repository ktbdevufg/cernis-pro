"""Uebergangs-Erkennung der monitoring-Domaene -- reine, deterministische Logik.

Verhaltensgleich aus dem Altcode portiert (``modules/monitor.py``, run_monitor
Z.250-262): stdlib only, kein I/O, kein Framework, kein subprocess/osascript,
kein Import aus anderen Domaenen.

Die Extraktion trennt ZWEI Belange, die im Altcode in EINEM if/elif-Baum
verwoben waren:

1. ``classify_transition`` -- bestimmt NUR den Event-Typ (oder ``None`` = kein
   Event). Reine Klassifikation, keine Notification, kein State-Write.
2. ``should_notify`` -- separates reines Praedikat fuer die Notification-Regel.
   Der Altcode rief ``_notify_macos`` INLINE in genau zwei Zweigen auf
   (up->down-Flanke und down->up-Flanke), NICHT bei der Erstmessung
   (``prev is None``) und NICHT bei ``degraded``. Diese Regel ist hier als
   typsicheres, testbares Praedikat herausgezogen; der Loop (M.5) ruft erst
   ``classify_transition``, dann ``should_notify`` und fuehrt die Notification
   ueber einen Notifier-Port (M.3) aus -- die Domaene bleibt seiteneffektfrei.

Die vollstaendige Wahrheitstabelle (empirisch gegen den Altcode belegt), mit den
zwei nicht-offensichtlichen Regeln:

    prev   now    loss>30  -> event
    None   True   -        -> up
    None   False  -        -> down
    True   False  -        -> down
    False  True   -        -> up        (auch bei loss>30: up ueberschattet degraded)
    True   True   nein     -> None
    True   True   JA       -> degraded  (NUR hier feuert degraded)
    False  False  -        -> None      (dauerhaft-ab erzeugt KEIN Event)
"""

from domain.monitoring.models import MonitorEventType


def classify_transition(
    prev: bool | None,
    now: bool,
    loss_pct: float,
) -> MonitorEventType | None:
    """Bestimmt den Uebergangs-Typ aus Vorzustand, Jetzt-Zustand und Verlustrate.

    ``prev`` ist der zuletzt bekannte alive-Zustand (``None`` = noch nie gemessen).
    Gibt ``None`` zurueck, wenn kein Uebergang vorliegt (stabil up ohne Degradation,
    oder dauerhaft down). Die if/elif-Reihenfolge ist 1:1 der Altcode-Reihenfolge --
    sie ist signifikant: der up/down-Flanken-Check ueberschattet den degraded-Check,
    weshalb degraded NUR bei stabilem up (prev=True, now=True) mit ``loss_pct > 30``
    erkannt wird.
    """
    if prev is None:
        # Erstmessung: up wenn lebendig, sonst down.
        return MonitorEventType.UP if now else MonitorEventType.DOWN
    if prev and not now:
        # Flanke up -> down.
        return MonitorEventType.DOWN
    if not prev and now:
        # Flanke down -> up. Ueberschattet den degraded-Zweig (auch bei loss>30).
        return MonitorEventType.UP
    if now and loss_pct > 30:
        # Stabil up, aber > 30 % Verlust -> degraded. Einziger degraded-Pfad.
        return MonitorEventType.DEGRADED
    # Stabil up ohne Degradation ODER dauerhaft down -> kein Event.
    return None


def should_notify(prev: bool | None, event: MonitorEventType | None) -> bool:
    """Praedikat: soll der Loop fuer diesen Uebergang eine Notification ausloesen?

    Bildet die Altcode-Inline-Regel exakt ab: ``_notify_macos`` lief NUR in der
    up->down- und der down->up-Flanke -- also wenn es einen Vorzustand gab
    (``prev is not None``, keine Erstmessung) UND das Event ``up`` oder ``down``
    ist. Bei der Erstmessung (``prev is None``) und bei ``degraded`` gab es im
    Altcode keine Notification.
    """
    if prev is None:
        return False
    return event in (MonitorEventType.UP, MonitorEventType.DOWN)
