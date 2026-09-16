"""Regel-Auswahl der alerting-Domaene -- reine, deterministische Logik.

Verhaltensgleich aus dem Altcode portiert (``modules/alerting.py``, ``fire_alert``
Z.284-294): stdlib only, kein I/O, kein Framework, kein SMTP/osascript, kein
Import aus anderen Domaenen.

Die Extraktion zieht NUR die AUSWAHL heraus -- WELCHE Regeln feuern sollen --, NICHT
das Feuern (Notification) und NICHT den History-Write. Das Feuern/Persistieren macht
der Use-Case (A.5) ueber Ports; die Domaene bleibt seiteneffektfrei.

Seiteneffektfrei heisst hier insbesondere: KEINE Uhr im Inneren. ``now`` wird als
Parameter hereingegeben (wie in monitoring die Zeit ueber Port/Parameter kam), damit
die Funktion deterministisch testbar ist.

Die vier Filterstufen (1:1 Altcode-Reihenfolge) + Cooldown-Floor:

    1. enabled:    ``not rule.enabled``                      -> raus
    2. rule_type:  ``rule.rule_type != rule_type``           -> raus (exakter Vergleich)
    3. target:     ``rule.target != "any" and != target``    -> raus ("any" matcht alles)
    4. Cooldown:   ``now - last_triggered < max(threshold, 60)`` -> raus (STRIKT <)

Der Cooldown-Floor ``max(threshold, 60)`` erzwingt mindestens 60 s zwischen zwei
Feuerungen derselben Regel, auch wenn ``threshold`` kleiner ist. Der Vergleich ist
STRIKT ``<``: bei genau ``cooldown`` Sekunden Abstand feuert die Regel wieder
(Altcode-treu, in A.1 per Grenz- und Mutationstest fixiert).
"""

from collections.abc import Sequence

from domain.alerting.models import AlertRule

# Mindest-Cooldown in Sekunden (Floor): keine Regel feuert oefter als einmal pro 60 s,
# auch wenn ihr ``threshold`` kleiner ist (Altcode ``max(rule["threshold"], 60)``).
COOLDOWN_FLOOR_SECONDS = 60


def select_rules_to_fire(
    rules: Sequence[AlertRule],
    rule_type: str,
    target: str,
    now: float,
) -> list[AlertRule]:
    """Waehlt die Regeln aus, die fuer ein Ereignis feuern sollen -- reine Auswahl.

    Wendet die vier Altcode-Filterstufen in exakter Reihenfolge an und beruecksichtigt
    den Cooldown-Floor. Gibt die feuerbereiten Regeln in Eingangsreihenfolge zurueck;
    feuert NICHT und schreibt NICHTS (das macht der A.5-Use-Case).

    ``rule_type``/``target`` sind die Werte des ausgeloesten Ereignisses; ``now`` ist
    der aktuelle Unix-Timestamp (von aussen hereingegeben, keine Uhr in der Domaene).
    """
    selected: list[AlertRule] = []
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.rule_type != rule_type:
            continue
        if rule.target != "any" and rule.target != target:
            continue
        cooldown = max(rule.threshold, COOLDOWN_FLOOR_SECONDS)
        if now - rule.last_triggered < cooldown:
            continue
        selected.append(rule)
    return selected
