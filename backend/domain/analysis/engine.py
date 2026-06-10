"""Die RuleEngine der analysis-Domaene -- eine reine, deterministische Funktion.

Kein I/O, keine Uhr, kein Framework (ADR 0002). ``evaluate`` ist der EINZIGE Ort mit
Auswertungslogik: ``Rule`` bleibt reines Datum (siehe ``rules.py``), die Interpretation
des deklarativen ``kind``-Feldes liegt hier in einem Dispatch pro Regel-``kind``. Eine
neue Regel-Art bedeutet genau einen neuen Dispatch-Zweig; eine neue konkrete Regel
braucht hier gar nichts (nur ein neues Daten-Objekt).

ROTE LINIE -- die Engine ordnet ein, sie urteilt nicht: sie erzeugt nur ``Observation``s
aus den vorhandenen Regeln und sortiert sie deterministisch.
"""

from collections.abc import Sequence

from domain.analysis.models import Snapshot
from domain.analysis.rules import Observation, Rule, Severity

# Sortier-Rang der Severity: "notable" (faellt auf) vor "info". KEINE Wertung -- nur
# eine stabile, dokumentierte Ordnung, damit die Ausgabe deterministisch ist.
_SEVERITY_RANK: dict[Severity, int] = {"notable": 0, "info": 1}


def evaluate(snapshot: Snapshot, rules: Sequence[Rule]) -> list[Observation]:
    """Wendet jede Regel auf den Snapshot an und liefert sortierte Beobachtungen -- rein.

    Deterministisch: gleiche Eingabe -> gleiche Ausgabe. Die Beobachtungen werden nach
    dem stabilen Schluessel ``(severity-Rang, rule_id, subject)`` aufsteigend sortiert.
    Ein leerer Snapshot oder ein nicht-treffender Regelsatz liefert ``[]``. Kein I/O,
    keine Uhr.
    """
    observations: list[Observation] = []
    for rule in rules:
        observations.extend(_apply_rule(rule, snapshot))
    observations.sort(key=lambda obs: (_SEVERITY_RANK[obs.severity], obs.rule_id, obs.subject))
    return observations


def _apply_rule(rule: Rule, snapshot: Snapshot) -> list[Observation]:
    """Dispatch ueber das deklarative ``rule.kind`` -- der einzige Auswertungs-Schalter.

    Ein unbekanntes ``kind`` ist (mypy-strict deckt die Vollstaendigkeit ab) ein Fehler
    in der Regel-Definition, kein stiller Rueckfall: wir lassen es laut auflaufen.
    """
    match rule.kind:
        case "process_temp_path":
            return _eval_process_temp_path(rule, snapshot)
        case "process_masquerade":
            return _eval_process_masquerade(rule, snapshot)
        case "connection_remote_port":
            return _eval_connection_remote_port(rule, snapshot)
        case "pid_connection_count":
            return _eval_pid_connection_count(rule, snapshot)


def _eval_process_temp_path(rule: Rule, snapshot: Snapshot) -> list[Observation]:
    """Treffer, wenn ein USERLAND-Prozess einen ``exe_path`` unter einem Praefix hat.

    Echte Kernel-Threads (``kind == "kernel"``) sind ausgeschlossen -- ihr fehlender Pfad
    ist Natur, kein Verhalten. Ein fehlender ``exe_path`` (None) loest hier NICHT aus
    (das ist der Tarnverdacht-Fall ``process_masquerade``) -- die beiden Faelle sind
    disjunkt.
    """
    out: list[Observation] = []
    for proc in snapshot.processes:
        if proc.kind == "kernel":
            continue
        path = proc.exe_path
        if path is None or not any(path.startswith(prefix) for prefix in rule.path_prefixes):
            continue
        subject = f"pid {proc.pid}"
        out.append(
            Observation(
                rule_id=rule.id,
                severity=rule.severity,
                title=rule.title,
                detail=rule.detail_template.format(subject=subject, value=path),
                help_kind=rule.help_kind,
                subject=subject,
            )
        )
    return out


def _eval_process_masquerade(rule: Rule, snapshot: Snapshot) -> list[Observation]:
    """Treffer, wenn ein USERLAND-Prozess wie Kernel-Infrastruktur aussieht.

    Tarnverdacht: leeres ``cmdline`` ODER fehlender ``exe_path`` (None), OBWOHL der Prozess
    Userland ist (``kind != "kernel"``). Echte Kernel-Threads sind ausgeschlossen -- ihr
    leeres ``cmdline``/fehlender Pfad ist Natur. DISJUNKT zu ``process_temp_path``: liegt
    der ``exe_path`` unter einem temp-Praefix, ist (a) zustaendig und (a2) schweigt -- so
    erzeugt ein /tmp-Prozess genau EINE Beobachtung, nie zwei.
    """
    out: list[Observation] = []
    for proc in snapshot.processes:
        if proc.kind == "kernel":
            continue
        path = proc.exe_path
        # Disjunktheit: ein temp-Pfad-Prozess gehoert (a), nicht hierher.
        if path is not None and any(path.startswith(prefix) for prefix in rule.path_prefixes):
            continue
        if path is None:
            value = "keinen erkennbaren Programmpfad"
        elif not proc.cmdline:
            value = "eine leere Kommandozeile"
        else:
            continue
        subject = f"pid {proc.pid}"
        out.append(
            Observation(
                rule_id=rule.id,
                severity=rule.severity,
                title=rule.title,
                detail=rule.detail_template.format(subject=subject, value=value),
                help_kind=rule.help_kind,
                subject=subject,
            )
        )
    return out


def _eval_connection_remote_port(rule: Rule, snapshot: Snapshot) -> list[Observation]:
    """Treffer, wenn der ``remote_port`` einer Verbindung in ``rule.ports`` liegt."""
    out: list[Observation] = []
    for conn in snapshot.connections:
        port = conn.remote_port
        if port is None or port not in rule.ports:
            continue
        # subject als ip:port, falls die IP bekannt ist -- sonst nur der Port.
        subject = f"{conn.remote_ip}:{port}" if conn.remote_ip else f"port {port}"
        out.append(
            Observation(
                rule_id=rule.id,
                severity=rule.severity,
                title=rule.title,
                detail=rule.detail_template.format(subject=subject, value=port),
                help_kind=rule.help_kind,
                subject=subject,
            )
        )
    return out


def _eval_pid_connection_count(rule: Rule, snapshot: Snapshot) -> list[Observation]:
    """Treffer je pid, dessen Anzahl Verbindungen die Schwelle STRIKT ueberschreitet.

    Verbindungen ohne pid (``None``) werden nicht gezaehlt -- sie lassen sich keinem
    Prozess zuordnen. Die Ausgabe ist deterministisch nach pid sortiert (die Engine
    sortiert am Ende ohnehin nach subject, aber wir bleiben hier schon geordnet).
    """
    counts: dict[int, int] = {}
    for conn in snapshot.connections:
        if conn.pid is None:
            continue
        counts[conn.pid] = counts.get(conn.pid, 0) + 1
    out: list[Observation] = []
    for pid in sorted(counts):
        count = counts[pid]
        if count <= rule.threshold:
            continue
        subject = f"pid {pid}"
        out.append(
            Observation(
                rule_id=rule.id,
                severity=rule.severity,
                title=rule.title,
                detail=rule.detail_template.format(subject=subject, value=count),
                help_kind=rule.help_kind,
                subject=subject,
            )
        )
    return out
