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
        case "host_remote_port":
            return _eval_host_remote_port(rule, snapshot)
        case "host_new":
            return _eval_host_new(rule, snapshot)


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
                kind=rule.kind,
            )
        )
    return out


def _eval_process_masquerade(rule: Rule, snapshot: Snapshot) -> list[Observation]:
    """Treffer, wenn ein USERLAND-Prozess wie Kernel-Infrastruktur aussieht -- rechte-bewusst.

    Tarnverdacht-Ausloeser fuer einen Userland-Prozess (``kind != "kernel"``), beide
    DISJUNKT zu ``process_temp_path`` (liegt der ``exe_path`` unter einem temp-Praefix,
    ist (a) zustaendig und diese Regel schweigt -- ein /tmp-Prozess erzeugt nie zwei):

    * (i) leeres ``cmdline`` -> IMMER ein Treffer (in beiden Modi rootless wie Root
      verlaesslich). Severity: ``info`` (= ``rule.severity``).
    * (ii) fehlender ``exe_path`` (None) -> Treffer NUR bei voller Prozess-Sicht
      (``snapshot.full_process_visibility``). Unter Root DARF jeder Pfad gelesen werden;
      fehlt er trotzdem, ist das ein echtes, staerkeres Signal (z. B. geloeschtes Binary)
      -> Severity ``notable`` (faellt auf), explizit in der Auswertung gesetzt (nicht
      ``rule.severity``, das ist der info-Default fuer (i)). Rootless
      (``full_process_visibility`` False) ist ein fehlender Pfad mehrdeutig (evtl. nur
      fehlende Leserechte) -> KEIN Treffer fuer (ii) (zu mehrdeutig, Vision 4.4: kein
      Anschwaerzen von Harmlosem).

    Echte Kernel-Threads sind ausgeschlossen (``kind == "kernel"`` greift VOR dem
    Pfad-Check) -- ihr leeres ``cmdline``/fehlender Pfad ist Natur.

    PRIORITAET bei beiden Ausloegern (leeres cmdline UND exe_path None unter Root): genau
    EINE Beobachtung, der staerkere Fall (ii) ``notable`` gewinnt. Rootless faellt (ii)
    weg, dann greift (i) ``info``. Reihenfolge/Determinismus unveraendert -- die Engine
    sortiert am Ende global.
    """
    out: list[Observation] = []
    for proc in snapshot.processes:
        if proc.kind == "kernel":
            continue
        path = proc.exe_path
        # Disjunktheit: ein temp-Pfad-Prozess gehoert (a), nicht hierher.
        if path is not None and any(path.startswith(prefix) for prefix in rule.path_prefixes):
            continue
        # (ii) kein Pfad -- nur unter voller Sicht (Root) ein verlaessliches Signal; dann
        # staerker als ein leeres cmdline -> notable. Prioritaet vor (i).
        if path is None and snapshot.full_process_visibility:
            value = "keinen erkennbaren Programmpfad"
            severity: Severity = "notable"
        # (i) leeres cmdline -- in beiden Modi verlaesslich -> info (rule.severity).
        elif not proc.cmdline:
            value = "eine leere Kommandozeile"
            severity = rule.severity
        else:
            continue
        subject = f"pid {proc.pid}"
        out.append(
            Observation(
                rule_id=rule.id,
                severity=severity,
                title=rule.title,
                detail=rule.detail_template.format(subject=subject, value=value),
                help_kind=rule.help_kind,
                subject=subject,
                kind=rule.kind,
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
                kind=rule.kind,
            )
        )
    return out


def _eval_host_remote_port(rule: Rule, snapshot: Snapshot) -> list[Observation]:
    """Treffer je HOST, der mindestens einen Port aus ``rule.ports`` offen haelt.

    Geraeteseitiges Gegenstueck zur Verbindungs-Regel ``connection_remote_port``: dort
    sieht die Engine eine VERBINDUNG zu einem Fernzugriffs-Port, hier ein GERAET, das so
    einen Port OFFEN anbietet (Stand letzter Scan, aus den projizierten Hosts).

    BUENDELUNG: pro Host genau EINE Beobachtung -- nicht eine je getroffenem Port. Sonst
    wuerde dasselbe Geraet mehrfach gemeldet. Die getroffenen Ports (Schnittmenge
    ``host.open_ports & rule.ports``) werden aufsteigend sortiert, kommagetrennt in den
    ``{value}``-Platzhalter gebuendelt (z. B. "22, 3389"). ``subject`` ist die Host-ip.

    Leere Schnittmenge -> kein Treffer fuer den Host. Hosts ohne ip (leerer String)
    werden uebersprungen (kein sinnvolles subject). Deterministisch: Hosts in
    Snapshot-Reihenfolge; die Engine sortiert am Ende ohnehin global nach
    (severity, rule_id, subject).
    """
    out: list[Observation] = []
    for host in snapshot.hosts:
        if not host.ip:
            continue
        matched = host.open_ports & rule.ports
        if not matched:
            continue
        value = ", ".join(str(port) for port in sorted(matched))
        subject = host.ip
        out.append(
            Observation(
                rule_id=rule.id,
                severity=rule.severity,
                title=rule.title,
                detail=rule.detail_template.format(subject=subject, value=value),
                help_kind=rule.help_kind,
                subject=subject,
                kind=rule.kind,
            )
        )
    return out


def _eval_host_new(rule: Rule, snapshot: Snapshot) -> list[Observation]:
    """Treffer je HOST, der im Netz ERSTMALS auftaucht (``is_known == False``).

    analysis' erstes GEDAECHTNIS -- aber die Engine bleibt ZUSTANDSLOS: ``is_known`` ist
    ein SNAPSHOT-FAKTUM (ein ``bool`` je ``ObservedHost``), das die Projektion in der
    Composition Root (C.2) aus dem Host-Historie-Repository gefuellt hat. Die Engine kennt
    KEIN Repository, KEINE Persistenz -- sie wertet nur das bool aus, GENAU wie
    ``full_process_visibility`` bei ``process_masquerade``. So bleibt die deterministische
    analysis-Engine rein.

    Treffer fuer jeden Host mit ``is_known == False`` UND nicht-leerer ``ip``. ``subject``
    ist die Host-ip; das ``detail_template`` nutzt NUR ``{subject}`` (kein ``{value}``) --
    darum genuegt ``.format(subject=...)``. Bekannte Hosts (``is_known == True``, der
    zurueckhaltende Default) ODER Hosts ohne ip (leerer String, kein sinnvolles subject)
    treffen NICHT. Deterministisch: Hosts in Snapshot-Reihenfolge; die Engine sortiert am
    Ende ohnehin global nach ``(severity, rule_id, subject)``.
    """
    out: list[Observation] = []
    for host in snapshot.hosts:
        if host.is_known or not host.ip:
            continue
        subject = host.ip
        out.append(
            Observation(
                rule_id=rule.id,
                severity=rule.severity,
                title=rule.title,
                detail=rule.detail_template.format(subject=subject),
                help_kind=rule.help_kind,
                subject=subject,
                kind=rule.kind,
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
                kind=rule.kind,
            )
        )
    return out
