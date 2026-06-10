"""Eingabe-Modelle der analysis-Domaene -- analysis' eigene, entkoppelte Sicht.

Reine Wertobjekte (stdlib + dataclasses, ADR 0002): kein I/O, keine Uhr, kein
Framework. analysis ist die interpretierende Domaene -- sie nimmt einen neutralen
Schnappschuss der Lage und laesst Regeln darueber laufen (siehe ``rules.py`` und
``engine.py``).

BEWUSST eigene Typen (independence-Contract): analysis importiert KEINE andere
domain-Subdomaene. Statt ``domain.traffic.Connection`` / ``domain.process.ProcessInfo``
/ ``domain.scanning.EnrichedHost`` zu verwenden, definiert analysis hier schlanke
eigene Eingabe-Typen mit genau den Feldern, die die Regeln brauchen. Die Projektion
aus den echten Fremd-Objekten in diese Sicht passiert spaeter im application-Ring --
NICHT hier (sonst koppelte analysis an Schwester-Domaenen, was der
independence-Contract maschinell verbietet).
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ObservedConnection:
    """Eine beobachtete Netzwerk-Verbindung -- analysis' Sicht (entkoppelt von traffic).

    Nur die Felder, die Regeln brauchen. ``app_name``/``pid``/``remote_ip``/
    ``remote_port`` sind ehrlich ``None``, wenn die Quelle sie nicht kennt -- KEIN
    erfundener Wert. ``l4`` ist das Transportprotokoll (z. B. "tcp"/"udp"),
    ``status`` der Verbindungszustand (z. B. "ESTABLISHED").
    """

    app_name: str | None = None
    pid: int | None = None
    remote_ip: str | None = None
    remote_port: int | None = None
    l4: str = ""
    status: str = ""


@dataclass(frozen=True)
class ObservedProcess:
    """Ein beobachteter Prozess -- analysis' Sicht (entkoppelt von process).

    ``pid`` ist immer vorhanden, ``name`` nie ``None`` (nicht lesbar -> ""). ``kind`` ist
    die kernel/userland-Einordnung (von der Projektion aus ``domain.process.classify_kind``
    gefuellt); echte Kernel-Threads werden von der Auffaelligkeits-Regel uebersprungen, weil
    ihr fehlender ``exe_path`` Natur ist, kein Verhalten. Bewusst als ``str`` modelliert
    (Werte "kernel"|"userland"), damit analysis NICHT den ``ProcessKind``-Typ aus
    ``domain.process`` importieren muss (independence-Contract). Default ``"userland"``: ein
    nicht gesetztes ``kind`` soll NICHT faelschlich als kernel ausgeblendet werden ("im
    Zweifel sichtbar/Userland"). ``exe_path`` ist der Pfad zum ausgefuehrten Programm und
    ehrlich ``None``, wenn nicht ermittelbar -- die Regeln unterscheiden bewusst zwischen
    "kein Pfad" (None) und einem konkreten Pfad. ``cmdline`` ist die Argumentliste (leeres
    Tuple = nicht lesbar).
    """

    pid: int
    name: str = ""
    kind: str = "userland"
    exe_path: str | None = None
    cmdline: tuple[str, ...] = ()


@dataclass(frozen=True)
class ObservedHost:
    """Ein beobachteter Host -- analysis' Sicht (entkoppelt von scanning).

    ``open_ports`` sind die Portnummern, deren Port-Zustand "open" ist -- BEWUSST nur
    die Nummern (``frozenset[int]``), nicht die vollen ``PortInfo``-Objekte aus scanning:
    analysis braucht fuer host-Regeln nur die Nummern, und so bleibt die Sicht entkoppelt
    (kein ``PortInfo``-Import -> independence-Contract). Die Projektion (Composition Root)
    filtert ``state == "open"`` und nimmt nur die port-Nummern.
    """

    ip: str
    hostname: str = ""
    vendor: str = ""
    open_ports: frozenset[int] = frozenset()


@dataclass(frozen=True)
class Snapshot:
    """analysis' GESAMTE Sicht auf die Lage zu einem Zeitpunkt -- ein neutraler Schnitt.

    Ein Schnappschuss buendelt die drei beobachteten Mengen (Verbindungen, Prozesse,
    Hosts), ueber die die RuleEngine deklarative Regeln laufen laesst. Jede Menge ist
    per Default leer -- ein leerer Snapshot ist gueltig und liefert keine Beobachtungen.
    Die Befuellung (Projektion aus traffic/process/scanning) ist Sache des
    application-Rings, nicht der Domaene.

    ``full_process_visibility`` sagt, ob die Prozess-Detailfelder vollstaendig lesbar
    sind (Root). Es steuert, ob die ``process_masquerade``-Regel den "kein exe_path"-Fall
    als Signal wertet (nur bei voller Sicht verlaesslich -- Root DARF jeden Pfad lesen,
    fehlt er trotzdem, ist das echt auffaellig); rootless ist ein fehlender Pfad
    mehrdeutig (evtl. nur fehlende Leserechte). KEIN Urteil, nur Kontext. Bewusst als
    ``bool``, NICHT als Permission-Port -- analysis bleibt entkoppelt (independence-
    Contract); die Composition Root fuellt es aus dem bestehenden
    ``CheckProcessPermission``-Ergebnis. Default ``False``: "im Zweifel rootless", also
    der zurueckhaltende Modus.
    """

    connections: tuple[ObservedConnection, ...] = field(default_factory=tuple)
    processes: tuple[ObservedProcess, ...] = field(default_factory=tuple)
    hosts: tuple[ObservedHost, ...] = field(default_factory=tuple)
    full_process_visibility: bool = False
