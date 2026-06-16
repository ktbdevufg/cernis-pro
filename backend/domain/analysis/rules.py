"""Regel- und Ergebnis-Vokabular der analysis-Domaene -- Regeln ALS DATEN.

Reine Domaenenlogik (stdlib + dataclasses + typing, ADR 0002): kein I/O, keine Uhr,
kein Framework. PEP-695-``type``-Aliase fuer die Literal-Unions wie im uebrigen
domain-Ring (process/traffic/scanning).

ROTE LINIE -- analysis urteilt NIE. Eine ``Observation`` ist eine wertneutrale
Beobachtung MIT Kontext, OHNE Urteil. ``Severity`` hat drei Stufen der Auffaelligkeit:
"info" (reine Einordnung), "notable" ("faellt auf") und "critical" (staerkste Stufe fuer
die Auffaelligkeits-Engine) -- KEIN "gefaehrlich"/"sicher", "critical" ist die staerkste
Auffaelligkeit, kein moralisches Urteil. Reihenfolge der Staerke: critical > notable >
info. ``help_kind`` ist ein stabiler Schluessel auf einen Hilfe-Typ, KEINE URL (die URL
ist spaeter Infrastruktur).

REGELN ALS DATEN -- jede Regel ist ein ``Rule``-Datenobjekt mit einem deklarativen
``kind``-Feld plus Parametern (Portmengen, Schwellen, Pfad-Praefixe). Die Bedingung
steckt NICHT als Lambda in der Regel, sondern wird von ``engine.evaluate`` anhand des
``kind`` interpretiert. Folge: eine neue Regel ist ein neues Daten-Objekt in
``DEFAULT_RULES`` (oder eine zur Laufzeit uebergebene Regel), KEINE neue
Code-Verzweigung im Domaenen-Kern -- bis auf ein wirklich neues ``kind``, das genau
einen neuen Dispatch-Zweig in der Engine bekommt.
"""

from dataclasses import dataclass, field
from typing import Literal

# Stabiler Schluessel auf einen Hilfe-Typ. KEINE URL -- die Aufloesung in eine konkrete
# Hilfe-Quelle ist spaeter Infrastruktur. Eine neue Regel-Art bringt einen neuen
# Schluessel mit.
type HelpKind = Literal[
    "process_suspicious_path",
    "process_masquerade",
    "remote_access_port",
    "high_connection_count",
    "new_host",
]

# Drei Stufen der Auffaelligkeit -- analysis urteilt nie. "info" = reine Einordnung,
# "notable" = "faellt auf", "critical" = staerkste Stufe (bewertend, fuer die
# Auffaelligkeits-Engine). KEIN "sicher"/"unsicher": "critical" ist die staerkste
# Auffaelligkeit, kein moralisches Urteil. Reihenfolge der Staerke: critical > notable
# > info. Die Stufe wird hier nur EINGEFUEHRT -- keine Built-in-Regel setzt sie aktuell.
type Severity = Literal["info", "notable", "critical"]

# Das deklarative Praedikat einer Regel -- WELCHE Art Pruefung die Engine anwendet.
# Eine neue ``kind`` ist die einzige Stelle, die einen neuen Dispatch-Zweig in
# ``engine.evaluate`` rechtfertigt. Die konkreten Schwellen/Mengen/Praefixe sind
# Parameter am ``Rule``-Objekt (Daten), keine Literale im Kern.
type RuleKind = Literal[
    "process_temp_path",
    "process_masquerade",
    "connection_remote_port",
    "pid_connection_count",
    "host_remote_port",
    "host_new",
]


@dataclass(frozen=True)
class Observation:
    """Eine wertneutrale Beobachtung MIT Kontext, OHNE Urteil (frozen).

    ``subject`` benennt das beobachtete Objekt menschenlesbar und stabil (z. B.
    "pid 1234" oder "1.2.3.4:5900") -- es geht in den deterministischen Sortier- und
    Dedup-Schluessel der Engine ein. ``help_kind`` verweist auf den passenden Hilfe-Typ.
    """

    rule_id: str
    severity: Severity
    title: str
    detail: str
    help_kind: HelpKind
    subject: str
    # kind der erzeugenden Regel -- erlaubt Konsumenten, Host- von Verbindungs-/Prozess-
    # Befunden zu unterscheiden, ohne rule_id-Listen zu pflegen.
    kind: RuleKind


@dataclass(frozen=True)
class Rule:
    """Eine Regel ALS DATEN -- deklarative Bedingung, von der Engine interpretiert (frozen).

    ``kind`` waehlt die Pruefart; die uebrigen Felder sind ihre Parameter:

    * ``path_prefixes`` -- Praefixe, unter denen ein ``exe_path`` als auffaellig gilt
      (z. B. /tmp, /dev/shm, /var/tmp). Genutzt von ``kind="process_temp_path"`` (Treffer
      nur fuer Userland-Prozesse, deren ``exe_path`` unter einem dieser Praefixe liegt).
      ``kind="process_masquerade"`` nutzt dieselben Praefixe NUR zur Abgrenzung (ein
      temp-Pfad-Prozess loest dort NICHT zusaetzlich aus -- die Faelle sind disjunkt).
    * ``ports`` -- Portmenge, deren ``remote_port`` als auffaellig gilt (z. B.
      Fernzugriffs-Ports). Genutzt von ``kind="connection_remote_port"``.
    * ``threshold`` -- Schwelle fuer die Anzahl aktiver Verbindungen je pid. Genutzt von
      ``kind="pid_connection_count"`` (Treffer, wenn die Anzahl die Schwelle
      UEBERSCHREITET, also strikt groesser ist).

    ``title``/``detail_template`` liefern den menschenlesbaren Text der erzeugten
    ``Observation``. ``detail_template`` darf die Platzhalter ``{subject}`` und
    ``{value}`` enthalten (``value`` z. B. der konkrete Port bzw. die Verbindungszahl);
    die Engine fuellt sie. Templates statt fertiger Saetze halten die Regel reines Datum.
    """

    id: str
    severity: Severity
    help_kind: HelpKind
    kind: RuleKind
    title: str
    detail_template: str
    path_prefixes: tuple[str, ...] = ()
    ports: frozenset[int] = field(default_factory=frozenset)
    threshold: int = 0


# Die Start-Regeln als Daten. Schwellen/Portlisten/Pfad-Praefixe sind hier
# REGEL-PARAMETER, keine Literale im Engine-Kern -- eine weitere Regel ist ein weiterer
# Eintrag in diesem Tuple (oder eine zur Laufzeit uebergebene Regel), nichts weiter.
DEFAULT_RULES: tuple[Rule, ...] = (
    # (a) Userland-Prozess, dessen exe_path unter einem temporaeren Praefix liegt.
    # Echte Kernel-Threads (kind=="kernel") sind ausgeschlossen -- ihr fehlender Pfad ist
    # Natur, kein Verhalten (siehe engine._eval_process_temp_path). DISJUNKT zu (b): ein
    # temp-Pfad-Prozess loest NUR hier aus, nicht zusaetzlich als Tarnverdacht.
    Rule(
        id="process_temp_path",
        severity="notable",
        help_kind="process_suspicious_path",
        kind="process_temp_path",
        title="Prozess laeuft aus einem temporaeren Verzeichnis",
        detail_template="Prozess {subject} laeuft aus einem temporaeren Verzeichnis ({value}).",
        path_prefixes=("/tmp/", "/dev/shm/", "/var/tmp/"),
    ),
    # (a2) Userland-Prozess, der sich wie Kernel-Infrastruktur tarnt: leeres cmdline ODER
    # fehlender exe_path (None), OBWOHL er Userland ist (kind != "kernel"). Zurueckhaltend
    # ("info"): rootless ist "kein Pfad" mehrdeutig; der Root-Kontext, der das verschaerfte,
    # ist ein spaeterer Schnitt. DISJUNKT zu (a): greift NICHT, wenn der exe_path unter einem
    # temp-Praefix liegt (dann ist (a) zustaendig) -- die Praedikate ueberschneiden sich nie.
    Rule(
        id="process_masquerade",
        severity="info",
        help_kind="process_masquerade",
        kind="process_masquerade",
        title="Userland-Prozess sieht aus wie Kernel-Infrastruktur",
        detail_template="Prozess {subject} hat {value}, ist aber kein Kernel-Thread "
        "-- moeglicher Tarnverdacht.",
        path_prefixes=("/tmp/", "/dev/shm/", "/var/tmp/"),
    ),
    # (b) Verbindung zu einem typischen Fernzugriffs-Port.
    Rule(
        id="remote_access_port",
        severity="notable",
        help_kind="remote_access_port",
        kind="connection_remote_port",
        title="Verbindung zu einem Fernzugriffs-Port",
        detail_template="Verbindung zu {subject} nutzt einen typischen "
        "Fernzugriffs-Port ({value}).",
        ports=frozenset({22, 3389, 5800, 5900}),
    ),
    # (b2) Geraeteseitiges Gegenstueck zu (b): ein HOST, der einen typischen
    # Fernzugriffs-Port OFFEN haelt. Waehrend (b) eine VERBINDUNG zu so einem Port sieht
    # (live, aus traffic), sieht diese Regel ein GERAET, das so einen Port offen anbietet
    # (Stand letzter Scan, aus den gespeicherten Hosts). Dieselbe Portmenge wie (b)
    # (konsistent) und derselbe ``help_kind`` "remote_access_port" -- ein Hilfe-Link fuer
    # beide. Thematisch direkt hinter (b) gruppiert.
    Rule(
        id="host_remote_access_port",
        severity="notable",
        help_kind="remote_access_port",
        kind="host_remote_port",
        title="Host hat einen Fernzugriffs-Port offen",
        detail_template="Host {subject} hat einen typischen Fernzugriffs-Port offen ({value}).",
        ports=frozenset({22, 3389, 5800, 5900}),
    ),
    # (b3) Ein HOST, der im Netz ERSTMALS auftaucht ("seit deinem letzten Scan neu
    # dazugekommen"). analysis' erstes GEDAECHTNIS: das "schon gesehen?" kommt als FAKTUM
    # in den Snapshot (``ObservedHost.is_known``), GENAU wie ``full_process_visibility``
    # bei ``process_masquerade`` -- die Engine wertet nur das bool aus, kennt KEINE
    # Persistenz. Die Historie-Mechanik (MAC-Abgleich) lebt im Repository (infrastructure)
    # + Composition Root (C.2), NICHT hier. Eigener ``help_kind`` "new_host": ein neues
    # Geraet ist ein eigenes Thema, kein Fernzugriff. Thematisch bei den host-Regeln.
    Rule(
        id="new_host_seen",
        severity="notable",
        help_kind="new_host",
        kind="host_new",
        title="Neues Geraet im Netzwerk",
        detail_template="Host {subject} ist neu -- in frueheren Scans nicht gesehen.",
    ),
    # (c) Ein pid mit ungewoehnlich vielen aktiven Verbindungen ueber der Schwelle.
    Rule(
        id="high_connection_count",
        severity="info",
        help_kind="high_connection_count",
        kind="pid_connection_count",
        title="Ungewoehnlich viele aktive Verbindungen",
        detail_template="{subject} haelt {value} aktive Verbindungen -- mehr als ueblich.",
        threshold=50,
    ),
)
