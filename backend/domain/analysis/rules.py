"""Regel- und Ergebnis-Vokabular der analysis-Domaene -- Regeln ALS DATEN.

Reine Domaenenlogik (stdlib + dataclasses + typing, ADR 0002): kein I/O, keine Uhr,
kein Framework. PEP-695-``type``-Aliase fuer die Literal-Unions wie im uebrigen
domain-Ring (process/traffic/scanning).

ROTE LINIE -- analysis urteilt NIE. Eine ``Observation`` ist eine wertneutrale
Beobachtung MIT Kontext, OHNE Urteil. Darum hat ``Severity`` BEWUSST nur zwei neutrale
Stufen: "info" und "notable" ("faellt auf") -- KEIN "gefaehrlich"/"sicher". ``help_kind``
ist ein stabiler Schluessel auf einen Hilfe-Typ, KEINE URL (die URL ist spaeter
Infrastruktur).

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
]

# BEWUSST nur zwei neutrale Stufen -- analysis urteilt nie. "info" = reine Einordnung,
# "notable" = "faellt auf" (NICHT "gefaehrlich"). Kein "sicher"/"unsicher".
type Severity = Literal["info", "notable"]

# Das deklarative Praedikat einer Regel -- WELCHE Art Pruefung die Engine anwendet.
# Eine neue ``kind`` ist die einzige Stelle, die einen neuen Dispatch-Zweig in
# ``engine.evaluate`` rechtfertigt. Die konkreten Schwellen/Mengen/Praefixe sind
# Parameter am ``Rule``-Objekt (Daten), keine Literale im Kern.
type RuleKind = Literal[
    "process_temp_path",
    "process_masquerade",
    "connection_remote_port",
    "pid_connection_count",
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
