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
    "process_path_prefix",
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
      (z. B. /tmp, /dev/shm, /var/tmp). Genutzt von ``kind="process_path_prefix"``;
      diese Pruefung schlaegt zusaetzlich an, wenn ``exe_path`` ganz fehlt (``None``).
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


# Die drei Start-Regeln als Daten. Schwellen/Portlisten/Pfad-Praefixe sind hier
# REGEL-PARAMETER, keine Literale im Engine-Kern -- eine vierte Regel ist ein weiterer
# Eintrag in diesem Tuple (oder eine zur Laufzeit uebergebene Regel), nichts weiter.
DEFAULT_RULES: tuple[Rule, ...] = (
    # (a) Prozess ohne erkennbaren exe_path ODER exe_path unter einem temporaeren Praefix.
    Rule(
        id="process_suspicious_path",
        severity="notable",
        help_kind="process_suspicious_path",
        kind="process_path_prefix",
        title="Prozess laeuft aus einem ungewoehnlichen Pfad",
        detail_template="Prozess {subject} hat keinen erkennbaren Programmpfad "
        "oder laeuft aus einem temporaeren Verzeichnis ({value}).",
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
