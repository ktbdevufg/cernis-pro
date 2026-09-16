"""Domaenenmodelle der cve-Domaene -- reine, zeitfreie Datentraeger (stdlib).

Zwei Aggregate:

* ``CveFindingRecord`` -- ein PERSISTIERTER CVE-Befund pro (mac, cve_id, port). Traegt
  die NVD-Daten (aus ``CveFinding`` am security-Rand uebernommen, aber hier domain-eigen,
  KEINE Kopplung an ``ports.security``) PLUS den CERNIS-Kontext: ``mac``/``ip`` (welches
  Geraet), ``first_seen_ts`` (wann CERNIS den Befund ZUERST sah -> Grundlage fuers
  "neu"-Flag) und ``last_seen_ts`` (letzte Bestaetigung). Identitaet = (mac, cve_id, port).

* ``HostCheckState`` -- der per-Host-Pruefstand: wann zuletzt geprueft und MIT WELCHEM
  Port-Set. Grundlage der Faelligkeits-Logik (``policy.due_reason``): Fall 2 (Port-Set
  geaendert) und Fall 3 (Auffrischung ueberfaellig) lesen genau diese zwei Felder.

Beide ``frozen`` (unveraenderliche Domaenenwerte). Zeit als roher epoch-``float`` (UTC) --
die Domaene erzeugt keine Uhr, der Adapter/Use-Case reicht ``now`` herein.
"""

from dataclasses import dataclass

__all__ = ["CveFindingRecord", "HostCheckState"]


@dataclass(frozen=True)
class CveFindingRecord:
    """Ein persistierter CVE-Befund eines Hosts (Identitaet: mac + cve_id + port).

    NVD-Felder (``cve_id``..``published``) sind charakterisierungstreu zu ``CveFinding``
    (security-Rand), aber hier domaeneneigen gefuehrt -- die cve-Domaene nennt
    ``ports.security`` NIE (independence). Der Kontext (``mac``/``ip``) und die zwei
    Zeitstempel machen aus dem fluechtigen NVD-Treffer einen verfolgbaren Befund:

    * ``first_seen_ts`` -- wann CERNIS diesen (mac, cve_id, port) ZUERST sah. Bleibt beim
      Upsert UNVERAENDERT (Basis fuers is_new-Flag, ``policy.is_new``).
    * ``last_seen_ts`` -- wann der Befund zuletzt bestaetigt wurde (jeder Upsert frischt ihn).

    ``port``/``service`` verorten den Befund am offenen Port; ``severity``/``cvss_score``
    tragen die Schwere fuers spaetere farbliche Hervorheben am api-Rand.
    """

    mac: str
    cve_id: str
    port: int
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    cvss_score: float
    description: str
    url: str
    published: str
    first_seen_ts: float
    last_seen_ts: float
    ip: str = ""
    service: str = ""


@dataclass(frozen=True)
class HostCheckState:
    """Pruefstand eines Hosts: wann zuletzt geprueft (``last_checked_ts``) + geprueftes
    Port-Set (``checked_ports``).

    ``checked_ports`` ist ein ``frozenset[int]`` (Reihenfolge irrelevant, Mengenvergleich
    fuer Fall 2 "Ports geaendert"); ``frozen``-tauglich. ``last_checked_ts`` ist epoch-float.
    Ein Host, der NOCH NIE geprueft wurde, hat KEINEN ``HostCheckState`` (das Repo liefert
    ``None``) -- das ist Fall 1 (neuer Host) und wird in ``policy.due_reason`` so behandelt.
    """

    mac: str
    last_checked_ts: float
    checked_ports: frozenset[int]
