"""Domaenenmodell der diagnostics-Domaene: DNS-Aufloesung + traceroute als reine Werte.

Reine Domaenenlogik (stdlib + dataclasses, ADR 0002) -- kein Wissen ueber ``dig``,
``traceroute`` oder Subprocess-Aufrufe (das ist Infrastruktur, ein spaeterer Schnitt),
kein HTTP, KEINE Uhr. Alles, was diese Domaene tut, ist deterministischer Strukturaufbau
ueber bereits eingelesene Rohwerte. Laufzeiten (``rtt_ms``) kommen als FELD herein -- die
Domaene misst nie selbst (testbar, deterministisch).

Vier Wertobjekte + eine reine Funktion:

* ``DnsRecord`` -- ein einzelner DNS-Eintrag (Typ + Wert) als reines Wertobjekt.
* ``DnsResult`` -- das Ergebnis einer Abfrage (Query, angefragte Typen, Eintraege).
  Leere ``records`` heisst "keine Antwort" -- KEIN Fehler (NXDOMAIN/leere Antwort ist
  ein gueltiges Ergebnis, kein Ausnahmefall).
* ``TracerouteHop`` -- ein einzelner Hop. ``address``/``rtt_ms`` sind ehrlich ``None``,
  wenn der Hop nicht antwortet (Timeout / ``*`` in der Ausgabe) -- KEIN erfundener Wert.
* ``TracerouteResult`` -- die Hop-Folge samt Ziel und ob die privilegierte (genauere)
  Methode verwendet wurde.
* ``dedup_records`` -- deterministische Dedup+Sortierung der Eintraege, rein und testbar.

DARSTELLUNG bleibt draussen: kein Mensch-lesbares Formatieren, keine Icons -- das fuehrt
api/Frontend. Die Domaene fuehrt nur Werte.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

# Angefragte/gelieferte DNS-Eintragsart. PEP-695-Alias wie im uebrigen domain-Ring
# (process/traffic/interfaces nutzen ``type X = ...``); als Literal-Union statt StrEnum,
# weil es ein reines Kategorie-Etikett ohne Verhalten ist.
type DnsRecordType = Literal["A", "AAAA", "PTR", "MX", "TXT", "NS", "SOA", "CNAME"]


@dataclass(frozen=True)
class DnsRecord:
    """Ein einzelner DNS-Eintrag als reines Wertobjekt (frozen).

    ``record_type`` ist die Eintragsart (A/AAAA/PTR/...), ``value`` der rohe Wert, wie
    ihn der Resolver geliefert hat (z. B. eine IP fuer A/AAAA, ein Hostname fuer PTR/NS,
    der TXT-Inhalt). Die Domaene interpretiert den Wert NICHT weiter -- sie fuehrt ihn.
    """

    record_type: DnsRecordType
    value: str


@dataclass(frozen=True)
class DnsResult:
    """Das Ergebnis einer DNS-Abfrage als reines Wertobjekt (frozen).

    ``query`` ist der abgefragte Name (bzw. die Adresse bei PTR), ``requested_types`` die
    vom Nutzer angefragten Eintragsarten (in angefragter Reihenfolge), ``records`` die
    gefundenen Eintraege. ``records`` LEER heisst "keine Antwort" -- das ist KEIN Fehler,
    sondern ein gueltiges Ergebnis (NXDOMAIN, leere Antwort, oder schlicht kein Eintrag
    der angefragten Art). Ein echter Fehler (fehlendes Binary) wird in application/ als
    Exception gefuehrt, nicht als leeres ``records``.
    """

    query: str
    requested_types: tuple[DnsRecordType, ...]
    records: tuple[DnsRecord, ...]


@dataclass(frozen=True)
class TracerouteHop:
    """Ein einzelner traceroute-Hop als reines Wertobjekt (frozen).

    ``hop`` ist die 1-basierte Hop-Nummer (immer vorhanden -- sie kommt aus der Zeilen-
    Position der Ausgabe). ``address`` und ``rtt_ms`` sind ehrlich ``None``, wenn der Hop
    nicht antwortet (Timeout, in der ``traceroute``-Ausgabe als ``*`` dargestellt) --
    KEIN erfundener Wert, KEIN Weglassen des Hops. Ein nicht-antwortender Hop bleibt als
    Luecke (``address=None``, ``rtt_ms=None``) sichtbar.
    """

    hop: int
    address: str | None
    rtt_ms: float | None


@dataclass(frozen=True)
class TracerouteResult:
    """Das Ergebnis eines traceroute als reines Wertobjekt (frozen).

    ``target`` ist das angefragte Ziel, ``privileged`` spiegelt, ob die privilegierte
    (genauere, Root-)Methode verwendet wurde (``True``) oder die unprivilegierte
    (ungenauere) Methode (``False``) -- die ehrliche Auskunft, WIE gemessen wurde.
    ``hops`` ist die Hop-Folge in Reihenfolge (leer = kein Hop ermittelt).
    """

    target: str
    privileged: bool
    hops: tuple[TracerouteHop, ...]


def dedup_records(records: Sequence[DnsRecord]) -> tuple[DnsRecord, ...]:
    """Entfernt doppelte DNS-Eintraege und sortiert deterministisch -- rein, testbar.

    Dedup ueber das Paar ``(record_type, value)``: zwei Eintraege gleichen Typs mit
    gleichem Wert sind derselbe Eintrag (``dig`` kann denselben Wert mehrfach liefern,
    z. B. ueber mehrere Abfragen). Das ERSTE Vorkommen gewinnt die Identitaet, doppelte
    spaetere werden verworfen.

    Deterministisch: das Ergebnis ist aufsteigend nach ``(record_type, value)`` sortiert
    -- gleiche Eingabe (in beliebiger Reihenfolge) -> gleiches Ergebnis. So bleibt die
    Wire-Form stabil, unabhaengig von der Abfrage-/Antwort-Reihenfolge.

    Rein: kein I/O, keine Uhr; gleiche Eingabe -> gleiches Ergebnis.
    """
    seen: set[tuple[str, str]] = set()
    unique: list[DnsRecord] = []
    for record in records:
        key = (record.record_type, record.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(record)
    return tuple(sorted(unique, key=lambda r: (r.record_type, r.value)))
