"""Domaenenmodell der sni-Domaene: passiv erfasste SNI-Hostnamen + Prozess-Zuordnung.

Reine Domaenenlogik (stdlib + dataclasses, ADR 0002) -- KEIN Wissen ueber scapy /
psutil / TLS-Byte-Parsing (das ist Infrastruktur, siehe ``infrastructure/sni``),
kein HTTP, KEINE Uhr. Die Domaene fuehrt nur Wertobjekte und deterministische,
zeitfreie Logik: die Hostname-Normalisierung und die reine Zuordnungs-Funktion
(welcher Socket-Snapshot liegt einem SNI-Hit am naechsten?).

ZEITSTEMPEL kommen als FELD herein (``monotonic_ts``) -- die Domaene fragt nie selbst
die Uhr (testbar, deterministisch, exakt wie ``domain.traffic`` mit
``ConnSample.monotonic_ts``).

Ein Datentraeger + zwei reine Funktionen:

* ``ObservedSni`` -- ein erfasster (und ggf. einem Prozess zugeordneter) SNI-Hit.
* ``normalize_hostname`` -- leerer/whitespace-only Hostname -> ``None`` (ehrliche
  Abwesenheit statt leerem String).
* ``match_snapshot`` -- ordnet einem Hit den zeitlich naechstgelegenen Socket-
  Snapshot zu, der den Ziel-Endpunkt kennt (reine Funktion, mit synthetischen
  Snapshots testbar -- das Herzstueck der Zuordnung, vom Sniff-/psutil-I/O getrennt).

Die schwere Arbeit (TLS-Parsing, scapy-Sniff, psutil-Snapshots, Namensaufloesung)
lebt ausschliesslich in der Infrastruktur. Diese Domaene rechnet nur mit dem, was
ihr als bereits eingelesene Werte hereingereicht wird.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class ObservedSni:
    """Ein passiv erfasster SNI-Hit, optional einem Prozess zugeordnet (frozen).

    Der Sniff-Teil fuellt ``hostname``/``remote_ip``/``remote_port``/``monotonic_ts``
    (der angefragte Name aus dem TLS-ClientHello + die Ziel-Gegenstelle + der
    monotone Erfassungs-Zeitstempel). Die Zuordnungs-Felder ``app_name``/``pid``/
    ``delta_ms`` sind ``None``, solange (oder wenn) kein passender Socket-Snapshot
    gefunden wurde -- die ehrliche "nicht (mehr) zuordenbar / benoetigt Root"-Luecke
    (rootless sieht psutil fremde Sockets ohne PID), KEIN Fehler und kein erfundener
    Wert.

    ``monotonic_ts`` ist ein monotoner Zeitstempel (Sekunden) -- ein FELD, KEINE
    interne Uhr: die Domaene rechnet nur mit dem, was hereinkommt (Muster
    ``domain.traffic.ConnSample``). ``delta_ms`` ist der zeitliche Abstand zwischen
    Hit und zugeordnetem Snapshot in Millisekunden (Qualitaets-Mass der Zuordnung;
    ``None`` ohne Zuordnung).
    """

    hostname: str
    remote_ip: str
    remote_port: int
    monotonic_ts: float
    app_name: str | None = None
    pid: int | None = None
    delta_ms: int | None = None


def normalize_hostname(raw: str) -> str | None:
    """Normalisiert einen rohen SNI-Hostnamen -- rein, deterministisch.

    Schneidet umgebenden Whitespace ab; ein leerer oder reiner-Whitespace-Hostname
    wird zu ``None`` (ehrliche Abwesenheit, kein leeres-String-Sentinel). Ein gefuellter
    Name wird getrimmt zurueckgegeben. Bewusst KEINE Lowercasing-/Punycode-/Validitaets-
    Logik hier: der Parser liefert bereits den rohen ASCII-Hostnamen aus dem
    ClientHello; die Domaene haelt nur die "leer -> None"-Regel an EINER Stelle.

    Rein: kein I/O, kein State; gleiches ``raw`` -> gleiches Ergebnis.
    """
    stripped = raw.strip()
    return stripped or None


def match_snapshot(
    remote_ip: str,
    remote_port: int,
    hit_ts: float,
    snapshots: Sequence[tuple[float, Mapping[tuple[str, int], int | None]]],
) -> tuple[int | None, int | None]:
    """Ordnet einem SNI-Hit den zeitlich naechstgelegenen passenden Snapshot zu -- rein.

    Aus dem Spike uebernommene Zuordnungs-Technik, hier als reine, zeitfreie Funktion
    (synthetisch testbar): Jeder ``snapshot`` ist ein ``(monotonic_ts, table)``-Paar,
    ``table`` bildet ``(remote_ip, remote_port) -> pid`` ab (``pid`` darf ``None`` sein
    -- rootless sieht psutil fremde Sockets ohne PID). Gesucht ist der Snapshot mit dem
    KLEINSTEN zeitlichen Abstand ``|snapshot_ts - hit_ts|``, dessen ``table`` den
    Ziel-Endpunkt ``(remote_ip, remote_port)`` enthaelt.

    Rueckgabe ``(pid, delta_ms)``:
    * Treffer -> der ``pid`` des naechstgelegenen passenden Snapshots (kann ``None``
      sein, wenn psutil den Socket rootless ohne PID sah -- der Endpunkt war bekannt,
      die PID nicht) und ``delta_ms`` (gerundeter Abstand in Millisekunden, >= 0).
    * Kein passender Snapshot -> ``(None, None)`` (ehrlich nicht zuordenbar).

    Die Namensaufloesung (pid -> Prozessname) ist NICHT Sache der Domaene -- sie braucht
    psutil und lebt im Adapter. Diese Funktion liefert nur die PID + das Delta.

    Rein: kein I/O, keine Uhr (``hit_ts`` und die Snapshot-Zeiten kommen herein);
    gleiche Eingabe -> gleiche Ausgabe.
    """
    target = (remote_ip, remote_port)
    best_pid: int | None = None
    best_delta = float("inf")
    found = False
    for snapshot_ts, table in snapshots:
        if target not in table:
            continue
        delta = abs(snapshot_ts - hit_ts)
        if delta < best_delta:
            best_delta = delta
            best_pid = table[target]
            found = True
    if not found:
        return (None, None)
    return (best_pid, round(best_delta * 1000))
