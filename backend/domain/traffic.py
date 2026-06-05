"""Domaenenmodell der traffic-Domaene: Verbindungen pro App + reine Aggregation/Raten.

Reine Domaenenlogik (stdlib + dataclasses, ADR 0002) -- kein Wissen ueber psutil /
``sock_diag`` / ``/proc`` (das ist Infrastruktur, T.3/T.4), kein HTTP, KEINE Uhr.
Alles, was diese Domaene tut, ist deterministische Normalisierung, Gruppierung und
Raten-Arithmetik ueber bereits eingelesene Werte. Zeitstempel kommen als
Sample-FELD herein (``ConnSample.monotonic_ts``) -- die Domaene fragt nie selbst die
Uhr (testbar, deterministisch).

Drei Datentraeger + vier reine Funktionen, gestaffelt nach den Vision-Stufen:

* ``normalize_status`` -- der rohe psutil-Status (``ESTABLISHED``/``LISTEN``/...)
  wird auf ein kleines, stabiles Domaenen-Vokabular abgebildet (Adapter-Rohwerte
  bleiben am Rand).
* ``aggregate_by_app`` -- Stufe-1-Sicht: Verbindungen pro App buendeln. Nicht
  zuordenbare Verbindungen (kein PID -- rootless-Realitaet) kommen in EINE ehrliche
  ``app_name=None``-Gruppe, statt verworfen oder je einzeln gezeigt zu werden
  (Vision 4.2: "zeigen+einordnen", 4.4: "ohne zu urteilen").
* ``compute_rate`` / ``match_samples`` -- Stufe-2-Sicht: aus zwei Messpunkten der
  kumulativen Socket-Byte-Zaehler (``ss -i``/``sock_diag``) eine grobe Rate in
  Bytes/s, Reset- und ``dt<=0``-sicher. Die Domaene rechnet nur, sie misst nicht.

DARSTELLUNG bleibt draussen: keine Icons/Emojis, kein Mensch-lesbares Formatieren
von Raten ("1,2 MB/s") -- das fuehrt api/Frontend. Die Domaene fuehrt nur Zahlen.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

# Transport-Protokoll der Verbindung. PEP-695-Alias wie im uebrigen domain-Ring
# (interfaces/settings/scanning nutzen ``type X = ...``); als Literal-Union statt
# StrEnum, weil es ein reines Klassifikations-Ergebnis ohne Verhalten ist. Name
# ``L4Protocol`` bewusst NICHT ``Protocol`` -- letzteres kollidiert mit
# ``typing.Protocol`` (dem Port-Vertrags-Mechanismus).
type L4Protocol = Literal["tcp", "udp"]

# Verbindungszustand auf das stabile Domaenen-Vokabular reduziert. psutil liefert
# u. a. ESTABLISHED/LISTEN/NONE (TCP) und NONE (UDP, das verbindungslos ist);
# alles ausserhalb von established/listen/none faellt auf ``other`` (kein
# stilles Verwerfen, kein Hochlaufen -- es ist ein gueltiger, nur unspezifischer
# Zustand).
type ConnectionStatus = Literal["established", "listen", "none", "other"]


@dataclass(frozen=True)
class Endpoint:
    """Eine Socket-Seite (lokal oder remote) als reines Wertobjekt.

    ``ip``/``port`` sind bereits geparst (der Adapter loest psutils ``addr``-Tuple
    auf). Ein nicht vorhandener Remote-Endpoint (z. B. LISTEN ohne Gegenstelle)
    wird NICHT durch ein leeres ``Endpoint`` dargestellt, sondern durch
    ``Connection.remote=None`` -- die Abwesenheit ist ehrlich None, kein Sentinel.
    """

    ip: str
    port: int


@dataclass(frozen=True)
class Connection:
    """Eine einzelne Netzwerk-Verbindung als reines Wertobjekt (frozen).

    Stufe 1 fuellt ``l4``/``status``/``local``/``remote``/``pid``/``app_name`` (aus
    psutil ``net_connections`` + PID->Name). Die Stufe-2-Felder
    ``bytes_sent``/``bytes_received`` (kumulativ, aus ``sock_diag``) und die daraus
    abgeleiteten ``send_rate_bps``/``recv_rate_bps`` sind ``None``, solange nur
    Stufe 1 vorliegt -- ``None`` heisst "nicht gemessen", nicht "null Bytes".

    ``pid``/``app_name`` sind ``None``, wenn die Verbindung dem User rootless nicht
    zuzuordnen ist (fremder Prozess) -- die ehrliche "benoetigt Root"-Luecke, die
    ``aggregate_by_app`` in die None-Gruppe buendelt.
    """

    l4: L4Protocol
    status: ConnectionStatus
    local: Endpoint
    remote: Endpoint | None = None
    pid: int | None = None
    app_name: str | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    send_rate_bps: float | None = None
    recv_rate_bps: float | None = None


@dataclass(frozen=True)
class AppTraffic:
    """Aggregat ueber alle Verbindungen derselben App (Stufe-1-Sicht).

    ``app_name=None`` ist die ehrliche Sammelgruppe der nicht zuordenbaren
    Verbindungen (kein PID -- rootless nicht aufloesbar), NICHT ein Fehler.
    ``pids`` ist die sortierte, dublettenfreie Menge der beteiligten PIDs (leer fuer
    die None-Gruppe). ``total_send_rate_bps``/``total_recv_rate_bps`` sind ``None``,
    solange KEINE Verbindung der Gruppe eine Rate kennt; sobald mindestens eine
    Rate vorliegt, ist die Summe die der BEKANNTEN Raten (unbekannte zaehlen 0) --
    so wird eine noch nicht gemessene Verbindung nicht als 0 unterschlagen, aber
    eine teils gemessene Gruppe liefert trotzdem eine brauchbare grobe Summe.
    """

    app_name: str | None
    pids: tuple[int, ...]
    connection_count: int
    total_send_rate_bps: float | None
    total_recv_rate_bps: float | None
    connections: tuple[Connection, ...]


@dataclass(frozen=True)
class ConnSample:
    """Ein Messpunkt der kumulativen Byte-Zaehler eines Sockets (Stufe 2).

    ``key`` ist die stabile Socket-Identitaet ueber zwei Messpunkte hinweg (der
    Adapter baut sie, z. B. ``f"{l4}:{local}:{remote}"``). ``bytes_sent``/
    ``bytes_received`` sind die KUMULATIVEN Zaehler zum Messzeitpunkt (monoton
    steigend, bis der Kernel den Socket schliesst/neu vergibt -> Reset).
    ``monotonic_ts`` ist ein uebergebener monotoner Zeitstempel (Sekunden) -- ein
    FELD, KEINE interne Uhr: die Domaene rechnet nur mit dem, was hereinkommt.
    """

    key: str
    bytes_sent: int
    bytes_received: int
    monotonic_ts: float


# Roh-Status (psutil, case-insensitiv) -> Domaenen-Vokabular. UDP-Sockets melden
# bei psutil ``NONE`` (verbindungslos) -- das ist ein gueltiger Zustand, kein
# Fehler, und mappt auf ``none``.
_STATUS_MAP: dict[str, ConnectionStatus] = {
    "ESTABLISHED": "established",
    "LISTEN": "listen",
    "NONE": "none",
}


def normalize_status(raw: str) -> ConnectionStatus:
    """Bildet den rohen Verbindungs-Status auf das Domaenen-Vokabular ab -- rein.

    Case-insensitiv (psutil liefert Grossbuchstaben, defensiv dennoch ``upper()``):
    ``ESTABLISHED``->established, ``LISTEN``->listen, ``NONE``->none. Jeder andere
    Zustand (``SYN_SENT``/``TIME_WAIT``/``CLOSE_WAIT``/... oder leer/unbekannt) ->
    ``other`` -- ein gueltiger, nur unspezifischer Zustand, KEIN Verwerfen und KEIN
    Hochlaufen. Rein: kein I/O, kein State, gleiches ``raw`` -> gleiches Ergebnis.
    """
    return _STATUS_MAP.get(raw.upper(), "other")


def _sum_known_rates(values: Sequence[float | None]) -> float | None:
    """Summiert nur die bekannten Raten; ``None``, wenn KEINE bekannt ist.

    Liegt keine einzige Rate vor (alle ``None``) -> ``None`` ("nicht gemessen").
    Sobald mindestens eine vorliegt -> Summe der bekannten (``None`` zaehlt 0). So
    wird eine ungemessene Verbindung nicht faelschlich als 0 ausgewiesen, eine
    teils gemessene Gruppe liefert aber trotzdem eine grobe Summe.
    """
    known = [v for v in values if v is not None]
    if not known:
        return None
    return sum(known)


def aggregate_by_app(conns: Sequence[Connection]) -> list[AppTraffic]:
    """Buendelt Verbindungen pro App zu ``AppTraffic`` -- rein, deterministisch.

    Gruppierungs-Schluessel ist ``app_name``. Verbindungen ohne ``app_name``
    (``None`` -- kein PID, rootless nicht zuordenbar) kommen in EINE gemeinsame
    ``app_name=None``-Gruppe; sie werden weder verworfen noch je einzeln gezeigt --
    das ist die ehrliche "nicht zuordenbar / benoetigt Root"-Gruppe (Vision 4.2).

    Pro Gruppe: ``connection_count`` (Anzahl), ``pids`` (sortierte, dublettenfreie
    PID-Menge; leer fuer die None-Gruppe), summierte Raten ueber
    ``_sum_known_rates`` (``None`` solange keine Rate bekannt, sonst Summe der
    bekannten). ``connections`` bewahrt die EINGANGSREIHENFOLGE innerhalb der Gruppe.

    Gruppen-Sortierung deterministisch: zuordenbare Apps zuerst, alphabetisch nach
    ``app_name``; die ``None``-Gruppe immer ans Ende (stabiler Tie-Break ueber den
    Namen, ``None`` als "kommt zuletzt"). Leere Eingabe -> ``[]``.

    Rein: kein I/O, keine Uhr; gleiche Eingabe -> gleiche Ausgabe.
    """
    # Gruppen in Erst-Vorkommens-Reihenfolge sammeln (dict bewahrt Insertion-Order),
    # damit die spaetere Sortierung einen stabilen Ausgangszustand hat.
    grouped: dict[str | None, list[Connection]] = {}
    for conn in conns:
        grouped.setdefault(conn.app_name, []).append(conn)

    apps = [
        AppTraffic(
            app_name=name,
            pids=tuple(sorted({c.pid for c in group if c.pid is not None})),
            connection_count=len(group),
            total_send_rate_bps=_sum_known_rates([c.send_rate_bps for c in group]),
            total_recv_rate_bps=_sum_known_rates([c.recv_rate_bps for c in group]),
            connections=tuple(group),
        )
        for name, group in grouped.items()
    ]
    # Zuordenbare zuerst alphabetisch, None-Gruppe ans Ende: Sortierschluessel
    # (is_none, name_or_leer) -- False<True schiebt None hinter alle benannten.
    apps.sort(key=lambda a: (a.app_name is None, a.app_name or ""))
    return apps


def compute_rate(prev: ConnSample, curr: ConnSample) -> tuple[float, float]:
    """Grobe Rate (Bytes/s) aus zwei Messpunkten -- rein, getrennt sent/received.

    ``rate = (curr.bytes - prev.bytes) / (curr.monotonic_ts - prev.monotonic_ts)``,
    je fuer ``bytes_sent`` und ``bytes_received``. Rueckgabe ``(send_bps, recv_bps)``.

    Zwei Randfaelle, beide -> ``0.0`` (nie eine sinnlose/negative Rate):
    * ``dt <= 0`` (gleiche oder ruecklaeufige Zeitstempel) -> ``0.0`` statt
      Division durch Null/Negativ. Beide Raten 0.0.
    * Zaehler-Reset (``curr.bytes < prev.bytes``, weil der Kernel den Socket
      geschlossen/neu vergeben hat) -> fuer DIESE Richtung ``0.0`` statt einer
      negativen Rate. Sent und received werden unabhaengig geprueft (eine Richtung
      kann resetten, die andere normal weiterzaehlen).

    KEINE Uhr: beide Zeitstempel kommen als ``ConnSample.monotonic_ts`` herein.
    Rein: gleiche Samples -> gleiche Rate.
    """
    dt = curr.monotonic_ts - prev.monotonic_ts
    if dt <= 0:
        return (0.0, 0.0)
    sent_delta = curr.bytes_sent - prev.bytes_sent
    recv_delta = curr.bytes_received - prev.bytes_received
    send_bps = sent_delta / dt if sent_delta >= 0 else 0.0
    recv_bps = recv_delta / dt if recv_delta >= 0 else 0.0
    return (send_bps, recv_bps)


def match_samples(
    prev: Sequence[ConnSample], curr: Sequence[ConnSample]
) -> list[tuple[ConnSample, ConnSample]]:
    """Paart Samples ueber zwei Messpunkte nach ``key`` -- reine Mengenoperation.

    Nur Sockets, die in BEIDEN Messpunkten existieren, werden gepaart (Schnittmenge
    der ``key``). Neue Sockets (nur in ``curr``) und verschwundene (nur in ``prev``)
    fallen heraus -- fuer sie laesst sich keine Rate bilden. Reihenfolge folgt
    ``curr`` (die aktuelle Sicht ist die fuehrende). Bei doppeltem ``key`` innerhalb
    einer Sequenz gewinnt das LETZTE Vorkommen (dict-Semantik) -- der Adapter baut
    eindeutige Keys, der Fall ist defensiv abgedeckt.

    Rein: kein I/O, keine Uhr; gleiche Eingabe -> gleiche Paarung.
    """
    prev_by_key = {s.key: s for s in prev}
    return [(prev_by_key[s.key], s) for s in curr if s.key in prev_by_key]
