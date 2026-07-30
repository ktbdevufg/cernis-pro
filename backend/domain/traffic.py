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

Dazu der Rechte-Befund der Stufe 2 (``TrafficPermissionState``/
``TrafficPermissionResult``): ob die Durchsatz-Messung steht, ob ihr nur die Rechte
fehlen oder ob die Plattform sie gar nicht anbietet. Diese Dreiteilung ist eine
fachliche Aussage und lebt darum hier, nicht im api-Rand (Begruendung am Enum).
``TrafficPermissionCause`` benennt dazu die URSACHE des nicht-nutzbaren Falls
(Werkzeug fehlt / Messlauf gescheitert / bewusster Rechte-Verzicht) -- ebenfalls als
Merkmal, nicht als Text.

DARSTELLUNG bleibt draussen: keine Icons/Emojis, kein Mensch-lesbares Formatieren
von Raten ("1,2 MB/s") -- das fuehrt api/Frontend. Die Domaene fuehrt nur Zahlen.
"""

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
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


class TrafficPermissionState(StrEnum):
    """Zustand der Durchsatz-Sicht (Stufe 2) -- die Rechte-/Verfuegbarkeits-Frage.

    ``GRANTED`` -- die volle Sicht steht; der Durchsatz ALLER Apps ist messbar
    (Linux mit Root bzw. ``CAP_NET_ADMIN``).
    ``NEEDS_PRIVILEGES`` -- die Plattform KOENNTE es, aber dem laufenden Prozess
    fehlen die Rechte. Der Zustand ist behebbar; der Grund benennt den Weg.
    ``NOT_APPLICABLE`` -- die Messung steht auf dieser Plattform nicht zur
    Verfuegung und ist NICHT behebbar. Zwei Auspraegungen, die ``cause`` trennt:
    die Plattform bietet die Messung ueberhaupt nicht an (macOS: kein
    ``sock_diag``/``ss`` -- ``cause`` bleibt ``None``), oder sie gaebe die Zahlen nur
    an dauerhaft privilegierte Programme heraus und CERNIS verzichtet bewusst darauf
    (Windows -- ``cause=PRIVILEGE_DECLINED``). Ein ehrlicher eigener Zustand, KEIN
    Fehler; fuer die Oberflaeche gilt in beiden Faellen dasselbe: es gibt nichts
    einzurichten und nichts zu raten.

    WARUM EIN EIGENER ZUSTAND UND KEIN TEXT: Der Unterschied zwischen "die Rechte
    fehlen" und "diese Plattform bietet es nicht" ist eine FACHLICHE Aussage und
    gehoert deshalb in die Domaene, nicht an den api-Rand. Steckte er nur im
    Meldungstext, muesste die Oberflaeche ihn aus einer Zeichenkette erraten -- und
    ein Text ist lokalisierbar, umformulierbar und als Merkmal unbrauchbar.

    Genau dieses Muster existiert im Projekt bereits fuer die Capture-Rechte-
    einrichtung: ``domain/capture_access.py`` fuehrt ``CaptureAccessState`` mit
    ``GRANTED``/``MISSING``/``NOT_APPLICABLE``. Benennung und Aufbau folgen diesem
    Vorbild, damit beide Rechte-Nahtstellen gleich aussehen.

    Muster ``StrEnum`` wie ``domain/capture_access.py`` -- der Wire-Wert ist der
    jeweilige String.
    """

    GRANTED = "granted"
    NEEDS_PRIVILEGES = "needs_privileges"
    NOT_APPLICABLE = "not_applicable"


class TrafficPermissionCause(StrEnum):
    """WARUM die Durchsatz-Sicht nicht steht -- maschinell, unabhaengig vom Zustand.

    ``TOOL_MISSING`` -- das Systemwerkzeug ``ss`` (Paket iproute2) ist auf diesem
    System nicht auffindbar; die Quelle existiert gar nicht erst.
    ``MEASUREMENT_FAILED`` -- das Werkzeug ist da und die statische Pruefung meldet
    nichts, aber der LAUFENDE Messlauf ist gescheitert.
    ``PRIVILEGE_DECLINED`` -- die Messung waere auf dieser Plattform technisch
    moeglich, das Betriebssystem gibt die Zahlen aber nur an dauerhaft mit erhoehten
    Rechten laufende Programme heraus, und CERNIS verzichtet bewusst darauf.

    WARUM EIN EIGENES MERKMAL: derselbe Zustand entsteht aus verschiedenen Ursachen,
    und sie verlangen verschiedene Erklaerungen -- ein fehlendes Paket ist ein
    Dauerzustand, ein gescheiterter Messlauf ein voruebergehender, ein bewusster
    Verzicht keines von beidem. ``ok``/``error``/``state`` fallen fuer sie zusammen;
    ohne dieses Feld muesste die Oberflaeche die Ursache aus dem Freitext von
    ``reason`` ERRATEN -- und ein Text ist lokalisierbar, umformulierbar und als
    Merkmal unbrauchbar. Dieselbe Begruendung, die ``TrafficPermissionState`` selbst
    traegt, eine Ebene feiner.

    ZUSTANDS-ZUORDNUNG: ``TOOL_MISSING``/``MEASUREMENT_FAILED`` gehoeren zu
    ``NEEDS_PRIVILEGES`` (die Quelle ist gerade nicht nutzbar, mit Grund).
    ``PRIVILEGE_DECLINED`` gehoert zu ``NOT_APPLICABLE``: nicht weil die Plattform
    die Messung nicht kennt, sondern weil sie auf dieser Plattform fuer CERNIS
    nicht in Frage kommt -- fuer die Oberflaeche ist beides gleichermassen NICHT
    behebbar, und genau das trennt ``NOT_APPLICABLE`` von ``NEEDS_PRIVILEGES``.
    ``NOT_APPLICABLE`` ist damit nicht mehr zwingend ursachenlos; ``None`` bleibt
    dort der Fall der echten Plattformgrenze (macOS kennt kein ``sock_diag``).

    KEIN Wert fuer "Rechte fehlen und koennten erlangt werden": genau das bietet
    CERNIS nicht an (Karls Entscheidung S57 -- keine Rechteerweiterung, kein
    Terminal-Befehl im Text, kein Zustimmungsdialog). ``PRIVILEGE_DECLINED`` ist der
    Verzicht, nicht der Weg dahin.

    Muster ``StrEnum`` wie ``TrafficPermissionState`` -- der Wire-Wert ist der
    jeweilige String.
    """

    TOOL_MISSING = "tool_missing"
    MEASUREMENT_FAILED = "measurement_failed"
    PRIVILEGE_DECLINED = "privilege_declined"


@dataclass(frozen=True, slots=True)
class TrafficPermissionResult:
    """Der Rechte-Befund der Durchsatz-Sicht: Zustand + optionale Begruendung.

    ``reason`` traegt bei ``NEEDS_PRIVILEGES`` den handlungsorientierten Weg zu mehr
    Rechten und bei ``NOT_APPLICABLE`` die ehrliche Einordnung (was fehlt, warum es
    fehlt, was trotzdem funktioniert). Bei ``GRANTED`` bleibt ``reason`` leer -- es
    gibt nichts zu erklaeren.

    ``cause`` benennt DIESELBE Aussage maschinell auswertbar, die ``reason`` nur als
    Freitext traegt -- damit die Oberflaeche die Ursache nicht aus einer Zeichenkette
    lesen muss (Begruendung an ``TrafficPermissionCause``). Bei ``GRANTED`` gibt es
    keine Ursache zu benennen; bei ``NOT_APPLICABLE`` traegt sie nur, wer sie hat
    (``PRIVILEGE_DECLINED`` -- der bewusste Verzicht), waehrend die echte
    Plattformgrenze ohne Ursache bleibt. ``None`` heisst "keine Ursache", nicht
    "unbekannte Ursache" -- die Abwesenheit ist ehrlich None, kein Sentinel (wie
    ``Connection.remote``).

    Aufbau wie ``CaptureAccessStatus``: ein Zustand plus ein erklaerender Text, nicht
    ein Text, aus dem der Zustand erst gelesen werden muesste.
    """

    state: TrafficPermissionState
    reason: str = ""
    cause: TrafficPermissionCause | None = None


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


def _canonical_ip(raw: str) -> str:
    """Kanonisiert eine IP-Adresse fuer die Socket-Identitaet -- rein, best-effort.

    Entfernt ss-Klammern (``[::1]`` -> ``::1``), loest IPv4-mapped IPv6 auf
    (``::ffff:172.18.1.156`` -> ``172.18.1.156``) und vereinheitlicht IPv6-
    Schreibweisen (``ip_address``-Kanonform). So werden die ss-Adressform (mit
    Klammern) und die psutil-Form (ohne) DECKUNGSGLEICH -- die Voraussetzung dafuer,
    dass derselbe Socket aus beiden Quellen denselben ``make_socket_key`` ergibt.

    Unparsebares -> roh zurueck (best-effort, nie werfen): ein nicht parsbarer Wert
    soll die Paarung nicht crashen, sondern hoechstens diesen einen Socket nicht
    paaren lassen. Rein: kein I/O.
    """
    stripped = raw.strip("[]")
    try:
        addr = ipaddress.ip_address(stripped)
    except ValueError:
        return raw  # best-effort: lieber die rohe Form als ein Crash
    # ``ipv4_mapped`` gibt es NUR auf IPv6Address (None, wenn nicht gemappt); eine
    # IPv4Address hat das Attribut gar nicht -> defensiv per getattr abfragen.
    mapped = getattr(addr, "ipv4_mapped", None)
    return str(mapped) if mapped else str(addr)


def make_socket_key(
    l4: L4Protocol,
    local_ip: str,
    local_port: int,
    remote_ip: str | None,
    remote_port: int | None,
) -> str:
    """Kanonische, quellenunabhaengige Socket-Identitaet fuer die Raten-Paarung -- rein.

    Stufe 1 (psutil) und Stufe 2 (``ss``) erzeugen damit denselben ``key`` fuer
    denselben Socket, trotz unterschiedlicher Adress-TEXTform (Klammern/mapped). Die
    IPs laufen durch ``_canonical_ip``, die Ports bleiben numerisch. Ein abwesender
    Remote-Endpunkt (z. B. LISTEN -> ``remote_ip``/``remote_port`` ``None``) wird als
    leerer Teil dargestellt -- der ``key`` bleibt stabil und kollidiert nicht mit
    einem echten Remote ``:0``.

    Form: ``f"{l4}:{lip}:{lport}:{rip}:{rport}"``. Rein: kein I/O, gleiche Eingabe ->
    gleicher ``key``.
    """
    lip = _canonical_ip(local_ip)
    rip = _canonical_ip(remote_ip) if remote_ip else ""
    rport_s = str(remote_port) if remote_port is not None else ""
    return f"{l4}:{lip}:{local_port}:{rip}:{rport_s}"


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
