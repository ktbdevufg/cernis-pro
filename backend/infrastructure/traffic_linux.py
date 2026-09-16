"""Linux-Adapter fuer ``PerProcessTrafficProvider`` (T.3, Stufe 1 ueber psutil).

Erfuellt den ``PerProcessTrafficProvider`` strukturell: ``list_connections`` liefert
die aktuelle Verbindungssicht als rohe ``domain.traffic.Connection`` (Stufe 1, ohne
Durchsatz -- ``bytes_*``/``*_rate_bps`` bleiben ``None``). Die App-Buendelung macht
der Use-Case ``ListAppTraffic`` ueber ``aggregate_by_app`` -- der Adapter liefert nur
die flache Verbindungsliste.

Schablone ``infrastructure/interfaces_linux.py``:

* ``list_connections`` ist ``async`` und kapselt das blockierende
  ``psutil.net_connections``-I/O ueber ``run_in_executor``, der Event-Loop bleibt frei.
* Der synchrone Kern (``_list_connections_sync``) und die reinen Mapping-Helfer
  liegen ausserhalb der Klasse, sind damit ohne Adapter-Instanz testbar.

ROOTLESS-REALITAET (Vision 4.2): ``psutil.net_connections`` wirft OHNE Root NICHT,
es zeigt nur weniger -- fremde Verbindungen erscheinen mit ``pid=None``. Diese werden
NICHT weggelassen: der Adapter setzt ``app_name=None``, und ``aggregate_by_app``
buendelt sie in die ehrliche None-Gruppe ("nicht zuordenbar / benoetigt Root").

SCOPE (CLAUDE.md "Nur Linux x64"): psutil ist plattformuebergreifend, aber die
v2-Stufe-2-Quelle (``sock_diag``) ist Linux. Stufe 1 hier ist plattformneutral; der
Plattform-Riegel sitzt im Rechte-Adapter (``traffic_permission.py``).

Stufe 2 (``sample_throughput``, T.4a) liest die KUMULATIVEN TCP-Byte-Zaehler ueber
``ss -tin`` (iproute2; diese Version hat kein JSON -> Text-Parsing). EINEN Messpunkt
je Aufruf; die Raten-Berechnung aus zwei Messpunkten macht der Use-Case ueber die
Domaene (``match_samples``/``compute_rate``). Der ``key`` ist ``tcp:local:remote``
(kein Inode/PID noetig -- ``ss -tin`` zeigt sie ohnehin nicht, und das Parsing
braucht KEIN Root: gemessen liefert ``ss -tin`` als gewoehnlicher Benutzer
dieselben Zaehlwerte wie als Systemverwalter). NUR TCP: UDP hat keine kumulativen
Byte-Zaehler. Der Adapter stempelt ``monotonic_ts`` (die Uhr lebt in der
Infrastruktur, nie in der Domaene). Der Poller + Lebenszyklus (AUTO/MANUELL) folgen
in T.4b.

SCHEITERN IST EIN FEHLER, KEINE NULL (S3): fehlt ``ss``, laeuft es in einen Timeout
oder endet mit Fehlerstatus, wirft ``_run`` eine ``ThroughputUnavailableError``,
statt einen leeren Messpunkt vorzutaeuschen -- eine leere Messung waere von "null
Bytes uebertragen" nicht zu unterscheiden. Stufe 1 (Verbindungsliste ueber psutil)
ist davon voellig unberuehrt und laeuft weiter.

Self-contained stdlib + psutil -- kein ``modules``-Import (import-linter-Contract
"neue Ringe importieren NICHT modules" bleibt unberuehrt).
"""

import asyncio
import os
import re
import socket
import subprocess
import time

import psutil

from domain.traffic import (
    Connection,
    ConnSample,
    Endpoint,
    L4Protocol,
    make_socket_key,
    normalize_status,
)

# ss wird mit erzwungener C-Locale gestartet, weil lokalisierte Ausgaben (z.B.
# Zeit= statt time=) das Parsing sonst still scheitern lassen.
_C_LOCALE_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}

# psutil-``SocketKind`` -> Domaenen-L4. NUR TCP/UDP werden aufgenommen; andere
# Socket-Typen (RAW/SEQPACKET o. Ae.) sind fuer die Per-App-Sicht uninteressant und
# werden im sync-Kern uebersprungen (kein "tcp"-Default-Raten, kein Verwerfen mit
# Fehler -- sie gehoeren schlicht nicht in diese Domaene).
_L4_BY_SOCKET_KIND: dict[int, L4Protocol] = {
    int(socket.SOCK_STREAM): "tcp",
    int(socket.SOCK_DGRAM): "udp",
}


def _resolve_app_name(pid: int) -> str | None:
    """PID -> Prozessname; defensiv (psutil-Fehler -> ``None``, wirft NIE).

    Ein Prozess kann zwischen ``net_connections`` und diesem Lookup verschwinden
    (``NoSuchProcess``) oder fuer den User nicht lesbar sein (``AccessDenied``) --
    beides ist KEIN Fehler, sondern bedeutet "nicht (mehr) zuordenbar" -> ``None``.
    ``aggregate_by_app`` buendelt solche Verbindungen in die None-Gruppe.
    """
    try:
        # psutil ist untypisiert (kein py.typed); name() ist Any -> explizit str.
        return str(psutil.Process(pid).name())
    except psutil.Error:
        return None


def _endpoint(addr: object) -> Endpoint | None:
    """psutil-``addr(ip, port)`` -> ``Endpoint``; leeres/abwesendes ``addr`` -> ``None``.

    ``raddr`` ist bei LISTEN/verbindungslos ``()`` (falsy) -- das wird zu ``None``
    (ehrliche Abwesenheit, kein leeres ``Endpoint``-Sentinel, Domaenen-Vertrag).
    """
    if not addr:
        return None
    return Endpoint(ip=addr.ip, port=addr.port)  # type: ignore[attr-defined]


class ThroughputUnavailableError(RuntimeError):
    """Der Durchsatz konnte nicht gemessen werden -- mit benennbarem Grund.

    Ersetzt den frueheren stillen Rueckfall auf "keine Daten" (S3): ein fehlendes
    ``ss``, ein Timeout oder ein Fehlerstatus des Werkzeugs ist ein ECHTER
    Fehlschlag des Durchsatz-Pfads und darf nicht als leere Messung erscheinen --
    sonst sieht "nichts gemessen" genauso aus wie "null Bytes uebertragen".

    Betrifft AUSSCHLIESSLICH Stufe 2 (Durchsatz). Die Verbindungsliste (Stufe 1,
    psutil) laeuft voellig unabhaengig davon weiter.
    """


def _run(cmd: list[str]) -> str:
    """Fuehrt das Durchsatz-Werkzeug aus und gibt stdout zurueck.

    KEIN stiller Fallback (S3): schlaegt der Aufruf fehl -- Werkzeug nicht
    vorhanden, Timeout, Fehlerstatus --, wird ``ThroughputUnavailableError``
    geworfen statt ein leerer String zurueckgegeben. Ein leerer String waere von
    "es gibt gerade keine TCP-Verbindungen" nicht zu unterscheiden und wuerde den
    Fehlschlag in eine Null verwandeln.

    Ein leeres stdout bei Rueckgabewert 0 ist dagegen KEIN Fehler, sondern die
    ehrliche Aussage "keine Sockets" -> ``""`` -> ``[]``.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=5,
            encoding="utf-8",
            errors="replace",
            env=_C_LOCALE_ENV,
        )
    except FileNotFoundError as exc:
        raise ThroughputUnavailableError(
            f"Werkzeug '{cmd[0]}' nicht gefunden (Paket iproute2) -- "
            "der Durchsatz je Programm kann nicht gemessen werden."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ThroughputUnavailableError(
            f"Werkzeug '{cmd[0]}' hat nicht rechtzeitig geantwortet -- "
            "der Durchsatz je Programm kann nicht gemessen werden."
        ) from exc
    except OSError as exc:
        raise ThroughputUnavailableError(
            f"Werkzeug '{cmd[0]}' nicht ausfuehrbar ({exc}) -- "
            "der Durchsatz je Programm kann nicht gemessen werden."
        ) from exc
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise ThroughputUnavailableError(
            f"Werkzeug '{cmd[0]}' endete mit Status {result.returncode}"
            f"{f': {stderr}' if stderr else ''} -- "
            "der Durchsatz je Programm kann nicht gemessen werden."
        )
    return result.stdout or ""


# Byte-Zaehler-Tokens in der ss-Detailzeile (z. B. ``bytes_sent:11320827``).
_BYTES_SENT_RE = re.compile(r"bytes_sent:(\d+)")
_BYTES_RECEIVED_RE = re.compile(r"bytes_received:(\d+)")


def _split_addr_port(token: str) -> tuple[str, int] | None:
    """``ss``-Adressspalte (``ip:port`` bzw. ``[ipv6]:port``) -> ``(ip, port)``.

    Der Port haengt immer hinter dem LETZTEN ``:`` (``rsplit``), die IP davor --
    das traegt sowohl IPv4 (``1.2.3.4:443``) als auch IPv6 (``[::1]:443``, der
    IPv6-Teil enthaelt selbst Doppelpunkte). Die ``[...]``-Klammern bleiben am IP-
    Teil und werden erst von ``_canonical_ip`` (Domaene) entfernt -- so liegt die
    Kanonisierung an EINER Stelle. Nicht-numerischer Port / fehlendes ``:`` ->
    ``None`` (der Aufrufer ueberspringt den Socket, best-effort).
    """
    ip, sep, port = token.rpartition(":")
    if not sep or not port.isdigit():
        return None
    return (ip, int(port))


def parse_ss_output(text: str) -> list[tuple[str, int, int]]:
    """Parst ``ss -tin``-Output zu ``(key, bytes_sent, bytes_received)`` je TCP-Socket.

    Zwei-Zeilen-Struktur von ``ss -tin``: eine Socket-Zeile OHNE fuehrenden Whitespace
    (``STATE recv-q send-q LOCAL:PORT PEER:PORT [Process]``), gefolgt von einer
    Detailzeile MIT fuehrendem Whitespace (die ``key:value``-Tokens inkl.
    ``bytes_sent``/``bytes_received``). Die Header-Zeile (``State Recv-Q ...``) wird
    uebersprungen.

    Der ``key`` entsteht ueber die Domaenen-Funktion ``make_socket_key`` (kanonische,
    quellenunabhaengige Identitaet) -- NICHT aus rohen ss-Strings: so ergibt derselbe
    Socket aus ss UND psutil denselben ``key`` (IPv4-mapped/IPv6-Klammern werden in
    ``_canonical_ip`` vereinheitlicht). Kein Inode/PID noetig, das Parsing braucht
    KEIN Root. Fehlendes ``bytes_sent``/``bytes_received`` -> ``0`` (frischer Socket
    ohne Verkehr; so taucht der Socket dennoch ueber BEIDE Messpunkte in
    ``match_samples`` auf). Sockets ohne (parsbare) Adressspalten werden uebersprungen.
    ZEITFREI -- kein ``monotonic`` hier (der Adapter stempelt). Best-effort:
    unparsebare Zeilen werden ignoriert, nie wird geworfen.
    """
    result: list[tuple[str, int, int]] = []
    current_key: str | None = None
    bytes_sent = 0
    bytes_received = 0
    have_socket = False

    def _flush() -> None:
        # Den zuletzt gesammelten Socket abschliessen (Bytes ggf. 0).
        if have_socket and current_key is not None:
            result.append((current_key, bytes_sent, bytes_received))

    for line in text.splitlines():
        if not line.strip():
            continue
        # Detailzeile: fuehrender Whitespace -> Byte-Tokens zum aktuellen Socket.
        if line[0].isspace():
            if not have_socket:
                continue  # Detailzeile ohne vorangehende Socket-Zeile -> ignorieren
            sent_match = _BYTES_SENT_RE.search(line)
            recv_match = _BYTES_RECEIVED_RE.search(line)
            if sent_match:
                bytes_sent = int(sent_match.group(1))
            if recv_match:
                bytes_received = int(recv_match.group(1))
            continue

        # Socket-Zeile (kein fuehrender Whitespace): vorigen Socket abschliessen.
        _flush()
        bytes_sent = 0
        bytes_received = 0
        have_socket = False
        current_key = None

        parts = line.split()
        # Header-Zeile (``State Recv-Q ...``) oder zu kurze Zeile -> kein Socket.
        if len(parts) < 5 or parts[0] in ("State", "Recv-Q"):
            continue
        local = _split_addr_port(parts[-2])
        remote = _split_addr_port(parts[-1])
        # Beide Adressspalten muessen als ip:port parsbar sein, sonst kein Socket.
        if local is None or remote is None:
            continue
        # Kanonischer key ueber die Domaene (deckt sich mit dem Stufe-1-key).
        current_key = make_socket_key("tcp", local[0], local[1], remote[0], remote[1])
        have_socket = True

    _flush()
    return result


class PsutilTrafficAdapter:
    """Erfuellt das ``PerProcessTrafficProvider``-Protocol (Executor-Wrapper, psutil)."""

    async def list_connections(self) -> list[Connection]:
        """Stufe 1: aktuelle Verbindungen als rohe ``Connection``-Liste.

        Blockierendes ``psutil``-I/O -> ``run_in_executor`` (Loop bleibt frei). Keine
        Verbindungen -> ``[]`` (vertraglicher Leer-Zustand, kein Fehler).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._list_connections_sync)

    def _list_connections_sync(self) -> list[Connection]:
        """Synchroner Verbindungs-Kern (laeuft im Executor-Thread).

        ``psutil.net_connections(kind="inet")`` -> je sconn eine ``Connection``. Nur
        TCP/UDP (``_L4_BY_SOCKET_KIND``); andere Socket-Typen werden uebersprungen.
        ``status`` ueber ``normalize_status``, ``local``/``remote`` ueber
        ``_endpoint``, ``app_name`` ueber ``_resolve_app_name`` (nur bei PID). Die
        Stufe-2-Felder (``bytes_*``/``*_rate_bps``) bleiben ``None`` -- Stufe-1-Sicht.
        """
        result: list[Connection] = []
        for conn in psutil.net_connections(kind="inet"):
            l4 = _L4_BY_SOCKET_KIND.get(int(conn.type))
            if l4 is None:
                continue  # weder TCP noch UDP -- nicht Teil der Per-App-Sicht
            local = _endpoint(conn.laddr)
            if local is None:
                continue  # ohne lokalen Endpunkt keine sinnvolle Verbindung
            app_name = _resolve_app_name(conn.pid) if conn.pid else None
            result.append(
                Connection(
                    l4=l4,
                    status=normalize_status(conn.status),
                    local=local,
                    remote=_endpoint(conn.raddr),
                    pid=conn.pid,
                    app_name=app_name,
                )
            )
        return result

    async def sample_throughput(self) -> list[ConnSample]:
        """Stufe 2: EIN Messpunkt der kumulativen TCP-Byte-Zaehler (``ss -tin``).

        Blockierendes ``ss``-Subprocess-I/O -> ``run_in_executor`` (Loop bleibt frei).
        Keine TCP-Sockets -> ``[]`` (vertraglicher Leer-Zustand). ``ss`` fehlt /
        Timeout / Fehlerstatus -> ``ThroughputUnavailableError`` (ehrlicher Fehler
        statt stiller Null, S3).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sample_throughput_sync)

    def _sample_throughput_sync(self) -> list[ConnSample]:
        """Synchroner Durchsatz-Kern (laeuft im Executor-Thread).

        ``ss -tin`` -> ``parse_ss_output`` (reine, zeitfreie Funktion) -> je Socket ein
        ``ConnSample``. Der Adapter stempelt EINEN gemeinsamen ``monotonic_ts`` fuer
        die ganze Momentaufnahme (die Uhr lebt hier in der Infrastruktur, nie in der
        Domaene). Die Raten aus zwei Messpunkten rechnet der Use-Case (T.4b).
        """
        text = _run(["ss", "-tin"])
        ts = time.monotonic()
        return [
            ConnSample(key=key, bytes_sent=sent, bytes_received=recv, monotonic_ts=ts)
            for key, sent, recv in parse_ss_output(text)
        ]
