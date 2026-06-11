"""Linux-Adapter der diagnostics-Domaene (1a): ``dig``-DNS + ``traceroute``-Pfad.

Erfuellt drei Vertraege strukturell ueber System-Binaries (Konsistenz mit ``ss`` in
traffic -- System-Tools statt Python-Libs, ADR 0014):

* ``DigDnsResolver`` (``DnsResolver``) -- ruft ``dig`` pro angefragtem Typ und parst die
  Antwort-Zeilen robust zu ``DnsRecord``-Werten.
* ``SystemTracerouteRunner`` (``TracerouteRunner``) -- ruft ``traceroute`` (privilegiert:
  ICMP via ``-I``; unprivilegiert: UDP-Default) und parst die Hop-Zeilen robust zu
  ``TracerouteHop`` (nicht-antwortende Hops als ``address``/``rtt_ms`` ``None``).
* ``LinuxTraceroutePermission`` (``TraceroutePermissionPort``) -- lokale, synchrone
  Rechte-Pruefung (Binary da? + ``geteuid``).
* ``ShutilToolDetector`` (``ToolDetector``, 1b) -- ein einzelnes Binary nutzbar?
  (``shutil.which``).
* ``LinuxPackageManagerDetector`` (``PackageManagerDetector``, 1b) -- der erste in fester,
  deterministischer Reihenfolge gefundene Paketmanager. Reine ``which``-Pruefung, KEIN
  Distro-Raten ueber ``/etc/os-release`` -- robust gegen Derivate (ein Derivat erbt den
  Paketmanager seiner Basis, nicht zwingend den Distro-Namen).
* ``SocketBannerGrabber`` (``BannerGrabber``, 2a) -- klopft EINMAL an einen Port und liest
  die Begruessung. Die Methode kommt aus ``domain.probe_for_port`` (passive vs. http_head);
  Verbindung ueber ``asyncio.open_connection`` mit ``wait_for``-Timeouts. SICHERHEITS-
  GRENZE: bei ``http_head`` wird GENAU eine minimale, standardkonforme HTTP-HEAD-Anfrage
  gesendet (keine konfigurierbaren Payloads); bei ``passive`` wird NICHTS gesendet, nur
  gelesen -- Banner-Grabbing bleibt Diagnose, kein Byte-Sender.

TLS-PORTS in 2a (ADR 0014 Block 2a): {443, 8443} sind in ``domain.probe_for_port`` bewusst
NICHT in der http_head-Menge -- ein roher Connect dorthin spraeche TLS, kein Klartext-HTTP.
Sie gelten als ``passive`` und gruessen bei rohem Connect nicht -> ehrlich ``no_banner``.
KEIN TLS-Handshake in 2a (das waere Scope-Ausweitung).

Schablone ``infrastructure/process_linux.py``: ``async``-Methoden kapseln das blockierende
Subprocess-I/O ueber ``run_in_executor`` (Event-Loop bleibt frei); der synchrone Kern und
die reinen Parser-Helfer liegen ausserhalb der Klassen und sind ohne Adapter-Instanz
testbar. Der Banner-Adapter (2a) ist nativ ``async`` (asyncio-Sockets statt Subprocess) --
sein blockierendes I/O ist bereits non-blocking ueber den Event-Loop gekapselt.

TOOL-FEHLT-NAHT (Ring-Realitaet, vom Auftrag vorgesehene Abweichung): Der
import-linter-Contract "infrastructure kennt nicht application/api" verbietet diesem Ring,
``application.diagnostics.errors.DiagnosticsToolMissingError`` zu importieren/werfen. Der
etablierte Repo-Weg fuer einen infrastruktur-erkannten Ausfall ist
``infrastructure.secret_store.SecretStoreUnavailableError``: eine INFRASTRUKTUR-eigene
Exception (``DiagnosticsToolMissing``), die der Composition Root (``app.py``) ueber einen
globalen ``exception_handler`` auf 503 abbildet. Darum wird hier ``DiagnosticsToolMissing``
geworfen (NUR neutrale Meldung, KEIN Install-Befehl -- das reichert Block 1b an).

SCOPE (CLAUDE.md "Nur Linux x64"): ``dig``/``traceroute`` sind Unix-Tools; der
Plattform-Riegel sitzt im Rechte-Adapter (``geteuid``/``which``). Kein ``modules``-Import
(import-linter-Contract "neue Ringe importieren NICHT modules" bleibt unberuehrt).
"""

import asyncio
import contextlib
import os
import re
import shutil
import subprocess
from collections.abc import Sequence

from domain.diagnostics import (
    BannerProbe,
    BannerResult,
    DnsRecord,
    DnsRecordType,
    DnsResult,
    PackageManager,
    TracerouteHop,
    TracerouteResult,
    dedup_records,
    probe_for_port,
    sanitize_banner,
)


class DiagnosticsToolMissing(Exception):
    """Ein benoetigtes System-Binary (``dig``/``traceroute``) fehlt -- infra-eigen.

    Vorbild ``infrastructure.secret_store.SecretStoreUnavailableError``: eine
    infrastruktur-eigene Exception, die der Composition Root (``app.py``) auf 503
    abbildet. ``tool`` ist der Name des fehlenden Binaries; ``message`` die neutrale,
    nutzerseitige Meldung (KEIN distro-spezifischer Install-Befehl -- das ist Block 1b).
    """

    def __init__(self, tool: str) -> None:
        self.tool = tool
        self.message = f"Programm '{tool}' wurde nicht gefunden."
        super().__init__(self.message)


# Kurzer Standard-Timeout fuer die Subprocess-Aufrufe -- ein haengender dig/traceroute
# darf den Request nicht unbegrenzt blockieren. ``traceroute`` ist von Natur aus langsam
# (mehrere Hops a mehrere Probes), darum grosszuegiger als dig.
_DIG_TIMEOUT_SECS = 10.0
_TRACEROUTE_TIMEOUT_SECS = 60.0
# Banner-Grabbing (2a): kurze Connect-/Read-Timeouts -- ein stiller Port darf den Request
# nicht haengen lassen. Getrennt, weil ein Connect schnell scheitern soll, das Lesen aber
# kurz auf die Begruessung wartet.
_BANNER_CONNECT_TIMEOUT_SECS = 3.0
_BANNER_READ_TIMEOUT_SECS = 3.0
# Maximale Rohbytes, die beim passiven Lauschen gelesen werden -- die Begruessung ist kurz;
# die Domaene (``sanitize_banner``) kuerzt ohnehin auf die erste Zeile + Maximallaenge.
_BANNER_READ_MAX_BYTES = 1024


# ── DNS-Parser (rein, testbar) ────────────────────────────────────────────────


def _parse_dig_answer(output: str, record_type: DnsRecordType) -> list[DnsRecord]:
    """Parst die ``dig +noall +answer``-Ausgabe einer Typ-Abfrage -> ``DnsRecord``-Liste.

    Jede Antwort-Zeile hat die Form ``<name> <ttl> <class> <type> <value...>`` (Tab-/
    Space-getrennt, z. B. ``example.com. 195 IN A 104.20.23.154``). Der Wert ist ALLES
    ab dem 5. Feld (bei MX ``10 smtp.google.com.``, bei TXT der gequotete Inhalt). Es
    werden NUR Zeilen uebernommen, deren Typ dem angefragten ``record_type`` entspricht
    -- so faellt eine begleitende CNAME-Zeile in einer A-Antwort nicht faelschlich als
    A-Record durch. Leere/kommentar-/formfremde Zeilen werden defensiv uebersprungen
    (kein Erfinden, kein Abbruch).
    """
    records: list[DnsRecord] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue  # Leerzeile oder dig-Kommentar
        fields = stripped.split()
        if len(fields) < 5:
            continue  # formfremde Zeile (kein vollstaendiger Antwort-Datensatz)
        line_type = fields[3]
        if line_type != record_type:
            continue  # anderer Typ (z. B. CNAME-Begleitzeile) -- nicht uebernehmen
        value = " ".join(fields[4:])
        records.append(DnsRecord(record_type=record_type, value=value))
    return records


# ── traceroute-Parser (rein, testbar) ─────────────────────────────────────────

# Eine Hop-Zeile beginnt mit Whitespace + Hop-Nummer, z. B. " 1  fritzbox (172.18.0.1)
# 0.674 ms ...". Die Kopfzeile ("traceroute to ...") wird verworfen (kein fuehrender int).
_HOP_LINE_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
# Erste IP in Klammern, z. B. "(172.18.0.1)" oder "(2001:db8::1)" -- bevorzugte Adresse.
_PAREN_ADDR_RE = re.compile(r"\(([^)]+)\)")
# Erster Hostname-Token (vor der ersten Klammer), falls keine Klammer-IP da ist.
_HOST_TOKEN_RE = re.compile(r"^([^\s(]+)")
# Erste RTT-Angabe "<float> ms".
_RTT_RE = re.compile(r"([0-9]+(?:\.[0-9]+)?)\s*ms")


def _parse_traceroute_hop(hop_number: int, rest: str) -> TracerouteHop:
    """Parst den Rest EINER traceroute-Hop-Zeile -> ``TracerouteHop`` -- rein.

    ``rest`` ist alles nach der Hop-Nummer. Ein nicht-antwortender Hop ist ``* * *`` ->
    ``address``/``rtt_ms`` ehrlich ``None`` (KEIN erfundener Wert). Sonst wird die erste
    Adresse (bevorzugt die IP in Klammern, sonst der erste Hostname-Token) und die erste
    ``<float> ms``-RTT uebernommen. Ein gemischter Hop (erst ``*``, dann eine Antwort)
    liefert die erste echte Adresse/RTT, die in der Zeile auftaucht.
    """
    addr_match = _PAREN_ADDR_RE.search(rest)
    address: str | None
    if addr_match is not None:
        address = addr_match.group(1)
    else:
        host_match = _HOST_TOKEN_RE.match(rest)
        # Ein nacktes "*" ist KEINE Adresse -- dann bleibt address None.
        if host_match is not None and host_match.group(1) != "*":
            address = host_match.group(1)
        else:
            address = None
    rtt_match = _RTT_RE.search(rest)
    rtt_ms = float(rtt_match.group(1)) if rtt_match is not None else None
    return TracerouteHop(hop=hop_number, address=address, rtt_ms=rtt_ms)


def _parse_traceroute(output: str) -> list[TracerouteHop]:
    """Parst die ganze ``traceroute``-Ausgabe -> ``TracerouteHop``-Liste -- rein.

    Die Kopfzeile (``traceroute to ...``) hat keine fuehrende Hop-Nummer und wird
    verworfen. Jede uebrige Zeile mit fuehrender Nummer ist ein Hop (auch ``* * *`` ->
    Luecke). Reihenfolge bleibt erhalten (Hop-Nummer aufsteigend, wie traceroute liefert).
    """
    hops: list[TracerouteHop] = []
    for line in output.splitlines():
        match = _HOP_LINE_RE.match(line)
        if match is None:
            continue  # Kopfzeile / Leerzeile -- kein Hop
        hop_number = int(match.group(1))
        hops.append(_parse_traceroute_hop(hop_number, match.group(2)))
    return hops


# ── Adapter ───────────────────────────────────────────────────────────────────


class DigDnsResolver:
    """Erfuellt das ``DnsResolver``-Protocol ueber das System-``dig``-Binary."""

    async def resolve(self, query: str, types: Sequence[DnsRecordType]) -> DnsResult:
        """Loest ``query`` ueber ``dig`` (pro Typ eine Abfrage) -> ``DnsResult``.

        Blockierendes ``dig``-Subprocess-I/O -> ``run_in_executor`` (Loop bleibt frei).
        Fehlt ``dig`` im PATH -> ``DiagnosticsToolMissing`` (kein stiller Fallback).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._resolve_sync, query, tuple(types))

    def _resolve_sync(self, query: str, types: tuple[DnsRecordType, ...]) -> DnsResult:
        """Synchroner DNS-Kern (laeuft im Executor-Thread).

        Fehlt ``dig`` -> ``DiagnosticsToolMissing``. Sonst je angefragtem Typ ein
        ``dig +noall +answer``-Aufruf; die Antwort-Zeilen ueber ``_parse_dig_answer`` zu
        Records, dann ueber die Domaene (``dedup_records``) deduppt+sortiert. Ein Aufruf,
        der scheitert oder leer bleibt (NXDOMAIN/kein Eintrag), traegt schlicht keine
        Records bei -- KEIN Fehler (leere Antwort ist ein gueltiges Ergebnis).
        """
        if shutil.which("dig") is None:
            raise DiagnosticsToolMissing("dig")
        collected: list[DnsRecord] = []
        for record_type in types:
            output = _run_dig(query, record_type)
            collected.extend(_parse_dig_answer(output, record_type))
        return DnsResult(
            query=query,
            requested_types=types,
            records=dedup_records(collected),
        )


class SystemTracerouteRunner:
    """Erfuellt das ``TracerouteRunner``-Protocol ueber das System-``traceroute``-Binary."""

    async def run(self, target: str, privileged: bool) -> TracerouteResult:
        """Misst den Pfad zu ``target`` ueber ``traceroute`` -> ``TracerouteResult``.

        Blockierendes ``traceroute``-Subprocess-I/O -> ``run_in_executor`` (Loop bleibt
        frei). Fehlt das Binary -> ``DiagnosticsToolMissing``.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._run_sync, target, privileged)

    def _run_sync(self, target: str, privileged: bool) -> TracerouteResult:
        """Synchroner traceroute-Kern (laeuft im Executor-Thread).

        Fehlt ``traceroute`` -> ``DiagnosticsToolMissing``. ``privileged=True`` -> ICMP
        (``-I``, genauere Root-Methode), ``False`` -> UDP-Default (unprivilegiert). Die
        Hop-Zeilen ueber ``_parse_traceroute`` zu ``TracerouteHop`` (nicht-antwortende
        Hops als ``None``-Luecke). ``privileged`` wird unveraendert ins Ergebnis gespiegelt
        -- die ehrliche Auskunft, WIE gemessen wurde.
        """
        if shutil.which("traceroute") is None:
            raise DiagnosticsToolMissing("traceroute")
        output = _run_traceroute(target, privileged)
        return TracerouteResult(
            target=target,
            privileged=privileged,
            hops=tuple(_parse_traceroute(output)),
        )


class LinuxTraceroutePermission:
    """Erfuellt das ``TraceroutePermissionPort``-Protocol (lokale Rechte-Pruefung, Linux)."""

    def is_available(self) -> bool:
        """``True``, wenn das ``traceroute``-Binary im PATH liegt, sonst ``False``."""
        return shutil.which("traceroute") is not None

    def check_permission(self) -> str | None:
        """``None`` wenn als Root laufend (``geteuid() == 0``), sonst der Hinweis-Text.

        Als Root ist die genauere (privilegierte, z. B. ICMP-)Methode moeglich -> ``None``.
        Sonst ein kurzer Begruendungstext: die genauere Methode braucht Root; ohne Root
        wird die unprivilegierte (ungenauere) Methode verwendet. KEIN stiller Fallback
        (S3), KEIN Install-Befehl (Block 1b). Keine Selbst-Eskalation -- der Adapter
        stellt nur fest, welche Rechte da sind.

        SCOPE (CLAUDE.md "Nur Linux x64"): ``os.geteuid`` ist Unix; auf Nicht-Unix gibt es
        kein euid-Konzept -- dort ist die privilegierte Methode nicht feststellbar, daher
        der Hinweis (defensiv, ``is_available`` riegelt ohnehin ueber das Binary ab).
        """
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return None
        return (
            "Die genauere (privilegierte) traceroute-Methode benoetigt Root. Ohne Root "
            "wird die unprivilegierte (ungenauere) Methode verwendet - starte das Backend "
            "als Root, z.B. 'sudo cernis-backend', fuer die genauere Messung."
        )


# ── Block 1b: Tool-/Paketmanager-Erkennung (reine which-Adapter) ───────────────

# Erkennungs-Reihenfolge der Paketmanager (fest + deterministisch). Der ERSTE im PATH
# gefundene gewinnt -- KEIN Distro-Raten ueber /etc/os-release (robust gegen Derivate).
# apt vor dnf/yum: Debian/Ubuntu-Linie zuerst; yum (RHEL-Alt) nach dnf (RHEL-neu), damit
# auf Systemen mit beiden der modernere dnf gewinnt.
_PACKAGE_MANAGER_ORDER: tuple[PackageManager, ...] = ("apt", "dnf", "yum", "zypper", "pacman")


class ShutilToolDetector:
    """Erfuellt das ``ToolDetector``-Protocol ueber ``shutil.which`` (1b)."""

    def is_available(self, tool: str) -> bool:
        """``True``, wenn ``tool`` im PATH liegt (``shutil.which`` != None), sonst ``False``."""
        return shutil.which(tool) is not None


class LinuxPackageManagerDetector:
    """Erfuellt das ``PackageManagerDetector``-Protocol ueber ``shutil.which`` (1b)."""

    def detect(self) -> PackageManager | None:
        """Der erste in ``_PACKAGE_MANAGER_ORDER`` gefundene Manager, sonst ``None``.

        Reine ``which``-Pruefung in fester Reihenfolge -- KEIN Distro-Raten ueber
        ``/etc/os-release`` (ein Derivat erbt den Paketmanager, nicht zwingend den Namen).
        Keiner im PATH -> ``None`` (dann liefert die Domaene ehrlich keinen Install-Befehl).
        """
        for manager in _PACKAGE_MANAGER_ORDER:
            if shutil.which(manager) is not None:
                return manager
        return None


# ── Block 2a: Banner-Grabbing (asyncio-Sockets, eine minimale Anfrage) ─────────


def _build_http_head_request(target: str) -> bytes:
    """Baut GENAU eine minimale, standardkonforme HTTP-HEAD-Anfrage -- rein, testbar.

    ``HEAD / HTTP/1.0\\r\\nHost: <target>\\r\\n\\r\\n`` -- HTTP/1.0 schliesst die Verbindung
    nach der Antwort von selbst (kein keep-alive-Aufraeumen noetig). ``HEAD`` fordert NUR
    die Header an (kein Body) -- genug fuer Statuszeile + ``Server``-Header. SICHERHEITS-
    GRENZE: das ist die EINZIGE Anfrage, die der Adapter je sendet; keine konfigurierbaren
    Payloads, kein generischer Byte-Sender (Banner-Grabbing bleibt Diagnose).
    """
    return f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode()


def _banner_from_http_head(response: str) -> str | None:
    """Extrahiert Statuszeile + ``Server``-Header aus einer HTTP-HEAD-Antwort -- rein.

    Die erste Zeile ist die Statuszeile (z. B. ``HTTP/1.0 200 OK``); ein ``Server:``-Header
    (case-insensitiv) wird, falls vorhanden, angehaengt (``HTTP/1.0 200 OK | Server:
    nginx``). Ohne lesbare Statuszeile -> ``None`` (der Aufrufer leitet daraus ``no_banner``
    ab). Rein: gleiche Eingabe -> gleiches Ergebnis (kein I/O).
    """
    lines = response.splitlines()
    status_line = lines[0].strip() if lines else ""
    if not status_line:
        return None
    for line in lines[1:]:
        if line.lower().startswith("server:"):
            server_value = line.split(":", 1)[1].strip()
            return f"{status_line} | Server: {server_value}"
    return status_line


class SocketBannerGrabber:
    """Erfuellt das ``BannerGrabber``-Protocol (2a) ueber rohe asyncio-TCP-Sockets.

    Bestimmt die Methode ueber ``domain.probe_for_port`` (passive vs. http_head),
    verbindet ueber ``asyncio.open_connection`` mit ``wait_for``-Timeouts und liest die
    Begruessung. SICHERHEITS-GRENZE: bei ``http_head`` GENAU eine minimale HTTP-HEAD-Anfrage
    (keine konfigurierbaren Payloads); bei ``passive`` wird NICHTS gesendet, nur gelesen.
    Ehrliche Semantik (kein erfundener Banner): Connect ok + Banner gelesen -> ``ok``;
    Connect ok + nichts Lesbares -> ``no_banner``; ConnectionRefused -> ``closed``;
    Timeout/unerreichbar -> ``filtered``.
    """

    async def grab(self, target: str, port: int) -> BannerResult:
        """Klopft an ``target:port`` und liest die Begruessung -> ``BannerResult``.

        Die Methode kommt aus ``domain.probe_for_port`` -- TLS-Ports {443, 8443} sind dort
        bewusst ``passive`` (kein TLS-Handshake in 2a; ein roher Connect gruesst dort nicht
        -> ehrlich ``no_banner``). Das blockierende Socket-I/O ist bereits non-blocking
        ueber den asyncio-Event-Loop gekapselt; die Methode bleibt sauber ``async``.
        """
        probe = probe_for_port(port)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=_BANNER_CONNECT_TIMEOUT_SECS,
            )
        except ConnectionRefusedError:
            # Aktiv abgewiesen -- der Port ist zu, aber erreichbar.
            return BannerResult(target=target, port=port, probe=probe, banner=None, state="closed")
        except (TimeoutError, OSError):
            # Timeout (asyncio.wait_for) oder unerreichbar (OSError, z. B. no route).
            return BannerResult(
                target=target, port=port, probe=probe, banner=None, state="filtered"
            )
        try:
            raw = await self._read_banner(reader, writer, target, probe)
        finally:
            writer.close()
            # Beim Schliessen darf ein bereits halb-offener Socket nicht den Befund kippen.
            with contextlib.suppress(OSError):
                await writer.wait_closed()
        if probe == "http_head":
            banner = _banner_from_http_head(raw)
        else:
            cleaned = sanitize_banner(raw)
            banner = cleaned or None
        if banner is None:
            # Verbunden, aber keine lesbare Antwort -> ehrlich no_banner (kein erfundener Wert).
            return BannerResult(
                target=target, port=port, probe=probe, banner=None, state="no_banner"
            )
        return BannerResult(
            target=target,
            port=port,
            probe=probe,
            banner=sanitize_banner(banner),
            state="ok",
        )

    async def _read_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: str,
        probe: BannerProbe,
    ) -> str:
        """Sendet (nur bei http_head) die EINE Anfrage und liest die rohe Antwort.

        ``http_head``: sendet GENAU die minimale HTTP-HEAD-Anfrage und liest die Header-
        Antwort. ``passive``: sendet NICHTS, liest nur kurz mit (der Dienst gruesst selbst).
        Ein Read-Timeout liefert die bis dahin gelesenen Bytes (ehrliche Teil-Sicht -- leer
        bei stillen Diensten, woraus der Aufrufer ``no_banner`` ableitet).
        """
        if probe == "http_head":
            writer.write(_build_http_head_request(target))
            await writer.drain()
        try:
            data = await asyncio.wait_for(
                reader.read(_BANNER_READ_MAX_BYTES),
                timeout=_BANNER_READ_TIMEOUT_SECS,
            )
        except (TimeoutError, OSError):
            # Stiller Dienst / Lesefehler -> leer (Aufrufer leitet no_banner ab).
            return ""
        return data.decode(errors="replace")


# ── Subprocess-Aufrufe (gekapselt, in Tests gemockt) ──────────────────────────


def _run_dig(query: str, record_type: DnsRecordType) -> str:
    """Ruft ``dig +noall +answer <query> <type>`` und gibt die rohe stdout zurueck.

    ``+noall +answer`` reduziert die Ausgabe auf die Antwort-Datensaetze (eine Zeile pro
    Record). Ein nicht-Null-Returncode oder ein Timeout (z. B. nicht aufloesbarer Name)
    wird als LEERE Ausgabe behandelt -- keine Antwort ist KEIN Fehler (leere ``records``).
    Ein fehlendes Binary faengt der Aufrufer ueber ``shutil.which`` ab.
    """
    try:
        completed = subprocess.run(
            ["dig", "+noall", "+answer", query, record_type],
            capture_output=True,
            text=True,
            timeout=_DIG_TIMEOUT_SECS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ""
    return completed.stdout


def _run_traceroute(target: str, privileged: bool) -> str:
    """Ruft ``traceroute`` (privilegiert: ``-I`` ICMP; sonst UDP-Default) -> rohe stdout.

    ``-n`` wird NICHT gesetzt -- die Hostnamen sind nuetzlich, der Parser nimmt bevorzugt
    die IP in Klammern. Ein nicht-Null-Returncode oder Timeout wird als die bis dahin
    gesammelte stdout behandelt (traceroute liefert Hops zeilenweise; ein Abbruch lieferte
    bereits ermittelte Hops). Ein fehlendes Binary faengt der Aufrufer ueber
    ``shutil.which`` ab.
    """
    args = ["traceroute"]
    if privileged:
        args.append("-I")  # ICMP-Echo -- genauere Root-Methode
    args.append(target)
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=_TRACEROUTE_TIMEOUT_SECS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        # Bis zum Timeout gesammelte Hops noch verwerten (ehrliche Teil-Sicht).
        partial = exc.stdout
        if isinstance(partial, bytes):
            return partial.decode(errors="replace")
        return partial or ""
    return completed.stdout
