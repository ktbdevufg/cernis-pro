"""Best-effort Ermittlung der REAL genutzten System-DNS-Nameserver (ADR 0043, Etappe 2).

Zweck: die tatsaechlich aktiven Resolver-IPs des Systems einsammeln, um sie spaeter dem
Nutzer zur Vertrauens-Einordnung VORzulegen -- NICHT, um sie automatisch als "erwartet"
zu setzen (das ist eine bewusste Kuratier-Entscheidung, keine Auto-Ableitung).

Streng fehlertolerant und mit HARTEM Timeout: das Einlesen darf nie blockieren. Bevorzugt
wird ``resolvectl`` (systemd-resolved kennt die je Link aktiven Upstream-Server); der
blockierende Subprocess laeuft im Executor-Thread mit ``asyncio.wait_for`` als hartem
Timeout -- Muster ``infrastructure/reverse_dns.py``. Jeglicher Fehler / Timeout / das Fehlen
von ``resolvectl`` liefert fuer diesen Weg eine leere Liste (KEIN Crash).

Faellt ``resolvectl`` leer aus, greift der Fallback ``/etc/resolv.conf`` (die
``nameserver <ip>``-Zeilen). WICHTIG: der systemd-resolved-Stub ``127.0.0.53`` -- und
generell jedes Loopback (``127.0.0.0/8`` / ``::1``) -- wird VERWORFEN: als echter Upstream-
Resolver ist er wertlos (er verweist nur zurueck auf den lokalen Stub).

EIGENSTAENDIG (Scope Linux x64): nur stdlib (``asyncio``, ``subprocess`` via
``create_subprocess_exec``, ``shutil.which``, ``ipaddress``, ``pathlib``). KEIN ``modules``-
Import, KEIN Import aus ``application``/``api`` (Contract "infrastructure kennt nicht
application/api"). Die reinen Parse-Kerne sind herausgezogen und ohne Subprocess/IO testbar.
"""

import asyncio
import contextlib
import ipaddress
import os
import shutil
import sys
from pathlib import Path

# resolvectl wird mit erzwungener C-Locale gestartet, weil lokalisierte Ausgaben (z.B.
# Zeit= statt time=) das Parsing sonst still scheitern lassen.
_C_LOCALE_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}

# Kurzer, harter Standard-Timeout (Sekunden) fuer den resolvectl-Subprocess: die Ermittlung
# ist Beigabe, kein Muss -- sie darf den Aufrufer nie fesseln (< 1.5s, Auftrag).
_RESOLVECTL_TIMEOUT_SECS = 1.2

# Standard-Pfad des glibc-Resolver-Fallbacks.
_RESOLV_CONF_PATH = Path("/etc/resolv.conf")


def _canonical_ip(raw: str) -> str | None:
    """Kanonisiert eine IP-Adresse via ``ipaddress`` -> kanonischer Str oder ``None``.

    Zieht eine etwaige systemd-Zone/Interface-Angabe (``%eth0``) und Klammern ab. Kein
    gueltiges IP-Literal -> ``None`` (die Zeile war kein Resolver, still verworfen). Loopback
    (``127.0.0.0/8`` / ``::1``) -> ``None``: der systemd-resolved-Stub ``127.0.0.53`` und jedes
    andere Loopback sind als echter Upstream-Resolver wertlos.
    """
    candidate = raw.strip().strip("[]")
    if not candidate:
        return None
    # systemd haengt bei link-lokalen Adressen eine Zone an (fe80::1%eth0) -- fuer die
    # Kanonisierung abschneiden.
    candidate = candidate.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if addr.is_loopback:
        return None
    return str(addr)


def _dedupe_stable(ips: list[str]) -> list[str]:
    """Dedupliziert unter Erhalt der ersten Reihenfolge (stabil)."""
    seen: set[str] = set()
    result: list[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def parse_resolvectl_output(output: str) -> list[str]:
    """Zieht die aktiven DNS-Server-IPs aus einer ``resolvectl status``-Ausgabe (reiner Kern).

    Beachtet die Zeilen ``Current DNS Server:`` (der aktuell gewaehlte) und ``DNS Servers:``
    (die Menge je Link, u. U. ueber mehrere Zeilen fortgesetzt). Loopback-Stubs werden ueber
    ``_canonical_ip`` verworfen, das Ergebnis stabil dedupliziert. Kein Treffer -> ``[]``.
    """
    collected: list[str] = []
    in_servers_block = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Current DNS Server:"):
            in_servers_block = False
            value = stripped.split(":", 1)[1]
            canonical = _canonical_ip(value)
            if canonical is not None:
                collected.append(canonical)
            continue
        if stripped.startswith("DNS Servers:"):
            # "DNS Servers: 1.1.1.1 8.8.8.8" -- die Server stehen (space-separiert) auf
            # derselben Zeile und koennen auf eingerueckten Folgezeilen fortgesetzt werden.
            in_servers_block = True
            value = stripped.split(":", 1)[1]
            collected.extend(_extract_ips_from_fragment(value))
            continue
        if in_servers_block:
            # Fortsetzungszeile: nur wenn sie (eingerueckt) weitere IPs traegt und KEIN
            # neues "Feld:" oeffnet -- ein ":" beendet den Block.
            if not line.startswith((" ", "\t")) or ":" in stripped:
                in_servers_block = False
                continue
            fragment_ips = _extract_ips_from_fragment(stripped)
            if fragment_ips:
                collected.extend(fragment_ips)
            else:
                in_servers_block = False
    return _dedupe_stable(collected)


def _extract_ips_from_fragment(fragment: str) -> list[str]:
    """Kanonisiert alle space-separierten Tokens eines Fragments -> gueltige IPs (Loopback raus)."""
    result: list[str] = []
    for token in fragment.split():
        canonical = _canonical_ip(token)
        if canonical is not None:
            result.append(canonical)
    return result


def parse_resolv_conf(content: str) -> list[str]:
    """Zieht die ``nameserver <ip>``-IPs aus einem ``/etc/resolv.conf``-Text (reiner Kern).

    Kommentar-/Leerzeilen werden ignoriert; der systemd-resolved-Stub ``127.0.0.53`` und
    jedes andere Loopback fallen ueber ``_canonical_ip`` heraus. Stabil dedupliziert.
    """
    collected: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        parts = stripped.split()
        if len(parts) < 2 or parts[0] != "nameserver":
            continue
        canonical = _canonical_ip(parts[1])
        if canonical is not None:
            collected.append(canonical)
    return _dedupe_stable(collected)


async def _run_resolvectl(timeout: float) -> list[str]:
    """Fuehrt ``resolvectl status`` best-effort mit hartem Timeout aus -> IP-Liste oder ``[]``.

    Fehlt ``resolvectl`` (``shutil.which`` -> ``None``) oder schlaegt der Aufruf fehl / laeuft
    in den Timeout, ist das Ergebnis leer (KEIN Crash). Der Timeout wird ueber
    ``asyncio.wait_for`` erzwungen; bei Ablauf wird der Subprocess getoetet.
    """
    if shutil.which("resolvectl") is None:
        return []
    proc: asyncio.subprocess.Process | None = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "resolvectl",
            "status",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=_C_LOCALE_ENV,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (TimeoutError, OSError):
        # Timeout ODER Start-/Laufzeit-Fehler -> leer. Bei Timeout den (u. U. noch
        # laufenden) Subprocess best-effort beenden, damit kein Zombie zurueckbleibt.
        if proc is not None and proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
        return []
    if proc.returncode != 0:
        return []
    return parse_resolvectl_output(stdout.decode("utf-8", errors="replace"))


def _read_resolv_conf(path: Path) -> list[str]:
    """Liest die ``nameserver``-IPs aus ``path`` best-effort -> IP-Liste oder ``[]``.

    Datei fehlt/unlesbar -> ``[]`` (KEIN Crash). Der reine Parser leistet das Verwerfen der
    Loopback-Stubs.
    """
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return parse_resolv_conf(content)


async def detect_system_resolvers(
    timeout: float = _RESOLVECTL_TIMEOUT_SECS,
    *,
    resolv_conf_path: Path = _RESOLV_CONF_PATH,
) -> list[str]:
    """Ermittelt die real genutzten System-DNS-Server best-effort -> kanonische IP-Liste.

    Auf Windows existieren weder ``resolvectl`` noch ``/etc/resolv.conf`` -- dort greift der
    native Windows-Zweig (``GetAdaptersAddresses`` via ctypes, Feld ``FirstDnsServerAddress``),
    der dieselbe kanonische, loopback-freie, stabil deduplizierte IP-Liste liefert. Auf Linux
    bleibt die bestehende Logik voellig unveraendert.

    Erst ``resolvectl status`` (mit hartem Timeout im Executor/Subprocess); liefert der Weg
    IPs, gewinnt er. Ist er leer (kein systemd-resolved, Fehler, Timeout), greift der
    ``/etc/resolv.conf``-Fallback. Beide Wege verwerfen Loopback-Stubs (insb. ``127.0.0.53``)
    und liefern kanonische, stabil deduplizierte IPs. Eine LEERE Liste ist ein gueltiges
    Ergebnis (der Nutzer bekommt dann eben nichts vorgelegt -- kein Fehler).
    """
    # Windows-Zweig: Import UND Aufruf stehen im positiven sys.platform-Guard, weil mypy
    # sys.platform statisch auswertet -- auf dem Linux-Runner existiert der im win32-Block
    # importierte Name sonst nicht (name-defined-Fehler, hat die CI bereits gebrochen). Der
    # native Aufruf ist nicht blockierend (kein Subprocess/IO-Wait) -> ohne Executor/Timeout.
    if sys.platform == "win32":
        from infrastructure.system_resolvers_windows import detect_windows_resolvers

        return detect_windows_resolvers()

    via_resolvectl = await _run_resolvectl(timeout)
    if via_resolvectl:
        return via_resolvectl
    return _read_resolv_conf(resolv_conf_path)
