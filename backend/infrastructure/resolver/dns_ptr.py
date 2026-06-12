"""resolver-Adapter (Teilschritt 2a): PTR + Vorwaerts-DNS ueber System-``dig``.

Erfuellt ``ports.resolver.PtrResolverPort`` strukturell ueber das System-``dig``-Binary
-- die Bausteine des Forward-Confirmed-Abgleichs (Reverse + Vorwaerts). Konsistent mit
``infrastructure.diagnostics_linux.DigDnsResolver`` (System-Tools statt Python-Libs):
das blockierende ``dig``-Subprocess-I/O wird ueber ``run_in_executor`` gekapselt (der
Event-Loop bleibt frei), und die reinen Helfer leben ausserhalb der Klasse (ohne
Adapter-Instanz testbar).

EIGENSTAENDIG (bewusst, kein Wiederverwenden): Dieser Adapter spricht System-``dig``
direkt ueber stdlib (``subprocess``/``shutil``/``ipaddress``). KEIN ``modules``-Import,
KEIN Import aus ``infrastructure.scanning.hostname_resolver`` (der haengt an der
ADR-0007-``modules``-Ausnahme -- hier ein sauberer, neuer Adapter). KEIN Import aus
``application``/``api`` (Contract "infrastructure kennt nicht application/api").

TOOL-FEHLT-NAHT: fehlt ``dig`` im PATH -> infra-eigene ``ResolverToolMissing`` (kein
stiller Fallback, S3). Ein scheiternder/leerer ``dig``-Aufruf ist dagegen KEIN Fehler,
sondern ein gueltiger Leer-Zustand (``""`` bzw. ``()``) -- Muster
``ports.resolver.PtrResolverPort`` (ein fehlender Eintrag ist gueltig, kein Fehler).
"""

import asyncio
import ipaddress
import shutil
import subprocess

from infrastructure.resolver.errors import ResolverToolMissing

# Kurzer Standard-Timeout fuer die ``dig``-Aufrufe -- ein haengender dig darf den Request
# nicht unbegrenzt blockieren. Eigene lokale Konstante (bewusst NICHT die diagnostics-
# Konstante importiert -- Adapter-Unabhaengigkeit), aber gleicher Wert wie dort.
_DIG_TIMEOUT_SECS = 10.0


def _run_dig(*args: str) -> str:
    """Ruft ``dig <args...>`` und gibt die rohe stdout zurueck -- gekapselt, gemockt.

    Ein nicht-Null-Returncode oder ein Timeout (z. B. nicht aufloesbarer Name) wird als
    LEERE Ausgabe behandelt -- keine Antwort ist KEIN Fehler (leerer Zustand beim
    Aufrufer). Ein fehlendes Binary faengt der Aufrufer ueber ``shutil.which`` ab.
    """
    try:
        completed = subprocess.run(
            ["dig", *args],
            capture_output=True,
            text=True,
            timeout=_DIG_TIMEOUT_SECS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ""
    return completed.stdout


def _first_ptr_name(output: str) -> str:
    """Liefert den ersten PTR-Namen aus einer ``dig +short -x``-Ausgabe ohne Punkt -- rein.

    ``dig +short -x`` liefert je PTR-Eintrag eine Zeile (z. B. ``one.one.one.one.``).
    Mehrere Antwortzeilen -> die erste nehmen; der abschliessende Wurzel-Punkt wird
    entfernt. Kein Eintrag/leere Ausgabe -> ``""`` (gueltiger Leer-Zustand). Rein: kein I/O.
    """
    for line in output.splitlines():
        name = line.strip()
        if name:
            return name.rstrip(".")
    return ""


def _valid_ips(output: str) -> tuple[str, ...]:
    """Filtert die gueltigen IP-Literale aus einer ``dig +short``-Ausgabe -- rein.

    ``dig +short <name> A``/``AAAA`` kann CNAME-Zwischenzeilen (Namen) liefern -- diese
    werden ueber ``ipaddress.ip_address`` verworfen (nur echte IP-Literale durchlassen).
    Dedupliziert bei stabiler Reihenfolge (erstes Auftreten gewinnt). Rein: kein I/O.
    """
    seen: set[str] = set()
    ips: list[str] = []
    for line in output.splitlines():
        candidate = line.strip()
        if not candidate or candidate in seen:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue  # CNAME-Zwischenzeile o. ae. -- kein IP-Literal, verwerfen
        seen.add(candidate)
        ips.append(candidate)
    return tuple(ips)


class DigDnsPtrResolver:
    """Erfuellt das ``PtrResolverPort``-Protocol ueber das System-``dig``-Binary."""

    async def resolve_ptr(self, ip: str) -> str:
        """Loest den PTR-Namen zur ``ip`` ueber ``dig +short -x`` -> Name oder ``""``.

        Blockierendes ``dig``-Subprocess-I/O -> ``run_in_executor`` (Loop bleibt frei).
        Fehlt ``dig`` im PATH -> ``ResolverToolMissing`` (kein stiller Fallback). Kein
        Eintrag/NXDOMAIN/leere oder scheiternde Abfrage -> ``""`` (gueltiger Leer-Zustand).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._resolve_ptr_sync, ip)

    def _resolve_ptr_sync(self, ip: str) -> str:
        """Synchroner PTR-Kern (laeuft im Executor-Thread).

        Fehlt ``dig`` -> ``ResolverToolMissing``. Sonst ``dig +short -x <ip>`` und den
        ersten PTR-Namen ohne abschliessenden Punkt; mehrere Zeilen -> erste nehmen.
        """
        if shutil.which("dig") is None:
            raise ResolverToolMissing("dig")
        return _first_ptr_name(_run_dig("+short", "-x", ip))

    async def resolve_forward(self, hostname: str) -> tuple[str, ...]:
        """Loest die Vorwaerts-IPs zum ``hostname`` (A + AAAA) -> IP-Tuple oder ``()``.

        Blockierendes ``dig``-Subprocess-I/O -> ``run_in_executor`` (Loop bleibt frei).
        Fehlt ``dig`` im PATH -> ``ResolverToolMissing``. Keine Treffer/scheiternde
        Abfrage -> ``()`` (gueltiger Leer-Zustand).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._resolve_forward_sync, hostname)

    def _resolve_forward_sync(self, hostname: str) -> tuple[str, ...]:
        """Synchroner Vorwaerts-Kern (laeuft im Executor-Thread).

        Fehlt ``dig`` -> ``ResolverToolMissing``. Sonst ``dig +short <hostname> A`` UND
        ``... AAAA`` (beide Familien); die Ausgaben zusammengefuehrt ueber ``_valid_ips``
        auf gueltige IP-Literale gefiltert (CNAME-Zwischenzeilen verworfen), dedupliziert
        bei stabiler Reihenfolge (A vor AAAA).
        """
        if shutil.which("dig") is None:
            raise ResolverToolMissing("dig")
        combined = _run_dig("+short", hostname, "A") + _run_dig("+short", hostname, "AAAA")
        return _valid_ips(combined)
