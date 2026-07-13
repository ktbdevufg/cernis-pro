"""Windows-Zweig des resolver-Adapters: PTR + Vorwaerts-DNS ueber ``dnspython``.

Erfuellt ``ports.resolver.PtrResolverPort`` strukturell -- exakt derselbe Vertrag,
dieselben Signaturen und dasselbe Leer-/Fehlerverhalten wie der bestehende
``infrastructure.resolver.dns_ptr.DigDnsPtrResolver``: Klasse
``DnspythonPtrResolver`` mit ``async def resolve_ptr``/``resolve_forward`` ueber
synchrone Kerne, die per ``run_in_executor`` im Thread laufen (Event-Loop bleibt frei).

DATENQUELLE (bewusst KEIN ``nslookup``-Parsing): das System-``dig``-Binary existiert auf
Windows nicht, und die Textausgabe von ``nslookup`` ist lokalisiert -- ein Textparser
scheitert auf deutschen/franzoesischen Windows-Versionen still (verboten). Stattdessen die
Bibliothek ``dnspython`` (bereits Projektabhaengigkeit), die die Resolver-Konfiguration des
Systems selbst einliest und die DNS-Antworten strukturiert liefert. ``dnspython`` ist
plattformunabhaengig -- daher KEIN ``sys.platform``-Guard im Modul noetig (anders als bei den
ctypes-Adaptern); die Plattform-Weiche sitzt im Composition Root (``app.py``).

VERHALTEN deckungsgleich zum ``dig``-Adapter:
* ``resolve_ptr`` -> erster PTR-Name OHNE abschliessenden Wurzel-Punkt, sonst ``""``.
* ``resolve_forward`` -> IP-Tuple (A vor AAAA), stabil dedupliziert, sonst ``()``.
* Zeitlimit: dieselbe lokale Konstante ``_DNS_TIMEOUT_SECS = 10.0`` (Wert des
  ``dig``-Adapters), als ``lifetime`` an die Abfrage gegeben -- ein haengender DNS-Server
  darf den Request nicht unbegrenzt blockieren.

KEIN STILLER FALLBACK (S3), aber Leer ist gueltig: ein fehlender Eintrag (NXDOMAIN), eine
leere Antwort (NoAnswer), erschoepfte/nicht antwortende Nameserver (NoNameservers) und ein
Timeout sind allesamt gueltige Leer-Zustaende (``""`` bzw. ``()``) -- exakt wie ein
scheiternder/leerer ``dig``-Aufruf. Erfasst wird dafuer ``dns.exception.DNSException`` (die
gemeinsame Basis all dieser Faelle); ein davon NICHT abgedeckter, echter Programmierfehler
wird NICHT verschluckt, sondern schlaegt durch.

EIGENSTAENDIG (wie der ``dig``-Adapter): kein ``modules``-Import, kein Import aus
``application``/``api``. Die reinen Helfer leben ausserhalb der Klasse (ohne Adapter-Instanz
und ohne Netz testbar).
"""

import asyncio
import ipaddress

import dns.exception
import dns.name
import dns.resolver
import dns.reversename

# Kurzer Standard-Timeout fuer die DNS-Abfragen -- ein haengender Nameserver darf den
# Request nicht unbegrenzt blockieren. Eigene lokale Konstante (bewusst NICHT die des
# dig-Adapters importiert -- Adapter-Unabhaengigkeit), aber GLEICHER Wert wie dort
# (``dns_ptr._DIG_TIMEOUT_SECS``).
_DNS_TIMEOUT_SECS = 10.0


def _first_ptr_name(names: list[str]) -> str:
    """Liefert den ersten PTR-Namen ohne abschliessenden Wurzel-Punkt -- rein.

    ``dnspython`` liefert je PTR-Eintrag einen Namen (z. B. ``one.one.one.one.``).
    Mehrere Antworten -> die erste nehmen; der abschliessende Wurzel-Punkt wird entfernt.
    Kein Eintrag/leere Liste -> ``""`` (gueltiger Leer-Zustand). Deckungsgleich zum
    ``_first_ptr_name`` des dig-Adapters (nur die Eingabe ist bereits eine Namensliste
    statt roher ``dig``-Textzeilen). Rein: kein I/O.
    """
    for name in names:
        stripped = name.strip()
        if stripped:
            return stripped.rstrip(".")
    return ""


def _valid_ips(candidates: list[str]) -> tuple[str, ...]:
    """Filtert die gueltigen IP-Literale aus einer Kandidatenliste -- rein.

    ``ipaddress.ip_address`` verwirft alles, was kein echtes IP-Literal ist (defensive
    Absicherung, obwohl dnspython bereits Adress-Rdata liefert). Dedupliziert bei stabiler
    Reihenfolge (erstes Auftreten gewinnt) -- deckungsgleich zum ``_valid_ips`` des
    dig-Adapters. Rein: kein I/O.
    """
    seen: set[str] = set()
    ips: list[str] = []
    for candidate in candidates:
        value = candidate.strip()
        if not value or value in seen:
            continue
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue  # kein IP-Literal -- verwerfen
        seen.add(value)
        ips.append(value)
    return tuple(ips)


def _query_names(qname: "dns.name.Name | str", rdtype: str) -> list[str]:
    """Fragt ``qname``/``rdtype`` ueber den System-Resolver -> Liste der Antwort-Strings.

    ``lifetime`` = ``_DNS_TIMEOUT_SECS`` begrenzt die Gesamtdauer (haengender Server).
    Ein fehlender Eintrag / eine leere Antwort / erschoepfte Nameserver / ein Timeout
    (allesamt ``dns.exception.DNSException``) sind KEIN Fehler, sondern ein gueltiger
    Leer-Zustand -> leere Liste (Muster: scheiternder/leerer ``dig``-Aufruf). Jeder Rdata
    wird ueber ``str`` in seinen Text ueberfuehrt (PTR-Name bzw. IP-Literal); die
    Aufbereitung leisten die reinen ``_first_ptr_name``/``_valid_ips``-Helfer.
    """
    try:
        answer = dns.resolver.resolve(qname, rdtype, lifetime=_DNS_TIMEOUT_SECS)
    except dns.exception.DNSException:
        return []
    return [str(rdata) for rdata in answer]


class DnspythonPtrResolver:
    """Erfuellt das ``PtrResolverPort``-Protocol ueber ``dnspython`` (Windows-Zweig)."""

    async def resolve_ptr(self, ip: str) -> str:
        """Loest den PTR-Namen zur ``ip`` ueber ``dnspython`` -> Name oder ``""``.

        Blockierendes DNS-I/O -> ``run_in_executor`` (Loop bleibt frei). Kein
        Eintrag/NXDOMAIN/leere oder scheiternde Abfrage/Timeout -> ``""`` (gueltiger
        Leer-Zustand). Deckungsgleich zum dig-Adapter (dort ``dig +short -x``).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._resolve_ptr_sync, ip)

    def _resolve_ptr_sync(self, ip: str) -> str:
        """Synchroner PTR-Kern (laeuft im Executor-Thread).

        ``dns.reversename.from_address(ip)`` bildet die ``in-addr.arpa``-/``ip6.arpa``-
        Abfrage; PTR-Query, dann den ersten Namen ohne abschliessenden Punkt. Eine
        ungueltige ``ip`` liefert ``ipaddress``/``dnspython`` einen ``ValueError`` bzw.
        eine ``DNSException`` -- Ersterer bleibt (echte Fehleingabe, kein Leer-Zustand);
        die DNS-Leerfaelle faengt ``_query_names`` ab.
        """
        qname = dns.reversename.from_address(ip)
        return _first_ptr_name(_query_names(qname, "PTR"))

    async def resolve_forward(self, hostname: str) -> tuple[str, ...]:
        """Loest die Vorwaerts-IPs zum ``hostname`` (A + AAAA) -> IP-Tuple oder ``()``.

        Blockierendes DNS-I/O -> ``run_in_executor`` (Loop bleibt frei). Keine
        Treffer/scheiternde Abfrage/Timeout -> ``()`` (gueltiger Leer-Zustand).
        Deckungsgleich zum dig-Adapter (dort ``dig +short <hostname> A``/``AAAA``).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._resolve_forward_sync, hostname)

    def _resolve_forward_sync(self, hostname: str) -> tuple[str, ...]:
        """Synchroner Vorwaerts-Kern (laeuft im Executor-Thread).

        A- UND AAAA-Query (beide Familien); die Ergebnisse zusammengefuehrt ueber
        ``_valid_ips`` auf gueltige IP-Literale gefiltert und dedupliziert bei stabiler
        Reihenfolge (A vor AAAA) -- exakt die Reihenfolge/Dedup-Semantik des dig-Adapters.
        """
        combined = _query_names(hostname, "A") + _query_names(hostname, "AAAA")
        return _valid_ips(combined)
