"""Ports der resolver-Domaene: vier Quell-Vertraege, je Belang getrennt.

Vier Vertraege, abschaltbar gedacht (jede Quelle kann fehlen, ohne die anderen zu
brechen) und nach Belang getrennt: PTR/Forward-DNS, RDAP, lokale Geo/ASN-DB und der
TLS-Zertifikatsabruf. Jeder Port liefert ROHFAKTEN, KEINE Verschmelzung -- das
Zusammenstellen zu ``RemoteEndpointFacts`` (samt Quellen-Tags) ist Sache des spaeteren
Use-Cases, nicht der Ports.

None/leerer Zustand ist GUELTIG, KEIN Fehler: ein PTR ohne Eintrag liefert ``""``, ein
RDAP-Lookup ohne Treffer liefert einen leeren ``RdapRawFacts``, ein TLS-Abruf bei
jeglichem Fehlschlag ``None``. Muster ``ports.scanning.HostnameResolverPort.resolve``
-> ``""`` statt zu werfen.

Async wo Netz-/Loop-I/O zu erwarten ist (PTR/RDAP/TLS reden ueber das Netz), sync wo
der Lookup rein lokal ist (Geo/ASN-DB -- Muster ``ports.scanning.VendorLookupPort``).

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie analysis/process/traffic/
scanning). Die Vertragspruefung traegt mypy statisch und die Verdrahtung im Composition
Root (``app.py``), nicht ``isinstance`` zur Laufzeit.

``ports/`` kennt NUR ``domain/resolver``-Typen + stdlib/typing. KEIN ``infrastructure/``-
und kein ``api/``-Import -- import-linter-Contract "ports kennen hoechstens domain".
"""

from typing import Protocol

from domain.resolver import GeoAsnRecord, RdapRawFacts, TlsCertDetails


class PtrResolverPort(Protocol):
    """Reverse- und Vorwaerts-DNS -- die Bausteine des Forward-Confirmed-Abgleichs.

    Async: beide Aufrufe reden ueber das Netz (DNS-Loop-I/O). Ein fehlender Eintrag ist
    ein gueltiger Leer-Zustand, KEIN Fehler.
    """

    async def resolve_ptr(self, ip: str) -> str:
        """Liefert den PTR-Namen zur ``ip`` oder ``""`` (kein Eintrag/Fehlschlag)."""
        ...

    async def resolve_forward(self, hostname: str) -> tuple[str, ...]:
        """Liefert die Vorwaerts-IPs zum ``hostname`` als Tuple (``()`` wenn keine)."""
        ...


class RdapClientPort(Protocol):
    """RDAP-Lookup -- liefert die Netz-/Org-/ASN-Rohfakten zur ``ip``.

    Async (Netz-I/O). Das RIR-spezifische Parsen (verschiedene Registries, verschachtelte
    Antworten) ist Sache des Adapters; der Port-Vertrag kennt nur den schmalen Rohtyp
    ``RdapRawFacts``. Eine leere/teilweise Antwort ist gueltig, KEIN Fehler.
    """

    async def lookup(self, ip: str) -> RdapRawFacts:
        """Liefert die RDAP-Rohfakten zur ``ip`` (leerer ``RdapRawFacts`` wenn nichts)."""
        ...


class GeoAsnDbPort(Protocol):
    """Lokaler Geo/ASN-DB-Lookup -- Land/ASN/ASN-Org zur ``ip``.

    Synchron: ein rein lokaler DB-Lookup ohne Netz-/Loop-I/O (Muster
    ``ports.scanning.VendorLookupPort.lookup``). Ein nicht gefundener Eintrag liefert
    einen leeren ``GeoAsnRecord``, KEIN Fehler.
    """

    def lookup(self, ip: str) -> GeoAsnRecord:
        """Liefert den Geo/ASN-Rohdatensatz zur ``ip`` (leerer Record wenn nichts)."""
        ...


class TlsCertPort(Protocol):
    """TLS-Zertifikatsabruf -- streng fehlertolerant, blockiert/wirft NIE.

    Async (Netz-I/O: TLS-Handshake). Vertraglich darf dieser Port bei JEGLICHEM
    Fehlschlag (Timeout, kein TLS, Handshake-Fehler, ...) ausschliesslich ``None``
    zurueckgeben -- er DARF nie blockieren und nie werfen. So bleibt eine nicht
    erreichbare/nicht-TLS-Gegenstelle ein gueltiger Leer-Zustand statt eines Fehlers.
    """

    async def fetch_cert(
        self, ip: str, port: int, hostname: str | None = None
    ) -> TlsCertDetails | None:
        """Liefert die Zertifikatsdetails zu ``ip``/``port`` oder ``None`` (Fehlschlag).

        ``hostname`` ist der optionale SNI-Servername (der PTR-Name, den der Use-Case
        ohnehin ermittelt). Ist er gesetzt -> SNI mit diesem Namen; ist er ``None`` ->
        GAR KEIN SNI (besser als eine IP als SNI, die SNI-strikte Server mit einem
        Dummy-Cert quittieren). Weiterhin streng fehlertolerant: ``None`` bei jeglichem
        Fehlschlag.
        """
        ...
