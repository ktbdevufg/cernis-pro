"""resolver-Adapter (Teilschritt 2b): TlsCertReader -- wertneutraler Cert-Abruf.

Erfuellt ``ports.resolver.TlsCertPort`` strukturell: holt per TLS-Handshake die nackten
anzeigbaren Zertifikatsfelder einer Gegenstelle als ``domain.resolver.TlsCertDetails``.

BEWUSST WERTNEUTRAL -- anders als ``infrastructure.security.tls``: dieser Adapter vergibt
KEIN Grade, sammelt KEINE warnings und trifft KEIN Sicherheitsurteil. Er liefert nur die
Rohfelder. Die EINZIGE Domaenenlogik ist ``domain.resolver.detect_self_signed`` -- eine
reine FESTSTELLUNG (subject == issuer), kein Urteil; sie lebt dort an EINER Stelle.

EIGENSTAENDIG (independence-Contract): die ssl/socket-Mechanik ist von
``infrastructure.security.tls`` NACHGEBAUT, NICHT importiert. KEIN Import aus
``infrastructure.security``, KEIN ``modules``-Import, KEIN Import aus ``application``/
``api`` (Contract "infrastructure kennt nicht application/api").

Bewusst dokumentiert (Vorbild ``security/tls.py``): ``ctx.check_hostname = False`` +
``CERT_OPTIONAL`` -- damit auch self-signed/abgelaufene Zertifikate auslesbar sind (das
Auslesen ist der Zweck; das Einordnen bleibt spaeteren Ringen ueberlassen).

STRENG FEHLERTOLERANT laut Port-Vertrag: bei JEGLICHEM Fehlschlag (Timeout,
ConnectionRefused, kein TLS, SSLError ohne ``.reason``, Parse-Fehler, beliebige
Exception) -> ``None``. NIE werfen, NIE ueber das feste Timeout hinaus blockieren.
"""

import asyncio
import hashlib
import socket
import ssl
from collections.abc import Iterable
from typing import Any

from domain.resolver import TlsCertDetails, detect_self_signed

# Festes Timeout fuer den Handshake -- ein haengender Peer darf den Request nicht
# unbegrenzt blockieren. Eigene lokale Konstante (Adapter-Unabhaengigkeit), gleicher Wert
# wie die security/tls.py-Vorlage (5.0s).
_HANDSHAKE_TIMEOUT_SECS = 5.0


def _extract_cn(name_tuples: Any) -> str | None:
    """Liefert den ``commonName`` aus einer getpeercert-Namensstruktur -- rein, kein I/O.

    ``getpeercert()`` liefert ``subject``/``issuer`` als verschachtelte Tupel
    (``(((key, value), ...), ...)``). Diese werden zu einem dict verflacht; der
    ``commonName`` daraus, sonst ``None`` (kein erfundener Wert). Rein: kein I/O.
    """
    if not name_tuples:
        return None
    flat = dict(entry[0] for entry in name_tuples)
    cn = flat.get("commonName")
    return str(cn) if cn is not None else None


def _extract_issuer(issuer_tuples: Any) -> str | None:
    """Liefert die Issuer-Kennung: ``organizationName``, sonst ``commonName``, sonst ``None``.

    Spiegelt die security/tls.py-Vorlage (Org bevorzugt, CN als Rueckfall), bleibt aber
    wertneutral -- nur das anzeigbare Feld, keine Einordnung. Rein: kein I/O.
    """
    if not issuer_tuples:
        return None
    flat = dict(entry[0] for entry in issuer_tuples)
    issuer = flat.get("organizationName", flat.get("commonName"))
    return str(issuer) if issuer is not None else None


def _san_values(cert_dict: dict[str, Any]) -> tuple[str, ...]:
    """Liefert die reinen Subject-Alternative-Name-Werte als Tuple -- rein, kein I/O.

    ``subjectAltName`` ist eine Liste von ``(typ, wert)``-Paaren (z. B.
    ``("DNS", "example.com")``); hier zaehlen nur die Werte. Keine SANs -> ``()``
    (gueltiger Leer-Zustand, kein Fehler). Rein: kein I/O.
    """
    return tuple(str(value) for _, value in cert_dict.get("subjectAltName", []))


def _fingerprint(der_bytes: bytes | None) -> str | None:
    """SHA-256 ueber die DER-Bytes als Gross-Doppelpunkt-Hex (z. B. ``AB:CD:..``) -- rein.

    Berechnet aus ``getpeercert(binary_form=True)``. Keine DER-Bytes (leer/``None``)
    -> ``None`` (kein erfundener Wert). Rein: kein I/O.
    """
    if not der_bytes:
        return None
    digest = hashlib.sha256(der_bytes).hexdigest().upper()
    return ":".join(_chunks(digest, 2))


def _chunks(text: str, size: int) -> Iterable[str]:
    """Zerlegt ``text`` in Stuecke fester ``size`` -- Helfer der Fingerprint-Formatierung."""
    for start in range(0, len(text), size):
        yield text[start : start + size]


def _parse_cert(cert_dict: dict[str, Any], der_bytes: bytes | None) -> TlsCertDetails:
    """Baut ``TlsCertDetails`` aus getpeercert()-dict + DER-Bytes -- wertneutral, rein.

    Fuellt ausschliesslich die nackten anzeigbaren Felder. ``self_signed`` kommt aus der
    reinen Domaenenfunktion ``detect_self_signed(subject_cn, issuer)`` (Feststellung
    subject == issuer, kein Urteil) -- die einzige erlaubte Domaenenlogik. Rein: kein I/O.
    """
    subject_cn = _extract_cn(cert_dict.get("subject"))
    issuer = _extract_issuer(cert_dict.get("issuer"))
    serial = cert_dict.get("serialNumber")
    return TlsCertDetails(
        subject_cn=subject_cn,
        san=_san_values(cert_dict),
        issuer=issuer,
        valid_from=cert_dict.get("notBefore"),
        valid_until=cert_dict.get("notAfter"),
        serial=str(serial) if serial is not None else None,
        fingerprint_sha256=_fingerprint(der_bytes),
        self_signed=detect_self_signed(subject_cn, issuer),
    )


class TlsCertReader:
    """Erfuellt das ``TlsCertPort``-Protocol -- wertneutraler TLS-Cert-Abruf (stdlib)."""

    async def fetch_cert(self, ip: str, port: int) -> TlsCertDetails | None:
        """Liefert die Zertifikatsdetails zu ``ip``/``port`` oder ``None`` (Fehlschlag).

        Blockierendes Handshake-I/O -> ``asyncio.to_thread`` (Loop bleibt frei). STRENG
        fehlertolerant laut Port-Vertrag: JEDER Fehlschlag (Timeout, kein TLS,
        Handshake-Fehler, Parse-Fehler, beliebige Exception) -> ``None``; NIE werfen, NIE
        ueber das feste Timeout hinaus blockieren.
        """
        return await asyncio.to_thread(self._fetch_cert_sync, ip, port)

    def _fetch_cert_sync(self, ip: str, port: int) -> TlsCertDetails | None:
        """Synchroner Handshake-Kern (laeuft im Thread). Orchestriert nur, faengt ALLES.

        Verbindet direkt zu ``ip``:``port`` (``server_hostname=ip``, ``check_hostname =
        False``, ``CERT_OPTIONAL`` -- damit auch self-signed/abgelaufene Zertifikate
        auslesbar sind). Klappt der Handshake, liefert aber kein Zertifikat (CERT_OPTIONAL,
        Gegenstelle ohne Cert), gilt das als Fehlschlag -> ``None`` (kein erfundenes
        leeres ``TlsCertDetails``). Jegliche Exception -> ``None``.
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_OPTIONAL

            with (
                socket.create_connection((ip, port), timeout=_HANDSHAKE_TIMEOUT_SECS) as sock,
                ctx.wrap_socket(sock, server_hostname=ip) as ssock,
            ):
                cert_dict = ssock.getpeercert()
                if not cert_dict:
                    return None  # Handshake ok, aber kein Cert -> Fehlschlag (None)
                der_bytes = ssock.getpeercert(binary_form=True)
                return _parse_cert(cert_dict, der_bytes)
        except Exception:
            # Port-Vertrag: bei JEGLICHEM Fehlschlag still None (kein Werfen, kein Log-
            # Urteil) -- Timeout, ConnectionRefused, SSLError (auch ohne .reason),
            # Parse-Fehler, beliebige Exception.
            return None
