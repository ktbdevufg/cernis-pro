"""Use-Cases fuers Aufraeumen nach Netz (S88-P3).

DER ANLASS: Der Geraetebestand kennt kein Netz. Ein Scan ist ein reines
MAC-Upsert je gefundenem Geraet; nicht gefundene Geraete werden gar nicht
angefasst. Scannt der Anwender ein ANDERES Netz, bleiben die alten Geraete
unmarkiert in der Liste stehen, und er wird sie heute nur einzeln los.

ZWEI Use-Cases:

* ``GruppiereGeraeteNachNetz`` -- rechnet die Netzgruppen aus dem Bestand aus.
* ``EntferneGeraeteMenge``     -- loescht eine MENGE von Geraeten vollstaendig.

WARUM DIE GRUPPIERUNG HIER LIEGT und nicht in der Domaene (Auftrag 2.1): Die
devices-Domaene kennt kein Netz und soll keines lernen. Ein ``Device`` traegt eine
``last_ip`` -- mehr nicht. Die Zuordnung IP -> Netz ist eine Rechnung ueber
vorhandene Daten, kein Wesenszug eines Geraets. Sie wird auch NICHT gespeichert
(Auftrag 2.4: keine neue Spalte, kein Schema-Eingriff) -- jede Abfrage rechnet sie
frisch aus dem aktuellen ``last_ip``-Stand.

Kennt ausschliesslich ``ports/`` + ``domain/`` (import-linter), NIE
``infrastructure/``.
"""

import ipaddress
from dataclasses import dataclass

import structlog

from ports.devices import DeviceRepository
from ports.maintenance import DevicePurgeRepository

__all__ = [
    "OHNE_IP",
    "EntferneGeraeteMenge",
    "GruppiereGeraeteNachNetz",
    "NetzGruppe",
]

_logger = structlog.get_logger(__name__)

# Die Kennung der Gruppe fuer Geraete OHNE brauchbare letzte IP (Auftrag 2.2).
# Bewusst KEINE gueltige Netzangabe, damit sie sich nie mit einer echten Gruppe
# verwechseln laesst; das Frontend uebersetzt sie in "Ohne bekannte IP" /
# "Without known IP" und schickt sie unveraendert zurueck.
OHNE_IP = "ohne-ip"


@dataclass(frozen=True)
class NetzGruppe:
    """Eine Netzgruppe: die Netzangabe, die Anzahl und die MACs.

    ``netz`` ist entweder eine /24-Angabe (``"192.168.1.0/24"``) oder die
    Konstante ``OHNE_IP``. ``macs`` ist sortiert, damit die Anzeige ruhig bleibt
    und ein Test sich auf die Reihenfolge verlassen kann.
    """

    netz: str
    anzahl: int
    macs: tuple[str, ...]


def _netz_von(last_ip: str | None) -> str:
    """Die /24-Netzangabe einer IP, oder ``OHNE_IP`` wenn unbrauchbar.

    ``None`` ist ein echter Fall, kein Sonderweg: ``Device.last_ip`` ist optional
    (ein von Hand angelegtes Geraet hat nie eine IP gehabt). Es faellt wie eine
    leere IP in die Ohne-IP-Gruppe.

    WARUM /24 (Auftrag 2.1): Das ist die Groesse, in der der Anwender sein Netz
    denkt -- "die 192.168.1er". Die echte Netzmaske des Interfaces waere technisch
    genauer, steht am Geraetebestand aber gar nicht zur Verfuegung (ein ``Device``
    traegt nur seine letzte IP, keine Maske), und sie zu raten waere schlechter als
    die Konvention, die jeder Heim- und Buero-Anwender ohnehin vor Augen hat.

    Unbrauchbar heisst: leer, kein gueltiges IP-Literal -- oder eine IPv6-Adresse.
    IPv6 faellt bewusst in die Ohne-IP-Gruppe statt in ein erfundenes /24: ein /24
    ist ein IPv4-Begriff, und ein IPv6-Praefix daraus zu basteln waere eine
    Zuordnung, die der Anwender nicht wiedererkennt. Kein stiller Ersatzwert (S3):
    diese Geraete verschwinden nicht, sie bekommen ihre eigene Gruppe (2.2).
    """
    roh = (last_ip or "").strip()
    if not roh:
        return OHNE_IP
    try:
        adresse = ipaddress.ip_address(roh)
    except ValueError:
        return OHNE_IP
    if not isinstance(adresse, ipaddress.IPv4Address):
        return OHNE_IP
    return str(ipaddress.ip_network(f"{adresse}/24", strict=False))


class GruppiereGeraeteNachNetz:
    """Rechnet die Netzgruppen des AKTIVEN Geraetebestands aus.

    ARCHIVIERTE GERAETE bleiben aussen vor (Auftrag 2.3: "miss, wie der Bestand sie
    in der aktiven Liste behandelt, und folge dem"). Gemessen: ``get_all`` filtert
    ``archived = 0`` (``SqliteDeviceRepository.get_all``), und die Geraeteverwaltung
    fuehrt das Archiv als EIGENE Tabelle mit eigenem Weg zurueck. Wer aufraeumt,
    raeumt also genau das ab, was er in der aktiven Liste vor sich sieht -- ein
    archiviertes Geraet ist bereits weggeraeumt und soll nicht unbemerkt mit
    geloescht werden.
    """

    def __init__(self, devices: DeviceRepository) -> None:
        self._devices = devices

    def __call__(self) -> list[NetzGruppe]:
        """Die Gruppen, sortiert: echte Netze zuerst, die Ohne-IP-Gruppe zuletzt.

        Leerer Bestand -> ``[]``. Eine Gruppe ohne Mitglieder entsteht nie (sie
        wird ja aus ihren Mitgliedern gebildet).
        """
        nach_netz: dict[str, list[str]] = {}
        for geraet in self._devices.get_all(known_only=False):
            nach_netz.setdefault(_netz_von(geraet.last_ip), []).append(geraet.mac)

        gruppen = [
            NetzGruppe(netz=netz, anzahl=len(macs), macs=tuple(sorted(macs)))
            for netz, macs in nach_netz.items()
        ]

        # Echte Netze aufsteigend nach Adresse (nicht alphabetisch -- sonst stuende
        # 192.168.10.0/24 vor 192.168.9.0/24); die Ohne-IP-Gruppe immer ans Ende,
        # weil sie kein Netz ist und der Anwender sie als Restposten liest.
        def _ordnung(gruppe: NetzGruppe) -> tuple[int, tuple[int, ...], str]:
            if gruppe.netz == OHNE_IP:
                return (1, (), "")
            netzwerk = ipaddress.ip_network(gruppe.netz)
            return (0, tuple(int(teil) for teil in str(netzwerk.network_address).split(".")), "")

        return sorted(gruppen, key=_ordnung)


class EntferneGeraeteMenge:
    """Loescht eine MENGE von Geraeten VOLLSTAENDIG -- Geraet, IP-Verlauf, Nebendaten.

    KEINE SCHLEIFE ueber ``DELETE /api/devices/{mac}`` (Auftrag 1.2), und auch keine
    Schleife ueber ``DeviceRepository.delete``. Begruendung: Nur EINE Transaktion
    haelt Geraet und Nebendaten zusammen. Ein Abbruch mitten in 23 Einzelaufrufen --
    Netz weg, Backend neu gestartet, DB gesperrt -- hinterliesse einen HALBEN
    Bestand: ein Teil der Geraete geloescht, der Rest da, und bei den geloeschten
    saessen die CVE-Befunde und ARP-Alarme verwaist in ihren Tabellen, ohne Geraet,
    auf das sie sich beziehen. Solche Reste sind schlimmer als gar keine Loeschung,
    weil sie sich nachtraeglich nicht mehr zuordnen lassen. Darum genau EIN Aufruf
    an den ``DevicePurgeRepository``, der alles in einer Transaktion abraeumt.
    """

    def __init__(self, purge: DevicePurgeRepository) -> None:
        self._purge = purge

    def __call__(self, macs: list[str]) -> int:
        """Loescht die uebergebenen Geraete; liefert die Zahl der entfernten Geraete.

        Eine LEERE Auswahl loescht nichts und ist KEIN Fehler (Auftrag 4.5) -- der
        Anwender, der ohne Haekchen bestaetigt, hat schlicht nichts gewaehlt; das
        ist kein Fehlverhalten, das eine Fehlermeldung verdiente.

        Unbekannte oder ungueltige MACs sind ebenfalls kein Fehler: sie raeumen nur
        nichts ab. Das folgt dem gemessenen Verhalten des Bestands bei
        ``DELETE /api/devices/{mac}``, das ausdruecklich idempotent ist ("Loeschen
        ist idempotent -> kein 404", ``api/devices.py``). Ein 404 mitten in einer
        Mengenloeschung waere auch fachlich unbrauchbar: die Liste, aus der der
        Anwender gewaehlt hat, kann zwischen Anzeige und Klick veraltet sein (ein
        paralleler Scan, ein zweites Fenster), und dann duerfte ein inzwischen
        verschwundenes Geraet nicht die Loeschung der uebrigen 22 verhindern.
        """
        entfernt = self._purge.purge_devices(macs)
        _logger.info("geraete_menge_entfernt", angefragt=len(macs), entfernt=entfernt)
        return entfernt
