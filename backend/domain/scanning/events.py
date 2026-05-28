"""ScanEvent-Vokabular der scanning-Domaene (frozen dataclasses).

Das vom Use-Case (application, S.5) erzeugte Ereignis-Vokabular; die api-Schicht
(S.6) uebersetzt es in WS-Frames. KEINE Transport-/JSON-Details hier.

``ScanEvent`` ist als Union (PEP-695-``type``-Alias) modelliert, NICHT als
Basisklasse: so kann mypy ein ``match`` ueber alle Event-Typen via
``typing.assert_never`` auf Vollstaendigkeit pruefen. Mit einer Basisklasse
koennte mypy die Menge der Subklassen nicht abschliessend kennen -- die
Exhaustiveness-Pruefung entfiele.
"""

from dataclasses import dataclass

from domain.scanning.models import EnrichedHost


@dataclass(frozen=True)
class ScanStarted:
    cidr: str
    total_hosts: int


@dataclass(frozen=True)
class PhaseChanged:
    phase: str
    status: str
    # phasenspezifisch: ``total`` bei running, ``alive_count`` bei discovery/done.
    total: int | None = None
    alive_count: int | None = None


@dataclass(frozen=True)
class HostFound:
    ip: str
    mac: str
    vendor: str
    rtt_ms: float | None
    is_unknown: bool
    source: str


@dataclass(frozen=True)
class HostEnriched:
    host: EnrichedHost


@dataclass(frozen=True)
class Progress:
    phase: str
    completed: int
    total: int
    pct: int


@dataclass(frozen=True)
class Info:
    message: str


@dataclass(frozen=True)
class ScanCompleted:
    total_found: int


@dataclass(frozen=True)
class ScanError:
    message: str


type ScanEvent = (
    ScanStarted
    | PhaseChanged
    | HostFound
    | HostEnriched
    | Progress
    | Info
    | ScanCompleted
    | ScanError
)
