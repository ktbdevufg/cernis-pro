"""SQLite-Adapter fuer den Port ``DefaultCredsHistoryRepository`` (Etappe B).

``SqliteDefaultCredsHistoryRepository`` protokolliert jede durchgefuehrte Standardzugangs-
Pruefung in einer eigenen Tabelle ``default_creds_history`` -- STIL EXAKT wie
``infrastructure/scanning/scan_history.py``:

* injizierter ``db_path`` (Pfad-Aufloesung im Composition Root, nicht hier),
* ``_ensure_schema`` im ``__init__``,
* ``@contextmanager _connect`` mit Transaktion (commit/rollback) + garantiertem ``close``,
* ``CREATE TABLE IF NOT EXISTS``,
* ``list`` selektiert bewusst NUR die Zusammenfassungs-Spalten (nicht den ``ergebnis_json``-
  Blob) -- das Findings-Detail kommt erst per ``get_eintrag`` (Muster ``ScanHistoryRepository``).

KEIN stiller Fallback bei kaputtem JSON (Finding S3 / Muster ``CorruptScanError``): ein
unlesbares oder formfremdes ``ergebnis_json`` wird zu ``CorruptDefaultCredsHistoryError``
MIT ``id``-Bezug (statt eines diffusen Tracebacks ODER eines leisen Rueckfalls auf ``[]``).
Die ``CredFinding`` <-> JSON-(De-)Serialisierung liegt VERLUSTFREI in dieser Infrastruktur
(nicht in der Domaene; ``CredFinding`` ist ein ports-Rand-Typ ohne Domaenenmodell).

UHR: ``geprueft_at`` wird beim Schreiben aus ``datetime.now(UTC)`` gesetzt (fixes ISO-UTC-
Text-Format, Muster ``_fmt_dt``/``_parse_dt`` aus ``device_repository``/``scan_history``).
Die Domaene traegt KEINE Zeit -- die Uhr lebt hier am Rand. Dieser Adapter importiert KEIN
``modules`` (kein ADR-0007).
"""

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from domain.security import PruefFall
from ports.security import (
    CredFinding,
    PruefHistorieDetail,
    PruefHistorieSummary,
)

__all__ = [
    "CorruptDefaultCredsHistoryError",
    "SqliteDefaultCredsHistoryRepository",
]

# Erlaubte Werte fuer den gespeicherten ``fall`` (deckungsgleich mit dem PruefFall-Literal
# der Domaene). Beim Lesen wird der Wert dagegen geprueft -- kein leiser Rueckfall bei
# formfremdem Wert (Muster CorruptScanError: kaputt ist ein Fehler, kein Fallback).
_FALL_WERTE: frozenset[str] = frozenset({"entwarnung", "kandidaten", "keine_infos"})


class CorruptDefaultCredsHistoryError(Exception):
    """Das ``ergebnis_json`` eines gespeicherten Historien-Datensatzes ist kaputt/formfremd.

    Ersetzt einen stillen Rueckfall (Finding S3 / Muster ``CorruptScanError``): ein
    unlesbares oder formfremdes ``ergebnis_json`` ist ein Fehler MIT ``id``-Bezug (statt
    eines diffusen Tracebacks ODER eines leisen Rueckfalls auf leere Findings).
    """

    def __init__(self, eintrag_id: int, raw_value: str) -> None:
        self.eintrag_id = eintrag_id
        self.raw_value = raw_value
        super().__init__(
            f"Historien-Eintrag {eintrag_id}: ergebnis_json ist keine gueltige "
            f"Findings-Liste: {raw_value!r}"
        )


def _fmt_dt(value: datetime) -> str:
    """datetime -> fixes ISO-8601-UTC-TEXT (immer 6-stellige Mikrosekunden).

    Naive Eingaben werden als UTC interpretiert (Muster ``device_repository._fmt_dt``).
    Das fixe Format macht TEXT-Vergleiche lexikografisch chronologisch korrekt.
    """
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat(timespec="microseconds")


def _findings_to_json(findings: Sequence[CredFinding]) -> str:
    """Serialisiert die Findings VERLUSTFREI nach JSON (Liste von Objekten).

    Jedes Finding wird zu ``{port, service, username, password, note}`` -- die Felder, die
    der Etappe-B-Verlauf braucht (host ist der Datensatz-host; success/method sind fuer die
    Historie nicht relevant -- ein gespeichertes Finding IST ein erfolgreicher Treffer).
    Deterministisch in der gegebenen Reihenfolge.
    """
    return json.dumps(
        [
            {
                "port": finding.port,
                "service": finding.service,
                "username": finding.username,
                "password": finding.password,
                "note": finding.note,
            }
            for finding in findings
        ]
    )


def _findings_from_json(eintrag_id: int, host: str, raw: str | None) -> tuple[CredFinding, ...]:
    """Deserialisiert ``ergebnis_json`` und validiert die Form -- KEIN stiller Fallback.

    Erwartet eine JSON-Liste von Objekten mit ``port`` (int), ``service``/``username``/
    ``password``/``note`` (str). Eine leere Liste (``[]``) ist ein gueltiger Zustand
    (Faelle "entwarnung"/"keine_infos" ODER eine Pruefung ohne Treffer). Ist ``raw``
    NULL/leer, kein JSON, keine Liste, oder hat ein Element die falsche Form ->
    ``CorruptDefaultCredsHistoryError`` (Muster ``CorruptScanError``). ``host`` stammt aus
    der Datensatz-Spalte (die Findings tragen ihn nicht doppelt) und rekonstruiert das
    ``CredFinding.host``-Feld verlustfrei.
    """
    if not raw:
        raise CorruptDefaultCredsHistoryError(eintrag_id, raw or "")
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CorruptDefaultCredsHistoryError(eintrag_id, raw) from exc
    if not isinstance(decoded, list):
        raise CorruptDefaultCredsHistoryError(eintrag_id, raw)

    findings: list[CredFinding] = []
    for element in decoded:
        if not isinstance(element, dict):
            raise CorruptDefaultCredsHistoryError(eintrag_id, raw)
        port = element.get("port")
        service = element.get("service")
        username = element.get("username")
        password = element.get("password")
        note = element.get("note")
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not isinstance(service, str)
            or not isinstance(username, str)
            or not isinstance(password, str)
            or not isinstance(note, str)
        ):
            raise CorruptDefaultCredsHistoryError(eintrag_id, raw)
        findings.append(
            CredFinding(
                host=host,
                port=port,
                service=service,
                username=username,
                password=password,
                # Ein gespeichertes Historien-Finding IST ein Treffer: success=True,
                # method aus dem service abgeleitet ist nicht rekonstruierbar/relevant --
                # die Historie zeigt WELCHES Cred-Paar auf welchem Port ging.
                success=True,
                method="",
                note=note,
            )
        )
    return tuple(findings)


class SqliteDefaultCredsHistoryRepository:
    """Erfuellt das ``DefaultCredsHistoryRepository``-Protocol strukturell (SQLite)."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._ensure_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Connection mit Transaktion (commit/rollback) und garantiertem close."""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        # AUTOINCREMENT-id, geprueft_at als ISO-UTC-TEXT (vom Adapter gesetzt, kein
        # datetime('now')-Default -- die Uhr lebt bewusst im Python-Rand), host/hersteller/
        # modell, fall (PruefFall-Literal), treffer_count, ergebnis_json (Findings-Blob).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS default_creds_history (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    geprueft_at   TEXT,
                    host          TEXT,
                    hersteller    TEXT,
                    modell        TEXT,
                    fall          TEXT,
                    treffer_count INTEGER,
                    ergebnis_json TEXT
                );
                """
            )

    def add_eintrag(
        self,
        host: str,
        hersteller: str,
        modell: str,
        fall: PruefFall,
        findings: Sequence[CredFinding],
    ) -> None:
        """Speichert einen Historien-Datensatz (``treffer_count = len(findings)``).

        ``geprueft_at`` wird HIER aus ``datetime.now(UTC)`` gesetzt (die Uhr lebt am Rand,
        nicht in der Domaene). Findings werden verlustfrei als ``ergebnis_json`` abgelegt.
        """
        payload = _findings_to_json(findings)
        geprueft_at = _fmt_dt(datetime.now(UTC))
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO default_creds_history "
                "(geprueft_at, host, hersteller, modell, fall, treffer_count, ergebnis_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (geprueft_at, host, hersteller, modell, fall, len(findings), payload),
            )

    def list_eintraege(self, limit: int = 50) -> list[PruefHistorieSummary]:
        """Die neuesten Datensaetze als ``PruefHistorieSummary``, neueste zuerst.

        Selektiert bewusst NUR die Zusammenfassungs-Spalten (nicht ``ergebnis_json``) --
        der Findings-Blob kommt erst per ``get_eintrag`` (Muster ``ScanHistoryRepository``).
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, geprueft_at, host, hersteller, modell, fall, treffer_count "
                "FROM default_creds_history ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            PruefHistorieSummary(
                eintrag_id=row["id"],
                geprueft_at=row["geprueft_at"] or "",
                host=row["host"],
                hersteller=row["hersteller"],
                modell=row["modell"],
                fall=cast(PruefFall, self._fall_or_raise(row["id"], row["fall"])),
                treffer_count=row["treffer_count"],
            )
            for row in rows
        ]

    def get_eintrag(self, eintrag_id: int) -> PruefHistorieDetail | None:
        """Ein Datensatz MIT Findings (``PruefHistorieDetail``). Unbekannte id -> ``None``.

        KEIN stiller Fallback bei kaputtem ``ergebnis_json``: dann
        ``CorruptDefaultCredsHistoryError`` (mit ``id``-Bezug).
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, geprueft_at, host, hersteller, modell, fall, treffer_count, "
                "ergebnis_json FROM default_creds_history WHERE id = ?",
                (eintrag_id,),
            ).fetchone()
        if row is None:
            return None
        findings = _findings_from_json(row["id"], row["host"], row["ergebnis_json"])
        return PruefHistorieDetail(
            eintrag_id=row["id"],
            geprueft_at=row["geprueft_at"] or "",
            host=row["host"],
            hersteller=row["hersteller"],
            modell=row["modell"],
            fall=cast(PruefFall, self._fall_or_raise(row["id"], row["fall"])),
            treffer_count=row["treffer_count"],
            findings=findings,
        )

    @staticmethod
    def _fall_or_raise(eintrag_id: int, raw: Any) -> str:
        """Prueft den gespeicherten ``fall`` gegen die erlaubten Werte -- kein Fallback.

        Ein formfremder ``fall`` (nur ueber manuelle DB-Manipulation moeglich -- der
        Schreibpfad legt ausschliesslich PruefFall-Literale ab) ist ein Fehler MIT
        ``id``-Bezug, kein leiser Rueckfall (Finding S3).
        """
        if not isinstance(raw, str) or raw not in _FALL_WERTE:
            raise CorruptDefaultCredsHistoryError(eintrag_id, str(raw))
        return raw
