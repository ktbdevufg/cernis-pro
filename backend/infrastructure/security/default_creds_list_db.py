"""SQLite-Adapter fuer die verwaltbare Standardzugangs-Liste (Etappe A).

``SqliteDefaultCredsListRepository`` persistiert die ``DefaultCredsEintrag``-Objekte in
einer eigenen Tabelle ``default_creds_list`` -- KEIN editierbares Config-File, sondern
dieselbe SQLite-Linie wie der uebrige Bestand. Stil EXAKT wie ``analysis_rules_db.py``:
injizierter ``db_path``, ``_ensure_schema`` im ``__init__``, ``@contextmanager _connect``
mit Transaktion + garantiertem ``close``, ``CREATE TABLE IF NOT EXISTS``. KEIN stiller
Fallback, KEIN ``modules``-Import.

ARCHITEKTUR-EINORDNUNG -- ZWEI ROLLEN, BEWUSST GETRENNT (Muster ``SqliteUserRuleRepository``):

* ``get_eintraege`` / ``finde_fuer_hersteller_modell`` sind der LESE-Pfad. Ihre
  Signaturen sind deckungsgleich mit ``ports.security.DefaultCredsListReader`` -- dieser
  Adapter erfuellt den Reader strukturell.
* ``add_eintrag``/``update_eintrag``/``delete_eintrag``/``set_aktiv``/``reset_auf_standard``
  sind der VERWALTUNGS-/SCHREIB-Pfad (``ports.security.DefaultCredsListStore``). Der
  validierende Schreibpfad ruft die REINE Domaenenfunktion
  ``domain.security.validate_eintraege`` (erlaubt: ``infrastructure`` darf ``domain``
  importieren). Er importiert NICHT ``application`` oder ``api`` (import-linter-Contract
  "infrastructure kennt nicht application/api").

KANDIDATEN_JSON -- BEGRUENDUNG: ein Eintrag traegt eine ``kandidaten``-Tuple aus
``CredentialKandidat`` (username/password/konfidenz), die nicht direkt spaltenfaehig ist.
Statt einer Kandidaten-Hilfstabelle haelt EIN ``kandidaten_json``-Feld die Liste
``[{username, password, konfidenz}]`` (params_json-Muster, VERLUSTFREI). Die Form wird
beim Lesen validiert -- kein leiser Rueckfall bei kaputtem JSON, sondern ein lauter
``CorruptDefaultCredsError`` (mit ``eintrag_id``-Bezug, Muster ``CorruptUserRuleError``).
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

from domain.security import (
    CredentialKandidat,
    DefaultCredsEintrag,
    Konfidenz,
    ListenZustand,
    validate_eintraege,
)
from infrastructure.security.default_creds_seed import SEED_EINTRAEGE

__all__ = ["CorruptDefaultCredsError", "SqliteDefaultCredsListRepository"]

# Erlaubte Werte fuer die validierende JSON-Deserialisierung (kein leiser Fallback bei
# formfremden Werten -- Muster CorruptUserRuleError). Deckungsgleich mit dem Konfidenz-
# Literal in der Domaene.
_KONFIDENZ_WERTE: frozenset[str] = frozenset({"gesichert", "auch_moeglich", "vermutet", "benutzer"})


class CorruptDefaultCredsError(Exception):
    """Das ``kandidaten_json`` eines gespeicherten Eintrags ist kaputt/formfremd.

    Ersetzt einen stillen Rueckfall (Finding S3 / Muster ``CorruptUserRuleError``): ein
    unlesbares oder formfremdes ``kandidaten_json`` ist ein Fehler MIT ``eintrag_id``-Bezug
    (statt eines diffusen Tracebacks ODER eines leisen Rueckfalls auf leere Kandidaten).
    """

    def __init__(self, eintrag_id: str, raw_value: str) -> None:
        self.eintrag_id = eintrag_id
        self.raw_value = raw_value
        super().__init__(
            f"Eintrag {eintrag_id!r}: kandidaten_json ist keine gueltige "
            f"Kandidaten-Liste: {raw_value!r}"
        )


class SqliteDefaultCredsListRepository:
    """Persistiert die Standardzugangs-Liste in SQLite (Etappe A).

    Erfuellt strukturell sowohl den Lese-Port ``ports.security.DefaultCredsListReader``
    (ueber ``get_eintraege``/``finde_fuer_hersteller_modell``) als auch den Verwaltungs-
    Port ``ports.security.DefaultCredsListStore`` (ueber die CRUD-/reset-Methoden).
    Injizierter ``db_path``; die Pfad-Aufloesung passiert im Composition Root (``app.py``),
    nicht hier.
    """

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
        # eintrag_id ist der PRIMARY KEY (fachlich eindeutig). Die Kandidaten liegen
        # verlustfrei in kandidaten_json -- Begruendung siehe Modul-Docstring. ``aktiv``
        # als INTEGER (0/1), sqlite kennt keinen bool (Muster alerting bool->int).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS default_creds_list (
                    eintrag_id      TEXT PRIMARY KEY,
                    hersteller      TEXT,
                    modell          TEXT,
                    zustand         TEXT,
                    kandidaten_json TEXT,
                    quelle_url      TEXT,
                    aktiv           INTEGER,
                    herkunft        TEXT
                );
                """
            )

    # ── Lese-Pfad (erfuellt DefaultCredsListReader-Port) ────────────────────

    def get_eintraege(self) -> list[DefaultCredsEintrag]:
        """Liest alle Eintraege und mappt jede Row -> ``DefaultCredsEintrag``.

        Signatur deckungsgleich mit ``DefaultCredsListReader.get_eintraege``. Eine leere
        Tabelle -> ``[]`` (gueltiger Leer-Zustand). KEIN stiller Fallback bei kaputtem
        ``kandidaten_json``: dann ``CorruptDefaultCredsError`` (mit ``eintrag_id``-Bezug).
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT eintrag_id, hersteller, modell, zustand, kandidaten_json, "
                "quelle_url, aktiv, herkunft "
                "FROM default_creds_list ORDER BY eintrag_id"
            ).fetchall()
        return [self._row_to_eintrag(row) for row in rows]

    def finde_fuer_hersteller_modell(
        self, hersteller: str, modell: str
    ) -> list[DefaultCredsEintrag]:
        """Die zu Hersteller/Modell passenden, AKTIVEN Eintraege.

        Matching (case-insensitive): exakter Hersteller-Match. Bei leerem Eintrag-Modell
        greift der Eintrag als Hersteller-Fallback (immer Treffer, wenn der Hersteller
        passt). Bei nicht-leerem Eintrag-Modell ist es ein Treffer, wenn das Eintrag-Modell
        als Teilstring im uebergebenen Modell steckt ODER umgekehrt. Nur ``aktiv``e
        Eintraege werden zurueckgegeben; kein Treffer -> ``[]`` (impliziter Zustand
        "unbekannt").
        """
        hersteller_norm = hersteller.strip().lower()
        modell_norm = modell.strip().lower()
        treffer: list[DefaultCredsEintrag] = []
        for eintrag in self.get_eintraege():
            if not eintrag.aktiv:
                continue
            if eintrag.hersteller.strip().lower() != hersteller_norm:
                continue
            eintrag_modell = eintrag.modell.strip().lower()
            if not eintrag_modell:
                # Herstellerweiter Fallback-Eintrag -- passt fuer jedes Modell.
                treffer.append(eintrag)
            elif eintrag_modell in modell_norm or modell_norm in eintrag_modell:
                treffer.append(eintrag)
        return treffer

    # ── Schreib-/Verwaltungs-Pfad (DefaultCredsListStore-Port) ──────────────

    def add_eintrag(self, eintrag: DefaultCredsEintrag) -> None:
        """Validierender Schreibpfad fuer einen neuen Eintrag.

        Prueft ueber ``validate_eintraege`` und wirft ``ValueError`` bei Issues. Die
        Eindeutigkeit der ``eintrag_id`` ist der PRIMARY KEY -- eine kollidierende id ist
        ein Fehler (INSERT wirft ``sqlite3.IntegrityError``), KEIN stilles Ueberschreiben.
        """
        self._validate_or_raise(eintrag)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO default_creds_list "
                "(eintrag_id, hersteller, modell, zustand, kandidaten_json, "
                "quelle_url, aktiv, herkunft) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                self._eintrag_to_row(eintrag),
            )

    def update_eintrag(self, eintrag: DefaultCredsEintrag) -> None:
        """Validierender Schreibpfad fuer einen bestehenden Eintrag (ueber ``eintrag_id``).

        Prueft ueber ``validate_eintraege`` und wirft ``ValueError`` bei Issues. Ein
        UPDATE auf eine nicht existierende ``eintrag_id`` aendert keine Zeile (kein
        stiller Insert) -- der Aufrufer entscheidet, ob das relevant ist.
        """
        self._validate_or_raise(eintrag)
        with self._connect() as conn:
            conn.execute(
                "UPDATE default_creds_list SET "
                "hersteller = ?, modell = ?, zustand = ?, kandidaten_json = ?, "
                "quelle_url = ?, aktiv = ?, herkunft = ? "
                "WHERE eintrag_id = ?",
                (
                    eintrag.hersteller,
                    eintrag.modell,
                    eintrag.zustand,
                    _kandidaten_to_json(eintrag.kandidaten),
                    eintrag.quelle_url,
                    1 if eintrag.aktiv else 0,
                    eintrag.herkunft,
                    eintrag.eintrag_id,
                ),
            )

    def delete_eintrag(self, eintrag_id: str) -> None:
        """Loescht einen Eintrag ueber seine ``eintrag_id`` (Muster ``delete_rule``)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM default_creds_list WHERE eintrag_id = ?", (eintrag_id,))

    def set_aktiv(self, eintrag_id: str, aktiv: bool) -> None:
        """Schaltet einen Eintrag aktiv/inaktiv, ohne ihn zu loeschen (bool->int)."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE default_creds_list SET aktiv = ? WHERE eintrag_id = ?",
                (1 if aktiv else 0, eintrag_id),
            )

    def reset_auf_standard(self) -> None:
        """Stellt die mitgelieferten Eintraege wieder her (behaelt herkunft='benutzer').

        Loescht alle Zeilen mit ``herkunft='mitgeliefert'`` und schreibt ``SEED_EINTRAEGE``
        frisch. Zeilen mit ``herkunft='benutzer'`` bleiben unangetastet.
        """
        with self._connect() as conn:
            conn.execute("DELETE FROM default_creds_list WHERE herkunft = 'mitgeliefert'")
            conn.executemany(
                "INSERT INTO default_creds_list "
                "(eintrag_id, hersteller, modell, zustand, kandidaten_json, "
                "quelle_url, aktiv, herkunft) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [self._eintrag_to_row(eintrag) for eintrag in SEED_EINTRAEGE],
            )

    def ensure_seeded(self) -> None:
        """Erst-Seeding: fuellt ``SEED_EINTRAEGE`` ein, WENN keine mitgelieferte Zeile da ist.

        Wird spaeter im Composition Root beim Start gerufen (in dieser Etappe nur
        implementiert, NICHT verdrahtet). Idempotent: existiert bereits mindestens eine
        Zeile mit ``herkunft='mitgeliefert'``, passiert nichts (kein Ueberschreiben von
        moeglichen Benutzeraenderungen an mitgelieferten Zeilen ausserhalb von reset).
        """
        with self._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM default_creds_list WHERE herkunft = 'mitgeliefert'"
            ).fetchone()[0]
            if count > 0:
                return
            conn.executemany(
                "INSERT INTO default_creds_list "
                "(eintrag_id, hersteller, modell, zustand, kandidaten_json, "
                "quelle_url, aktiv, herkunft) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [self._eintrag_to_row(eintrag) for eintrag in SEED_EINTRAEGE],
            )

    # ── Validierung + Mapping ───────────────────────────────────────────────

    @staticmethod
    def _validate_or_raise(eintrag: DefaultCredsEintrag) -> None:
        """Ruft die reine Domaenen-Validierung; bei Issues -> lesbarer ``ValueError``.

        Muster "validierender Schreibpfad": die Domaene meldet strukturelle Maengel als
        Issue-Liste (wirft nie), der Adapter macht daraus eine Exception fuer den
        Schreibpfad.
        """
        issues = validate_eintraege((eintrag,))
        if issues:
            meldung = "; ".join(f"{issue.code}: {issue.message}" for issue in issues)
            raise ValueError(f"Eintrag {eintrag.eintrag_id!r} ist ungueltig: {meldung}")

    @staticmethod
    def _eintrag_to_row(eintrag: DefaultCredsEintrag) -> tuple[Any, ...]:
        """Serialisiert einen Eintrag in das 8-Spalten-Row-Tuple (aktiv als int 0/1)."""
        return (
            eintrag.eintrag_id,
            eintrag.hersteller,
            eintrag.modell,
            eintrag.zustand,
            _kandidaten_to_json(eintrag.kandidaten),
            eintrag.quelle_url,
            1 if eintrag.aktiv else 0,
            eintrag.herkunft,
        )

    @staticmethod
    def _row_to_eintrag(row: sqlite3.Row) -> DefaultCredsEintrag:
        # kandidaten_json -> tuple[CredentialKandidat, ...]; zustand/herkunft sind
        # gespeicherte Literale (der Schreibpfad legt nur die Domaenen-Literale ab).
        kandidaten = _kandidaten_from_json(row["eintrag_id"], row["kandidaten_json"])
        return DefaultCredsEintrag(
            eintrag_id=row["eintrag_id"],
            hersteller=row["hersteller"],
            modell=row["modell"],
            zustand=cast(ListenZustand, row["zustand"]),
            kandidaten=kandidaten,
            quelle_url=row["quelle_url"],
            aktiv=bool(row["aktiv"]),
            herkunft=cast("Any", row["herkunft"]),
        )


def _kandidaten_to_json(kandidaten: tuple[CredentialKandidat, ...]) -> str:
    """Serialisiert die Kandidaten-Tuple verlustfrei nach JSON.

    Jeder Kandidat wird zu ``{"username", "password", "konfidenz"}``. Deterministisch in
    der gegebenen Reihenfolge (die Tuple-Ordnung ist fachlich -- gesichert vor vermutet).
    """
    return json.dumps(
        [
            {
                "username": kandidat.username,
                "password": kandidat.password,
                "konfidenz": kandidat.konfidenz,
            }
            for kandidat in kandidaten
        ]
    )


def _kandidaten_from_json(eintrag_id: str, raw: str | None) -> tuple[CredentialKandidat, ...]:
    """Deserialisiert ``kandidaten_json`` und validiert die Form -- KEIN stiller Fallback.

    Erwartet eine JSON-Liste von Objekten mit ``username``/``password``/``konfidenz``
    (alle str; ``konfidenz`` aus der erlaubten Menge). Eine leere Liste (``[]``) ist ein
    gueltiger Zustand (Eintraege mit ``keine_bekannten_defaults`` haben keine Kandidaten).
    Ist ``raw`` NULL/leer, kein JSON, keine Liste, oder hat ein Element die falsche Form,
    -> ``CorruptDefaultCredsError`` (Muster ``CorruptUserRuleError``): ein kaputter Wert
    ist ein Fehler, kein leiser Rueckfall auf leere Kandidaten.
    """
    if not raw:
        raise CorruptDefaultCredsError(eintrag_id, raw or "")
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CorruptDefaultCredsError(eintrag_id, raw) from exc
    if not isinstance(decoded, list):
        raise CorruptDefaultCredsError(eintrag_id, raw)

    kandidaten: list[CredentialKandidat] = []
    for element in decoded:
        if not isinstance(element, dict):
            raise CorruptDefaultCredsError(eintrag_id, raw)
        username = element.get("username")
        password = element.get("password")
        konfidenz = element.get("konfidenz")
        if (
            not isinstance(username, str)
            or not isinstance(password, str)
            or not isinstance(konfidenz, str)
            or konfidenz not in _KONFIDENZ_WERTE
        ):
            raise CorruptDefaultCredsError(eintrag_id, raw)
        kandidaten.append(
            CredentialKandidat(
                username=username,
                password=password,
                konfidenz=cast(Konfidenz, konfidenz),
            )
        )
    return tuple(kandidaten)
