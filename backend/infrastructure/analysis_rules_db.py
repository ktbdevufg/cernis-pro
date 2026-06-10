"""SQLite-Adapter fuer benutzer-eigene analysis-Regeln (A.2).

``SqliteUserRuleRepository`` persistiert die vom Benutzer angelegten ``Rule``-Objekte
in einer eigenen Tabelle ``analysis_user_rules`` -- KEIN editierbares Config-File, sondern
dieselbe SQLite-Linie wie der uebrige Bestand. Im Stil von ``scan_history.py`` und
``alerting/rule_repository.py``: injizierter ``db_path``, ``_ensure_schema`` im ``__init__``,
``@contextmanager _connect`` mit Transaktion + garantiertem ``close``, ``CREATE TABLE IF
NOT EXISTS``. KEIN stiller Fallback, KEIN ``modules``-Import.

ARCHITEKTUR-EINORDNUNG -- ZWEI ROLLEN, BEWUSST GETRENNT:

* ``get_rules`` ist der LESE-Pfad. Seine Signatur ist deckungsgleich mit dem
  ``ports.analysis.RuleProvider``-Port: dieser Adapter erfuellt den RuleProvider
  strukturell und kann darum (per ``CompositeRuleProvider`` im Composition Root, additiv
  mit den eingebauten ``DEFAULT_RULES`` kombiniert) als Regelquelle der Engine dienen.
* ``add_rules``/``delete_rule`` sind der VERWALTUNGS-/SCHREIB-Pfad. Sie sind BEWUSST KEINE
  ``RuleProvider``-Port-Methoden: der RuleProvider ist NUR die Lese-Quelle fuer die Engine.
  Der validierende Schreibpfad ist ein EIGENER Adapter-Vertrag, den der api-Rand bzw. die
  Composition Root nutzt (per ``ports.analysis.UserRuleStore``-Protocol typisiert).

Der Adapter ruft die REINE Domaenenfunktion ``domain.analysis.validate_rules`` -- erlaubt,
weil ``infrastructure`` ``domain`` importieren darf. Er importiert NICHT ``application``
oder ``api`` (import-linter-Contract "infrastructure kennt nicht application/api").

PARAMS_JSON -- BEGRUENDUNG: Eine ``Rule`` traegt fachliche Parameter, die nicht direkt
spaltenfaehig sind -- ``ports`` ist ein ``frozenset[int]``, ``path_prefixes`` ein
``tuple[str, ...]``. Statt fuer jede dieser Mengen eine eigene Hilfstabelle/Spalte
anzulegen, haelt EIN ``params_json``-Feld ein JSON-Objekt mit genau den fuer das jeweilige
``kind`` relevanten Parametern (``{"ports": [...], "path_prefixes": [...], "threshold":
int}``). Das haelt das Schema stabil, falls ``Rule`` spaeter Parameter-Felder bekommt
(ein neuer Schluessel im JSON statt einer Schema-Migration). Die (De-)Serialisierung ist
VERLUSTFREI, und die Form wird beim Lesen validiert (kein leiser Rueckfall auf Defaults
bei kaputtem JSON -- stattdessen ein lauter ``CorruptUserRuleError``).
"""

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from domain.analysis import DEFAULT_RULES, Rule, RuleIssue, validate_rules

__all__ = ["CorruptUserRuleError", "SqliteUserRuleRepository"]


class CorruptUserRuleError(Exception):
    """Das ``params_json`` einer gespeicherten Regel ist kaputt/formfremd.

    Ersetzt einen stillen Rueckfall (Finding S3 / Muster ``CorruptScanError``): ein
    unlesbares oder formfremdes ``params_json`` ist ein Fehler MIT ``rule_id``-Bezug
    (statt eines diffusen Tracebacks ODER eines leisen Rueckfalls auf Defaults).
    """

    def __init__(self, rule_id: str, raw_value: str) -> None:
        self.rule_id = rule_id
        self.raw_value = raw_value
        super().__init__(
            f"Regel {rule_id!r}: params_json ist kein gueltiges Parameter-Objekt: {raw_value!r}"
        )


class SqliteUserRuleRepository:
    """Persistiert benutzer-eigene ``Rule``-Objekte in SQLite (A.2).

    Erfuellt strukturell sowohl den Lese-Port ``ports.analysis.RuleProvider``
    (ueber ``get_rules``) als auch den Verwaltungs-Port ``ports.analysis.UserRuleStore``
    (ueber ``get_rules``/``add_rules``/``delete_rule``). Injizierter ``db_path``; die
    Pfad-Aufloesung passiert im Composition Root (``app.py``), nicht hier.
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
        # id ist der PRIMARY KEY (die benutzergegebene Rule.id, fachlich eindeutig).
        # Die fachlichen Parameter (ports/path_prefixes/threshold) liegen verlustfrei in
        # params_json -- Begruendung siehe Modul-Docstring.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS analysis_user_rules (
                    id              TEXT PRIMARY KEY,
                    kind            TEXT,
                    severity        TEXT,
                    help_kind       TEXT,
                    title           TEXT,
                    detail_template TEXT,
                    params_json     TEXT
                );
                """
            )

    # ── Lese-Pfad (erfuellt RuleProvider-Port) ─────────────────────────────

    def get_rules(self) -> tuple[Rule, ...]:
        """Liest alle gespeicherten Regeln und mappt jede Row -> ``Rule``.

        Signatur deckungsgleich mit ``ports.analysis.RuleProvider.get_rules`` -- dieser
        Adapter erfuellt den Lese-Port strukturell. Eine leere Tabelle -> ``()`` (gueltiger
        Leer-Zustand). KEIN stiller Fallback bei kaputtem ``params_json``: dann
        ``CorruptUserRuleError`` (mit ``rule_id``-Bezug), kein leiser Rueckfall auf Defaults.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, kind, severity, help_kind, title, detail_template, params_json "
                "FROM analysis_user_rules ORDER BY id"
            ).fetchall()
        return tuple(self._row_to_rule(row) for row in rows)

    # ── Schreib-/Verwaltungs-Pfad (EIGENER Adapter-Vertrag, KEINE Port-Methode
    #     des RuleProvider -- der UserRuleStore-Port typisiert ihn) ──────────

    def add_rules(self, new_rules: Sequence[Rule]) -> list[RuleIssue]:
        """Validierender Schreibpfad fuer neue Regeln -- GESTUFT (Karl-Entscheidung).

        Ablauf:
          1. Bestand = ``DEFAULT_RULES`` + bereits gespeicherte Regeln.
          2. ``issues = validate_rules(new_rules, bestand)`` (reine Domaenenfunktion).
          3. Eindeutigkeit der id pruefen (PRIMARY KEY = fachliche Eindeutigkeit): liegt
             eine ``new_rule``-id bereits im Bestand/in der DB ODER doppelt in ``new_rules``,
             -> zusaetzliches ``RuleIssue`` ``severity="error"`` ``code="duplicate_id"``.
          4. Enthaelt die (kombinierte) Issue-Liste IRGENDEIN ``error`` -> NICHTS speichern,
             die Issues zurueckgeben (der Aufrufer/api-Rand macht daraus HTTP 422). KEINE
             Teil-Speicherung.
          5. Sonst (nur ``warning`` oder leer) -> alle ``new_rules`` speichern (INSERT) und
             die (ggf. leeren / nur-warning) Issues zurueckgeben.

        Konsequenz: ``error``/``duplicate_id`` -> nichts gespeichert; nur ``warning`` ->
        gespeichert UND die warnings gemeldet (gestuft sichtbar).
        """
        bestand = (*DEFAULT_RULES, *self.get_rules())
        issues = list(validate_rules(new_rules, bestand))

        # Eindeutigkeit der id: PRIMARY KEY -- die fachliche Eindeutigkeit ist die id,
        # NICHT die Parameter (Parameter-Gleichheit ist nur ein "warning" der Validierung).
        # INSERT OR REPLACE waere ein stilles Ueberschreiben -- eine kollidierende id ist
        # hier bewusst ein Fehler. Geprueft gegen Bestand (Defaults + DB) UND new-vs-new.
        existing_ids = {rule.id for rule in bestand}
        seen_new: set[str] = set()
        for rule in new_rules:
            if rule.id in existing_ids or rule.id in seen_new:
                issues.append(
                    RuleIssue(
                        rule_id=rule.id,
                        severity="error",
                        code="duplicate_id",
                        message="Eine Regel mit dieser id existiert bereits.",
                    )
                )
            seen_new.add(rule.id)

        if any(issue.severity == "error" for issue in issues):
            return issues  # error -> NICHTS speichern (keine Teil-Speicherung)

        # Nur warnings (oder leer): alle neuen Regeln speichern.
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO analysis_user_rules "
                "(id, kind, severity, help_kind, title, detail_template, params_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        rule.id,
                        rule.kind,
                        rule.severity,
                        rule.help_kind,
                        rule.title,
                        rule.detail_template,
                        _rule_to_params_json(rule),
                    )
                    for rule in new_rules
                ],
            )
        return issues

    def delete_rule(self, rule_id: str) -> None:
        """Loescht eine gespeicherte eigene Regel (Muster ``alerting`` delete)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM analysis_user_rules WHERE id = ?", (rule_id,))

    # ── Mapping ─────────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_rule(row: sqlite3.Row) -> Rule:
        # params_json -> frozenset/tuple/threshold; fehlende kind-spezifische Parameter
        # erhalten dieselben Defaults wie domain.Rule (leer / 0).
        params = _params_from_json(row["id"], row["params_json"])
        return Rule(
            id=row["id"],
            severity=row["severity"],
            help_kind=row["help_kind"],
            kind=row["kind"],
            title=row["title"],
            detail_template=row["detail_template"],
            path_prefixes=tuple(params["path_prefixes"]),
            ports=frozenset(params["ports"]),
            threshold=params["threshold"],
        )


def _rule_to_params_json(rule: Rule) -> str:
    """Serialisiert die fachlichen ``Rule``-Parameter verlustfrei nach JSON.

    ``ports`` (frozenset) wird zu einer sortierten Liste (deterministisch), ``path_prefixes``
    (tuple) zu einer Liste, ``threshold`` (int) bleibt int. Nur diese drei Parameter sind
    fachlich -- id/kind/severity/help_kind/title/detail_template liegen in eigenen Spalten.
    """
    return json.dumps(
        {
            "ports": sorted(rule.ports),
            "path_prefixes": list(rule.path_prefixes),
            "threshold": rule.threshold,
        }
    )


def _params_from_json(rule_id: str, raw: str | None) -> dict[str, Any]:
    """Deserialisiert ``params_json`` und validiert die Form -- KEIN stiller Fallback.

    Erwartet ein JSON-Objekt mit (optionalen) Schluesseln ``ports`` (Liste von int),
    ``path_prefixes`` (Liste von str), ``threshold`` (int). Fehlende Schluessel erhalten
    die ``domain.Rule``-Defaults (leer / 0). Ist ``raw`` NULL/leer, kein Objekt, oder hat
    ein Feld die falsche Form, -> ``CorruptUserRuleError`` (Muster ``CorruptScanError``):
    ein kaputter Wert ist ein Fehler, kein leiser Rueckfall.
    """
    if not raw:
        raise CorruptUserRuleError(rule_id, raw or "")
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CorruptUserRuleError(rule_id, raw) from exc
    if not isinstance(decoded, dict):
        raise CorruptUserRuleError(rule_id, raw)

    ports = decoded.get("ports", [])
    path_prefixes = decoded.get("path_prefixes", [])
    threshold = decoded.get("threshold", 0)

    # Form pruefen: ports/path_prefixes Listen, threshold int (bool ist in Python ein int-
    # Subtyp -- hier bewusst ausgeschlossen, eine Schwelle ist kein Flag).
    if (
        not isinstance(ports, list)
        or not all(isinstance(port, int) and not isinstance(port, bool) for port in ports)
        or not isinstance(path_prefixes, list)
        or not all(isinstance(prefix, str) for prefix in path_prefixes)
        or not isinstance(threshold, int)
        or isinstance(threshold, bool)
    ):
        raise CorruptUserRuleError(rule_id, raw)

    return {"ports": ports, "path_prefixes": path_prefixes, "threshold": threshold}
