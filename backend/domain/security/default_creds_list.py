"""Standardzugangs-Liste ALS DATEN -- verwaltbare Werks-Credentials je Geraet.

Reine Domaenenlogik (stdlib + dataclasses + typing, ADR 0002): kein I/O, keine Uhr,
kein Framework, KEIN ``modules``-Import. PEP-695-``type``-Aliase fuer die Literal-Unions
wie im uebrigen domain-Ring (analysis/process/traffic). ``domain``-Subpakete sind
wechselseitig unabhaengig (import-linter ``independence``) -- dieses Modul importiert
KEIN anderes ``domain``-Subpaket.

WAS IST DIE STANDARDZUGANGS-LISTE: eine pflegbare Zuordnung Hersteller/Modell ->
Werks-Credentials mit einer KONFIDENZ je Kandidat und einem ZUSTAND je Eintrag. Sie ist
das kuratierte Wissen "welches Geraet kam ab Werk mit welchem Login" -- als DATEN, nicht
als Code. Ein neuer Eintrag ist ein neues ``DefaultCredsEintrag``-Datenobjekt (im Seed
oder zur Laufzeit vom Benutzer angelegt), KEINE neue Code-Verzweigung.

DREI KONFIDENZ-/ZUSTANDS-ACHSEN, BEWUSST GETRENNT:

* ``Konfidenz`` bewertet EINEN Kandidaten -- wie sicher dieses konkrete user/pwd-Paar
  das Werks-Login ist ("gesichert" > "auch_moeglich" > "vermutet"; "benutzer" fuer vom
  Benutzer selbst eingetragene Kandidaten). Der Umlaut in "auch_moeglich" ist BEWUSST als
  ``oe`` geschrieben (Projektkonvention: keine Umlaute in Strings).
* ``ListenZustand`` bewertet den EINTRAG -- ob fuer dieses Geraet ueberhaupt Defaults
  bekannt sind ("hat_defaults") oder ob positiv bekannt ist, dass es KEINE gibt
  ("keine_bekannten_defaults", secure-by-default). Der dritte Fall "unbekannt" ist KEIN
  gespeicherter Zustand -- er ergibt sich IMPLIZIT aus dem Fehlen eines Eintrags und ist
  darum bewusst NICHT als Literal aufgenommen.
* ``Herkunft`` bewertet die QUELLE des Eintrags -- ob mitgeliefert (kuratierter Seed) oder
  vom Benutzer angelegt. Sie steuert ``reset_auf_standard`` (nur mitgelieferte werden
  zurueckgesetzt, benutzer-eigene bleiben).

VALIDIERUNG (``validate_eintraege``) prueft die Invarianten strukturell und gibt Befunde
als Liste zurueck -- sie WIRFT NIE (Muster ``domain.analysis.validate_rules`` /
``RuleIssue``). Der validierende Schreibpfad (infrastructure) entscheidet, was ein Befund
praktisch bedeutet.
"""

from dataclasses import dataclass
from typing import Literal

# Konfidenz EINES Kandidaten -- wie sicher dieses user/pwd-Paar das Werks-Login ist.
# Reihenfolge der Sicherheit: gesichert > auch_moeglich > vermutet. "benutzer" markiert
# vom Benutzer selbst eingetragene Kandidaten (keine kuratierte Sicherheitsaussage).
# "auch_moeglich" ist BEWUSST mit oe statt Umlaut geschrieben (Projektkonvention).
type Konfidenz = Literal["gesichert", "auch_moeglich", "vermutet", "benutzer"]

# Zustand EINES Eintrags -- ob fuer dieses Geraet Defaults bekannt sind. "hat_defaults":
# es gibt mindestens einen Kandidaten. "keine_bekannten_defaults": positiv bekannt, dass
# es KEINE Werks-Defaults gibt (secure-by-default) -> keine Kandidaten. Der dritte Fall
# "unbekannt" ist KEIN Literal: er ergibt sich implizit aus dem FEHLEN eines Eintrags.
type ListenZustand = Literal["hat_defaults", "keine_bekannten_defaults"]

# Herkunft EINES Eintrags -- steuert reset_auf_standard. "mitgeliefert": kuratierter Seed.
# "benutzer": vom Benutzer angelegt (bleibt bei reset_auf_standard unangetastet).
type Herkunft = Literal["mitgeliefert", "benutzer"]


@dataclass(frozen=True)
class CredentialKandidat:
    """Ein Werks-Credential-Paar mit Konfidenz (frozen).

    ``password`` darf leer sein (``""``) -- das ist ein blank-Login (Anmeldung ohne
    Passwort), ein legitimer realer Werkszustand, KEIN fehlender Wert.
    """

    username: str
    password: str
    konfidenz: Konfidenz


@dataclass(frozen=True)
class DefaultCredsEintrag:
    """Ein Standardzugangs-Eintrag: Hersteller/Modell -> Kandidaten mit Zustand (frozen).

    ``eintrag_id`` ist der stabile, fachlich eindeutige Schluessel (im Seed sprechend,
    z. B. "seed-netgear-legacy"). ``modell`` leer (``""``) bedeutet ein HERSTELLERWEITER
    Fallback-Eintrag (greift, wenn kein modellspezifischer Eintrag passt). ``kandidaten``
    ist bei ``zustand="keine_bekannten_defaults"`` leer und bei ``zustand="hat_defaults"``
    mindestens einer (Invariante, siehe ``validate_eintraege``). ``aktiv`` erlaubt das
    Ausblenden ohne Loeschen; ``herkunft`` steuert ``reset_auf_standard``.
    """

    eintrag_id: str
    hersteller: str
    modell: str
    zustand: ListenZustand
    kandidaten: tuple[CredentialKandidat, ...]
    quelle_url: str
    aktiv: bool
    herkunft: Herkunft


# Bewertet den EINTRAG (kaputt/inkonsistent), NICHT einen Kandidaten. BEWUSST getrennt
# von ``Konfidenz``: error sagt etwas ueber die strukturelle Integritaet des Eintrags,
# ``Konfidenz`` sagt etwas ueber die Sicherheit eines Kandidaten. Analog ``IssueSeverity``
# in der analysis-Domaene ("error"/"warning"); hier genuegt "error" -- die geprueften
# Invarianten sind objektive Kaputtheiten, keine Geschmacksurteile.
type EintragIssueSeverity = Literal["error"]


@dataclass(frozen=True)
class EintragIssue:
    """Ein BEFUND ueber einen Standardzugangs-Eintrag -- KEIN Urteil ueber ein Geraet.

    ``severity`` ist "error" (die Invarianten sind objektiv kaputt). ``code`` ist ein
    stabiler Maschinen-Code (z. B. "empty_id", "defaults_without_candidate"), ``message``
    die menschenlesbare, neutrale Begruendung (Deutsch). ``eintrag_id`` benennt den
    betroffenen Eintrag. Analog ``domain.analysis.RuleIssue``.
    """

    eintrag_id: str
    severity: EintragIssueSeverity
    code: str
    message: str


def validate_eintraege(eintraege: tuple[DefaultCredsEintrag, ...]) -> list[EintragIssue]:
    """Pruefe Standardzugangs-Eintraege strukturell -- gibt Befunde als Liste zurueck.

    Geprueft werden je Eintrag die Invarianten:

    * ``eintrag_id`` nicht leer ("empty_id").
    * ``hersteller`` nicht leer ("empty_hersteller").
    * ``zustand="hat_defaults"`` -> mindestens ein Kandidat ("defaults_without_candidate").
    * ``zustand="keine_bekannten_defaults"`` -> KEIN Kandidat ("no_defaults_with_candidate").

    Befunde sind RUECKGABEWERTE, keine Exceptions: diese Funktion wirft NIE (Muster
    ``validate_rules``). Der Adapter entscheidet, was "error" praktisch bedeutet.

    DETERMINISMUS: das Ergebnis ist stabil sortiert nach ``(eintrag_id, code)``. Gleiche
    Eingabe liefert dieselbe Ausgabe. Leere Liste = alles in Ordnung.
    """
    issues: list[EintragIssue] = []

    for eintrag in eintraege:
        if not eintrag.eintrag_id:
            issues.append(
                EintragIssue(
                    eintrag_id=eintrag.eintrag_id,
                    severity="error",
                    code="empty_id",
                    message="Der Eintrag hat keine eintrag_id.",
                )
            )
        if not eintrag.hersteller:
            issues.append(
                EintragIssue(
                    eintrag_id=eintrag.eintrag_id,
                    severity="error",
                    code="empty_hersteller",
                    message="Der Eintrag hat keinen Hersteller.",
                )
            )
        if eintrag.zustand == "hat_defaults" and not eintrag.kandidaten:
            issues.append(
                EintragIssue(
                    eintrag_id=eintrag.eintrag_id,
                    severity="error",
                    code="defaults_without_candidate",
                    message="Zustand 'hat_defaults' ohne Kandidat "
                    "-- es muss mindestens einen Kandidaten geben.",
                )
            )
        if eintrag.zustand == "keine_bekannten_defaults" and eintrag.kandidaten:
            issues.append(
                EintragIssue(
                    eintrag_id=eintrag.eintrag_id,
                    severity="error",
                    code="no_defaults_with_candidate",
                    message="Zustand 'keine_bekannten_defaults' mit Kandidat "
                    "-- ohne bekannte Defaults darf es keinen Kandidaten geben.",
                )
            )

    issues.sort(key=lambda issue: (issue.eintrag_id, issue.code))
    return issues


# ── Pruefplan: die drei Ergebnis-Faelle einer geraetebezogenen Abfrage ───────
#
# Etappe B fuehrt den intelligenten Scan-Workflow ein. Sein ERSTER Schritt ist reine
# Domaenenlogik: aus den zu Hersteller/Modell passenden Eintraegen (dem Reader-Ergebnis)
# ableiten, WAS der Aufrufer als Naechstes tun soll. Das sind genau DREI Faelle, die hier
# als expliziter Domaenen-Typ statt als api-/UI-Verzweigung modelliert werden:
#
# * "entwarnung"  -- fuer dieses Geraet ist POSITIV bekannt, dass es keine Werks-Defaults
#                    gibt (nur ``keine_bekannten_defaults``-Treffer). Keine Pruefung noetig.
# * "kandidaten"  -- es gibt mindestens einen ``hat_defaults``-Treffer: dem Aufrufer werden
#                    die Kandidaten zur Auswahl vorgelegt (Etappe-C/D-UI), dann gezielt
#                    geprueft (Aufgabe 2). "kandidaten" hat VORRANG vor "entwarnung":
#                    liegt auch nur EIN ``hat_defaults``-Treffer vor, ist der Fall
#                    "kandidaten" (der Anwender soll pruefen koennen), unabhaengig davon,
#                    ob daneben ein ``keine_bekannten_defaults``-Treffer steht.
# * "keine_infos" -- gar kein Eintrag (der implizite Zustand "unbekannt", ADR: NICHT als
#                    ListenZustand gespeichert). Der Anwender bekommt die (hier leeren)
#                    Quellen-URLs fuer die "schau selbst"-Recherche.
#
# REIN: kein I/O, keine Uhr, deterministisch. domain-Subpaket-Unabhaengigkeit gewahrt
# (nur Typen aus DIESEM Modul).
type PruefFall = Literal["entwarnung", "kandidaten", "keine_infos"]


@dataclass(frozen=True)
class PruefPlan:
    """Der aus den Reader-Treffern abgeleitete Ergebnis-Fall (frozen).

    ``fall`` benennt einen der drei Faelle explizit (s. Modul-Abschnitt). ``eintraege``
    traegt die JEWEILS relevanten Treffer: bei "kandidaten" die ``hat_defaults``-Treffer,
    bei "entwarnung" die ``keine_bekannten_defaults``-Treffer, bei "keine_infos" leer.
    ``quelle_urls`` ist die DEDUPLIZIERTE, reihenfolge-erhaltende Liste der ``quelle_url``
    der ``eintraege`` (fuer den "schau selbst"-Hinweis; leere URLs entfallen).
    """

    fall: PruefFall
    eintraege: tuple[DefaultCredsEintrag, ...]
    quelle_urls: tuple[str, ...]


def _dedup_quelle_urls(eintraege: tuple[DefaultCredsEintrag, ...]) -> tuple[str, ...]:
    """Sammelt die ``quelle_url`` der Eintraege dedupliziert, reihenfolge-erhaltend.

    Leere URLs (``""``) entfallen (kein "schau selbst"-Ziel). Reihenfolge ist die der
    Eintraege (deterministisch), Duplikate werden nur beim ersten Auftreten behalten.
    """
    gesehen: set[str] = set()
    urls: list[str] = []
    for eintrag in eintraege:
        url = eintrag.quelle_url
        if url and url not in gesehen:
            gesehen.add(url)
            urls.append(url)
    return tuple(urls)


def bestimme_pruefplan(treffer: tuple[DefaultCredsEintrag, ...]) -> PruefPlan:
    """Leitet aus den Reader-Treffern den ``PruefPlan`` ab -- rein, deterministisch.

    Regeln (s. Modul-Abschnitt "Pruefplan"):

    * ``treffer`` leer -> ``fall="keine_infos"``, ``eintraege=()``, ``quelle_urls=()``.
    * mindestens ein ``zustand="hat_defaults"``-Treffer -> ``fall="kandidaten"``,
      ``eintraege`` = die ``hat_defaults``-Treffer, ``quelle_urls`` deren URLs dedupliziert.
    * sonst (nur ``keine_bekannten_defaults``-Treffer) -> ``fall="entwarnung"``,
      ``eintraege`` = diese, ``quelle_urls`` dedupliziert.

    Kein I/O, keine Uhr. Gleiche Eingabe -> gleiche Ausgabe.
    """
    if not treffer:
        return PruefPlan(fall="keine_infos", eintraege=(), quelle_urls=())

    hat_defaults = tuple(e for e in treffer if e.zustand == "hat_defaults")
    if hat_defaults:
        return PruefPlan(
            fall="kandidaten",
            eintraege=hat_defaults,
            quelle_urls=_dedup_quelle_urls(hat_defaults),
        )

    # Kein hat_defaults-Treffer, aber mind. ein Treffer -> nur keine_bekannten_defaults.
    return PruefPlan(
        fall="entwarnung",
        eintraege=treffer,
        quelle_urls=_dedup_quelle_urls(treffer),
    )
