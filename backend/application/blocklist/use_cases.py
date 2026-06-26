"""Use-Cases der blocklist-Domaene: Quellen verwalten, laden, abgleichen, pruefen.

Kennt NUR ``ports/`` + ``domain/`` + stdlib (import-linter: ``application kennt nicht
infrastructure/api``). Alle Ports kommen per Constructor-Injection herein (Hausstil wie
``application/maintenance``/``application/cve``). Netz-I/O (Download) ist erlaubt, aber
hinter der ``BlocklistFetcher``-Naht GEKAPSELT: ein injiziertes Protocol, dessen echte
Impl in ``infrastructure`` lebt (TEIL C) -- so laeuft im Test KEIN echtes Netz, und der
Application-Ring nennt die Infrastruktur nie.

ZEIT: als injizierter ``now_provider: Callable[[], float] = time.time`` (Muster
``RefreshSource``/``RunCveMonitor``). ``import time`` ist stdlib, keine Domaenenlogik.

WIRE-HEBUNG: rohe Wire-Strings (group/fmt/strictness) werden AUTORITATIV hier in die
Domaenen-Enums gehoben; ein nicht zum Vokabular passender Wert wirft ``BlocklistError``
(bzw. ``UnknownStrictnessError``), den der api-Rand auf 422 mappt (Regel 4: der api-Ring
kennt die Domaenen-Enums NICHT).
"""

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

import structlog

from application.blocklist.errors import (
    BlocklistError,
    UnknownStrictnessError,
)
from application.blocklist.parsing import parse_blocklist
from domain.blocklist import (
    DEFAULT_SOURCES,
    BlocklistFormat,
    BlocklistGroup,
    BlocklistMatch,
    BlocklistSource,
    BlocklistStatus,
    ContactMatchResult,
    MatchStrictness,
    SourceOrigin,
    detect_license_hint,
    domain_suffix_candidates,
    strictness_allows,
)
from ports.blocklist import BlocklistEntryRepository, BlocklistSourceRepository

__all__ = [
    "AddSourceResult",
    "AddUserSource",
    "BlocklistFetcher",
    "CheckBlocklistHealth",
    "ContactInput",
    "DeleteUserSource",
    "HealthIssue",
    "ImportResult",
    "ImportUploadedSource",
    "ListBlocklistSources",
    "MatchContacts",
    "RefreshDueSources",
    "RefreshResult",
    "RefreshSource",
    "ResetSourcesToDefaults",
    "SeedDefaultSources",
    "UpdateUserSource",
    "strictness_from_wire",
]

_logger = structlog.get_logger(__name__)

# Sekunden pro Tag -- die Faelligkeit (interval_days) rechnet gegen last_fetched_ts.
_SECONDS_PER_DAY = 86400


# ── Fetcher-Naht ──────────────────────────────────────────────────────────────


class BlocklistFetcher(Protocol):
    """Laedt den rohen Listentext einer Quelle -- die Netz-NAHT (Impl in infrastructure).

    Strukturelles Protocol (kein ``@runtime_checkable``, Hausstil): die echte Impl
    (``UrllibBlocklistFetcher``, TEIL C) erfuellt es ohne Import-Bindung. Ein Misserfolg
    (HTTP-/Timeout-/Groessen-Fehler, leerer Body) wird als Exception signalisiert -- der
    ``RefreshSource``-Use-Case faengt sie breit und setzt status BROKEN (kein Werfen nach
    aussen). Im Test wird ein Fake injiziert, der nie echtes Netz beruehrt.
    """

    def fetch(self, url: str) -> str:
        """Laedt ``url`` und liefert den Listentext; wirft bei Misserfolg eine Exception."""
        ...


# ── Ergebnis-Datentraeger (Application-Rand) ──────────────────────────────────


@dataclass(frozen=True)
class AddSourceResult:
    """Ergebnis von ``AddUserSource``: die vergebene id + der freundliche Lizenz-Hinweis.

    ``license_hint`` ist ``None`` oder ein HINWEIS-String (s. ``detect_license_hint``) --
    er verweigert NICHTS, der Aufrufer zeigt ihn nur an.
    """

    source_id: str
    license_hint: str | None


@dataclass(frozen=True)
class ImportResult:
    """Ergebnis von ``ImportUploadedSource``: die vergebene id + Zahl geparster Eintraege."""

    source_id: str
    entry_count: int


@dataclass(frozen=True)
class RefreshResult:
    """Ergebnis EINES Lade-Laufs (``RefreshSource``): ok/Fehler + Eintragszahl.

    ``ok`` ist ``True`` bei erfolgreichem Download+Parse; dann traegt ``entry_count`` die
    Zahl, ``error`` ist ``None``. Bei Fehlschlag ist ``ok`` ``False``, ``error`` ein
    kurzer Befund-Text und ``entry_count`` ``None`` (die alte Eintragszahl bleibt in der
    Quelle erhalten -- s. ``RefreshSource``).
    """

    source_id: str
    ok: bool
    entry_count: int | None
    error: str | None


@dataclass(frozen=True)
class ContactInput:
    """Ein einzelner abzugleichender Aussenkontakt (kleiner Wire-Eingangs-Datentraeger).

    Bewusst eine eigene frozen dataclass (statt ``tuple[str, str | None]``) -- die
    benannten Felder ``remote_ip``/``hostname`` machen ``MatchContacts`` lesbar, und der
    api-Rand baut sie aus seinem Wire-Body. ``hostname`` ist optional (nur IP bekannt).
    """

    remote_ip: str
    hostname: str | None


@dataclass(frozen=True)
class HealthIssue:
    """EIN Gesundheits-Befund: eine Quelle steht auf BROKEN (+ optionaler Ersatzvorschlag).

    ``suggested_replacement_id`` ist die id der ersten passenden Ersatzquelle derselben
    Gruppe (s. ``CheckBlocklistHealth``) oder ``None`` (kein Vorschlag). NUR ein Befund +
    Vorschlag -- die Loeschung/der Ersatz bleibt Nutzer-Aktion (Delete/Add im Frontend).
    """

    source_id: str
    name: str
    group: BlocklistGroup
    suggested_replacement_id: str | None


# ── Wire-Hebung ───────────────────────────────────────────────────────────────


def strictness_from_wire(value: str) -> MatchStrictness:
    """Hebt einen rohen Strenge-String in ``MatchStrictness`` (422-Naht).

    Ein nicht zum Vokabular passender Wert wirft ``UnknownStrictnessError`` (Unterklasse
    von ``BlocklistError``), den der api-Rand auf 422 mappt -- kein stiller Fallback (S3).
    """
    try:
        return MatchStrictness(value)
    except ValueError as exc:
        raise UnknownStrictnessError(f"Unbekannte Strenge: {value!r}") from exc


def _group_from_wire(value: str) -> BlocklistGroup:
    """Hebt einen rohen Gruppen-String in ``BlocklistGroup`` (422-Naht)."""
    try:
        return BlocklistGroup(value)
    except ValueError as exc:
        raise BlocklistError(f"Unbekannte Gruppe: {value!r}") from exc


def _format_from_wire(value: str) -> BlocklistFormat:
    """Hebt einen rohen Format-String in ``BlocklistFormat`` (422-Naht)."""
    try:
        return BlocklistFormat(value)
    except ValueError as exc:
        raise BlocklistError(f"Unbekanntes Format: {value!r}") from exc


def _slugify(name: str, existing_ids: set[str]) -> str:
    """Baut eine stabile slug-id aus ``name`` (lowercase, nicht-alnum -> ``_``).

    Kollidiert die Basis-id mit einer bestehenden, wird ``_2``, ``_3`` ... angehaengt,
    bis sie frei ist. Ein leerer/rein-symbolischer Name faellt auf ``"source"`` zurueck.
    """
    base = re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")
    if not base:
        base = "source"
    if base not in existing_ids:
        return base
    suffix = 2
    while f"{base}_{suffix}" in existing_ids:
        suffix += 1
    return f"{base}_{suffix}"


# ── Lese-Use-Cases ────────────────────────────────────────────────────────────


class ListBlocklistSources:
    """Liefert alle Quellen-Definitionen als Domaenen-Objekte (Projektion macht der Rand).

    Gibt ``list[BlocklistSource]`` zurueck -- die Wire-Projektion uebernimmt der
    Composition-Root-Runner im api-Rand (Muster ``maintenance``/``outbound_log``: der Rand
    projiziert, der Use-Case bleibt domaenen-nah). ``entries`` wird mitgefuehrt, damit ein
    spaeterer Lese-Pfad bei Bedarf die Live-Zahl ziehen koennte; aktuell traegt schon die
    Quelle ihren ``entry_count``.
    """

    def __init__(
        self, sources: BlocklistSourceRepository, entries: BlocklistEntryRepository
    ) -> None:
        self._sources = sources
        self._entries = entries

    def __call__(self) -> list[BlocklistSource]:
        return self._sources.list_all()


class CheckBlocklistHealth:
    """Liefert je BROKEN-Quelle einen ``HealthIssue`` samt einfachem Ersatzvorschlag.

    VORSCHLAGSREGEL (bewusst einfach): fuer eine BROKEN-Quelle der Gruppe G wird die
    erste Ersatz-id derselben Gruppe G vorgeschlagen, die

    * bereits vorhanden und NICHT BROKEN ist (eine andere, gesunde Quelle derselben
      Gruppe -- Reihenfolge nach ``list_all``: group, dann name), ODER
    * falls keine solche vorhanden ist: die erste builtin-Default-Quelle derselben Gruppe
      aus ``DEFAULT_SOURCES``, die nicht die kaputte Quelle selbst ist.

    Findet sich nichts, ist ``suggested_replacement_id`` ``None``. KEIN automatisches
    Loeschen/Ersetzen -- nur Befund + Vorschlag (der Nutzer handelt im Frontend).
    """

    def __init__(self, sources: BlocklistSourceRepository) -> None:
        self._sources = sources

    def __call__(self) -> list[HealthIssue]:
        all_sources = self._sources.list_all()
        # Gesunde, vorhandene Quellen je Gruppe (nicht BROKEN), in list_all-Reihenfolge.
        healthy_by_group: dict[BlocklistGroup, list[str]] = {}
        for source in all_sources:
            if source.status is not BlocklistStatus.BROKEN:
                healthy_by_group.setdefault(source.group, []).append(source.id)

        issues: list[HealthIssue] = []
        for source in all_sources:
            if source.status is not BlocklistStatus.BROKEN:
                continue
            issues.append(
                HealthIssue(
                    source_id=source.id,
                    name=source.name,
                    group=source.group,
                    suggested_replacement_id=self._suggest_replacement(source, healthy_by_group),
                )
            )
        return issues

    @staticmethod
    def _suggest_replacement(
        broken: BlocklistSource, healthy_by_group: dict[BlocklistGroup, list[str]]
    ) -> str | None:
        # 1) eine andere, gesunde, vorhandene Quelle derselben Gruppe.
        for candidate_id in healthy_by_group.get(broken.group, []):
            if candidate_id != broken.id:
                return candidate_id
        # 2) sonst die erste builtin-Default derselben Gruppe (nicht die kaputte selbst).
        for default in DEFAULT_SOURCES:
            if default.group is broken.group and default.id != broken.id:
                return default.id
        return None


# ── Schreib-/Verwaltungs-Use-Cases ────────────────────────────────────────────


class SeedDefaultSources:
    """Legt fehlende ``DEFAULT_SOURCES`` an -- idempotent, ohne Bestehendes zu ueberschreiben.

    Beim App-Start (Verdrahtung TEIL D/E) einmal gerufen: jede Werksquelle, deren id noch
    NICHT existiert, wird angelegt; vorhandene bleiben UNANGETASTET (Nutzer-Aenderungen
    wie ``enabled``/``status`` ueberleben einen Neustart). Mehrfach-Aufruf ist harmlos.
    """

    def __init__(self, sources: BlocklistSourceRepository) -> None:
        self._sources = sources

    def __call__(self) -> None:
        added = 0
        for default in DEFAULT_SOURCES:
            if self._sources.get(default.id) is None:
                self._sources.upsert(default)
                added += 1
        if added:
            _logger.info("blocklist_default_sources_seeded", added=added)


class ResetSourcesToDefaults:
    """Werkszustand der Listen: leert Eintraege + Quellen, legt alle Defaults neu an.

    Anders als ``SeedDefaultSources`` (nur Fehlende) raeumt dies ZUERST komplett ab
    (``entries.clear_all`` + ``sources.clear_all``) und schreibt DANACH alle
    ``DEFAULT_SOURCES`` frisch -- nutzer-hinzugefuegte Quellen und alle Lade-Stände
    fallen weg (bewusster Reset-Knopf).
    """

    def __init__(
        self, sources: BlocklistSourceRepository, entries: BlocklistEntryRepository
    ) -> None:
        self._sources = sources
        self._entries = entries

    def __call__(self) -> None:
        self._entries.clear_all()
        self._sources.clear_all()
        for default in DEFAULT_SOURCES:
            self._sources.upsert(default)
        _logger.info("blocklist_sources_reset_to_defaults", count=len(DEFAULT_SOURCES))


class AddUserSource:
    """Fuegt eine Nutzer-Quelle per URL hinzu (origin USER_URL) -- ohne sofort zu laden.

    Hebt ``group``/``fmt`` autoritativ in die Enums (Fehlwert -> ``BlocklistError`` -> 422
    im Rand). Vergibt eine slug-id aus ``name`` (Kollision -> Suffix). Die Quelle startet
    ``enabled=True``, ``status=NEVER``, ``license="unknown"``, ``attribution_required=
    False`` -- der erste ``RefreshSource`` laedt sie. ``detect_license_hint(url)`` liefert
    einen freundlichen Hinweis im Ergebnis (verweigert NICHTS).
    """

    def __init__(self, sources: BlocklistSourceRepository) -> None:
        self._sources = sources

    def __call__(self, name: str, url: str, group: str, fmt: str) -> AddSourceResult:
        group_enum = _group_from_wire(group)
        fmt_enum = _format_from_wire(fmt)
        existing_ids = {source.id for source in self._sources.list_all()}
        source_id = _slugify(name, existing_ids)
        source = BlocklistSource(
            id=source_id,
            name=name,
            group=group_enum,
            fmt=fmt_enum,
            origin=SourceOrigin.USER_URL,
            url=url,
            license="unknown",
            attribution_required=False,
            enabled=True,
            last_fetched_ts=None,
            status=BlocklistStatus.NEVER,
            entry_count=None,
        )
        self._sources.upsert(source)
        return AddSourceResult(source_id=source_id, license_hint=detect_license_hint(url))


class ImportUploadedSource:
    """Importiert eine hochgeladene Liste (origin UPLOAD, ``url=None``) und parst SOFORT.

    Wie ``AddUserSource`` (group/fmt-Hebung, slug-id), aber ohne URL: ``raw_text`` wird
    direkt ueber ``parse_blocklist`` zerlegt und ueber ``entries.replace_entries``
    geschrieben; die Quelle startet ``status=OK``, ``last_fetched_ts=now`` (injizierter
    ``now_provider``), ``entry_count`` = Zahl der geparsten Eintraege. ``license`` bleibt
    ``"unknown"`` (Upload traegt keine bekannte Lizenz).
    """

    def __init__(
        self,
        sources: BlocklistSourceRepository,
        entries: BlocklistEntryRepository,
        now_provider: Callable[[], float] = time.time,
    ) -> None:
        self._sources = sources
        self._entries = entries
        self._now = now_provider

    def __call__(self, name: str, group: str, fmt: str, raw_text: str) -> ImportResult:
        group_enum = _group_from_wire(group)
        fmt_enum = _format_from_wire(fmt)
        existing_ids = {source.id for source in self._sources.list_all()}
        source_id = _slugify(name, existing_ids)

        domains, ip_cidrs = parse_blocklist(fmt_enum, raw_text)
        entry_count = len(domains) + len(ip_cidrs)
        self._entries.replace_entries(source_id, domains, ip_cidrs)

        source = BlocklistSource(
            id=source_id,
            name=name,
            group=group_enum,
            fmt=fmt_enum,
            origin=SourceOrigin.UPLOAD,
            url=None,
            license="unknown",
            attribution_required=False,
            enabled=True,
            last_fetched_ts=self._now(),
            status=BlocklistStatus.OK,
            entry_count=entry_count,
        )
        self._sources.upsert(source)
        return ImportResult(source_id=source_id, entry_count=entry_count)


class UpdateUserSource:
    """Partielles Update einer bestehenden Quelle (nur die nicht-``None``-Felder ersetzen).

    Liest die Quelle (unbekannte id -> ``BlocklistError`` -> 404 im Rand), ersetzt die
    uebergebenen Felder (``name``/``url``/``group``/``fmt``/``enabled``) und schreibt per
    ``upsert`` zurueck. ``group``/``fmt`` werden bei Angabe ueber die Wire-Hebung geprueft
    (Fehlwert -> ``BlocklistError`` -> 422). ``status``/``last_fetched_ts``/``entry_count``
    bleiben unangetastet -- ein Update aendert die Definition, nicht den Lade-Stand.
    """

    def __init__(self, sources: BlocklistSourceRepository) -> None:
        self._sources = sources

    def __call__(
        self,
        source_id: str,
        *,
        name: str | None = None,
        url: str | None = None,
        group: str | None = None,
        fmt: str | None = None,
        enabled: bool | None = None,
    ) -> None:
        source = self._sources.get(source_id)
        if source is None:
            raise BlocklistError(f"Unbekannte Quelle: {source_id!r}")
        new_group = _group_from_wire(group) if group is not None else source.group
        new_fmt = _format_from_wire(fmt) if fmt is not None else source.fmt
        updated = BlocklistSource(
            id=source.id,
            name=name if name is not None else source.name,
            group=new_group,
            fmt=new_fmt,
            origin=source.origin,
            url=url if url is not None else source.url,
            license=source.license,
            attribution_required=source.attribution_required,
            enabled=enabled if enabled is not None else source.enabled,
            last_fetched_ts=source.last_fetched_ts,
            status=source.status,
            entry_count=source.entry_count,
        )
        self._sources.upsert(updated)


class DeleteUserSource:
    """Loescht eine Quelle samt ihrer Eintraege -- idempotent.

    ``entries.delete_for`` + ``sources.delete``; eine unbekannte id ist KEIN Fehler (beide
    Adapter sind idempotent). So bleibt kein verwaister Eintrag ohne Definition zurueck.
    """

    def __init__(
        self, sources: BlocklistSourceRepository, entries: BlocklistEntryRepository
    ) -> None:
        self._sources = sources
        self._entries = entries

    def __call__(self, source_id: str) -> None:
        self._entries.delete_for(source_id)
        self._sources.delete(source_id)


# ── Lade-Use-Cases ────────────────────────────────────────────────────────────


class RefreshSource:
    """Laedt EINE Quelle: download -> parse -> entries ersetzen -> Quelle fortschreiben.

    Bei Erfolg: ``fetcher.fetch(url)`` + ``parse_blocklist`` + ``entries.replace_entries``,
    dann ``upsert`` mit ``status=OK``, ``last_fetched_ts=now``, ``entry_count=len``;
    ``RefreshResult(ok=True, ...)``.

    Bei Fehlschlag (Download-Exception der Fetcher-Naht ODER ein Parse-/Verarbeitungs-
    Problem) faengt der Use-Case BREIT (``Exception``) -- die Naht ist das Protocol, die
    Impl wirft stdlib/eigene Exceptions, der Application-Ring nennt die Infrastruktur nie.
    Dann ``upsert`` mit ``status=BROKEN`` (``last_fetched_ts``/``entry_count`` BLEIBEN
    erhalten -- der letzte gute Stand verfaellt nicht) und ``RefreshResult(ok=False,
    error=...)``. KEIN Werfen nach aussen -- der BROKEN-Status ist der ehrliche Befund
    (der Aufrufer/Health-Check verarbeitet ihn).

    Eine unbekannte id oder eine Quelle ohne ``url`` (UPLOAD) ist ein Aufrufer-Fehler ->
    ``BlocklistError`` (kein BROKEN-Status, da es nichts zu laden gibt).
    """

    def __init__(
        self,
        sources: BlocklistSourceRepository,
        entries: BlocklistEntryRepository,
        fetcher: BlocklistFetcher,
        now_provider: Callable[[], float] = time.time,
    ) -> None:
        self._sources = sources
        self._entries = entries
        self._fetcher = fetcher
        self._now = now_provider

    def __call__(self, source_id: str) -> RefreshResult:
        source = self._sources.get(source_id)
        if source is None:
            raise BlocklistError(f"Unbekannte Quelle: {source_id!r}")
        if source.url is None:
            raise BlocklistError(f"Quelle ohne URL (Upload) ist nicht ladbar: {source_id!r}")

        try:
            raw_text = self._fetcher.fetch(source.url)
            domains, ip_cidrs = parse_blocklist(source.fmt, raw_text)
            entry_count = len(domains) + len(ip_cidrs)
            self._entries.replace_entries(source_id, domains, ip_cidrs)
        except Exception as exc:  # bewusst breit: BROKEN statt Loop-Tod (S3).
            # Download-/Parse-Fehler -> BROKEN, OHNE last_fetched_ts/entry_count zu
            # verlieren (letzter guter Stand bleibt sichtbar). Kein Werfen nach aussen.
            self._sources.upsert(
                BlocklistSource(
                    id=source.id,
                    name=source.name,
                    group=source.group,
                    fmt=source.fmt,
                    origin=source.origin,
                    url=source.url,
                    license=source.license,
                    attribution_required=source.attribution_required,
                    enabled=source.enabled,
                    last_fetched_ts=source.last_fetched_ts,
                    status=BlocklistStatus.BROKEN,
                    entry_count=source.entry_count,
                )
            )
            _logger.warning("blocklist_refresh_broken", source_id=source_id, error=str(exc))
            return RefreshResult(source_id=source_id, ok=False, entry_count=None, error=str(exc))

        self._sources.upsert(
            BlocklistSource(
                id=source.id,
                name=source.name,
                group=source.group,
                fmt=source.fmt,
                origin=source.origin,
                url=source.url,
                license=source.license,
                attribution_required=source.attribution_required,
                enabled=source.enabled,
                last_fetched_ts=self._now(),
                status=BlocklistStatus.OK,
                entry_count=entry_count,
            )
        )
        return RefreshResult(source_id=source_id, ok=True, entry_count=entry_count, error=None)


class RefreshDueSources:
    """Laedt alle FAELLIGEN aktiven Quellen ueber ``RefreshSource`` (Faelligkeit via ts).

    FAELLIG ist eine ``enabled``-Quelle MIT ``url``, deren ``last_fetched_ts`` ``None`` ist
    (noch nie geladen) ODER aelter als ``interval_days * 86400`` Sekunden (gegen den
    injizierten ``now_provider`` -- Muster cve ``due_reason``). Speist BEIDES: den
    Scheduler-Handler (Auto-Refresh) UND den manuellen "alle faelligen jetzt"-Knopf.
    UPLOAD-Quellen (``url is None``) sind nie faellig (nichts zu laden).
    """

    def __init__(
        self,
        sources: BlocklistSourceRepository,
        refresh: RefreshSource,
        now_provider: Callable[[], float] = time.time,
    ) -> None:
        self._sources = sources
        self._refresh = refresh
        self._now = now_provider

    def __call__(self, interval_days: int) -> list[RefreshResult]:
        now = self._now()
        threshold = max(0, interval_days) * _SECONDS_PER_DAY
        results: list[RefreshResult] = []
        for source in self._sources.list_all():
            if not source.enabled or source.url is None:
                continue
            if source.last_fetched_ts is None or (now - source.last_fetched_ts) >= threshold:
                results.append(self._refresh(source.id))
        return results


# ── Abgleich-Use-Case ─────────────────────────────────────────────────────────


class MatchContacts:
    """Gleicht Aussenkontakte gegen die aktiven, geladenen Listen ab (zeigt + ordnet ein).

    Pro Kontakt: ``domain_suffix_candidates(hostname)`` -> ``entries.lookup_domains`` und
    ``entries.lookup_ips(remote_ip)``. Je Roh-Treffer wird die Quelle aufgeloest
    (einmaliges ``list_all`` -> dict, gecacht) und gefiltert nach:

    * ``strictness_allows(group, strictness)`` -- die Anzeige-Strenge (Domaenenregel),
    * ``enabled_groups`` (``None`` = keine Gruppen-Einschraenkung) -- die Settings-
      Gruppen-Feinschalter,
    * ``source.enabled`` -- nur aktive Quellen.

    Die ueberlebenden Treffer werden zu ``BlocklistMatch`` gebaut, dedupliziert pro
    ``(source_id, matched_on)`` bei stabiler Reihenfolge, und je Kontakt in einem
    ``ContactMatchResult`` gebuendelt (auch leere ``matches`` sind zulaessig -- "auf keiner
    aktiven Liste"). CERNIS urteilt NICHT: ``group`` ist die Gruppe der TREFFENDEN Quelle.
    """

    def __init__(
        self, sources: BlocklistSourceRepository, entries: BlocklistEntryRepository
    ) -> None:
        self._sources = sources
        self._entries = entries

    def __call__(
        self,
        contacts: list[ContactInput],
        strictness: MatchStrictness,
        enabled_groups: frozenset[BlocklistGroup] | None = None,
    ) -> list[ContactMatchResult]:
        by_id = {source.id: source for source in self._sources.list_all()}
        results: list[ContactMatchResult] = []
        for contact in contacts:
            matches = self._match_one(contact, strictness, enabled_groups, by_id)
            results.append(
                ContactMatchResult(
                    remote_ip=contact.remote_ip,
                    hostname=contact.hostname,
                    matches=matches,
                )
            )
        return results

    def _match_one(
        self,
        contact: ContactInput,
        strictness: MatchStrictness,
        enabled_groups: frozenset[BlocklistGroup] | None,
        by_id: dict[str, BlocklistSource],
    ) -> tuple[BlocklistMatch, ...]:
        raw_hits: list[tuple[str, str]] = []
        if contact.hostname:
            candidates = list(domain_suffix_candidates(contact.hostname))
            raw_hits.extend(self._entries.lookup_domains(candidates))
        if contact.remote_ip:
            raw_hits.extend(self._entries.lookup_ips(contact.remote_ip))

        matches: list[BlocklistMatch] = []
        seen: set[tuple[str, str]] = set()
        for source_id, matched_on in raw_hits:
            key = (source_id, matched_on)
            if key in seen:
                continue
            source = by_id.get(source_id)
            if source is None or not source.enabled:
                continue
            if not strictness_allows(source.group, strictness):
                continue
            if enabled_groups is not None and source.group not in enabled_groups:
                continue
            seen.add(key)
            matches.append(
                BlocklistMatch(
                    source_id=source.id,
                    source_name=source.name,
                    group=source.group,
                    matched_on=matched_on,
                )
            )
        return tuple(matches)
