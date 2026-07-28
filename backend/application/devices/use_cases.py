"""Use-Cases der devices-Domaene (Variante A).

Orchestrieren Domaene (``merge_scan``, ``should_append_ip``) + Ports
(``DeviceRepository``, ``Clock``). Kennen ``domain/`` und ``ports/``, NIEMALS
``infrastructure/`` (maschinell per import-linter erzwungen). Ports kommen per
Constructor-Injection als Protocol-Typ herein -- nie ein konkreter Adapter.
Kein State ueber Aufrufe, keine Framework-Imports.

Hier verschwinden die Ist-Analyse-Bugs strukturell:

* BUG 3 (Dual-Write): es gibt nur EINEN Schreibpfad (``repo.save``), kein
  ``known_devices`` mehr.
* BUG 2 (is_known): ``merge_scan`` bewahrt ``is_known`` -- ein Scan setzt es nie
  zurueck (siehe ``RecordScannedHost``).
* active_24h-Zeitzonen-Bug: die 24h-Grenze entsteht HIER aus ``clock.now()``
  (tz-aware UTC), nicht im Repo.
"""

from collections.abc import Sequence
from dataclasses import replace
from datetime import timedelta
from typing import Any

from application.devices.errors import (
    DeviceAlreadyExistsError,
    DeviceBroadcastMacError,
    DeviceNotFoundError,
    InvalidTrustStateError,
)
from domain.devices import (
    Device,
    DeviceSource,
    DeviceStats,
    DeviceWithHistory,
    IpHistoryEntry,
    ScannedHost,
    TrustState,
    is_broadcast_mac,
    merge_scan,
    normalize_mac,
    register_archive_prompt,
    should_append_ip,
)
from ports.devices import Clock, DeviceRepository


class GetDeviceStats:
    """Aggregierte Zaehler; die 24h-Aktiv-Grenze entsteht hier aus der Uhr."""

    def __init__(self, repository: DeviceRepository, clock: Clock) -> None:
        self._repository = repository
        self._clock = clock

    def __call__(self) -> DeviceStats:
        active_since = self._clock.now() - timedelta(hours=24)
        return self._repository.stats(active_since)


class GetDevices:
    """Liste aller Geraete, optional auf bekannte gefiltert."""

    def __init__(self, repository: DeviceRepository) -> None:
        self._repository = repository

    def __call__(self, known_only: bool) -> list[Device]:
        return self._repository.get_all(known_only)


class GetUnclassifiedDevices:
    """Die Gaeste-/Unbekannt-Wache: noch nicht eingeordnete, nicht weggelegte Geraete.

    Reine Lese-Orchestrierung -- die Filterung (``is_known=0 AND
    watch_dismissed=0``) und die Sortierung (``last_seen`` absteigend) liegen im
    Repository. Leerer Bestand -> ``[]``.
    """

    def __init__(self, repository: DeviceRepository) -> None:
        self._repository = repository

    def __call__(self) -> list[Device]:
        return self._repository.get_unclassified()


class GetDevice:
    """Ein Geraet samt IP-Historie; unbekannte MAC -> ``DeviceNotFoundError``."""

    def __init__(self, repository: DeviceRepository) -> None:
        self._repository = repository

    def __call__(self, mac: str) -> DeviceWithHistory:
        norm = normalize_mac(mac)
        device = self._repository.get(norm)
        if device is None:
            raise DeviceNotFoundError(norm)
        history = self._repository.get_ip_history(norm)
        return DeviceWithHistory(device=device, ip_history=tuple(history))


class UpdateDeviceMeta:
    """Partielles Update der User-Metadaten; unbekannte MAC -> ``DeviceNotFoundError``.

    Read-modify-write ueber ``dataclasses.replace`` (``Device`` ist frozen) und
    genau EIN Schreibpfad (``repo.save``) -- BUG-3-Fix: kein Dual-Write in eine
    zweite Tabelle. ``None`` bedeutet "Feld nicht aendern".
    """

    def __init__(self, repository: DeviceRepository) -> None:
        self._repository = repository

    def __call__(
        self,
        mac: str,
        label: str | None = None,
        tags: Sequence[str] | None = None,
        notes: str | None = None,
        category: str | None = None,
        is_known: bool | None = None,
        trust_state: TrustState | str | None = None,
        watch_dismissed: bool | None = None,
    ) -> Device:
        norm = normalize_mac(mac)
        existing = self._repository.get(norm)
        if existing is None:
            raise DeviceNotFoundError(norm)

        changes: dict[str, Any] = {}
        if label is not None:
            changes["label"] = label
        if tags is not None:
            changes["tags"] = tuple(tags)
        if notes is not None:
            changes["notes"] = notes
        if category is not None:
            changes["category"] = category
        if is_known is not None:
            changes["is_known"] = is_known
        if watch_dismissed is not None:
            # Generischer Update-Pfad fuer das Wache-Wegleg-Flag; der bequeme
            # Spezialpfad fuers Frontend ist DismissDeviceFromWatch. None laesst
            # das Feld unberuehrt, wie alle anderen optionalen Parameter.
            changes["watch_dismissed"] = watch_dismissed
        if trust_state is not None:
            # Hebung str->TrustState hier (der api-Ring darf domain nicht
            # importieren). Ungueltiger Wert -> lauter Application-Fehler, kein
            # stiller Fallback (Finding S3).
            try:
                resolved = TrustState(trust_state)
            except ValueError as exc:
                raise InvalidTrustStateError(str(trust_state)) from exc
            changes["trust_state"] = resolved
            # Konsistenz-Regel: wer trusted/watch setzt, hat das Geraet damit
            # eingeordnet -> is_known mitsetzen. NEUTRAL laesst is_known
            # unberuehrt. Explizit uebergebenes is_known hat Vorrang (oben bereits
            # in changes), wird hier NICHT ueberschrieben.
            if resolved in (TrustState.TRUSTED, TrustState.WATCH) and "is_known" not in changes:
                changes["is_known"] = True

        updated = replace(existing, **changes)
        self._repository.save(updated)
        return updated


class DismissDeviceFromWatch:
    """Legt ein Geraet aus der Wache weg (ignorieren, NICHT loeschen) -- ruecknehmbar.

    Bequemer Spezialpfad fuers Frontend: setzt ``watch_dismissed`` ueber
    read-modify-write (``dataclasses.replace``, ``Device`` ist frozen) mit genau
    EINEM Schreibpfad (``repo.save``) -- wie ``UpdateDeviceMeta``, nur auf das
    eine Feld fokussiert. ``dismissed=True`` legt weg (Geraet verschwindet aus
    der Wache, bleibt aber im Bestand), ``dismissed=False`` holt es zurueck
    (ruecknehmbar). Unbekannte MAC -> ``DeviceNotFoundError``.
    """

    def __init__(self, repository: DeviceRepository) -> None:
        self._repository = repository

    def __call__(self, mac: str, dismissed: bool) -> Device:
        norm = normalize_mac(mac)
        existing = self._repository.get(norm)
        if existing is None:
            raise DeviceNotFoundError(norm)
        updated = replace(existing, watch_dismissed=dismissed)
        self._repository.save(updated)
        return updated


class DeleteDevice:
    """Loescht ein Geraet (inkl. IP-History, BUG-1-Fix im Repo). Idempotent."""

    def __init__(self, repository: DeviceRepository) -> None:
        self._repository = repository

    def __call__(self, mac: str) -> None:
        # Kein DeviceNotFoundError: das Repo-delete ist idempotent, ein Fehler
        # bei unbekannter MAC waere inkonsistent zu diesem Vertrag.
        self._repository.delete(normalize_mac(mac))


class RecordScannedHost:
    """Verbucht einen gescannten Host: mergen (Domaene) -> speichern -> ggf. History.

    Der Use-Case, den spaeter die scanning-Domaene aufruft. Die Merge-Logik liegt
    in ``domain.merge_scan`` (inkl. BUG-2-Fix: ``is_known`` bleibt erhalten); hier
    nur die Orchestrierung.

    Die Broadcast-Adresse wird still uebersprungen -> Rueckgabe ``None``. Der
    Rueckgabetyp ist deshalb ``Device | None``; ein ``None`` heisst "nicht
    aufgenommen", nicht "Fehler" (der einzige produktive Aufrufer,
    ``ws_scan.record_host_best_effort``, verwirft den Rueckgabewert ohnehin).
    """

    def __init__(self, repository: DeviceRepository, clock: Clock) -> None:
        self._repository = repository
        self._clock = clock

    def __call__(self, scanned: ScannedHost) -> Device | None:
        # Die Broadcast-Adresse ist kein Geraet, sondern eine Adressierungsform --
        # sie wird still uebersprungen wie eine leere MAC im Scan-Aufnahmepfad und
        # NICHT geworfen, weil ein Scan an einem Nicht-Geraet nicht scheitern darf.
        if is_broadcast_mac(scanned.mac):
            return None
        now = self._clock.now()
        existing = self._repository.get(scanned.mac)
        merged = merge_scan(existing, scanned, now)
        self._repository.save(merged)

        scanned_ip = scanned.ip
        if scanned_ip is not None and should_append_ip(existing, scanned_ip):
            self._repository.append_ip_history(
                IpHistoryEntry(mac=merged.mac, ip=scanned_ip, seen_at=now)
            )
        return merged


class CreateDevice:
    """Legt ein Geraet von Hand an; bekannte MAC -> ``DeviceAlreadyExistsError``.

    Die Broadcast-Adresse -> ``DeviceBroadcastMacError``: sie ist kein Geraet,
    sondern eine Adressierungsform, und wird von Hand benannt abgelehnt (keine
    stille Uebergehung wie im Scan-Pfad -- hier steht ein Mensch dahinter, S3).

    Manuelles Anlegen ist KEIN Upsert: existiert die MAC schon, ist das ein
    Konflikt (der Aufrufer soll bearbeiten/wiederherstellen, nicht ueberschreiben).
    Das neue Geraet startet mit ``times_seen=0``, weil es noch nie real gescannt
    wurde -- ein spaeterer Scan derselben MAC merged ueber ``merge_scan`` (das
    vorhandene Verhalten) und zaehlt hoch; die hier von Hand gesetzten Felder
    (``label``/``notes``/``category``/``tags``) bleiben dabei erhalten, weil
    ``merge_scan`` sie bewahrt. ``is_known=True``, weil ein von Hand eingetragenes
    Geraet per Definition bewusst eingeordnet ist; ``source=MANUAL`` haelt die
    Herkunft fest (ein Re-Scan aendert sie nicht).
    """

    def __init__(self, repository: DeviceRepository, clock: Clock) -> None:
        self._repository = repository
        self._clock = clock

    def __call__(
        self,
        mac: str,
        label: str = "",
        notes: str = "",
        category: str = "",
        tags: Sequence[str] | None = None,
    ) -> Device:
        norm = normalize_mac(mac)
        # Die Broadcast-Adresse ist kein Geraet: benannte Ablehnung VOR dem Bau
        # des Device, kein stiller Verzicht (Finding S3). Der Router bildet das
        # auf HTTP 422 ab.
        if is_broadcast_mac(norm):
            raise DeviceBroadcastMacError(norm)
        if self._repository.get(norm) is not None:
            raise DeviceAlreadyExistsError(norm)
        now = self._clock.now()
        device = Device(
            mac=norm,
            first_seen=now,
            last_seen=now,
            last_ip=None,
            times_seen=0,
            is_known=True,
            source=DeviceSource.MANUAL,
            label=label,
            notes=notes,
            category=category,
            tags=tuple(tags) if tags is not None else (),
        )
        self._repository.save(device)
        return device


class ArchiveDevice:
    """Archiviert ein Geraet direkt; unbekannte MAC -> ``DeviceNotFoundError``.

    Direktes Archivieren ueber die Geraeteverwaltung, unabhaengig vom
    Nachfrage-Workflow (``AnswerArchivePrompt``). Read-modify-write ueber
    ``dataclasses.replace`` mit genau EINEM Schreibpfad (``repo.save``).
    """

    def __init__(self, repository: DeviceRepository) -> None:
        self._repository = repository

    def __call__(self, mac: str) -> Device:
        norm = normalize_mac(mac)
        existing = self._repository.get(norm)
        if existing is None:
            raise DeviceNotFoundError(norm)
        updated = replace(existing, archived=True)
        self._repository.save(updated)
        return updated


class RestoreDevice:
    """Holt ein archiviertes Geraet zurueck; unbekannte MAC -> ``DeviceNotFoundError``.

    Gegenstueck zu ``ArchiveDevice``: setzt ``archived=False`` und bringt das
    Geraet zurueck in den aktiven Bestand. Setzt den Nachfrage-Zustand bewusst
    NICHT zurueck (``archive_prompt_count``/``archive_prompt_dismissed`` bleiben,
    wie sie sind) -- kein erneutes Nachfrage-Karussell beim Zurueckholen.
    """

    def __init__(self, repository: DeviceRepository) -> None:
        self._repository = repository

    def __call__(self, mac: str) -> Device:
        norm = normalize_mac(mac)
        existing = self._repository.get(norm)
        if existing is None:
            raise DeviceNotFoundError(norm)
        updated = replace(existing, archived=False)
        self._repository.save(updated)
        return updated


class GetArchivedDevices:
    """Die Archiv-Liste: alle archivierten Geraete. Reine Lese-Orchestrierung.

    Filterung (``archived=1``) und Sortierung (``last_seen`` absteigend) liegen
    im Repository. Leerer Bestand -> ``[]``.
    """

    def __init__(self, repository: DeviceRepository) -> None:
        self._repository = repository

    def __call__(self) -> list[Device]:
        return self._repository.get_archived()


class GetArchiveCandidates:
    """Geraete, die lange nicht gesehen wurden -- die Nachfrage-Kandidaten.

    Reine Lese-Orchestrierung fuer einen passiven, scan-quellen-agnostischen
    Lese-Endpunkt: das Frontend fragt nach Scan-Abschluss ab, ob Geraete zur
    Archivierung vorgeschlagen werden sollen. Hier wird NICHTS automatisch
    archiviert.

    Die Schwelle (Tage) kommt vom Aufrufer (der Composition Root liest das
    Setting ``device_archive_prompt_days``); die Zeitgrenze entsteht HIER aus der
    Uhr (Muster ``GetDeviceStats``). Das Repository filtert rein nach
    ``last_seen <= Grenze``.
    """

    def __init__(self, repository: DeviceRepository, clock: Clock) -> None:
        self._repository = repository
        self._clock = clock

    def __call__(self, threshold_days: int) -> list[Device]:
        not_seen_since = self._clock.now() - timedelta(days=threshold_days)
        return self._repository.get_archive_candidates(not_seen_since)


class AnswerArchivePrompt:
    """Bildet die Nutzerantwort auf die Scan-Nachfrage ab.

    Unbekannte MAC -> ``DeviceNotFoundError``.
    Ja -> archivieren, Nein -> Zaehler hoch, ab dem 3. Nein nicht mehr fragen.
    Die 3x-Regel lebt in der Domaene (``register_archive_prompt``); hier nur die
    Orchestrierung (read-modify-write, genau EIN Schreibpfad ``repo.save``).
    """

    def __init__(self, repository: DeviceRepository) -> None:
        self._repository = repository

    def __call__(self, mac: str, archive: bool) -> Device:
        norm = normalize_mac(mac)
        existing = self._repository.get(norm)
        if existing is None:
            raise DeviceNotFoundError(norm)
        updated = register_archive_prompt(existing, archive)
        self._repository.save(updated)
        return updated
