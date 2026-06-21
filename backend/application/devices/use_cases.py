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

from application.devices.errors import DeviceNotFoundError, InvalidTrustStateError
from domain.devices import (
    Device,
    DeviceStats,
    DeviceWithHistory,
    IpHistoryEntry,
    ScannedHost,
    TrustState,
    merge_scan,
    normalize_mac,
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
    """

    def __init__(self, repository: DeviceRepository, clock: Clock) -> None:
        self._repository = repository
        self._clock = clock

    def __call__(self, scanned: ScannedHost) -> Device:
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
