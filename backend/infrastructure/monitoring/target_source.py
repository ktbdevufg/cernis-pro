"""Adapter fuer ``MonitorTargetSource`` -- komponiert die Monitor-Targets.

Reproduziert die heterogene Komposition des Altcodes (``_build_monitor_targets``,
in v2 als Uebergangs-Kruecke nach ``app.py`` hochgezogen, P2.1b) aus DREI Quellen:

1. **Interface-Gateways** -- ``modules.interfaces.get_interfaces`` (unmigriertes
   Hilfsmodul); je Interface mit Gateway + IPv4 ein Gateway-Target. Der
   ``modules``-Import ist durch die ADR-0007-Erweiterung gedeckt -- der EINZIGE
   modules-Bezug dieses Adapters.
2. **Fest verdrahtete Internet-Targets** -- 8.8.8.8 (Google DNS) / 1.1.1.1
   (Cloudflare), im Adapter konstant.
3. **Benutzerdefinierte Targets** -- ``monitor_custom_targets`` aus den Settings,
   gelesen ueber den MIGRIERTEN ``ports/settings.SettingsRepository``-Port (NICHT
   ``modules.storage.get_setting`` -- wo ein v2-Port existiert, wird er genutzt).
   Adapter -> Port ist import-linter-konform: der infrastructure-Contract verbietet
   nur ``application``/``api``, nicht ``ports``.

LIVE-RELOAD (Port-Vertrag): ``load()`` liest bei JEDEM Aufruf frisch -- Interfaces
neu abgefragt, Settings neu gelesen. So wirkt ein ueber ``/api/monitor/targets``
geaendertes Custom-Target beim naechsten ``load`` (Altcode-Semantik).

``SettingsRepository.get`` liefert ein ``Setting`` mit bereits dekodiertem ``value``
(der settings-Adapter ruft ``_decode`` -> ``monitor_custom_targets`` kommt als
``list[dict]``). Nicht gesetzt -> ``None`` -> keine Custom-Targets (die fest
verdrahteten Internet-Targets bleiben; die Liste ist nie leer).
"""

from typing import Any

import structlog

from domain.monitoring import CUSTOM_TARGETS_KEY, MonitorTarget
from modules.interfaces import get_interfaces
from ports.settings import SettingsRepository

_logger = structlog.get_logger(__name__)


class CompositeTargetSource:
    """Erfuellt das ``MonitorTargetSource``-Protocol strukturell (3-Quellen-Komposition)."""

    def __init__(self, settings: SettingsRepository) -> None:
        self._settings = settings

    def load(self) -> list[MonitorTarget]:
        """Setzt die Target-Liste frisch aus Interfaces + Hardcoded + Settings zusammen."""
        targets: list[MonitorTarget] = []

        # 1. Interface-Gateways (modules.interfaces, unmigriertes Hilfsmodul).
        for iface in get_interfaces():
            if iface.gateway and iface.ipv4:
                targets.append(
                    MonitorTarget(
                        id=f"gw_{iface.name}",
                        label=f"Gateway ({iface.name})",
                        host=iface.gateway,
                        interface=iface.name,
                        enabled=True,
                    )
                )

        # 2. Fest verdrahtete Internet-Targets (Altcode-Konstanten).
        targets.append(
            MonitorTarget(
                id="internet_primary",
                label="Internet (Google DNS)",
                host="8.8.8.8",
                interface="",
                enabled=True,
            )
        )
        targets.append(
            MonitorTarget(
                id="internet_secondary",
                label="Internet (Cloudflare)",
                host="1.1.1.1",
                interface="",
                enabled=True,
            )
        )

        # 3. Custom-Targets aus den Settings (migrierter Port). Best-effort PRO
        # Eintrag (Linie wie Fritz S.7c / devices-Projektion S.7d): der Loop (M.5)
        # ruft load() periodisch -- ein EINZELNER kaputter User-Eintrag (z. B. ohne
        # "host") darf nicht die GESAMTE Target-Liste reissen (sonst fielen auch
        # Gateways + Internet-Targets aus, Monitoring waere komplett tot). Der
        # kaputte Eintrag wird sichtbar geloggt (kein stiller S3-Fallback) und
        # uebersprungen; die KeyError-Treue im Mapping bleibt erhalten (ein Target
        # ohne host IST ein Fehler -- er wird geloggt, nicht als gueltig akzeptiert).
        setting = self._settings.get(CUSTOM_TARGETS_KEY)
        if setting is not None and isinstance(setting.value, list):
            for entry in setting.value:
                if not isinstance(entry, dict):
                    continue
                try:
                    targets.append(_target_from_setting(entry))
                except (KeyError, ValueError, TypeError) as exc:
                    _logger.warning("monitor_custom_target_skipped", error=str(exc), entry=entry)
                    continue

        return targets


def _target_from_setting(entry: dict[str, Any]) -> MonitorTarget:
    """Baut ein ``MonitorTarget`` aus einem Custom-Settings-dict (Altcode: ``**t``).

    Defaults wie der Altcode-Datentraeger: ``interface=""``, ``enabled=True``.
    ``id``/``label``/``host`` sind im Custom-Eintrag erwartet (vom POST-Endpunkt
    gesetzt -- ``/api/monitor/targets``).
    """
    return MonitorTarget(
        id=str(entry["id"]),
        label=str(entry["label"]),
        host=str(entry["host"]),
        interface=str(entry.get("interface", "")),
        enabled=bool(entry.get("enabled", True)),
    )
