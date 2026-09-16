"""Use-Cases der Lizenzaufstellung und ihre Application-Exceptions.

Der ``api``-Ring importiert AUSSCHLIESSLICH von hier (import-linter: api -> nur
application) -- die Fehlerklassen werden darum mit re-exportiert, damit der Router
sie fangen kann, ohne ``ports`` oder ``infrastructure`` zu nennen. Dasselbe Muster
nutzt ``api/outbound_log.py`` fuer ``InvalidRecordingTransition``.
"""

from application.license_manifest.errors import (
    LicenseManifestApplicationError,
    LicenseManifestUnavailable,
    LicenseTextUnknown,
)
from application.license_manifest.normalisierung import normalisiere_lizenz_id
from application.license_manifest.use_cases import (
    GetLicenseManifest,
    GetLicenseText,
    ProgrammPruefung,
)

__all__ = [
    "GetLicenseManifest",
    "GetLicenseText",
    "LicenseManifestApplicationError",
    "LicenseManifestUnavailable",
    "LicenseTextUnknown",
    "ProgrammPruefung",
    "normalisiere_lizenz_id",
]
