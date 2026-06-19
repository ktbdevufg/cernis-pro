"""Use-Cases der diagnostics-Domaene und ihre Application-Exceptions."""

from application.diagnostics.errors import (
    DiagnosticsApplicationError,
    DiagnosticsToolMissingError,
    ExternalCheckError,
    RogueDhcpPermissionError,
)
from application.diagnostics.use_cases import (
    DEFAULT_CPNETCHECK_URL,
    BuildRouteGeo,
    CheckDhcpPermission,
    CheckDiagnosticsTools,
    CheckExternalReachability,
    CheckTraceroutePermission,
    DetectRogueDhcp,
    GeoLookup,
    GrabBanner,
    ResolveDns,
    RunTraceroute,
)

__all__ = [
    "DEFAULT_CPNETCHECK_URL",
    "BuildRouteGeo",
    "CheckDhcpPermission",
    "CheckDiagnosticsTools",
    "CheckExternalReachability",
    "CheckTraceroutePermission",
    "DetectRogueDhcp",
    "DiagnosticsApplicationError",
    "DiagnosticsToolMissingError",
    "ExternalCheckError",
    "GeoLookup",
    "GrabBanner",
    "ResolveDns",
    "RogueDhcpPermissionError",
    "RunTraceroute",
]
