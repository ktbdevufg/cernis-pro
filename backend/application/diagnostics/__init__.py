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
    EnrichRouteOrgs,
    GeoLookup,
    GetLatestRogueDhcp,
    GrabBanner,
    OrgLookup,
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
    "EnrichRouteOrgs",
    "ExternalCheckError",
    "GeoLookup",
    "GetLatestRogueDhcp",
    "GrabBanner",
    "OrgLookup",
    "ResolveDns",
    "RogueDhcpPermissionError",
    "RunTraceroute",
]
