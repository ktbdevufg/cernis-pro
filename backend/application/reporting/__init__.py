"""Use-Cases der reporting-Domaene (Sicherheitsbericht)."""

from application.reporting.security_report import (
    CveFinding,
    NetFinding,
    PortFinding,
    SecurityReport,
    build_device_burdens,
    build_security_report,
    severity_rank,
)
from application.reporting.security_score import (
    DeviceBurden,
    SecurityScore,
    compute_security_score,
)

__all__ = [
    "CveFinding",
    "DeviceBurden",
    "NetFinding",
    "PortFinding",
    "SecurityReport",
    "SecurityScore",
    "build_device_burdens",
    "build_security_report",
    "compute_security_score",
    "severity_rank",
]
