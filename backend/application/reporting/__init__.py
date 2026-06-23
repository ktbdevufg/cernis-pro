"""Use-Cases der reporting-Domaene (Sicherheitsbericht)."""

from application.reporting.security_score import (
    DeviceBurden,
    SecurityScore,
    compute_security_score,
)

__all__ = [
    "DeviceBurden",
    "SecurityScore",
    "compute_security_score",
]
