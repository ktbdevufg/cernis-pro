"""structlog-Konfiguration fuer CERNIS PRO.

Einheitliches, strukturiertes Logging. ConsoleRenderer fuer die Entwicklung,
JSONRenderer fuer den produktiven/maschinellen Betrieb (per Konfiguration
umschaltbar). Wird im Composition Root beim Start aufgerufen.
"""

import logging

import structlog
from structlog.typing import Processor


def configure_logging(*, level: str = "INFO", json_logs: bool = False) -> None:
    """Konfiguriert structlog global.

    :param level: Log-Level als Name (z. B. ``"INFO"``, ``"DEBUG"``).
    :param json_logs: Bei ``True`` JSON-Ausgabe, sonst lesbare Konsolen-Ausgabe.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    processors.append(
        structlog.processors.JSONRenderer() if json_logs else structlog.dev.ConsoleRenderer()
    )

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
