"""Structured logging configuration using structlog with file output and audit support."""

from __future__ import annotations

import logging
import os
import platform
import socket
import sys
from datetime import datetime

import structlog


def get_audit_context() -> dict:
    """Gather audit information about the scan runner."""
    try:
        hostname = socket.gethostname()
        username = os.getenv("USER") or os.getenv("USERNAME") or "unknown"
        ip = socket.gethostbyname(hostname) if hostname else "unknown"
    except Exception:
        hostname = platform.node()
        username = "unknown"
        ip = "unknown"

    return {
        "scan_runner": username,
        "hostname": hostname,
        "ip": ip,
        "platform": platform.platform(),
        "pid": os.getpid(),
        "start_time": datetime.utcnow().isoformat(),
    }


def configure_logging(verbose: bool = False, log_file: str = "adsentinel.log") -> None:
    """Configure structured logging with console + file output."""
    log_level = logging.DEBUG if verbose else logging.INFO

    # File handler for persistent audit logs
    file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    file_handler.setLevel(log_level)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),  # For file
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    # Add file logging
    root_logger = logging.getLogger()
    root_logger.addHandler(file_handler)
    root_logger.setLevel(log_level)

    # Inject audit context
    structlog.contextvars.bind_contextvars(**get_audit_context())

    logger = get_logger(__name__)
    logger.info("logging_initialized", log_file=log_file)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a structured logger for a module."""
    return structlog.get_logger(name)
