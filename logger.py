"""
logger.py - Centralized logging configuration for AISE ASK.

Usage in any module:
    from logger import get_logger
    log = get_logger(__name__)

    log.info("User registered", extra={"props": {"username": "brett"}})
    log.warning("Failed login attempt", extra={"props": {"username": "unknown"}})
    log.error("Groq API error", extra={"props": {"status_code": 502}})

Configuration via environment variables:
    LOG_LEVEL  - DEBUG, INFO, WARNING, ERROR  (default: INFO)
    LOG_FORMAT - text, json                   (default: text)
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone

# ── Configuration ────────────────────────────────────────────────────────────

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.getenv("LOG_FORMAT", "text").lower()

# ── Formatters ───────────────────────────────────────────────────────────────

class TextFormatter(logging.Formatter):
    """Human-readable single-line format for development.

    Example:
        2026-02-21 13:00:12 | INFO    | routers.auth     | User registered | username=brett
    """

    LEVEL_COLORS = {
        "DEBUG":    "\033[36m",   # cyan
        "INFO":     "\033[32m",   # green
        "WARNING":  "\033[33m",   # yellow
        "ERROR":    "\033[31m",   # red
        "CRITICAL": "\033[35m",   # magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        level = record.levelname.ljust(8)
        name = record.name.ljust(18)[:18]
        message = record.getMessage()

        color = self.LEVEL_COLORS.get(record.levelname, "")
        level_str = f"{color}{level}{self.RESET}"

        # Append any structured props passed via extra={"props": {...}}
        props = getattr(record, "props", None)
        props_str = ""
        if props:
            props_str = " | " + " ".join(f"{k}={v}" for k, v in props.items())

        return f"{timestamp} | {level_str} | {name} | {message}{props_str}"


class JsonFormatter(logging.Formatter):
    """JSON-lines format for production log aggregation (Datadog, CloudWatch, etc).

    Example:
        {"timestamp": "2026-02-21T13:00:12Z", "level": "INFO", "logger": "routers.auth",
         "message": "User registered", "username": "brett"}
    """

    def format(self, record: logging.LogRecord) -> str:
        props = getattr(record, "props", {}) or {}
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            **props,
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


# ── Root logger setup ────────────────────────────────────────────────────────

def _configure_root_logger() -> None:
    """Configure the root logger once at import time."""
    numeric_level = getattr(logging, LOG_LEVEL, logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)

    if LOG_FORMAT == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(TextFormatter())

    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Avoid duplicate handlers if the module is imported multiple times
    if not root.handlers:
        root.addHandler(handler)

    # Quiet down noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


_configure_root_logger()


# ── Public API ───────────────────────────────────────────────────────────────

def get_logger(name: str) -> logging.Logger:
    """Return a logger for the given module name.

    Args:
        name: Typically __name__ from the calling module.

    Returns:
        A configured Logger instance.
    """
    return logging.getLogger(name)
