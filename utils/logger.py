"""
utils/logger.py
===============
AI Red Team Harness v3 — Structured Logging System

Responsibilities:
  - Provide a single get_logger() factory used by every module
  - Configure root logger once at import time (no duplicate handlers)
  - Support console + rotating file output simultaneously
  - Emit structured JSON log records to logs/execution.log
  - Emit human-readable coloured output to the console
  - Respect LOG_LEVEL environment variable

Usage (in any module):
    from utils.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Something happened | key=%s value=%d", key, value)

Author: AI Red Team Harness v3
Python: 3.10+
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG_DIR      = Path("logs")
LOG_FILE     = LOG_DIR / "execution.log"
MAX_BYTES    = 10 * 1024 * 1024   # 10 MB per file
BACKUP_COUNT = 5                   # keep 5 rotated files
DEFAULT_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

# ANSI colour codes for console output
_COLOURS = {
    "DEBUG":    "\033[36m",    # cyan
    "INFO":     "\033[32m",    # green
    "WARNING":  "\033[33m",    # yellow
    "ERROR":    "\033[31m",    # red
    "CRITICAL": "\033[35m",    # magenta
    "RESET":    "\033[0m",
}

_CONFIGURED = False   # guard against double-init


# ---------------------------------------------------------------------------
# JSON Formatter (for file output)
# ---------------------------------------------------------------------------

class JSONFormatter(logging.Formatter):
    """
    Emits one JSON object per log line.
    Downstream tools (Splunk, ELK, Loki) can ingest these directly.
    """

    def format(self, record: logging.LogRecord) -> str:
        doc: dict[str, Any] = {
            "ts":      time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level":   record.levelname,
            "logger":  record.name,
            "msg":     record.getMessage(),
            "module":  record.module,
            "line":    record.lineno,
        }
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Coloured Console Formatter
# ---------------------------------------------------------------------------

class ColourFormatter(logging.Formatter):
    """Human-readable, coloured console output."""

    FMT = "{colour}[{level:<8}]{reset} {asctime} | {name:<30} | {message}"

    def format(self, record: logging.LogRecord) -> str:
        colour = _COLOURS.get(record.levelname, "")
        reset  = _COLOURS["RESET"]
        record.asctime = self.formatTime(record, "%H:%M:%S")
        line = self.FMT.format(
            colour  = colour,
            level   = record.levelname,
            reset   = reset,
            asctime = record.asctime,
            name    = record.name[-30:],   # truncate long module names
            message = record.getMessage(),
        )
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


# ---------------------------------------------------------------------------
# Setup (called once)
# ---------------------------------------------------------------------------

def _setup_logging() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(getattr(logging, DEFAULT_LEVEL, logging.INFO))

    # --- Console handler ---
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(getattr(logging, DEFAULT_LEVEL, logging.INFO))
    console.setFormatter(ColourFormatter())
    root.addHandler(console)

    # --- Rotating JSON file handler ---
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes    = MAX_BYTES,
        backupCount = BACKUP_COUNT,
        encoding    = "utf-8",
    )
    file_handler.setLevel(logging.DEBUG)   # always debug-level to file
    file_handler.setFormatter(JSONFormatter())
    root.addHandler(file_handler)

    # Silence noisy third-party loggers
    for noisy in ("urllib3", "asyncio", "aiohttp", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Public Factory
# ---------------------------------------------------------------------------

def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger. Configures the root logger on first call.

    Args:
        name: Typically __name__ from the calling module.

    Returns:
        logging.Logger instance.
    """
    _setup_logging()
    return logging.getLogger(name)


def set_level(level: str) -> None:
    """Change the log level at runtime (e.g., 'DEBUG', 'WARNING')."""
    numeric = getattr(logging, level.upper(), None)
    if numeric is None:
        raise ValueError(f"Unknown log level: {level!r}")
    logging.getLogger().setLevel(numeric)
    # Update all existing handlers
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(
            handler, logging.FileHandler
        ):
            handler.setLevel(numeric)