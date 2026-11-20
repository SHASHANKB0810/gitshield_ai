"""GitShield AI Structured Logging Module.

Configures application-wide logging with automatic secret redaction.
Never exposes API keys, authorization tokens, or sensitive values.
"""

import logging
import re
import sys
from typing import Optional
from backend.core.config import settings

# Patterns for sensitive data redaction
SENSITIVE_PATTERNS = [
    re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{8,}", re.IGNORECASE),
    re.compile(r"(api[_-]?key\s*[:=]\s*['\"]?)[A-Za-z0-9_\-\.]{8,}(['\"]?)", re.IGNORECASE),
    re.compile(r"(token\s*[:=]\s*['\"]?)[A-Za-z0-9_\-\.]{8,}(['\"]?)", re.IGNORECASE),
    re.compile(r"(password\s*[:=]\s*['\"]?)[^\s'\"]+(['\"]?)", re.IGNORECASE),
    re.compile(r"(ghp_[A-Za-z0-9]{30,})", re.IGNORECASE),
    re.compile(r"(gho_[A-Za-z0-9]{30,})", re.IGNORECASE),
]


class RedactingFormatter(logging.Formatter):
    """Custom log formatter that scrubs sensitive credentials from log records."""

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        redacted = original
        
        # Redact known configured secret strings if present
        if settings.LLM_API_KEY and len(settings.LLM_API_KEY) > 4:
            redacted = redacted.replace(settings.LLM_API_KEY, "[REDACTED_LLM_KEY]")
        if settings.GITHUB_TOKEN and len(settings.GITHUB_TOKEN) > 4:
            redacted = redacted.replace(settings.GITHUB_TOKEN, "[REDACTED_GH_TOKEN]")

        # Redact generic matching patterns
        for pattern in SENSITIVE_PATTERNS:
            redacted = pattern.sub(r"\1[REDACTED]\2" if r"\2" in pattern.pattern else r"[REDACTED]", redacted)

        return redacted


def setup_logger(name: str = "gitshield", level: Optional[str] = None) -> logging.Logger:
    """Initialize and configure a standard logger with secret scrubbing."""
    logger = logging.getLogger(name)
    log_level = level or settings.LOG_LEVEL
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = RedactingFormatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s:%(funcName)s:%(lineno)d] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False

    return logger


# Default logger instance
logger = setup_logger()
