"""Structured logging with mandatory secret redaction."""
from __future__ import annotations

import logging
import re
import sys
from typing import Any

_SECRET_KEY = re.compile(
    r"(pass(word)?|secret|token|api[_-]?key|authorization|bearer|cookie|"
    r"private[_-]?key|credential|passwd|otp)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+")
_LONG_HEX = re.compile(r"\b[A-Fa-f0-9]{32,}\b")

REDACTION = "***REDACTED***"


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and _SECRET_KEY.search(k):
                out[k] = REDACTION
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, (list, tuple)):
        return type(value)(redact(v) for v in value)
    if isinstance(value, str):
        v = _BEARER.sub("bearer " + REDACTION, value)
        v = _LONG_HEX.sub(REDACTION, v)
        return v
    return value


_configured = False


def configure(level: str = "INFO") -> None:
    global _configured
    if _configured:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    root = logging.getLogger("eve")
    root.handlers = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.propagate = False
    _configured = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"eve.{name}")
