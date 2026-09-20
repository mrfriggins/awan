"""Central configuration for the EVE Offensive Execution Engine.

All values are read from the environment with safe, offline-first defaults so
the engine runs with zero external services (no Postgres/Redis required) for
development and testing, while remaining production-configurable.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class ExecutionLimits:
    """Hard bounds that keep the autonomous loop finite. Never optional."""

    max_steps: int = 64
    max_retries_per_step: int = 2
    max_duration_seconds: int = 900
    max_adaptations: int = 8
    step_timeout_seconds: int = 30
    authz_recheck_interval_seconds: int = 30


@dataclass(frozen=True)
class Settings:
    database_url: str = field(
        default_factory=lambda: os.environ.get("EVE_DATABASE_URL", "sqlite:///./eve.db")
    )
    redis_url: Optional[str] = field(
        default_factory=lambda: os.environ.get("EVE_REDIS_URL") or None
    )
    sentinel_fail_closed: bool = field(
        default_factory=lambda: _bool("EVE_SENTINEL_FAIL_CLOSED", True)
    )
    autorun: bool = field(default_factory=lambda: _bool("EVE_AUTORUN", True))
    limits: ExecutionLimits = field(default_factory=ExecutionLimits)
    log_level: str = field(default_factory=lambda: os.environ.get("EVE_LOG_LEVEL", "INFO"))

    @staticmethod
    def load() -> "Settings":
        return Settings(
            limits=ExecutionLimits(
                max_steps=_int("EVE_MAX_STEPS", 64),
                max_retries_per_step=_int("EVE_MAX_RETRIES", 2),
                max_duration_seconds=_int("EVE_MAX_DURATION_SECONDS", 900),
                max_adaptations=_int("EVE_MAX_ADAPTATIONS", 8),
                step_timeout_seconds=_int("EVE_STEP_TIMEOUT_SECONDS", 30),
                authz_recheck_interval_seconds=_int("EVE_AUTHZ_RECHECK_SECONDS", 30),
            )
        )
