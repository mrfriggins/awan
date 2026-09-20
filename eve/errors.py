"""Typed error hierarchy. Guard failures are explicit and deterministic."""
from __future__ import annotations


class EveError(Exception):
    """Base class for all engine errors."""


class ValidationError(EveError):
    """Plan/graph/schema validation failed."""


class AuthorizationError(EveError):
    """Deterministic authorization denied the action."""


class ScopeError(AuthorizationError):
    """A target or action fell outside the approved scope."""


class ApprovalError(AuthorizationError):
    """Approval missing, expired, or bound to a different operation."""


class SentinelDenied(EveError):
    """MIRA Sentinel denied or halted the operation."""


class SentinelUnavailable(SentinelDenied):
    """Sentinel could not be consulted; fail closed."""


class EmergencyStopError(EveError):
    """Global emergency stop is engaged."""


class ToolError(EveError):
    """Tool registry / adapter failure."""


class UnknownToolError(ToolError):
    """Planner referenced a tool or action not in the registry."""


class StateTransitionError(EveError):
    """Illegal operation state transition."""


class ExecutionBudgetExceeded(EveError):
    """A bound (steps, retries, duration, adaptations) was hit."""
