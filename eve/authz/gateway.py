"""Authorization Gateway — the single deterministic decision point."""
from __future__ import annotations

from dataclasses import dataclass

from .scope import ScopeValidator


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: str
    actor: str
    target: str
    action: str
    phase: str


class AuthorizationGateway:
    def __init__(self, scope: ScopeValidator) -> None:
        self.scope = scope

    def authorize_step(self, actor: str, target: str, action: str,
                       phase: str) -> AuthorizationDecision:
        decision = self.scope.check(actor, target, action, phase)
        return AuthorizationDecision(
            allowed=decision.allowed, reason=decision.reason, actor=actor,
            target=target, action=action, phase=phase)

    def authorize_operation(self, actor: str, targets, phases) -> AuthorizationDecision:
        for target in targets:
            for phase in phases:
                d = self.scope.check(actor, target, "*", phase)
                if not d.allowed and "action" not in d.reason:
                    return AuthorizationDecision(False, d.reason, actor, target,
                                                 "*", phase)
        return AuthorizationDecision(True, "operation targets within scope", actor,
                                     ",".join(targets), "*", ",".join(phases))
