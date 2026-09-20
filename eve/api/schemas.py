"""Request/response schemas for the HTTP API."""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class CreateOperationRequest(BaseModel):
    goal: str = Field(min_length=3, max_length=2000)
    targets: List[str] = Field(min_length=1)
    phases: Optional[List[str]] = None
    require_approval: bool = False

    @field_validator("targets")
    @classmethod
    def _clean_targets(cls, v: List[str]) -> List[str]:
        cleaned = [t.strip() for t in v if t and t.strip()]
        if not cleaned:
            raise ValueError("at least one target is required")
        return cleaned


class ApproveRequest(BaseModel):
    pass


class EmergencyStopRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


class GrantAuthorizationRequest(BaseModel):
    actor: str
    target: str
    allowed_actions: List[str] = Field(default_factory=list)
    allowed_phases: List[str] = Field(default_factory=list)
    ttl_seconds: int = Field(default=3600, ge=1, le=7 * 24 * 3600)


class MessageResponse(BaseModel):
    ok: bool = True
    message: str = ""
