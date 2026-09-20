"""Authentication + authorization dependencies for the API."""
from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request, status

from ..authz.actors import Actor


def get_engine(request: Request):
    engine = getattr(request.app.state, "engine", None)
    if engine is None:  # pragma: no cover
        raise HTTPException(status_code=500, detail="engine not initialized")
    return engine


def current_actor(request: Request,
                  authorization: str | None = Header(default=None)) -> Actor:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    actor = request.app.state.engine.actors.resolve(token)
    if actor is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="invalid token")
    return actor


def require_role(*roles: str):
    def _dep(actor: Actor = Depends(current_actor)) -> Actor:
        if roles and not any(actor.has_role(r) for r in roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"requires role: {', '.join(roles)}")
        return actor
    return _dep
