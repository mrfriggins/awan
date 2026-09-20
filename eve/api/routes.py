"""HTTP routes for the EVE Offensive Execution Engine."""
from __future__ import annotations

import json
import threading

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse

from ..authz.actors import Actor
from ..errors import ApprovalError, EveError
from .deps import current_actor, get_engine, require_role
from .schemas import (ApproveRequest, CreateOperationRequest,
                      EmergencyStopRequest, GrantAuthorizationRequest,
                      MessageResponse)

router = APIRouter(prefix="/api")


def _run_async(engine, operation_id: str) -> None:
    t = threading.Thread(target=engine.controller.run_to_completion,
                         args=(operation_id,), daemon=True)
    t.start()


@router.get("/tools")
def list_tools(engine=Depends(get_engine), actor: Actor = Depends(current_actor)):
    return {"tools": [s.to_dict() for s in engine.registry.list_specs()]}


@router.post("/authorizations", response_model=MessageResponse)
def grant_authorization(body: GrantAuthorizationRequest,
                        engine=Depends(get_engine),
                        actor: Actor = Depends(require_role("operator", "admin"))):
    authz_id = engine.authorize_target(
        actor=body.actor, target=body.target,
        allowed_actions=body.allowed_actions, allowed_phases=body.allowed_phases,
        ttl_seconds=body.ttl_seconds)
    return MessageResponse(message=authz_id)


@router.get("/authorizations")
def list_authorizations(engine=Depends(get_engine),
                        actor: Actor = Depends(current_actor)):
    rows = engine.repo.list_authorizations(actor.id)
    return {"targets": engine.controller.scope.authorized_targets(actor.id),
            "grants": [{"target": r.target, "allowed_actions": r.allowed_actions,
                        "allowed_phases": r.allowed_phases,
                        "expires_at": r.expires_at.isoformat(),
                        "revoked": r.revoked} for r in rows]}


@router.post("/operations", status_code=status.HTTP_201_CREATED)
def create_operation(body: CreateOperationRequest, engine=Depends(get_engine),
                     actor: Actor = Depends(require_role("operator", "admin"))):
    try:
        snap = engine.controller.create_operation(
            actor=actor.id, goal=body.goal, targets=body.targets,
            phases=body.phases, require_approval=body.require_approval,
            mode=body.mode)
    except (EveError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if engine.settings.autorun and snap.state.value == "QUEUED":
        _run_async(engine, snap.id)
    return snap.model_dump(mode="json")


@router.get("/operations")
def list_operations(engine=Depends(get_engine),
                    actor: Actor = Depends(current_actor)):
    return {"operations": [s.model_dump(mode="json")
                           for s in engine.controller.list_snapshots()]}


@router.get("/operations/{operation_id}")
def get_operation(operation_id: str, engine=Depends(get_engine),
                  actor: Actor = Depends(current_actor)):
    try:
        return engine.controller.get_snapshot(operation_id).model_dump(mode="json")
    except KeyError:
        raise HTTPException(status_code=404, detail="operation not found")


@router.post("/operations/{operation_id}/run")
def run_operation(operation_id: str, engine=Depends(get_engine),
                  actor: Actor = Depends(require_role("operator", "admin"))):
    try:
        snap = engine.controller.run_to_completion(operation_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="operation not found")
    return snap.model_dump(mode="json")


@router.post("/operations/{operation_id}/pause")
def pause_operation(operation_id: str, engine=Depends(get_engine),
                    actor: Actor = Depends(require_role("operator", "admin"))):
    try:
        return engine.controller.pause(operation_id).model_dump(mode="json")
    except KeyError:
        raise HTTPException(status_code=404, detail="operation not found")


@router.post("/operations/{operation_id}/resume")
def resume_operation(operation_id: str, engine=Depends(get_engine),
                     actor: Actor = Depends(require_role("operator", "admin"))):
    try:
        snap = engine.controller.resume(operation_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="operation not found")
    if engine.settings.autorun and snap.state.value == "RUNNING":
        _run_async(engine, snap.id)
    return snap.model_dump(mode="json")


@router.post("/operations/{operation_id}/cancel")
def cancel_operation(operation_id: str, engine=Depends(get_engine),
                     actor: Actor = Depends(require_role("operator", "admin"))):
    try:
        return engine.controller.cancel(operation_id).model_dump(mode="json")
    except KeyError:
        raise HTTPException(status_code=404, detail="operation not found")


@router.post("/operations/{operation_id}/approve")
def approve_operation(operation_id: str, body: ApproveRequest | None = None,
                      engine=Depends(get_engine),
                      actor: Actor = Depends(require_role("approver", "admin"))):
    try:
        snap = engine.controller.approve(operation_id, approver=actor.id)
    except KeyError:
        raise HTTPException(status_code=404, detail="operation not found")
    except ApprovalError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if engine.settings.autorun and snap.state.value == "QUEUED":
        _run_async(engine, snap.id)
    return snap.model_dump(mode="json")


@router.get("/operations/{operation_id}/events")
def get_events(operation_id: str, engine=Depends(get_engine),
               actor: Actor = Depends(current_actor)):
    rows = engine.repo.list_events(operation_id)
    return {"events": [{"seq": r.seq, "type": r.type, "message": r.message,
                        "data": r.data, "hash": r.hash,
                        "created_at": r.created_at.isoformat()} for r in rows]}


@router.get("/operations/{operation_id}/events/stream")
def stream_events(operation_id: str, token: str | None = None,
                  engine=Depends(get_engine)):
    if engine.actors.resolve(token) is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="invalid token")
    sub = engine.bus.subscribe(operation_id)

    def gen():
        try:
            for r in engine.repo.list_events(operation_id):
                yield f"data: {json.dumps({'seq': r.seq, 'type': r.type, 'message': r.message})}\n\n"
            for event in sub.stream():
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            sub.close()

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.get("/operations/{operation_id}/report")
def get_report(operation_id: str, engine=Depends(get_engine),
               actor: Actor = Depends(current_actor)):
    try:
        snap = engine.controller.get_snapshot(operation_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="operation not found")
    if snap.report is None:
        raise HTTPException(status_code=409, detail="report not yet available")
    return snap.report.model_dump(mode="json")


@router.get("/operations/{operation_id}/audit")
def verify_audit(operation_id: str, engine=Depends(get_engine),
                 actor: Actor = Depends(current_actor)):
    ok, msg = engine.controller.audit.verify_chain(operation_id)
    return {"intact": ok, "message": msg}


@router.post("/emergency-stop", response_model=MessageResponse)
def emergency_stop(body: EmergencyStopRequest, engine=Depends(get_engine),
                   actor: Actor = Depends(require_role("operator", "admin"))):
    engine.controller.emergency_stop_all(reason=body.reason, by=actor.id)
    return MessageResponse(message="emergency stop engaged")


@router.post("/emergency-stop/reset", response_model=MessageResponse)
def reset_emergency_stop(engine=Depends(get_engine),
                         actor: Actor = Depends(require_role("admin", "operator"))):
    engine.controller.reset_emergency_stop(by=actor.id)
    return MessageResponse(message="emergency stop reset")


@router.get("/status")
def engine_status(engine=Depends(get_engine),
                  actor: Actor = Depends(current_actor)):
    return {"emergency_stop": engine.emergency_stop.is_engaged(),
            "sentinel_available": engine.sentinel.available,
            "tools": len(engine.registry.list_specs())}
