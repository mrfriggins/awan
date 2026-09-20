"""Deterministic authorization, scope, expiry, out-of-scope."""
from eve.domain.enums import OperationState


def test_authorized_operation_reaches_queued(authorized_engine):
    snap = authorized_engine.controller.create_operation(
        actor="operator", goal="full assessment", targets=["lab-web-01"])
    assert snap.state == OperationState.QUEUED
    assert snap.authorization_ok is True


def test_unauthorized_target_rejected(engine):
    snap = engine.controller.create_operation(
        actor="operator", goal="full assessment", targets=["lab-web-01"])
    assert snap.state == OperationState.FAILED
    assert snap.authorization_ok is False
    assert any("unauthorized" in e for e in snap.errors)


def test_out_of_scope_target_rejected(engine):
    engine.authorize_target(actor="operator", target="lab-web-01")
    snap = engine.controller.create_operation(
        actor="operator", goal="full", targets=["prod-crown-jewels"])
    assert snap.state == OperationState.FAILED


def test_expired_authorization_blocks_execution(engine, clock):
    engine.authorize_target(actor="operator", target="lab-web-01", ttl_seconds=60)
    snap = engine.controller.create_operation(
        actor="operator", goal="full", targets=["lab-web-01"])
    assert snap.state == OperationState.QUEUED
    clock.advance(120)
    snap = engine.controller.run_to_completion(snap.id)
    assert snap.state == OperationState.FAILED
    assert snap.authorization_ok is False


def test_action_not_permitted_by_grant(engine):
    engine.authorize_target(actor="operator", target="lab-web-01",
                            allowed_actions=["asset_inventory", "service_discovery",
                                             "tech_identification"])
    snap = engine.controller.create_operation(
        actor="operator", goal="full", targets=["lab-web-01"])
    snap = engine.controller.run_to_completion(snap.id)
    assert snap.state == OperationState.FAILED


def test_authorized_targets_listing(engine, clock):
    engine.authorize_target(actor="operator", target="lab-web-01")
    engine.authorize_target(actor="operator", target="lab-db-01", ttl_seconds=1)
    clock.advance(5)
    assert engine.controller.scope.authorized_targets("operator") == ["lab-web-01"]
