"""Bounded, scope-preserving adaptive replanning."""
from eve.domain.enums import OperationState, Phase


def test_adaptive_injects_in_scope_steps(authorized_engine):
    c = authorized_engine.controller
    snap = c.create_operation(actor="operator", goal="full", targets=["lab-web-01"])
    # force deep discovery so the hidden admin service surfaces (unexpected)
    disc = [s for s in snap.plan.steps if s.action == "service_discovery"][0]
    disc.params["deep"] = True
    before = len(snap.plan.steps)
    snap = c.run_to_completion(snap.id)
    assert snap.state == OperationState.SUCCEEDED
    assert snap.adaptations >= 1
    assert len(snap.plan.steps) > before
    # every injected step stays on the authorized target
    assert all(s.target == "lab-web-01" for s in snap.plan.steps)


def test_adaptation_never_adds_new_target(authorized_engine):
    c = authorized_engine.controller
    snap = c.create_operation(actor="operator", goal="full", targets=["lab-web-01"])
    disc = [s for s in snap.plan.steps if s.action == "service_discovery"][0]
    disc.params["deep"] = True
    snap = c.run_to_completion(snap.id)
    assert set(s.target for s in snap.plan.steps) == {"lab-web-01"}
