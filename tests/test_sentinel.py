"""MIRA Sentinel: denial, outage (fail-closed), emergency stop, forbidden caps."""
from eve.domain.enums import OperationState
from eve.sentinel.mira import MiraSentinel, SentinelContext, EmergencyStop


def test_sentinel_denies_specific_target(authorized_engine):
    authorized_engine.sentinel.deny_target("lab-web-01")
    snap = authorized_engine.controller.create_operation(
        actor="operator", goal="full", targets=["lab-web-01"])
    snap = authorized_engine.controller.run_to_completion(snap.id)
    assert snap.state == OperationState.FAILED
    assert snap.sentinel_ok is False


def test_sentinel_outage_fails_closed(authorized_engine):
    authorized_engine.sentinel.set_available(False)
    snap = authorized_engine.controller.create_operation(
        actor="operator", goal="full", targets=["lab-web-01"])
    snap = authorized_engine.controller.run_to_completion(snap.id)
    assert snap.state == OperationState.FAILED
    assert any("fail-closed" in e or "unavailable" in e for e in snap.errors)


def test_sentinel_fail_open_when_configured():
    s = MiraSentinel(EmergencyStop(), fail_closed=False)
    s.set_available(False)
    v = s.evaluate(SentinelContext("op", "a", "t", "recon", "RECONNAISSANCE"))
    assert v.allowed is True and v.available is False


def test_forbidden_capability_denied():
    s = MiraSentinel(EmergencyStop())
    v = s.evaluate(SentinelContext("op", "a", "t", "x", "Y",
                                   capabilities={"lateral_movement"}))
    assert v.allowed is False


def test_destructive_action_denied():
    s = MiraSentinel(EmergencyStop())
    v = s.evaluate(SentinelContext("op", "a", "t", "x", "Y", destructive=True))
    assert v.allowed is False


def test_emergency_stop_halts_running_operation(authorized_engine):
    c = authorized_engine.controller
    snap = c.create_operation(actor="operator", goal="full", targets=["lab-web-01"])
    c.step(snap.id)
    assert c.get_snapshot(snap.id).state == OperationState.RUNNING
    c.emergency_stop_all("kill", by="operator")
    assert c.get_snapshot(snap.id).state == OperationState.STOPPED
    snap = c.run_to_completion(snap.id)
    assert snap.state == OperationState.STOPPED


def test_emergency_stop_blocks_new_execution(authorized_engine):
    c = authorized_engine.controller
    c.emergency_stop_all("halt")
    snap = c.create_operation(actor="operator", goal="full", targets=["lab-web-01"])
    snap = c.run_to_completion(snap.id)
    assert snap.state == OperationState.STOPPED


def test_emergency_stop_reset_allows_new_ops(authorized_engine):
    c = authorized_engine.controller
    c.emergency_stop_all("halt")
    c.reset_emergency_stop()
    snap = c.create_operation(actor="operator", goal="full", targets=["lab-web-01"])
    snap = c.run_to_completion(snap.id)
    assert snap.state == OperationState.SUCCEEDED
