"""Execution loop: retries, adapter failure, crash, timeout bounds, lifecycle."""
from eve.config import ExecutionLimits, Settings
from eve.domain.enums import OperationState, StepState
from eve.factory import build_engine

from conftest import CrashAdapter, FlakyAdapter, register_recon


def test_retry_then_succeed(engine):
    register_recon(engine, FlakyAdapter(fail_times=1))
    engine.authorize_target(actor="operator", target="lab-web-01")
    c = engine.controller
    snap = c.create_operation(actor="operator", goal="recon only",
                              targets=["lab-web-01"], phases=["RECONNAISSANCE"])
    snap = c.run_to_completion(snap.id)
    # the flaky asset_inventory failed once then succeeded → operation completes
    assert snap.state == OperationState.SUCCEEDED
    asset = [s for s in snap.plan.steps if s.action == "asset_inventory"][0]
    assert asset.state == StepState.SUCCEEDED and asset.attempts == 2


def test_retry_limit_exhausted_fails_and_skips(engine):
    register_recon(engine, FlakyAdapter(always_fail=True))
    engine.authorize_target(actor="operator", target="lab-web-01")
    c = engine.controller
    snap = c.create_operation(actor="operator", goal="recon only",
                              targets=["lab-web-01"], phases=["RECONNAISSANCE"])
    snap = c.run_to_completion(snap.id)
    asset = [s for s in snap.plan.steps if s.action == "asset_inventory"][0]
    assert asset.state == StepState.FAILED
    assert asset.attempts == asset.max_retries + 1
    # dependents were skipped, operation completes-with-failures then SUCCEEDED
    assert snap.state == OperationState.SUCCEEDED
    assert snap.report.outcome == "completed_with_failures"


def test_adapter_crash_is_caught(engine):
    register_recon(engine, CrashAdapter())
    engine.authorize_target(actor="operator", target="lab-web-01")
    c = engine.controller
    snap = c.create_operation(actor="operator", goal="recon only",
                              targets=["lab-web-01"], phases=["RECONNAISSANCE"])
    snap = c.run_to_completion(snap.id)
    asset = [s for s in snap.plan.steps if s.action == "asset_inventory"][0]
    assert asset.state == StepState.FAILED
    assert "boom" in (asset.error or "")


def test_max_steps_budget(tmp_path, clock):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/e.db", autorun=False,
                        limits=ExecutionLimits(max_steps=2))
    eng = build_engine(settings, clock=clock)
    eng.authorize_target(actor="operator", target="lab-web-01")
    snap = eng.controller.create_operation(actor="operator", goal="full",
                                           targets=["lab-web-01"])
    snap = eng.controller.run_to_completion(snap.id)
    assert snap.state == OperationState.FAILED
    assert any("max steps" in e for e in snap.errors)


def test_max_duration_budget(tmp_path, clock):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/e.db", autorun=False,
                        limits=ExecutionLimits(max_duration_seconds=0))
    eng = build_engine(settings, clock=clock)
    eng.authorize_target(actor="operator", target="lab-web-01")
    snap = eng.controller.create_operation(actor="operator", goal="full",
                                           targets=["lab-web-01"])
    snap = eng.controller.run_to_completion(snap.id)
    assert snap.state == OperationState.FAILED
    assert any("max duration" in e for e in snap.errors)


def test_cancellation(authorized_engine):
    c = authorized_engine.controller
    snap = c.create_operation(actor="operator", goal="full", targets=["lab-web-01"])
    c.step(snap.id)
    snap = c.cancel(snap.id)
    assert snap.state == OperationState.CANCELLED
    snap = c.run_to_completion(snap.id)
    assert snap.state == OperationState.CANCELLED


def test_pause_and_resume(authorized_engine):
    c = authorized_engine.controller
    snap = c.create_operation(actor="operator", goal="full", targets=["lab-web-01"])
    c.step(snap.id)
    snap = c.pause(snap.id)
    assert snap.state == OperationState.PAUSED
    snap = c.run_to_completion(snap.id)  # paused → no progress
    assert snap.state == OperationState.PAUSED
    c.resume(snap.id)
    snap = c.run_to_completion(snap.id)
    assert snap.state == OperationState.SUCCEEDED
