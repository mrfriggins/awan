"""Plan generation, validation, dependency graph, cycles, dupes, unknown tools."""
import pytest

from eve.domain.enums import Phase, StepState
from eve.domain.models import Plan, PlannedStep
from eve.errors import UnknownToolError, ValidationError
from eve.planning.interpreter import GoalInterpreter
from eve.planning.planner import OperationPlanner, ready_steps, validate_plan
from eve.tools.registry import ToolRegistry
from eve.tools.simulator.adapters import register_simulator


@pytest.fixture
def registry():
    r = ToolRegistry()
    register_simulator(r)
    return r


def _step(sid, tool="sim.recon", action="asset_inventory", deps=None):
    return PlannedStep(id=sid, phase=Phase.RECONNAISSANCE, tool_id=tool,
                       action=action, target="lab-web-01", depends_on=deps or [])


def test_full_pipeline_phase_inference():
    intent = GoalInterpreter().interpret("run a full assessment", ["lab-web-01"])
    assert intent.phases[0] == Phase.RECONNAISSANCE
    assert Phase.POST_ASSESSMENT in intent.phases
    assert len(intent.phases) == 5


def test_partial_goal_infers_prerequisites():
    intent = GoalInterpreter().interpret("just do vulnerability analysis", ["h"])
    assert Phase.RECONNAISSANCE in intent.phases
    assert Phase.ENUMERATION in intent.phases


def test_interpreter_requires_target():
    with pytest.raises(ValueError):
        GoalInterpreter().interpret("recon", [])


def test_plan_generation_and_validation(registry):
    intent = GoalInterpreter().interpret("full", ["lab-web-01"])
    plan = OperationPlanner(registry).build(intent)
    OperationPlanner(registry).validate(plan)
    assert len(plan.steps) == 7
    recon = [s for s in plan.steps if s.phase == Phase.RECONNAISSANCE]
    assert all(s.depends_on == [] for s in recon)


def test_dependency_resolution_ready_steps(registry):
    intent = GoalInterpreter().interpret("full", ["lab-web-01"])
    plan = OperationPlanner(registry).build(intent)
    ready = ready_steps(plan)
    assert len(ready) == 3
    for s in ready:
        s.state = StepState.SUCCEEDED
    assert any(s.phase == Phase.ENUMERATION for s in ready_steps(plan))


def test_duplicate_step_ids_rejected(registry):
    with pytest.raises(ValidationError, match="duplicate"):
        validate_plan(Plan(steps=[_step("dup"), _step("dup")]), registry)


def test_missing_dependency_rejected(registry):
    with pytest.raises(ValidationError, match="missing"):
        validate_plan(Plan(steps=[_step("a", deps=["ghost"])]), registry)


def test_self_dependency_rejected(registry):
    with pytest.raises(ValidationError):
        validate_plan(Plan(steps=[_step("a", deps=["a"])]), registry)


def test_cycle_detection(registry):
    plan = Plan(steps=[_step("a", deps=["b"]), _step("b", deps=["a"])])
    with pytest.raises(ValidationError, match="cycle"):
        validate_plan(plan, registry)


def test_unknown_tool_rejected(registry):
    with pytest.raises(UnknownToolError):
        validate_plan(Plan(steps=[_step("a", tool="nonexistent.tool")]), registry)


def test_unknown_action_rejected(registry):
    with pytest.raises(UnknownToolError):
        validate_plan(Plan(steps=[_step("a", action="rm_rf")]), registry)


def test_unavailable_tool_rejected(registry):
    registry.set_available("sim.recon", False)
    with pytest.raises(ValidationError, match="unavailable"):
        validate_plan(Plan(steps=[_step("a")]), registry)


def test_multi_target_plan_scales(registry):
    intent = GoalInterpreter().interpret("full", ["lab-web-01", "lab-db-01"])
    plan = OperationPlanner(registry).build(intent)
    assert len(plan.steps) == 14
