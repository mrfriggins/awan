"""Tool registry & adapter behavior."""
import pytest

from eve.errors import UnknownToolError
from eve.tools.registry import ToolRegistry, ToolSpec
from eve.tools.simulator.adapters import register_simulator


@pytest.fixture
def registry():
    r = ToolRegistry()
    register_simulator(r)
    return r


def test_all_simulator_tools_registered(registry):
    ids = {s.tool_id for s in registry.list_specs()}
    assert ids == {"sim.recon", "sim.enum", "sim.vuln", "sim.validate"}


def test_specs_are_complete(registry):
    for spec in registry.list_specs():
        assert spec.name and spec.version and spec.description
        assert spec.supported_actions and spec.required_permissions
        assert spec.input_schema and spec.output_schema


def test_register_rejects_adapter_missing_action(registry):
    from eve.tools.adapter import ToolAdapter, AdapterResult

    class Bad(ToolAdapter):
        supported_actions = ["a"]
        def execute(self, action, target, params):
            return AdapterResult(ok=True)

    spec = ToolSpec(tool_id="x", name="x", version="1", description="x",
                    supported_actions=["a", "b"])
    with pytest.raises(UnknownToolError):
        registry.register(spec, Bad())


def test_validate_action_unknown_tool(registry):
    with pytest.raises(UnknownToolError):
        registry.validate_action("ghost", "x")


def test_recon_rejects_unknown_target(registry):
    res = registry.get_adapter("sim.recon").execute("asset_inventory", "evil.com", {})
    assert res.ok is False and "not in lab inventory" in res.error


def test_deep_discovery_flags_unexpected(registry):
    res = registry.get_adapter("sim.recon").execute(
        "service_discovery", "lab-web-01", {"deep": True})
    assert res.unexpected is True
    assert len(res.output["services"]) == 3
