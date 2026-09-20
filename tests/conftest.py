import datetime as dt
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eve.clock import FrozenClock
from eve.config import Settings, ExecutionLimits
from eve.factory import build_engine
from eve.tools.adapter import AdapterResult, ToolAdapter
from eve.tools.registry import ToolSpec


@pytest.fixture
def clock():
    return FrozenClock(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))


@pytest.fixture
def settings(tmp_path):
    return Settings(database_url=f"sqlite:///{tmp_path}/eve.db", autorun=False,
                    redis_url=None, sentinel_fail_closed=True,
                    limits=ExecutionLimits())


@pytest.fixture
def engine(settings, clock):
    return build_engine(settings, clock=clock)


@pytest.fixture
def authorized_engine(engine):
    engine.authorize_target(actor="operator", target="lab-web-01")
    engine.authorize_target(actor="operator", target="lab-db-01")
    return engine


class FlakyAdapter(ToolAdapter):
    """Fails `fail_times` on asset_inventory then succeeds (retry tests)."""

    tool_id = "sim.recon"
    supported_actions = ["asset_inventory", "service_discovery", "tech_identification"]

    def __init__(self, fail_times=1, always_fail=False):
        self.calls = 0
        self.fail_times = fail_times
        self.always_fail = always_fail

    def execute(self, action, target, params):
        if action != "asset_inventory":
            return AdapterResult(ok=True, output={"noop": action})
        self.calls += 1
        if self.always_fail or self.calls <= self.fail_times:
            return AdapterResult(ok=False, error=f"simulated failure #{self.calls}")
        return AdapterResult(ok=True, output={"ok": True})


class CrashAdapter(ToolAdapter):
    tool_id = "sim.recon"
    supported_actions = ["asset_inventory", "service_discovery", "tech_identification"]

    def execute(self, action, target, params):
        if action == "asset_inventory":
            raise RuntimeError("boom")
        return AdapterResult(ok=True, output={})


def register_recon(engine, adapter):
    spec = ToolSpec(tool_id="sim.recon", name="Test Recon", version="1.0.0",
                    description="test", capabilities=["recon"],
                    supported_actions=["asset_inventory", "service_discovery",
                                       "tech_identification"],
                    required_permissions=["operator"], target_requirements=["host"])
    engine.registry.register(spec, adapter)
