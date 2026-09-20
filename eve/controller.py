"""EVE Execution Controller — orchestrates the full UNDERSTAND->...->REPORT loop.

This is the single coordinator that ties together the goal interpreter, planner,
scope/authorization gateway, MIRA sentinel, approval manager, scheduler, tool
registry/adapters, result analyzer, adaptive planner, verification, evidence,
audit, and reporting. Every side effect passes through a deterministic guard:
authorization and the sentinel are consulted before each step, and the loop is
strictly bounded (steps, retries, duration, adaptations).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .analysis.analyzer import ResultAnalyzer
from .analysis.verify import VerificationEngine
from .audit.audit import AuditSystem
from .authz.actors import ActorStore
from .authz.approvals import ApprovalManager
from .authz.gateway import AuthorizationGateway
from .authz.scope import ScopeValidator
from .clock import Clock, SystemClock
from .config import Settings
from .domain.enums import (Confidence, EventType, OperationState, StepState,
                           can_transition)
from .domain.models import OperationSnapshot, Plan, PlannedStep
from .errors import (ApprovalError, StateTransitionError, UnknownToolError,
                     ValidationError)
from .events.bus import EventBus
from .evidence.manager import EvidenceManager
from .execution.scheduler import ExecutionScheduler
from .ids import operation_id as new_op_id, request_id as new_req_id
from .persistence.repository import Repository
from .planning.adaptive import AdaptivePlanner
from .planning.interpreter import GoalInterpreter, OperationIntent
from .planning.planner import OperationPlanner
from .reporting.reporter import ReportingEngine
from .sentinel.mira import EmergencyStop, MiraSentinel, SentinelContext
from .tools.registry import ToolRegistry


@dataclass
class _Runtime:
    snap: OperationSnapshot
    intent: OperationIntent
    evidence: EvidenceManager
    analyzer: ResultAnalyzer
    require_approval: bool
    executed: int = 0
    start_monotonic: float = 0.0
    lock: threading.RLock = field(default_factory=threading.RLock)


_TERMINAL = {OperationState.SUCCEEDED, OperationState.FAILED,
             OperationState.CANCELLED, OperationState.STOPPED}


class EveExecutionController:
    def __init__(self, *, settings: Settings, repo: Repository,
                 registry: ToolRegistry, bus: EventBus, sentinel: MiraSentinel,
                 emergency_stop: EmergencyStop, actors: ActorStore,
                 clock: Clock | None = None) -> None:
        self.settings = settings
        self.repo = repo
        self.registry = registry
        self.bus = bus
        self.sentinel = sentinel
        self.emergency_stop = emergency_stop
        self.actors = actors
        self.clock = clock or SystemClock()
        self.scope = ScopeValidator(repo, self.clock)
        self.gateway = AuthorizationGateway(self.scope)
        self.approvals = ApprovalManager(repo, self.clock)
        self.interpreter = GoalInterpreter()
        self.planner = OperationPlanner(registry, settings.limits.max_retries_per_step)
        self.adaptive = AdaptivePlanner()
        self.verifier = VerificationEngine()
        self.reporter = ReportingEngine(self.clock)
        self.audit = AuditSystem(repo, bus)
        self.scheduler = ExecutionScheduler()
        self._runtime: Dict[str, _Runtime] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ API
    def create_operation(self, *, actor: str, goal: str, targets: List[str],
                         phases: Optional[List[str]] = None,
                         require_approval: bool = False,
                         request_id: Optional[str] = None) -> OperationSnapshot:
        rid = request_id or new_req_id()
        intent = self.interpreter.interpret(goal, targets, phases)
        now = self.clock.now()
        snap = OperationSnapshot(
            id=new_op_id(), request_id=rid, goal=goal, actor=actor,
            state=OperationState.CREATED, targets=list(targets),
            current_step=None, plan=Plan(), created_at=now, updated_at=now)
        ev = EvidenceManager(self.clock)
        rt = _Runtime(snap=snap, intent=intent, evidence=ev,
                      analyzer=ResultAnalyzer(ev, self.clock),
                      require_approval=require_approval)
        with self._lock:
            self._runtime[snap.id] = rt

        self.audit.record(snap.id, EventType.OPERATION_CREATED,
                          f"operation created for goal: {goal}",
                          {"actor": actor, "targets": targets,
                           "phases": [p.value for p in intent.phases]})
        self._to(rt, OperationState.VALIDATING)

        decision = self.gateway.authorize_operation(
            actor, targets, [p.value for p in intent.phases])
        snap.authorization_ok = decision.allowed
        self.audit.record(snap.id, EventType.AUTHORIZATION_DECISION,
                          f"operation authorization: {decision.reason}",
                          {"allowed": decision.allowed})
        if not decision.allowed:
            self._fail(rt, f"unauthorized: {decision.reason}")
            return snap

        try:
            plan = self.planner.build(intent)
            self.planner.validate(plan)
        except (ValidationError, UnknownToolError) as exc:
            self._fail(rt, f"plan validation failed: {exc}")
            return snap
        snap.plan = plan
        self.audit.record(snap.id, EventType.PLAN_GENERATED,
                          f"generated {len(plan.steps)} step(s)",
                          {"steps": len(plan.steps)})

        if require_approval:
            self._to(rt, OperationState.AWAITING_APPROVAL)
        else:
            snap.approval_ok = True
            self._to(rt, OperationState.QUEUED)
        self._persist(rt)
        return snap

    def approve(self, operation_id: str, approver: str) -> OperationSnapshot:
        rt = self._require(operation_id)
        snap = rt.snap
        if snap.state != OperationState.AWAITING_APPROVAL:
            raise ApprovalError(
                f"operation not awaiting approval (state={snap.state.value})")
        for target in snap.targets:
            actions = _actions_for_target(snap.plan, target)
            self.approvals.grant(
                request_id=f"{snap.request_id}:{target}", operation_id=snap.id,
                actor=snap.actor, approver=approver, target=target,
                allowed_actions=actions)
            self.audit.record(snap.id, EventType.APPROVAL_GRANTED,
                              f"approval granted for {target} by {approver}",
                              {"approver": approver, "target": target})
        snap.approval_ok = True
        self._to(rt, OperationState.QUEUED)
        self._persist(rt)
        return snap

    def pause(self, operation_id: str) -> OperationSnapshot:
        rt = self._require(operation_id)
        with rt.lock:
            if rt.snap.state in (OperationState.RUNNING, OperationState.QUEUED):
                self._to(rt, OperationState.PAUSED)
                self.audit.record(rt.snap.id, EventType.PAUSED, "operation paused")
                self._persist(rt)
        return rt.snap

    def resume(self, operation_id: str) -> OperationSnapshot:
        rt = self._require(operation_id)
        with rt.lock:
            if rt.snap.state == OperationState.PAUSED:
                self._to(rt, OperationState.RUNNING)
                self.audit.record(rt.snap.id, EventType.RESUMED, "operation resumed")
                self._persist(rt)
        return rt.snap

    def cancel(self, operation_id: str) -> OperationSnapshot:
        rt = self._require(operation_id)
        with rt.lock:
            if rt.snap.state not in _TERMINAL:
                self._to(rt, OperationState.CANCELLED, force=True)
                rt.snap.finished_at = self.clock.now()
                self.audit.record(rt.snap.id, EventType.CANCELLED,
                                  "operation cancelled")
                self._persist(rt)
        return rt.snap

    def emergency_stop_all(self, reason: str, by: str = "operator") -> None:
        self.emergency_stop.engage(reason, by)
        with self._lock:
            runtimes = list(self._runtime.values())
        for rt in runtimes:
            with rt.lock:
                if rt.snap.state not in _TERMINAL:
                    self._to(rt, OperationState.STOPPED, force=True)
                    rt.snap.finished_at = self.clock.now()
                    rt.snap.errors.append(f"emergency stop: {reason}")
                    self.audit.record(rt.snap.id, EventType.EMERGENCY_STOP,
                                      f"emergency stop engaged: {reason}",
                                      {"by": by})
                    self._persist(rt)

    def reset_emergency_stop(self, by: str = "operator") -> None:
        self.emergency_stop.reset(by)

    # --------------------------------------------------------------- running
    def step(self, operation_id: str) -> OperationSnapshot:
        rt = self._require(operation_id)
        with rt.lock:
            if rt.snap.state == OperationState.QUEUED:
                self._to(rt, OperationState.RUNNING)
                rt.start_monotonic = time.monotonic()
            if rt.snap.state != OperationState.RUNNING:
                return rt.snap
            if not self._preflight(rt):
                return rt.snap
            nxt = self.scheduler.next_step(rt.snap.plan)
            if nxt is None:
                self._finalize(rt)
                return rt.snap
            self._execute_step(rt, nxt)
            if (self.scheduler.next_step(rt.snap.plan) is None
                    and rt.snap.state == OperationState.RUNNING):
                self._finalize(rt)
        return rt.snap

    def run_to_completion(self, operation_id: str) -> OperationSnapshot:
        rt = self._require(operation_id)
        with rt.lock:
            if rt.snap.state == OperationState.QUEUED:
                self._to(rt, OperationState.RUNNING)
                rt.start_monotonic = time.monotonic()
            if rt.snap.state != OperationState.RUNNING:
                return rt.snap
            limits = self.settings.limits
            while True:
                if not self._preflight(rt):
                    break
                if rt.executed >= limits.max_steps:
                    self._fail(rt, "execution budget exceeded: max steps")
                    break
                if (time.monotonic() - rt.start_monotonic) > limits.max_duration_seconds:
                    self._fail(rt, "execution budget exceeded: max duration")
                    break
                nxt = self.scheduler.next_step(rt.snap.plan)
                if nxt is None:
                    self._finalize(rt)
                    break
                self._execute_step(rt, nxt)
                if rt.snap.state != OperationState.RUNNING:
                    break
        return rt.snap

    # ------------------------------------------------------------- internals
    def _preflight(self, rt: _Runtime) -> bool:
        snap = rt.snap
        if self.emergency_stop.is_engaged():
            self._to(rt, OperationState.STOPPED, force=True)
            snap.finished_at = self.clock.now()
            snap.errors.append(f"emergency stop: {self.emergency_stop.reason}")
            self.audit.record(snap.id, EventType.EMERGENCY_STOP,
                              "emergency stop halted operation")
            self._persist(rt)
            return False
        if snap.state == OperationState.PAUSED or snap.state in _TERMINAL:
            return False
        if rt.require_approval and not snap.approval_ok:
            self._to(rt, OperationState.AWAITING_APPROVAL)
            self._persist(rt)
            return False
        return True

    def _execute_step(self, rt: _Runtime, step: PlannedStep) -> None:
        snap = rt.snap
        snap.current_step = step.id
        step.attempts += 1
        step.state = StepState.RUNNING
        self.audit.record(snap.id, EventType.TOOL_SELECTED,
                          f"selected {step.tool_id}.{step.action} on {step.target}",
                          {"step": step.id, "tool": step.tool_id,
                           "action": step.action, "phase": step.phase.value})
        self.audit.record(snap.id, EventType.STEP_STARTED,
                          f"step {step.id} started (attempt {step.attempts})",
                          {"step": step.id})

        decision = self.gateway.authorize_step(
            snap.actor, step.target, step.action, step.phase.value)
        self.audit.record(snap.id, EventType.AUTHORIZATION_DECISION,
                          f"step authorization: {decision.reason}",
                          {"step": step.id, "allowed": decision.allowed})
        if not decision.allowed:
            snap.authorization_ok = False
            step.state = StepState.FAILED
            step.error = f"authorization denied: {decision.reason}"
            self._fail(rt, step.error)
            return

        if rt.require_approval:
            try:
                self.approvals.verify(
                    request_id=f"{snap.request_id}:{step.target}",
                    operation_id=snap.id, actor=snap.actor, target=step.target,
                    action=step.action)
            except ApprovalError as exc:
                step.state = StepState.FAILED
                step.error = f"approval invalid: {exc}"
                self._fail(rt, step.error)
                return

        caps = self.registry.capabilities_for(step.tool_id)
        verdict = self.sentinel.evaluate(SentinelContext(
            operation_id=snap.id, actor=snap.actor, target=step.target,
            action=step.action, phase=step.phase.value, capabilities=caps,
            destructive=bool(step.params.get("_destructive"))))
        snap.sentinel_ok = verdict.allowed
        self.audit.record(snap.id, EventType.SENTINEL_DECISION,
                          f"sentinel: {verdict.reason}",
                          {"step": step.id, "allowed": verdict.allowed,
                           "available": verdict.available})
        if not verdict.allowed:
            step.state = StepState.FAILED
            step.error = f"sentinel denied: {verdict.reason}"
            if not verdict.available:
                self._fail(rt, f"sentinel unavailable (fail-closed): {verdict.reason}")
            elif self.emergency_stop.is_engaged():
                self._to(rt, OperationState.STOPPED, force=True)
                snap.finished_at = self.clock.now()
                self._persist(rt)
            else:
                self._fail(rt, step.error)
            return

        if not self.registry.is_available(step.tool_id):
            step.state = StepState.FAILED
            step.error = "tool unavailable"
            self._maybe_retry_or_fail(rt, step)
            return

        params = dict(step.params)
        if step.action == "vuln_analysis":
            params["_evidence"] = [e.model_dump() for e in
                                   rt.evidence.for_target(step.target)]
        if step.action == "validate_finding":
            params["findings"] = [f.model_dump() for f in snap.findings
                                  if f.target == step.target
                                  and f.confidence in (Confidence.UNVERIFIED,
                                                       Confidence.LOW,
                                                       Confidence.MEDIUM,
                                                       Confidence.HIGH)]
        adapter = self.registry.get_adapter(step.tool_id)
        t0 = time.monotonic()
        try:
            raw = adapter.execute(step.action, step.target, params)
        except Exception as exc:
            step.error = f"adapter error: {exc}"
            step.state = StepState.FAILED
            self.audit.record(snap.id, EventType.STEP_FAILED,
                              f"step {step.id} adapter crashed: {exc}",
                              {"step": step.id})
            self._maybe_retry_or_fail(rt, step)
            return
        duration_ms = int((time.monotonic() - t0) * 1000)

        result, evidence_list, findings = rt.analyzer.analyze(step, raw)
        result.duration_ms = duration_ms
        self.repo.save_result(snap.id, result)
        for ev in evidence_list:
            self.repo.save_evidence(snap.id, ev)
            self.audit.record(snap.id, EventType.EVIDENCE_STORED,
                              f"evidence {ev.kind}: {ev.summary}",
                              {"evidence_id": ev.id, "sha256": ev.sha256})

        if not raw.ok:
            step.error = raw.error or "tool reported failure"
            step.state = StepState.FAILED
            self.audit.record(snap.id, EventType.STEP_FAILED,
                              f"step {step.id} failed: {step.error}",
                              {"step": step.id})
            self._maybe_retry_or_fail(rt, step)
            return

        if step.action == "validate_finding":
            verdicts = raw.output.get("verdicts", {})
            self.verifier.apply_validation(snap.findings, verdicts)
            for fid, v in verdicts.items():
                self.audit.record(snap.id, EventType.RESULT_VALIDATED,
                                  f"finding {fid}: {v}",
                                  {"finding_id": fid, "verdict": v})
        else:
            for f in findings:
                snap.findings.append(f)
                self.audit.record(snap.id, EventType.FINDING_RECORDED,
                                  f"finding: {f.title} ({f.severity.value}, "
                                  f"{f.confidence.value})",
                                  {"finding_id": f.id, "target": f.target})

        step.result_id = result.id
        step.state = StepState.SUCCEEDED
        self.audit.record(snap.id, EventType.STEP_COMPLETED,
                          f"step {step.id} completed",
                          {"step": step.id, "unexpected": raw.unexpected})

        if raw.unexpected and snap.adaptations < self.settings.limits.max_adaptations:
            adaptation = self.adaptive.revise(snap.plan, step, result, rt.intent)
            valid_new: List[PlannedStep] = []
            for ns in adaptation.new_steps:
                d = self.gateway.authorize_step(snap.actor, ns.target, ns.action,
                                                ns.phase.value)
                try:
                    self.registry.validate_action(ns.tool_id, ns.action)
                except UnknownToolError:
                    continue
                if d.allowed and ns.target in rt.intent.targets:
                    valid_new.append(ns)
            if valid_new:
                snap.plan.steps.extend(valid_new)
                snap.plan.revision += 1
                snap.adaptations += 1
                self.audit.record(snap.id, EventType.ADAPTATION,
                                  adaptation.rationale,
                                  {"added": [s.id for s in valid_new],
                                   "revision": snap.plan.revision})

        rt.executed += 1
        self._persist(rt)

    def _maybe_retry_or_fail(self, rt: _Runtime, step: PlannedStep) -> None:
        if step.attempts <= step.max_retries:
            step.state = StepState.PENDING
            self.audit.record(rt.snap.id, EventType.STEP_RETRY,
                              f"retrying step {step.id} "
                              f"({step.attempts}/{step.max_retries})",
                              {"step": step.id})
            self._persist(rt)
        else:
            step.state = StepState.FAILED
            rt.snap.errors.append(f"step {step.id} failed: {step.error}")
            self.audit.record(rt.snap.id, EventType.STEP_FAILED,
                              f"step {step.id} exhausted retries",
                              {"step": step.id})
            self._skip_blocked(rt)
            self._persist(rt)

    def _skip_blocked(self, rt: _Runtime) -> None:
        failed = {s.id for s in rt.snap.plan.steps if s.state == StepState.FAILED}
        changed = True
        while changed:
            changed = False
            for s in rt.snap.plan.steps:
                if s.state == StepState.PENDING and \
                        any(d in failed for d in s.depends_on):
                    s.state = StepState.SKIPPED
                    failed.add(s.id)
                    changed = True

    def _finalize(self, rt: _Runtime) -> None:
        snap = rt.snap
        if snap.state != OperationState.RUNNING:
            return
        self._to(rt, OperationState.COMPLETING)
        any_failed = any(s.state == StepState.FAILED for s in snap.plan.steps)
        outcome = "completed_with_failures" if any_failed else "completed"
        report = self.reporter.build(
            operation_id=snap.id, goal=snap.goal, targets=snap.targets,
            plan=snap.plan, findings=snap.findings, adaptations=snap.adaptations,
            outcome=outcome)
        snap.report = report
        snap.current_step = None
        snap.finished_at = self.clock.now()
        self.audit.record(snap.id, EventType.REPORT_GENERATED,
                          "final report generated",
                          {"findings": len(report.findings), "outcome": outcome})
        self._to(rt, OperationState.SUCCEEDED)
        self.audit.record(snap.id, EventType.OPERATION_FINISHED,
                          f"operation finished: {outcome}")
        self._persist(rt)

    def _to(self, rt: _Runtime, state: OperationState, force: bool = False) -> None:
        snap = rt.snap
        if snap.state == state:
            return
        if not force and not can_transition(snap.state, state):
            raise StateTransitionError(
                f"illegal transition {snap.state.value} -> {state.value}")
        old = snap.state
        snap.state = state
        snap.updated_at = self.clock.now()
        if state == OperationState.RUNNING and snap.started_at is None:
            snap.started_at = self.clock.now()
        self.audit.record(snap.id, EventType.STATE_CHANGED,
                          f"{old.value} -> {state.value}",
                          {"from": old.value, "to": state.value})

    def _fail(self, rt: _Runtime, reason: str) -> None:
        snap = rt.snap
        snap.errors.append(reason)
        if snap.state not in _TERMINAL:
            self._to(rt, OperationState.FAILED, force=True)
        snap.finished_at = self.clock.now()
        self.audit.record(snap.id, EventType.ERROR, reason)
        self.audit.record(snap.id, EventType.OPERATION_FINISHED, "operation failed")
        self._persist(rt)

    def _persist(self, rt: _Runtime) -> None:
        rt.snap.updated_at = self.clock.now()
        self.repo.save_operation(rt.snap)

    def _require(self, operation_id: str) -> _Runtime:
        with self._lock:
            rt = self._runtime.get(operation_id)
        if rt is None:
            snap = self.repo.load_operation(operation_id)
            if snap is None:
                raise KeyError(f"unknown operation '{operation_id}'")
            ev = EvidenceManager(self.clock)
            rt = _Runtime(snap=snap,
                          intent=OperationIntent(snap.goal, snap.targets),
                          evidence=ev, analyzer=ResultAnalyzer(ev, self.clock),
                          require_approval=not snap.approval_ok)
            with self._lock:
                self._runtime[operation_id] = rt
        return rt

    def get_snapshot(self, operation_id: str) -> OperationSnapshot:
        return self._require(operation_id).snap

    def list_snapshots(self) -> List[OperationSnapshot]:
        return self.repo.list_operations()


def _actions_for_target(plan: Plan, target: str) -> List[str]:
    return sorted({s.action for s in plan.steps if s.target == target})
