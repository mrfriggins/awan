# Architecture

EVE is a modular pipeline coordinated by the **EVE Execution Controller**. Each
component has a single responsibility and a clear interface.

```
EVE EXECUTION CONTROLLER (eve/controller.py)
    ├── Goal Interpreter        eve/planning/interpreter.py
    ├── Operation Planner       eve/planning/planner.py
    ├── Scope Validator         eve/authz/scope.py
    ├── Authorization Gateway   eve/authz/gateway.py
    ├── MIRA Sentinel           eve/sentinel/mira.py
    ├── Approval Manager        eve/authz/approvals.py
    ├── Execution Scheduler     eve/execution/scheduler.py
    ├── Tool Adapter Registry   eve/tools/registry.py + eve/tools/adapter.py
    ├── Result Analyzer         eve/analysis/analyzer.py
    ├── Adaptive Planner        eve/planning/adaptive.py
    ├── Verification Engine     eve/analysis/verify.py
    ├── Evidence Manager        eve/evidence/manager.py
    ├── Audit System            eve/audit/audit.py
    └── Reporting Engine        eve/reporting/reporter.py
```

Supporting infrastructure: persistence (`eve/persistence/`), event bus
(`eve/events/`), config (`eve/config.py`), clock (`eve/clock.py`), redaction-aware
logging (`eve/logging_.py`), HTTP API (`eve/api/`), and the assembly factory
(`eve/factory.py`).

## The bounded autonomous loop

`EveExecutionController.run_to_completion` (and `.step` for single-step control):

```
while operation is RUNNING:
    preflight:  emergency-stop? paused? terminal? approval still valid?
    budget:     stop if executed >= max_steps or elapsed > max_duration
    pick:       scheduler.next_step(plan)   # dependency- and phase-ordered
    execute_step:
        authorize (gateway)          -> deny => FAIL
        approval (if required)       -> invalid => FAIL
        sentinel.evaluate(context)   -> deny => FAIL; unavailable => FAIL CLOSED;
                                        emergency stop => STOPPED
        tool available?              -> no => retry/fail
        adapter.execute(...)         -> collect result + evidence + findings
        analyze + persist + audit
        if not ok:  retry up to max_retries, else FAIL + skip blocked deps
        if unexpected: adaptive.revise() -> re-authorize each injected step,
                                            append only in-scope steps (bounded)
    if no runnable steps left: finalize -> COMPLETING -> report -> SUCCEEDED
```

Every branch emits an audit event; every state change is validated against the
transition table.

## State machine

`CREATED → VALIDATING → {AWAITING_APPROVAL | QUEUED} → RUNNING → COMPLETING →
SUCCEEDED`, with `PAUSED`, and terminal `FAILED / CANCELLED / STOPPED`.
Transitions are enforced in `eve/domain/enums.py`; terminal states never move,
and a STOPPED operation is never auto-restarted.

## Security spine (out of model control)

Three guards are pure, deterministic backend code with **no** tool/API surface
that a plan, adapter, or LLM could use to weaken them:

1. **Authorization Gateway + Scope Validator** — actor/target/action/phase must
   match an active, unexpired, non-revoked grant. Re-checked on *every* step, so
   an expiry mid-operation stops it.
2. **MIRA Sentinel** — denies destructive/forbidden capabilities and denied
   targets; **fails closed** when unavailable.
3. **Emergency Stop** — a global switch; engaging it moves every non-terminal
   operation to STOPPED and blocks new execution until an operator resets it.

## Persistence

SQLAlchemy ORM (`eve/persistence/tables.py`), one schema for SQLite and
Postgres. Tables: `operations`, `operation_steps`, `tool_registrations`,
`target_authorizations`, `approvals`, `operation_events`, `execution_results`,
`evidence`, `schema_version`. Redis (optional) is transient event fan-out only;
the authoritative audit log lives in the database.

## Data flow for a finding

recon/enum adapters → **Evidence** (content-addressed, deduped) → vuln adapter
correlates evidence into **proposed findings** (confidence `LOW`) → validate
adapter runs a non-destructive check → Verification Engine marks each
`CONFIRMED` or `FALSE_POSITIVE` → Reporting Engine emits a structured report
(false positives excluded, confirmed first).
