# Usage

## Running

- **Dev (sqlite, in-memory events):** `python -m eve`
- **ASGI:** `uvicorn eve.asgi:app --host 0.0.0.0 --port 8000`
- **Docker (Postgres + Redis):** `docker compose up --build`

## A full workflow

1. **Authorize a target** (operator/admin). Scope is deterministic and
   time-boxed:
   ```bash
   curl -X POST $BASE/api/authorizations -H "$OP" -H 'Content-Type: application/json' \
     -d '{"actor":"operator","target":"lab-web-01","ttl_seconds":3600}'
   ```
   Optionally restrict `allowed_actions` and `allowed_phases`.

2. **Create an operation.** With `EVE_AUTORUN=true` it starts immediately;
   otherwise call `/run`. Use `require_approval: true` to gate it.

3. **Watch it.** Poll `/api/operations/{id}` or subscribe to
   `/api/operations/{id}/events/stream`. The console does both.

4. **Read the report** at `/api/operations/{id}/report` and verify the audit
   chain at `/api/operations/{id}/audit`.

## Control operations

- **Pause / Resume:** `/pause`, `/resume`.
- **Cancel:** `/cancel` (terminal).
- **Emergency stop:** `/api/emergency-stop` halts *everything* now;
  `/api/emergency-stop/reset` re-enables execution. The console's red button
  does this.

## The offline lab

Fixtures live in `eve/tools/simulator/fixtures.py`:

- `lab-web-01` — Ubuntu host; ssh + nginx 1.18.0 (outdated), directory listing
  enabled (validatable → CONFIRMED), version disclosure (→ FALSE_POSITIVE), and
  a hidden staging admin panel that surfaces under deep discovery to trigger
  **adaptive replanning**.
- `lab-db-01` — Debian host; ssh + PostgreSQL 12.2 (outdated).

## Extending with a new tool

1. Subclass `ToolAdapter` (`eve/tools/adapter.py`), implement `execute` returning
   an `AdapterResult` (`ok`, `output`, `evidence`, `findings`, `unexpected`).
2. Register it with a full `ToolSpec` via `ToolRegistry.register` (see
   `eve/tools/simulator/adapters.py:register_simulator`).
3. Map it into a phase in `eve/planning/planner.py` if the planner should select
   it automatically.

Any capability listed in `FORBIDDEN_CAPABILITIES`
(`eve/sentinel/mira.py`) is denied by the sentinel regardless of registration —
this is where destructive/persistence/lateral-movement/exfil/evasion/C2/DoS
capabilities are blocked.

## Configuration

See the table in the top-level `README.md`. Production deployments **must** set
`EVE_ACTORS` to real tokens and use a Postgres `EVE_DATABASE_URL`.

## Tests

`python -m pytest` runs 61 tests with no external services (sqlite + in-memory
bus + a frozen clock). Coverage spans planning/validation, dependency
graph/cycles, tool registry, authorization/expiry/scope, approvals, sentinel
denial + outage (fail-closed), emergency stop, retries, adapter failure/crash,
loop budgets, cancellation, pause/resume, adaptive replanning, state
persistence/restart, audit integrity + tamper detection, and the HTTP API
(authn/authz + end-to-end).
