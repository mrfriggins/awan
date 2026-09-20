# EVE — Offensive Execution Engine

An autonomous, **authorized-lab** security-operations executor. EVE runs a full
assessment loop — **UNDERSTAND → PLAN → VALIDATE → AUTHORIZE → EXECUTE → OBSERVE
→ ANALYZE → ADAPT → VERIFY → REPORT** — over a registry of tools, while every
action is gated by deterministic (non-LLM) authorization and a fail-closed MIRA
Sentinel, and can be halted instantly by an out-of-model emergency stop.

> **Safety model.** This build ships **offline simulator tools only**. Adapters
> read static lab fixtures; there is **no network access, no shell, and no real
> exploitation**. The engine is designed for teaching, framework development, and
> assessment orchestration in explicitly authorized labs. Real tools can be added
> later behind the same adapter interface — and they remain subject to the same
> authorization, sentinel, approval, and emergency-stop guards, which the model
> cannot bypass or disable.

## Highlights

- **Bounded autonomous loop** — hard limits on steps, retries, duration, and
  adaptations. The model can never create an infinite loop.
- **Deterministic authorization** — a backend gateway checks actor + scope +
  expiry before every step. The LLM's claim of authorization is never trusted.
- **MIRA Sentinel** — an independent guard that denies destructive/forbidden
  capabilities and **fails closed** if it can't render a decision.
- **Emergency stop** — a global kill switch, independent of the model, that
  halts every running operation immediately.
- **Adaptive planning** — when a step returns something unexpected, EVE injects
  new steps, but only for **already-authorized targets** (scope never expands).
- **Persistent state machine** — 11 states, validated transitions, operations
  survive restarts (a STOPPED operation is never auto-restarted).
- **Hash-chained audit log** — tamper-evident event history in Postgres, with
  secret redaction on every record.
- **Structured reports** — findings tied to assets, with honest confidence
  (nothing is "confirmed" without a non-destructive validation step).
- **Operations console** — a mobile-friendly web UI with live event streaming
  and a prominent emergency-stop control.

## Quick start (zero external services)

```bash
pip install -r requirements.txt
python -m eve                       # serves on http://localhost:8000
```

Open `http://localhost:8000/` for the Operations console. The default dev tokens
are `operator-token`, `approver-token`, `viewer-token` (override in production
via `EVE_ACTORS`).

### Drive it from the API

```bash
BASE=http://localhost:8000
OP="Authorization: Bearer operator-token"

# 1. Authorize a lab target for the operator (deterministic scope grant)
curl -s -X POST $BASE/api/authorizations -H "$OP" -H 'Content-Type: application/json' \
  -d '{"actor":"operator","target":"lab-web-01"}'

# 2. Create an operation (autoruns by default)
curl -s -X POST $BASE/api/operations -H "$OP" -H 'Content-Type: application/json' \
  -d '{"goal":"run a full assessment","targets":["lab-web-01"]}'

# 3. Fetch status / report / audit
curl -s $BASE/api/operations/<op_id> -H "$OP"
curl -s $BASE/api/operations/<op_id>/report -H "$OP"
curl -s $BASE/api/operations/<op_id>/audit -H "$OP"
```

## Run with Postgres + Redis

```bash
docker compose up --build
```

This starts Postgres, Redis, and EVE. **Override `EVE_ACTORS`** with real tokens
before exposing it anywhere.

## Tests

```bash
pip install -r requirements.txt
python -m pytest            # 61 tests, no external services required
```

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — components and the loop.
- [`docs/API.md`](docs/API.md) — endpoint reference.
- [`docs/USAGE.md`](docs/USAGE.md) — workflows, configuration, extending tools.
- [`docs/SECURITY.md`](docs/SECURITY.md) — the safety model and boundaries.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `EVE_DATABASE_URL` | `sqlite:///./eve.db` | SQLAlchemy URL (Postgres-ready) |
| `EVE_REDIS_URL` | _(unset)_ | Optional cross-process event fan-out |
| `EVE_SENTINEL_FAIL_CLOSED` | `true` | Deny when the sentinel is unavailable |
| `EVE_AUTORUN` | `true` | Auto-run a queued operation in the background |
| `EVE_ACTORS` | dev tokens | `token:actor:role1\|role2,...` |
| `EVE_MAX_STEPS` | `64` | Loop bound: max steps |
| `EVE_MAX_RETRIES` | `2` | Loop bound: retries per step |
| `EVE_MAX_DURATION_SECONDS` | `900` | Loop bound: wall-clock |
| `EVE_MAX_ADAPTATIONS` | `8` | Loop bound: replans |

## License

MIT (see `LICENSE`).
