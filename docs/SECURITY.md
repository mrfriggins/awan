# Security Model & Boundaries

EVE is built for **legitimate offensive-security engineering in explicitly
authorized environments** (labs and assessments). The safety properties below
are structural, not advisory.

## What this build does NOT do

The shipped tools are **offline simulators over static fixtures**. There is:

- no network access, no DNS, no arbitrary-internet targeting;
- no shell or arbitrary command execution;
- no real exploitation, credential theft, malware, persistence, lateral
  movement, command-and-control, evasion, or destructive actions.

The MIRA Sentinel denies the capability classes above unconditionally
(`FORBIDDEN_CAPABILITIES`), so even a future adapter cannot smuggle them past the
guards by registering them.

## Guards the model cannot bypass

- **Authorization is deterministic backend code.** The planner/LLM never mints
  identity or asserts authorization; the gateway checks every step against a
  stored, time-boxed scope grant.
- **The sentinel and emergency stop have no disable path.** No tool, action, API
  route, or plan step can turn them off. The sentinel fails closed.
- **Adaptive planning cannot widen scope.** Injected steps are re-authorized and
  must target an already-authorized asset; new targets are impossible.
- **The loop is bounded.** Steps, retries, duration, and adaptations all have
  hard caps, so runaway/infinite execution cannot occur.

## Auditing & data handling

- Every operation has a **hash-chained, append-only** event log; tampering is
  detectable via `/api/operations/{id}/audit`.
- All log and audit payloads pass through `redact()`, which strips
  credential/token/secret-shaped keys and values.

## Operator responsibilities

- Replace `EVE_ACTORS` dev tokens with real secrets; serve behind HTTPS.
- Grant target authorizations only for assets you are authorized to assess.
- Keep `EVE_SENTINEL_FAIL_CLOSED=true` in production.
- Adding real tools is a deliberate act: they inherit these guards, and must be
  registered with an accurate capability set so the sentinel can reason about
  them.
