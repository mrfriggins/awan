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

## Live (online) mode boundaries

When `EVE_ALLOW_LIVE=true`, the `net.*` adapters may contact real targets, but
only within these structural limits:

- **Read-only recon only.** GET/HEAD, headers, `robots.txt`/`security.txt`, TLS
  certificate + security-header inspection, DNS lookup. No port scanning, no
  fuzzing, no exploitation, no credential/auth attempts.
- **Authorization still required.** A live target must have an explicit,
  unexpired scope grant; the deterministic gateway checks it every step.
- **SSRF protection.** Hosts resolving to loopback/private/link-local/reserved/
  cloud-metadata addresses are refused unless `EVE_LIVE_ALLOW_PRIVATE=true`
  (for internal authorized labs). An optional `EVE_LIVE_ALLOWED_HOSTS`
  allowlist further constrains reachable hosts.
- **Bounded requests.** http/https only, GET/HEAD only, capped redirects,
  response-size cap, short timeout, no auth headers sent.
- **Sentinel unchanged.** `net.*` adapters carry no forbidden capability; adding
  any intrusive capability would be denied by the sentinel regardless.

Organization egress policies (e.g. a filtering proxy returning 403) are honored,
not bypassed: a blocked target surfaces as a failed recon step, never a retry
storm.

## Operator responsibilities

- Replace `EVE_ACTORS` dev tokens with real secrets; serve behind HTTPS.
- Grant target authorizations only for assets you are authorized to assess.
- Keep `EVE_SENTINEL_FAIL_CLOSED=true` in production.
- Adding real tools is a deliberate act: they inherit these guards, and must be
  registered with an accurate capability set so the sentinel can reason about
  them.
