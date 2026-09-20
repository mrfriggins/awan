# API Reference

Base URL defaults to `http://localhost:8000`. All `/api/*` routes require a
bearer token: `Authorization: Bearer <token>`. Roles: `viewer` (read),
`operator` (create/run/control), `approver` (approve), `admin` (all).

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/healthz` | none | Liveness probe |
| GET | `/api/status` | any | Emergency-stop + sentinel + tool count |
| GET | `/api/tools` | any | Registered tool specs |
| POST | `/api/authorizations` | operator | Grant a target scope authorization |
| GET | `/api/authorizations` | any | List caller's authorized targets/grants |
| POST | `/api/operations` | operator | Create an operation (autoruns if queued) |
| GET | `/api/operations` | any | List operations |
| GET | `/api/operations/{id}` | any | Full operation snapshot |
| POST | `/api/operations/{id}/run` | operator | Run to completion (bounded) |
| POST | `/api/operations/{id}/pause` | operator | Pause a running/queued operation |
| POST | `/api/operations/{id}/resume` | operator | Resume a paused operation |
| POST | `/api/operations/{id}/cancel` | operator | Cancel (terminal) |
| POST | `/api/operations/{id}/approve` | approver | Approve a gated operation |
| GET | `/api/operations/{id}/events` | any | Persisted audit events |
| GET | `/api/operations/{id}/events/stream` | any* | SSE live event stream |
| GET | `/api/operations/{id}/report` | any | Final structured report |
| GET | `/api/operations/{id}/audit` | any | Verify the hash-chained audit log |
| POST | `/api/emergency-stop` | operator | Engage the global kill switch |
| POST | `/api/emergency-stop/reset` | operator | Reset the kill switch |

\* The SSE stream accepts the token as `?token=...` because `EventSource` cannot
send headers.

## Create operation body

```json
{
  "goal": "run a full assessment",
  "targets": ["lab-web-01"],
  "phases": ["RECONNAISSANCE", "ENUMERATION", "VULNERABILITY_ANALYSIS",
             "VALIDATION", "POST_ASSESSMENT"],
  "require_approval": false
}
```

`phases` is optional — when omitted, the goal is interpreted into a phase set.
Available lab targets in the shipped fixtures: `lab-web-01`, `lab-db-01`.

## Snapshot shape (abridged)

```json
{
  "id": "op_...", "state": "SUCCEEDED", "goal": "...", "actor": "operator",
  "targets": ["lab-web-01"], "current_step": null, "adaptations": 1,
  "authorization_ok": true, "approval_ok": true, "sentinel_ok": true,
  "plan": {"steps": [{"id":"step_...","phase":"RECONNAISSANCE","tool_id":"sim.recon",
           "action":"asset_inventory","target":"lab-web-01","state":"SUCCEEDED"}]},
  "findings": [{"title":"Outdated nginx web server","severity":"MEDIUM",
                "confidence":"CONFIRMED","target":"lab-web-01","remediation":"..."}],
  "report": {"outcome":"completed","summary":"...","findings":[...]}
}
```
