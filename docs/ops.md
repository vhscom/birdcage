# Ops API and management TUI

## TUI

```sh
BIRDCAGE_CTL_ADDR=https://your-domain.example.com \
BIRDCAGE_CTL_API_KEY=<agent-key> \
birdcage ctl
```

Optionally set `BIRDCAGE_CTL_PROVISIONING_SECRET` to enable agent provisioning and revocation.

The TUI provides menu-driven access to sessions, events, agents, and nodes. Live event streaming supports type filters (e.g. `login.*,session.revoke,passkey.*`). Press `f` during event tailing to open the frame inspector.

## REST API

All endpoints require `Authorization: Bearer <agent-key>`. Agent create/delete require `X-Provisioning-Secret` instead.

```
GET    /ops/sessions              List sessions (active, limit, offset)
POST   /ops/sessions/revoke       Revoke by scope (all, user, session)
GET    /ops/agents                List agent credentials
POST   /ops/agents                Provision new agent
DELETE /ops/agents/{name}         Revoke agent
GET    /ops/events                Query security events (type, ip, since)
GET    /ops/events/stats          Event counts by type
GET    /ops/nodes                 List mesh nodes
GET    /ops/cloak                 Cloak status (active, until, remaining_sec)
POST   /ops/cloak                 Enable cloak mode; body: {"duration_min": N}
DELETE /ops/cloak                 Disable cloak mode
```

### Cloak mode

When cloak mode is active, all `/ops/*` and `/ws` endpoints return `404` to requests
from public IPs. Requests from WireGuard mesh IPs (`WG_SUBNET`) and loopback always
pass through regardless of cloak state.

Enable for 20 minutes:
```sh
curl -X POST https://your-domain.example.com/ops/cloak \
  -H "Authorization: Bearer <agent-key>" \
  -H "Content-Type: application/json" \
  -d '{"duration_min": 20}'
```

Cloak expires automatically; `DELETE /ops/cloak` cancels it early.

#### Auto-trigger (`CLOAK_ON_ATTACK`)

Cloak auto-enables when attack event counts exceed a threshold within a rolling
5-minute window. This is **on by default** — set `CLOAK_ON_ATTACK=false` to disable.

| Event type | Threshold | Env var |
|---|---|---|
| `tls.rejected` | 5 | — |
| `agent.auth_failure` | 3 | — |
| `rate_limit.reject` | 5 | — |

Auto-triggered cloak uses the same duration as manual enable (`CLOAK_DURATION_MIN`,
default 60 minutes). DB threshold checks are debounced at 30 seconds per event type
to avoid query storms during sustained attacks.

#### Environment variables

| Variable | Default | Description |
|---|---|---|
| `CLOAK_ON_ATTACK` | `true` | Auto-enable cloak on attack thresholds. Set to `false` to disable. |
| `CLOAK_DURATION_MIN` | `60` | Duration of a cloak window in minutes (max 1440). |
| `WG_SUBNET` | `10.0.0.0/24` | CIDR that always bypasses cloak. |

## WebSocket

The agent WebSocket (`/ws`) supports ops capabilities alongside mesh capabilities:

- `cloak_control` — enable and disable cloak mode (`cloak.enable`, `cloak.disable`)
- `query_events` — event query with type/ip/since filters and aggregate mode
- `query_sessions` — session query with active filter
- `revoke_session` — session revocation by scope
- `subscribe_events` — live event streaming with wildcard type filters
- `unsubscribe_events` — stop event subscription
