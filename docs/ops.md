# Ops API and management TUI

## TUI

```sh
BIRDCAGE_CTL_ADDR=https://your-domain.example.com \
BIRDCAGE_CTL_API_KEY=<agent-key> \
birdcage ctl
```

Optionally set `BIRDCAGE_CTL_PROVISIONING_SECRET` to enable agent provisioning and revocation.

The TUI provides menu-driven access to sessions, events, agents, and nodes. Live event streaming supports type filters (e.g. `login.*,session.revoke`). Press `f` during event tailing to open the frame inspector.

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
```

## WebSocket

The agent WebSocket (`/ws`) supports ops capabilities alongside mesh capabilities:

- `query_events` — event query with type/ip/since filters and aggregate mode
- `query_sessions` — session query with active filter
- `revoke_session` — session revocation by scope
- `subscribe_events` — live event streaming with wildcard type filters
- `unsubscribe_events` — stop event subscription
