package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// GET /ops/sessions
func handleOpsSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	active := q.Get("active") != "false"
	limit := intOr(q.Get("limit"), 50)
	offset := intOr(q.Get("offset"), 0)
	if limit > 200 {
		limit = 200
	}

	where := "1=1"
	args := []any{}
	if active {
		where += " AND expires_at > datetime('now')"
	}
	args = append(args, limit, offset)

	rows, err := store.Query(
		"SELECT id, user_id, ip_address, user_agent, created_at, expires_at FROM session WHERE "+where+" ORDER BY created_at DESC LIMIT ? OFFSET ?",
		args...,
	)
	if err != nil {
		jsonError(w, 500, "INTERNAL_ERROR", "Query failed")
		return
	}
	defer rows.Close()

	sessions := make([]map[string]any, 0)
	for rows.Next() {
		var id, ip, ua, created, expires string
		var uid int
		rows.Scan(&id, &uid, &ip, &ua, &created, &expires)
		sessions = append(sessions, map[string]any{
			"id": id, "user_id": uid, "ip_address": ip, "user_agent": ua,
			"created_at": created, "expires_at": expires,
		})
	}
	jsonOK(w, map[string]any{"sessions": sessions, "count": len(sessions)})
}

// POST /ops/sessions/revoke
func handleOpsSessionRevoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope string `json:"scope"`
		ID    any    `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, 400, "INVALID_BODY", "Invalid JSON")
		return
	}

	res, code, msg := revokeSessions(body.Scope, body.ID)
	if code != "" {
		jsonError(w, 400, code, msg)
		return
	}

	cred := getAgentCred(r)
	actor := "agent:unknown"
	if cred != nil {
		actor = "agent:" + cred.Name
	}
	emitEvent("session.ops_revoke", clientIP(r), 0, r.UserAgent(), 200, map[string]any{
		"scope": body.Scope, "revoked": res, "actor": actor,
	})
	jsonOK(w, map[string]any{"success": true, "revoked": res})
}

// GET /ops/agents
func handleOpsAgentList(w http.ResponseWriter, r *http.Request) {
	rows, err := store.Query(
		"SELECT id, name, created_at, revoked_at FROM agent_credential ORDER BY created_at DESC",
	)
	if err != nil {
		jsonError(w, 500, "INTERNAL_ERROR", "Query failed")
		return
	}
	defer rows.Close()

	agents := make([]map[string]any, 0)
	for rows.Next() {
		var id int
		var name, created string
		var revoked *string
		rows.Scan(&id, &name, &created, &revoked)
		a := map[string]any{
			"id": id, "name": name, "created_at": created,
		}
		if revoked != nil {
			a["revoked_at"] = *revoked
		}
		agents = append(agents, a)
	}
	jsonOK(w, map[string]any{"agents": agents})
}

// POST /ops/agents
func handleOpsAgentCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, 400, "INVALID_BODY", "Invalid JSON")
		return
	}
	if body.Name == "" {
		jsonError(w, 400, "VALIDATION_ERROR", "Name required")
		return
	}

	apiKey := randomHex(32) // 256-bit key
	keyHash := hashAPIKey(apiKey)

	_, err := store.Exec(
		"INSERT INTO agent_credential (name, key_hash) VALUES (?,?)",
		body.Name, keyHash,
	)
	if err != nil {
		if isUniqueViolation(err) {
			jsonError(w, 409, "AGENT_EXISTS", "Agent name already exists")
			return
		}
		jsonError(w, 500, "INTERNAL_ERROR", "Failed to create agent")
		return
	}

	emitEvent("agent.provisioned", clientIP(r), 0, r.UserAgent(), 201, map[string]any{"name": body.Name})
	jsonCreated(w, map[string]any{
		"name": body.Name, "apiKey": apiKey,
	})
}

// DELETE /ops/agents/{name}
func handleOpsAgentRevoke(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		jsonError(w, 400, "VALIDATION_ERROR", "Agent name required")
		return
	}
	res, err := store.Exec(
		"UPDATE agent_credential SET revoked_at = datetime('now') WHERE name = ? AND revoked_at IS NULL", name,
	)
	if err != nil {
		jsonError(w, 500, "INTERNAL_ERROR", "Failed to revoke agent")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		jsonError(w, 404, "NOT_FOUND", "Agent not found")
		return
	}
	emitEvent("agent.revoked", clientIP(r), 0, r.UserAgent(), 200, map[string]any{"name": name})
	jsonOK(w, map[string]any{"success": true})
}

// GET /ops/events
func handleOpsEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := intOr(q.Get("limit"), 50)
	offset := intOr(q.Get("offset"), 0)
	if limit > 200 {
		limit = 200
	}

	where := "created_at >= ?"
	args := []any{parseSince(q.Get("since"))}
	if t := q.Get("type"); t != "" {
		where += " AND type = ?"
		args = append(args, t)
	}
	if ip := q.Get("ip"); ip != "" {
		where += " AND ip_address = ?"
		args = append(args, ip)
	}
	if actor := q.Get("actor_id"); actor != "" {
		where += " AND actor_id = ?"
		args = append(args, actor)
	}
	args = append(args, limit, offset)

	rows, err := store.Query(
		"SELECT id, type, ip_address, user_id, detail, created_at, actor_id FROM security_event WHERE "+where+" ORDER BY created_at DESC LIMIT ? OFFSET ?",
		args...,
	)
	if err != nil {
		jsonError(w, 500, "INTERNAL_ERROR", "Query failed")
		return
	}
	defer rows.Close()

	events := make([]map[string]any, 0)
	for rows.Next() {
		var id int
		var typ, ip, created, actor string
		var uid *int
		var detail *string
		rows.Scan(&id, &typ, &ip, &uid, &detail, &created, &actor)
		e := map[string]any{
			"id": id, "type": typ, "ip_address": ip, "created_at": created, "actor_id": actor,
		}
		if uid != nil {
			e["user_id"] = *uid
		}
		if detail != nil {
			e["detail"] = *detail
		}
		events = append(events, e)
	}
	jsonOK(w, map[string]any{"events": events, "count": len(events)})
}

// GET /ops/events/stats
func handleOpsEventStats(w http.ResponseWriter, r *http.Request) {
	since := parseSince(r.URL.Query().Get("since"))

	rows, err := store.Query(
		"SELECT type, COUNT(*) as count FROM security_event WHERE created_at >= ? GROUP BY type", since,
	)
	if err != nil {
		jsonError(w, 500, "INTERNAL_ERROR", "Query failed")
		return
	}
	defer rows.Close()

	stats := map[string]int{}
	for rows.Next() {
		var typ string
		var count int
		rows.Scan(&typ, &count)
		stats[typ] = count
	}
	jsonOK(w, map[string]any{"since": since, "stats": stats})
}

// GET /ops/nodes
func handleOpsNodeList(w http.ResponseWriter, r *http.Request) {
	rows, err := store.Query(
		`SELECT id, label, wg_pubkey, wg_endpoint, allowed_ips,
			agent_credential_id, last_seen_at, created_at
		FROM node ORDER BY created_at DESC`,
	)
	if err != nil {
		jsonError(w, 500, "INTERNAL_ERROR", "Query failed")
		return
	}
	defer rows.Close()

	nodes := make([]map[string]any, 0)
	for rows.Next() {
		var id int
		var label, pubkey, allowedIPs, created string
		var endpoint, lastSeen *string
		var agentCredID *int
		rows.Scan(&id, &label, &pubkey, &endpoint, &allowedIPs, &agentCredID, &lastSeen, &created)
		n := map[string]any{
			"id": id, "label": label, "wg_pubkey": pubkey,
			"allowed_ips": allowedIPs, "created_at": created,
		}
		if endpoint != nil {
			n["wg_endpoint"] = *endpoint
		}
		if agentCredID != nil {
			n["agent_credential_id"] = *agentCredID
		}
		if lastSeen != nil {
			n["last_seen_at"] = *lastSeen
		}
		nodes = append(nodes, n)
	}
	jsonOK(w, map[string]any{"nodes": nodes})
}

// --- Helpers ---

func intOr(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func numericID(v any) (int, bool) {
	switch id := v.(type) {
	case float64:
		return int(id), true
	case string:
		n, err := strconv.Atoi(id)
		return n, err == nil
	}
	return 0, false
}

func parseSince(s string) string {
	if s == "" {
		return timeNow().UTC().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format("2006-01-02 15:04:05")
		}
	}
	return timeNow().UTC().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
}
