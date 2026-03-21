package main

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// --- Event subscription polling ---

const (
	subFallbackInterval = 30 * time.Second // safety net if broadcast is missed
	subBackpressureAt   = 100
)

type subscriptions struct {
	mu     sync.Mutex
	active map[string]chan struct{} // key → stop channel
}

func (s *subscriptions) start(key string, stop chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.active[key]; ok {
		close(old) // stop previous
	}
	s.active[key] = stop
}

func (s *subscriptions) stop(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.active[key]; ok {
		close(ch)
		delete(s.active, key)
		return true
	}
	return false
}

func (s *subscriptions) stopAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, ch := range s.active {
		close(ch)
		delete(s.active, k)
	}
}

func handleWSQueryEvents(conn *wsConn, id string, payload json.RawMessage) {
	var p struct {
		Since     string `json:"since"`
		EventType string `json:"event_type"`
		IP        string `json:"ip"`
		Limit     int    `json:"limit"`
		Aggregate bool   `json:"aggregate"`
	}
	json.Unmarshal(payload, &p)
	if p.Limit <= 0 || p.Limit > 200 {
		p.Limit = 50
	}

	since := parseSince(p.Since)

	if p.Aggregate {
		rows, err := store.Query(
			"SELECT type, COUNT(*) FROM security_event WHERE created_at >= ? GROUP BY type", since,
		)
		if err != nil {
			sendWSError(conn, id, "QUERY_ERROR", err.Error())
			return
		}
		defer rows.Close()
		stats := map[string]int{}
		for rows.Next() {
			var t string
			var c int
			rows.Scan(&t, &c)
			stats[t] = c
		}
		sendWSResult(conn, id, "query_events", map[string]any{"stats": stats})
		return
	}

	where := "created_at >= ?"
	args := []any{since}
	if p.EventType != "" {
		where += " AND type = ?"
		args = append(args, p.EventType)
	}
	if p.IP != "" {
		where += " AND ip_address = ?"
		args = append(args, p.IP)
	}
	args = append(args, p.Limit)

	rows, err := store.Query(
		"SELECT id, type, ip_address, user_id, detail, created_at, actor_id FROM security_event WHERE "+where+" ORDER BY created_at DESC LIMIT ?",
		args...,
	)
	if err != nil {
		sendWSError(conn, id, "QUERY_ERROR", err.Error())
		return
	}
	defer rows.Close()

	events := make([]map[string]any, 0)
	for rows.Next() {
		var eid int
		var typ, ip, created, actor string
		var uid *int
		var detail *string
		rows.Scan(&eid, &typ, &ip, &uid, &detail, &created, &actor)
		e := map[string]any{"id": eid, "type": typ, "ip_address": ip, "created_at": created, "actor_id": actor}
		if uid != nil {
			e["user_id"] = *uid
		}
		if detail != nil {
			e["detail"] = *detail
		}
		events = append(events, e)
	}
	sendWSResult(conn, id, "query_events", map[string]any{"events": events})
}

func handleWSQuerySessions(conn *wsConn, id string, payload json.RawMessage) {
	var p struct {
		Active bool `json:"active"`
		Limit  int  `json:"limit"`
	}
	p.Active = true
	p.Limit = 50
	json.Unmarshal(payload, &p)
	if p.Limit > 200 {
		p.Limit = 200
	}

	where := "1=1"
	args := []any{}
	if p.Active {
		where += " AND expires_at > datetime('now')"
	}
	args = append(args, p.Limit)

	rows, err := store.Query(
		"SELECT id, user_id, ip_address, user_agent, created_at, expires_at FROM session WHERE "+where+" ORDER BY created_at DESC LIMIT ?",
		args...,
	)
	if err != nil {
		sendWSError(conn, id, "QUERY_ERROR", err.Error())
		return
	}
	defer rows.Close()

	sessions := make([]map[string]any, 0)
	for rows.Next() {
		var sid, ip, ua, created, expires string
		var uid int
		rows.Scan(&sid, &uid, &ip, &ua, &created, &expires)
		sessions = append(sessions, map[string]any{
			"id": sid, "user_id": uid, "ip_address": ip, "user_agent": ua,
			"created_at": created, "expires_at": expires,
		})
	}
	sendWSResult(conn, id, "query_sessions", map[string]any{"sessions": sessions})
}

func handleWSRevokeSession(conn *wsConn, id string, payload json.RawMessage, cred *AgentCredential, connID string) {
	var p struct {
		Scope    string `json:"scope"`
		TargetID any    `json:"target_id"`
	}
	json.Unmarshal(payload, &p)

	res, code, msg := revokeSessions(p.Scope, p.TargetID)
	if code != "" {
		sendWSError(conn, id, code, msg)
		return
	}

	emitEvent("session.ops_revoke", "", 0, "", 200, map[string]any{
		"scope": p.Scope, "revoked": res, "actor": "agent:" + cred.Name, "connectionId": connID,
	})
	sendWSResult(conn, id, "revoke_session", map[string]any{"success": true, "revoked": res})
}

func handleWSSubscribeEvents(conn *wsConn, id string, payload json.RawMessage, subs *subscriptions) {
	var p struct {
		Types []string `json:"types"`
	}
	json.Unmarshal(payload, &p)

	// Acknowledge subscription
	ack := map[string]any{
		"type": "subscribe_events.result",
		"ok":   true,
		"payload": map[string]any{
			"mode": "realtime",
		},
	}
	if id != "" {
		ack["id"] = id
	}
	b, _ := json.Marshal(ack)
	conn.safeWrite(websocket.TextMessage, b)

	stop := make(chan struct{})
	subs.start("events", stop)

	// Start subscription goroutine — wakes on broadcast or fallback ticker
	go func() {
		highWaterMark := time.Now().UTC().Format("2006-01-02 15:04:05")
		ticker := time.NewTicker(subFallbackInterval)
		defer ticker.Stop()

		for {
			sig := eventSignal()
			select {
			case <-stop:
				return
			case <-sig:
				// new event broadcast — immediate wake
			case <-ticker.C:
				// fallback poll
			}

			events := pollNewEvents(highWaterMark, p.Types)
			if len(events) == 0 {
				continue
			}

			if last, ok := events[len(events)-1]["created_at"].(string); ok {
				highWaterMark = last
			}

			for _, e := range events {
				msg := map[string]any{
					"type":    "event",
					"payload": e,
				}
				b, _ := json.Marshal(msg)
				if err := conn.safeWrite(websocket.TextMessage, b); err != nil {
					return
				}
			}

			if len(events) >= subBackpressureAt {
				bp := map[string]any{
					"type":    "subscription.backpressure",
					"payload": map[string]any{"queued": len(events)},
				}
				b, _ := json.Marshal(bp)
				conn.safeWrite(websocket.TextMessage, b)
			}
		}
	}()
}

func handleWSUnsubscribeEvents(conn *wsConn, id string, subs *subscriptions) {
	stopped := subs.stop("events")
	sendWSResult(conn, id, "unsubscribe_events", map[string]any{"unsubscribed": stopped})
}

func pollNewEvents(since string, types []string) []map[string]any {
	where := "created_at > ?"
	args := []any{since}

	if len(types) > 0 {
		clauses := make([]string, 0, len(types))
		for _, t := range types {
			if strings.Contains(t, "*") {
				// Wildcard: login.* → login.%
				clauses = append(clauses, "type LIKE ?")
				args = append(args, strings.ReplaceAll(t, "*", "%"))
			} else {
				clauses = append(clauses, "type = ?")
				args = append(args, t)
			}
		}
		where += " AND (" + strings.Join(clauses, " OR ") + ")"
	}

	rows, err := store.Query(
		"SELECT id, type, ip_address, user_id, user_agent, status, detail, created_at, actor_id FROM security_event WHERE "+where+" ORDER BY created_at ASC LIMIT 200",
		args...,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var events []map[string]any
	for rows.Next() {
		var eid, status int
		var typ, ip, created, actor string
		var uid *int
		var ua, detail *string
		rows.Scan(&eid, &typ, &ip, &uid, &ua, &status, &detail, &created, &actor)
		e := map[string]any{
			"event_id": eid, "event_type": typ, "ip_address": ip,
			"status": status, "created_at": created, "actor_id": actor,
		}
		if uid != nil {
			e["user_id"] = *uid
		}
		if ua != nil {
			e["user_agent"] = *ua
		}
		if detail != nil {
			var parsed any
			if json.Unmarshal([]byte(*detail), &parsed) == nil {
				e["detail"] = parsed
			} else {
				e["detail"] = *detail
			}
		}
		events = append(events, e)
	}
	return events
}
