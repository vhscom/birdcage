package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Agent WebSocket close codes
const (
	wsNormal            = 1000
	wsHandshakeTimeout  = 4001
	wsProtocolError     = 4002
	wsRateLimited       = 4008
	wsCredentialRevoked = 4010
	wsPingTimeout       = 4011
)

const (
	wsHandshakeDeadline = 5 * time.Second
	wsHeartbeatInterval = 25 * time.Second
	wsPingDeadline      = 90 * time.Second
	wsMsgRateWindow     = 60 * time.Second
	wsMsgRateMax        = 60
	wsWriteTimeout      = 10 * time.Second
)

func checkWSOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // non-browser clients
	}
	if cfg.WSAllowedOrigins == "" {
		return false
	}
	for _, allowed := range strings.Split(cfg.WSAllowedOrigins, ",") {
		if strings.TrimSpace(allowed) == origin {
			return true
		}
	}
	return false
}

// wsConn wraps a websocket.Conn, caching the remote address for later use.
type wsConn struct {
	*websocket.Conn
	remoteAddr string
}

func (c *wsConn) safeWrite(mt websocket.MessageType, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), wsWriteTimeout)
	defer cancel()
	return c.Conn.Write(ctx, mt, data)
}

// All agents get mesh + ops capabilities.
var agentCapabilities = map[string]bool{
	"wg_sync":            true,
	"wg_status":          true,
	"endpoint_discovery": true,
	"key_rotate":         true,
	"query_events":       true,
	"query_sessions":     true,
	"subscribe_events":   true,
	"revoke_session":     true,
	"cloak_control":      true,
}

func handleAgentWS(w http.ResponseWriter, r *http.Request) {
	cred := getAgentCred(r)
	if cred == nil {
		jsonError(w, 401, "UNAUTHORIZED", "Agent key required")
		return
	}

	if !checkWSOrigin(r) {
		http.Error(w, "Origin not allowed", http.StatusForbidden)
		return
	}

	opts := &websocket.AcceptOptions{}
	if cfg.WSAllowedOrigins != "" {
		for _, o := range strings.Split(cfg.WSAllowedOrigins, ",") {
			if o = strings.TrimSpace(o); o != "" {
				opts.OriginPatterns = append(opts.OriginPatterns, o)
			}
		}
	}
	c, err := websocket.Accept(w, r, opts)
	if err != nil {
		return
	}
	conn := &wsConn{Conn: c, remoteAddr: r.RemoteAddr}
	defer conn.CloseNow()

	conn.SetReadLimit(1 << 20)
	connID := randomHex(8)

	subs := &subscriptions{active: make(map[string]chan struct{})}
	defer subs.stopAll()

	emitEvent("ws.connect", clientIP(r), 0, r.UserAgent(), 101, map[string]any{
		"connectionId": connID, "agent": cred.Name,
	})

	// Capability negotiation
	granted := negotiateCapabilities(r.Context(), conn, cred, connID)
	if granted == nil {
		return
	}

	// Register as node agent
	var nodeID int
	if granted["wg_sync"] || granted["wg_status"] {
		nodeID = lookupNodeForAgent(cred.ID)
		if nodeID > 0 {
			registerNode(&connectedNode{
				conn: conn, agentID: cred.ID, nodeID: nodeID,
			})
			defer func() {
				unregisterNode(nodeID)
				cleanupRelayBindings(nodeID)
			}()
			notifyNodeSync()
		}
	}

	// Heartbeat
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() { once.Do(func() { close(done) }) }

	go heartbeatLoop(conn, cred, connID, done, closeDone)

	// Message rate limiting
	var msgCount int
	windowStart := time.Now()

	for {
		readCtx, readCancel := context.WithTimeout(r.Context(), wsPingDeadline)
		mt, data, err := conn.Read(readCtx)
		readCancel()
		if err != nil {
			break
		}

		if mt == websocket.MessageBinary {
			if nodeID > 0 {
				handleRelayPacket(nodeID, data)
			}
			continue
		}

		now := time.Now()
		if now.Sub(windowStart) > wsMsgRateWindow {
			windowStart = now
			msgCount = 0
		}
		msgCount++
		if msgCount > wsMsgRateMax {
			closeWSAgent(conn, wsRateLimited, "Rate limited")
			break
		}

		handleAgentMessage(conn, cred, granted, data, connID, nodeID, subs)
	}

	closeDone()
	emitEvent("ws.disconnect", clientIP(r), 0, r.UserAgent(), 200, map[string]any{
		"connectionId": connID, "agent": cred.Name,
	})
}

func negotiateCapabilities(ctx context.Context, conn *wsConn, cred *AgentCredential, connID string) map[string]bool {
	// Run the read in a goroutine so the handshake deadline can close cleanly.
	// coder/websocket closes the connection when a Read context is cancelled,
	// which would prevent sending the 4001 close frame afterward.
	type readResult struct {
		data []byte
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		_, data, err := conn.Read(ctx)
		ch <- readResult{data, err}
	}()

	var data []byte
	select {
	case res := <-ch:
		if res.err != nil {
			closeWSAgent(conn, wsHandshakeTimeout, "Handshake timeout")
			return nil
		}
		data = res.data
	case <-time.After(wsHandshakeDeadline):
		closeWSAgent(conn, wsHandshakeTimeout, "Handshake timeout")
		return nil
	}

	var msg struct {
		Type         string   `json:"type"`
		Capabilities []string `json:"capabilities"`
	}
	if json.Unmarshal(data, &msg) != nil || msg.Type != "capability.request" {
		closeWSAgent(conn, wsProtocolError, "Expected capability.request")
		return nil
	}

	granted := map[string]bool{}
	denied := []map[string]string{}

	for _, cap := range msg.Capabilities {
		if agentCapabilities[cap] {
			granted[cap] = true
		} else {
			denied = append(denied, map[string]string{"capability": cap, "reason": "not_allowed"})
		}
	}

	grantedList := make([]string, 0, len(granted))
	for c := range granted {
		grantedList = append(grantedList, c)
	}

	resp := map[string]any{
		"type":          "capability.granted",
		"connection_id": connID,
		"agent":         cred.Name,
		"granted":       grantedList,
		"denied":        denied,
	}
	b, _ := json.Marshal(resp)
	conn.safeWrite(websocket.MessageText, b)

	emitEvent("ws.capability_granted", "", 0, "", 200, map[string]any{
		"connectionId": connID, "agent": cred.Name,
		"granted": grantedList, "denied": denied,
	})
	return granted
}

func heartbeatLoop(conn *wsConn, cred *AgentCredential, connID string, done chan struct{}, closeDone func()) {
	ticker := time.NewTicker(wsHeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			var revokedAt *string
			err := store.QueryRow(
				"SELECT revoked_at FROM agent_credential WHERE id = ?", cred.ID,
			).Scan(&revokedAt)
			if err != nil || revokedAt != nil {
				emitEvent("ws.credential_revoked", "", 0, "", 200, map[string]any{
					"connectionId": connID, "agent": cred.Name,
				})
				closeWSAgent(conn, wsCredentialRevoked, "Credential revoked")
				closeDone()
				return
			}

			hb := map[string]any{
				"type":            "heartbeat",
				"ts":              time.Now().Unix(),
				"next_check_ms":   wsHeartbeatInterval.Milliseconds(),
				"ping_timeout_ms": wsPingDeadline.Milliseconds(),
			}
			b, _ := json.Marshal(hb)
			conn.safeWrite(websocket.MessageText, b)
		}
	}
}

func handleAgentMessage(conn *wsConn, cred *AgentCredential, granted map[string]bool, data []byte, connID string, nodeID int, subs *subscriptions) {
	var msg struct {
		Type    string          `json:"type"`
		ID      string          `json:"id"`
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(data, &msg) != nil {
		sendWSError(conn, "", "PARSE_ERROR", "Invalid JSON")
		return
	}

	switch msg.Type {
	case "ping":
		resp := map[string]any{"type": "pong"}
		if msg.ID != "" {
			resp["id"] = msg.ID
		}
		b, _ := json.Marshal(resp)
		conn.safeWrite(websocket.MessageText, b)

	case "wg.status":
		if !granted["wg_status"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleWGStatus(cred, msg.Payload, nodeID)

	case "wg.sync.result":
		var p struct {
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		json.Unmarshal(msg.Payload, &p)
		if !p.Success {
			slog.Warn("wg.sync.result failed", "agent", cred.Name, "error", p.Error)
		}

	case "endpoint.discovered":
		if !granted["endpoint_discovery"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleEndpointDiscovered(conn, cred, msg.ID, msg.Payload, nodeID)

	case "key.rotate":
		if !granted["key_rotate"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleKeyRotate(conn, cred, msg.ID, msg.Payload, nodeID)

	case "relay.bind":
		if nodeID == 0 {
			sendWSError(conn, msg.ID, "NOT_NODE", "Not registered as a node")
			return
		}
		handleRelayBind(conn, msg.ID, nodeID, msg.Payload)

	case "relay.unbind":
		if nodeID == 0 {
			return
		}
		handleRelayUnbind(nodeID, msg.Payload)

	case "query_events":
		if !granted["query_events"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleWSQueryEvents(conn, msg.ID, msg.Payload)

	case "query_sessions":
		if !granted["query_sessions"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleWSQuerySessions(conn, msg.ID, msg.Payload)

	case "revoke_session":
		if !granted["revoke_session"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleWSRevokeSession(conn, msg.ID, msg.Payload, cred, connID)

	case "subscribe_events":
		if !granted["subscribe_events"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleWSSubscribeEvents(conn, msg.ID, msg.Payload, subs)

	case "unsubscribe_events":
		handleWSUnsubscribeEvents(conn, msg.ID, subs)

	case "cloak.enable":
		if !granted["cloak_control"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleWSCloakEnable(conn, cred, msg.ID, msg.Payload)

	case "cloak.disable":
		if !granted["cloak_control"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleWSCloakDisable(conn, cred, msg.ID)

	default:
		sendWSError(conn, msg.ID, "UNKNOWN_TYPE", "Unknown message type: "+msg.Type)
	}
}

func handleEndpointDiscovered(conn *wsConn, cred *AgentCredential, id string, payload json.RawMessage, nodeID int) {
	var p struct {
		Endpoint string `json:"endpoint"`
	}
	if json.Unmarshal(payload, &p) != nil || p.Endpoint == "" {
		sendWSError(conn, id, "VALIDATION_ERROR", "Endpoint required")
		return
	}
	if !validEndpoint(p.Endpoint) {
		sendWSError(conn, id, "VALIDATION_ERROR", "Invalid endpoint")
		return
	}

	if nodeID == 0 {
		sendWSError(conn, id, "NOT_NODE", "Agent not associated with a node")
		return
	}

	result, err := store.Exec(
		"UPDATE node SET wg_endpoint = ?, wg_endpoint_source = 'stun', updated_at = datetime('now') WHERE id = ? AND wg_endpoint_source != 'manual'",
		p.Endpoint, nodeID,
	)
	if err != nil {
		sendWSError(conn, id, "INTERNAL_ERROR", "Failed to update endpoint")
		return
	}

	rows, _ := result.RowsAffected()
	sendWSResult(conn, id, "endpoint.discovered", map[string]any{
		"updated": rows > 0,
	})

	if rows > 0 {
		slog.Info("endpoint discovered", "node", nodeID, "endpoint", p.Endpoint)
		// Update server-side WireGuard peer
		serverUpdatePeer(nodeID)
		go notifyNodeSync()
	}
}

func handleKeyRotate(conn *wsConn, cred *AgentCredential, id string, payload json.RawMessage, nodeID int) {
	var p struct {
		PublicKey string `json:"public_key"`
	}
	if json.Unmarshal(payload, &p) != nil || p.PublicKey == "" {
		sendWSError(conn, id, "VALIDATION_ERROR", "Public key required")
		return
	}
	if !validWGPubkey(p.PublicKey) {
		sendWSError(conn, id, "VALIDATION_ERROR", "Invalid WireGuard public key")
		return
	}

	if nodeID == 0 {
		sendWSError(conn, id, "NOT_NODE", "Agent not associated with a node")
		return
	}

	_, err := store.Exec(
		"UPDATE node SET wg_pubkey = ?, updated_at = datetime('now') WHERE id = ?",
		p.PublicKey, nodeID,
	)
	if err != nil {
		sendWSError(conn, id, "INTERNAL_ERROR", "Failed to update public key")
		return
	}

	emitEvent("node.key_rotated", "", 0, "", 200, map[string]any{
		"node_id": nodeID, "agent": cred.Name,
	})

	sendWSResult(conn, id, "key.rotate", map[string]any{
		"success": true,
	})

	slog.Info("key rotated", "node", nodeID, "agent", cred.Name)
	serverUpdatePeer(nodeID)
	go notifyNodeSync()
}

func handleRelayBind(conn *wsConn, id string, nodeID int, payload json.RawMessage) {
	var p struct {
		PeerNodeID int `json:"peer_node_id"`
	}
	if json.Unmarshal(payload, &p) != nil || p.PeerNodeID == 0 {
		sendWSError(conn, id, "VALIDATION_ERROR", "peer_node_id required")
		return
	}

	ok := registerRelayBinding(nodeID, p.PeerNodeID)
	sendWSResult(conn, id, "relay.bind", map[string]any{
		"success": ok,
	})
}

func handleRelayUnbind(nodeID int, payload json.RawMessage) {
	var p struct {
		PeerNodeID int `json:"peer_node_id"`
	}
	if json.Unmarshal(payload, &p) != nil || p.PeerNodeID == 0 {
		return
	}
	unregisterRelayBinding(nodeID, p.PeerNodeID)
}

// --- WS helpers ---

func sendWSResult(conn *wsConn, id, typ string, payload any) {
	msg := map[string]any{"type": typ + ".result", "payload": payload}
	if id != "" {
		msg["id"] = id
	}
	b, _ := json.Marshal(msg)
	conn.safeWrite(websocket.MessageText, b)
}

func sendWSError(conn *wsConn, id, code, message string) {
	msg := map[string]any{"type": "error", "code": code, "message": message}
	if id != "" {
		msg["id"] = id
	}
	b, _ := json.Marshal(msg)
	conn.safeWrite(websocket.MessageText, b)
}

func closeWSAgent(conn *wsConn, code int, reason string) {
	conn.Close(websocket.StatusCode(code), reason)
}

func handleWSCloakEnable(conn *wsConn, cred *AgentCredential, id string, payload json.RawMessage) {
	var p struct {
		DurationMin int `json:"duration_min"`
	}
	json.Unmarshal(payload, &p) // #nosec G104 — optional payload, defaults on error

	durMin := cfg.CloakDurationMin
	if p.DurationMin > 0 && p.DurationMin <= 1440 {
		durMin = p.DurationMin
	}

	enableCloak(time.Duration(durMin) * time.Minute)

	emitEvent("cloak.enabled", stripPort(conn.remoteAddr), 0, "", 200, map[string]any{
		"duration_min": durMin, "actor": "agent:" + cred.Name, "auto": false,
	})
	sendWSResult(conn, id, "cloak.enable", map[string]any{
		"active": true,
		"until":  cloakUntil().UTC().Format(time.RFC3339),
	})
}

func handleWSCloakDisable(conn *wsConn, cred *AgentCredential, id string) {
	disableCloak()
	emitEvent("cloak.disabled", stripPort(conn.remoteAddr), 0, "", 200, map[string]any{
		"actor": "agent:" + cred.Name,
	})
	sendWSResult(conn, id, "cloak.disable", map[string]any{"active": false})
}
