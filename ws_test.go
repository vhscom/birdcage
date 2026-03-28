package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// --- Setup helpers ---

func setupWSServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	initDB(":memory:")
	cfg = &Config{
		AgentKey:         "test-agent-key-that-is-32-chars!!",
		AccessSecret:     "test-access-secret-that-is-32-chars!!",
		RefreshSecret:    "test-refresh-secret-that-is-32-chars!",
		WSAllowedOrigins: "",
	}

	apiKey := "ws-test-key-for-agent-connections"
	keyHash := hashAPIKey(apiKey)
	_, err := store.Exec(
		"INSERT INTO agent_credential (name, key_hash) VALUES (?, ?)",
		"ws-test-agent", keyHash,
	)
	if err != nil {
		t.Fatalf("insert agent credential: %v", err)
	}

	// Track WS handler completion — hijacked connections aren't tracked
	// by httptest.Server.Close or Shutdown, so we need to wait explicitly.
	var handlerWG sync.WaitGroup

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			handlerWG.Add(1)
			requireAgentKey(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer handlerWG.Done()
				handleAgentWS(w, r)
			})).ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		handlerWG.Wait()
	})
	return srv, apiKey
}

func dialWS(t *testing.T, serverURL, apiKey string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(serverURL, "http") + "/ws"

	conn, _, err := websocket.Dial(t.Context(), wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + apiKey},
		},
	})
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}

func negotiateTestCaps(t *testing.T, conn *websocket.Conn, caps []string) map[string]any {
	t.Helper()
	wsSend(t, conn, map[string]any{
		"type":         "capability.request",
		"capabilities": caps,
	})
	resp := wsRead(t, conn)
	if resp["type"] != "capability.granted" {
		t.Fatalf("expected capability.granted, got %v", resp["type"])
	}
	return resp
}

func wsSend(t *testing.T, conn *websocket.Conn, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	conn.Write(t.Context(), websocket.MessageText, b)
}

func wsRead(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, raw, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("wsRead: %v", err)
	}
	var msg map[string]any
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("wsRead unmarshal: %v (raw: %s)", err, raw)
	}
	return msg
}

// wsReadSkipSync reads messages, skipping server-initiated async messages
// (wg.sync, heartbeat) that may arrive after capability negotiation.
func wsReadSkipSync(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	for {
		msg := wsRead(t, conn)
		typ, _ := msg["type"].(string)
		if typ == "wg.sync" || typ == "heartbeat" {
			continue
		}
		return msg
	}
}

// --- Tests ---

func TestAgentWSConnect(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	conn := dialWS(t, srv.URL, apiKey)

	resp := negotiateTestCaps(t, conn, []string{"wg_sync", "wg_status"})

	granted, ok := resp["granted"].([]any)
	if !ok {
		t.Fatalf("granted is not a list: %T", resp["granted"])
	}

	grantedSet := map[string]bool{}
	for _, g := range granted {
		grantedSet[g.(string)] = true
	}
	if !grantedSet["wg_sync"] {
		t.Error("wg_sync not in granted list")
	}
	if !grantedSet["wg_status"] {
		t.Error("wg_status not in granted list")
	}

	if resp["connection_id"] == nil || resp["connection_id"] == "" {
		t.Error("connection_id missing from capability.granted")
	}
	if resp["agent"] != "ws-test-agent" {
		t.Errorf("agent = %v, want ws-test-agent", resp["agent"])
	}
}

func TestAgentWSPing(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	conn := dialWS(t, srv.URL, apiKey)
	negotiateTestCaps(t, conn, []string{"wg_sync", "wg_status"})

	wsSend(t, conn, map[string]any{"type": "ping", "id": "1"})

	resp := wsReadSkipSync(t, conn)
	if resp["type"] != "pong" {
		t.Errorf("type = %v, want pong", resp["type"])
	}
	if resp["id"] != "1" {
		t.Errorf("id = %v, want 1", resp["id"])
	}
}

func TestAgentWSHandshakeTimeout(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	conn := dialWS(t, srv.URL, apiKey)

	// Don't send capability.request — server should close with 4001
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	_, _, err := conn.Read(ctx)
	if err == nil {
		t.Fatal("expected close error, got nil")
	}

	var closeErr websocket.CloseError
	if !errors.As(err, &closeErr) {
		t.Fatalf("expected websocket.CloseError, got %T: %v", err, err)
	}
	if closeErr.Code != websocket.StatusCode(wsHandshakeTimeout) {
		t.Errorf("close code = %d, want %d (wsHandshakeTimeout)", closeErr.Code, wsHandshakeTimeout)
	}
}

func TestAgentWSRateLimit(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	conn := dialWS(t, srv.URL, apiKey)
	// Avoid wg_sync/wg_status to prevent wg.sync messages arriving between sends.
	negotiateTestCaps(t, conn, []string{"query_events"})

	// Send one more than the per-window max; server should close with 4008.
	msg := map[string]any{"type": "wg.sync.result", "payload": map[string]any{"success": true}}
	for i := 0; i <= wsMsgRateMax; i++ {
		wsSend(t, conn, msg)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, _, err := conn.Read(ctx)
	if err == nil {
		t.Fatal("expected close error after rate limit, got nil")
	}
	var closeErr websocket.CloseError
	if !errors.As(err, &closeErr) {
		t.Fatalf("expected websocket.CloseError, got %T: %v", err, err)
	}
	if closeErr.Code != websocket.StatusCode(wsRateLimited) {
		t.Errorf("close code = %d, want %d (wsRateLimited)", closeErr.Code, wsRateLimited)
	}
}

// --- Origin tests ---

func TestCheckWSOrigin(t *testing.T) {
	cases := []struct {
		name    string
		origin  string
		allowed string
		want    bool
	}{
		{"no origin header", "", "", true},
		{"no origin, allowlist set", "", "https://app.example.com", true},
		{"origin, empty allowlist", "https://evil.com", "", false},
		{"origin matches allowlist", "https://app.example.com", "https://app.example.com", true},
		{"origin not in allowlist", "https://evil.com", "https://app.example.com", false},
		{"origin matches one of multiple", "https://b.com", "https://a.com, https://b.com", true},
		{"origin matches none of multiple", "https://evil.com", "https://a.com, https://b.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg = &Config{WSAllowedOrigins: tc.allowed}
			r, _ := http.NewRequest("GET", "/ws", nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if got := checkWSOrigin(r); got != tc.want {
				t.Errorf("checkWSOrigin() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAgentWSOriginBlocked(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	// WSAllowedOrigins is "" — any Origin header must be rejected before upgrade

	req, _ := http.NewRequest("GET", srv.URL+"/ws", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Origin", "https://evil.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAgentWSOriginAllowed(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	cfg.WSAllowedOrigins = "https://app.example.com"

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := websocket.Dial(t.Context(), wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + apiKey},
			"Origin":        []string{"https://app.example.com"},
		},
	})
	if err != nil {
		t.Fatalf("dial with allowed origin: %v", err)
	}
	defer conn.CloseNow()
	negotiateTestCaps(t, conn, []string{"wg_sync"})
}

func TestAgentWSUnknownType(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	conn := dialWS(t, srv.URL, apiKey)
	negotiateTestCaps(t, conn, []string{"wg_sync", "wg_status"})

	wsSend(t, conn, map[string]any{"type": "bogus"})

	resp := wsReadSkipSync(t, conn)
	if resp["type"] != "error" {
		t.Errorf("type = %v, want error", resp["type"])
	}
	if resp["code"] != "UNKNOWN_TYPE" {
		t.Errorf("code = %v, want UNKNOWN_TYPE", resp["code"])
	}
}

// --- Cloak WS tests ---

func TestWSCloakEnable(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	cfg.CloakDurationMin = 15
	resetCloakState(t)
	conn := dialWS(t, srv.URL, apiKey)
	negotiateTestCaps(t, conn, []string{"cloak_control"})

	wsSend(t, conn, map[string]any{
		"type":    "cloak.enable",
		"id":      "1",
		"payload": map[string]any{"duration_min": 30},
	})

	resp := wsReadSkipSync(t, conn)
	if resp["type"] != "cloak.enable.result" {
		t.Fatalf("type = %v, want cloak.enable.result", resp["type"])
	}
	payload, _ := resp["payload"].(map[string]any)
	if active, _ := payload["active"].(bool); !active {
		t.Error("active should be true in payload")
	}
	if payload["until"] == nil || payload["until"] == "" {
		t.Error("until should be present in payload")
	}
	if !isCloaked() {
		t.Error("isCloaked() should be true after cloak.enable")
	}
}

func TestWSCloakDisable(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	cfg.CloakDurationMin = 15
	resetCloakState(t)
	enableCloak(time.Hour)
	conn := dialWS(t, srv.URL, apiKey)
	negotiateTestCaps(t, conn, []string{"cloak_control"})

	wsSend(t, conn, map[string]any{
		"type": "cloak.disable",
		"id":   "2",
	})

	resp := wsReadSkipSync(t, conn)
	if resp["type"] != "cloak.disable.result" {
		t.Fatalf("type = %v, want cloak.disable.result", resp["type"])
	}
	payload, _ := resp["payload"].(map[string]any)
	if active, _ := payload["active"].(bool); active {
		t.Error("active should be false in payload")
	}
	if isCloaked() {
		t.Error("isCloaked() should be false after cloak.disable")
	}
}

func TestWSCloakEnable_NotGranted(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	cfg.CloakDurationMin = 15
	resetCloakState(t)
	conn := dialWS(t, srv.URL, apiKey)
	// Negotiate without cloak_control
	negotiateTestCaps(t, conn, []string{"wg_sync"})

	wsSend(t, conn, map[string]any{
		"type":    "cloak.enable",
		"id":      "3",
		"payload": map[string]any{"duration_min": 10},
	})

	resp := wsReadSkipSync(t, conn)
	if resp["type"] != "error" {
		t.Errorf("type = %v, want error", resp["type"])
	}
	if resp["code"] != "NOT_GRANTED" {
		t.Errorf("code = %v, want NOT_GRANTED", resp["code"])
	}
	if isCloaked() {
		t.Error("cloak should not be enabled without capability")
	}
}
