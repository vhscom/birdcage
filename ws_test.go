package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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
	header := http.Header{}
	header.Set("Authorization", "Bearer "+apiKey)

	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		body := ""
		if resp != nil {
			b := make([]byte, 512)
			n, _ := resp.Body.Read(b)
			body = string(b[:n])
		}
		t.Fatalf("dial ws: %v (response body: %s)", err, body)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func negotiateTestCaps(t *testing.T, conn *websocket.Conn, caps []string) map[string]any {
	t.Helper()
	wsSend(conn, map[string]any{
		"type":         "capability.request",
		"capabilities": caps,
	})
	resp := wsRead(t, conn)
	if resp["type"] != "capability.granted" {
		t.Fatalf("expected capability.granted, got %v", resp["type"])
	}
	return resp
}

func wsSend(conn *websocket.Conn, v any) {
	b, _ := json.Marshal(v)
	conn.WriteMessage(websocket.TextMessage, b)
}

func wsRead(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, raw, err := conn.ReadMessage()
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

	wsSend(conn, map[string]any{"type": "ping", "id": "1"})

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
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _, err := conn.ReadMessage()
	if err == nil {
		t.Fatal("expected close error, got nil")
	}

	closeErr, ok := err.(*websocket.CloseError)
	if !ok {
		t.Fatalf("expected *websocket.CloseError, got %T: %v", err, err)
	}
	if closeErr.Code != wsHandshakeTimeout {
		t.Errorf("close code = %d, want %d (wsHandshakeTimeout)", closeErr.Code, wsHandshakeTimeout)
	}
}

func TestAgentWSUnknownType(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	conn := dialWS(t, srv.URL, apiKey)
	negotiateTestCaps(t, conn, []string{"wg_sync", "wg_status"})

	wsSend(conn, map[string]any{"type": "bogus"})

	resp := wsReadSkipSync(t, conn)
	if resp["type"] != "error" {
		t.Errorf("type = %v, want error", resp["type"])
	}
	if resp["code"] != "UNKNOWN_TYPE" {
		t.Errorf("code = %v, want UNKNOWN_TYPE", resp["code"])
	}
}
