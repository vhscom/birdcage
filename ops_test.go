package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- Setup helpers ---

func setupOpsServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	initDB(":memory:")
	cfg = &Config{
		AgentKey:         "test-agent-key-that-is-32-chars!!",
		AccessSecret:     "test-access-secret-that-is-32-chars!!",
		RefreshSecret:    "test-refresh-secret-that-is-32-chars!",
		WSAllowedOrigins: "",
	}

	ensureAgentCredential()

	mux := http.NewServeMux()

	// Agent WS endpoint
	mux.HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			requireAgentKey(http.HandlerFunc(handleAgentWS)).ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})

	// Ops routes (same as main.go)
	mux.Handle("GET /ops/sessions", requireAgentKey(http.HandlerFunc(handleOpsSessions)))
	mux.Handle("POST /ops/sessions/revoke", requireAgentKey(http.HandlerFunc(handleOpsSessionRevoke)))
	mux.Handle("GET /ops/agents", requireAgentKey(http.HandlerFunc(handleOpsAgentList)))
	mux.Handle("POST /ops/agents", requireProvisioningSecret(http.HandlerFunc(handleOpsAgentCreate)))
	mux.Handle("DELETE /ops/agents/{name}", requireProvisioningSecret(http.HandlerFunc(handleOpsAgentRevoke)))
	mux.Handle("GET /ops/events", requireAgentKey(http.HandlerFunc(handleOpsEvents)))
	mux.Handle("GET /ops/events/stats", requireAgentKey(http.HandlerFunc(handleOpsEventStats)))
	mux.Handle("GET /ops/nodes", requireAgentKey(http.HandlerFunc(handleOpsNodeList)))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, cfg.AgentKey
}

func agentGet(url, apiKey string) (*http.Response, map[string]any) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(body, &result)
	return resp, result
}

func agentPost(url string, body any, apiKey string) (*http.Response, map[string]any) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(raw, &result)
	return resp, result
}

func provisioningPost(url string, body any, secret string) (*http.Response, map[string]any) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("X-Provisioning-Secret", secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(raw, &result)
	return resp, result
}

func provisioningDelete(url, secret string) (*http.Response, map[string]any) {
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	req.Header.Set("X-Provisioning-Secret", secret)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(raw, &result)
	return resp, result
}

// --- Tests ---

func TestOpsAuth_NoKey(t *testing.T) {
	srv, _ := setupOpsServer(t)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/ops/sessions", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestOpsAuth_InvalidKey(t *testing.T) {
	srv, _ := setupOpsServer(t)

	resp, _ := agentGet(srv.URL+"/ops/sessions", "totally-wrong-key")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestSessionsQuery(t *testing.T) {
	srv, apiKey := setupOpsServer(t)

	// Insert an account and a session
	_, err := store.Exec(
		"INSERT INTO account (id, email, password_data) VALUES (1, 'test@example.com', 'dummy')",
	)
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	created := time.Now().UTC().Format(time.RFC3339)
	_, err = store.Exec(
		"INSERT INTO session (id, user_id, user_agent, ip_address, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"sess-001", 1, "TestAgent/1.0", "127.0.0.1", expires, created,
	)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}

	resp, body := agentGet(srv.URL+"/ops/sessions", apiKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	sessions, ok := body["sessions"].([]any)
	if !ok {
		t.Fatalf("sessions is not a list: %T", body["sessions"])
	}
	if len(sessions) == 0 {
		t.Fatal("expected at least one session")
	}

	found := false
	for _, s := range sessions {
		sess := s.(map[string]any)
		if sess["id"] == "sess-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("session sess-001 not found in response")
	}
}

func TestSessionRevoke_All(t *testing.T) {
	srv, apiKey := setupOpsServer(t)

	// Insert account and sessions
	store.Exec("INSERT INTO account (id, email, password_data) VALUES (1, 'test@example.com', 'dummy')")
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	created := time.Now().UTC().Format(time.RFC3339)
	store.Exec(
		"INSERT INTO session (id, user_id, user_agent, ip_address, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"sess-r1", 1, "UA/1", "127.0.0.1", expires, created,
	)
	store.Exec(
		"INSERT INTO session (id, user_id, user_agent, ip_address, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"sess-r2", 1, "UA/2", "127.0.0.1", expires, created,
	)

	resp, body := agentPost(srv.URL+"/ops/sessions/revoke", map[string]any{"scope": "all"}, apiKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	success, _ := body["success"].(bool)
	if !success {
		t.Error("expected success=true")
	}

	revoked, _ := body["revoked"].(float64)
	if revoked < 2 {
		t.Errorf("revoked = %v, want >= 2", revoked)
	}
}

func TestSessionRevoke_Session(t *testing.T) {
	srv, apiKey := setupOpsServer(t)

	store.Exec("INSERT INTO account (id, email, password_data) VALUES (1, 'test@example.com', 'dummy')")
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	created := time.Now().UTC().Format(time.RFC3339)
	store.Exec(
		"INSERT INTO session (id, user_id, user_agent, ip_address, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"sess-target", 1, "UA/1", "127.0.0.1", expires, created,
	)
	store.Exec(
		"INSERT INTO session (id, user_id, user_agent, ip_address, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"sess-keep", 1, "UA/2", "127.0.0.1", expires, created,
	)

	resp, body := agentPost(srv.URL+"/ops/sessions/revoke", map[string]any{
		"scope": "session",
		"id":    "sess-target",
	}, apiKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	revoked, _ := body["revoked"].(float64)
	if revoked != 1 {
		t.Errorf("revoked = %v, want 1", revoked)
	}

	// Verify sess-keep is still active
	var keepExpires string
	store.QueryRow("SELECT expires_at FROM session WHERE id = 'sess-keep'").Scan(&keepExpires)
	expT, _ := time.Parse(time.RFC3339, keepExpires)
	if expT.Before(time.Now()) {
		t.Error("sess-keep should still be active")
	}
}

func TestSessionRevoke_BadScope(t *testing.T) {
	srv, apiKey := setupOpsServer(t)

	resp, body := agentPost(srv.URL+"/ops/sessions/revoke", map[string]any{"scope": "invalid"}, apiKey)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if code, _ := body["code"].(string); code != "INVALID_SCOPE" {
		t.Errorf("code = %v, want INVALID_SCOPE", code)
	}
}

func TestEventsQuery(t *testing.T) {
	srv, apiKey := setupOpsServer(t)

	emitEvent("test.event", "10.0.0.1", 0, "TestUA", 200, map[string]any{"foo": "bar"})

	resp, body := agentGet(srv.URL+"/ops/events", apiKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	events, ok := body["events"].([]any)
	if !ok {
		t.Fatalf("events is not a list: %T", body["events"])
	}

	found := false
	for _, e := range events {
		ev := e.(map[string]any)
		if ev["type"] == "test.event" {
			found = true
			break
		}
	}
	if !found {
		t.Error("test.event not found in response")
	}
}

func TestEventsQuery_TypeFilter(t *testing.T) {
	srv, apiKey := setupOpsServer(t)

	emitEvent("alpha.event", "10.0.0.1", 0, "UA", 200, nil)
	emitEvent("beta.event", "10.0.0.1", 0, "UA", 200, nil)

	resp, body := agentGet(srv.URL+"/ops/events?type=alpha.event", apiKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	events := body["events"].([]any)
	for _, e := range events {
		ev := e.(map[string]any)
		if ev["type"] != "alpha.event" {
			t.Errorf("unexpected event type %v when filtering for alpha.event", ev["type"])
		}
	}
	if len(events) == 0 {
		t.Error("expected at least one alpha.event")
	}
}

func TestEventStats(t *testing.T) {
	srv, apiKey := setupOpsServer(t)

	emitEvent("stat.typeA", "10.0.0.1", 0, "UA", 200, nil)
	emitEvent("stat.typeA", "10.0.0.2", 0, "UA", 200, nil)
	emitEvent("stat.typeB", "10.0.0.3", 0, "UA", 200, nil)

	resp, body := agentGet(srv.URL+"/ops/events/stats", apiKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	stats, ok := body["stats"].(map[string]any)
	if !ok {
		t.Fatalf("stats is not a map: %T", body["stats"])
	}

	aCount, _ := stats["stat.typeA"].(float64)
	bCount, _ := stats["stat.typeB"].(float64)
	if aCount < 2 {
		t.Errorf("stat.typeA count = %v, want >= 2", aCount)
	}
	if bCount < 1 {
		t.Errorf("stat.typeB count = %v, want >= 1", bCount)
	}
}

func TestAgentProvisioning(t *testing.T) {
	srv, _ := setupOpsServer(t)

	// Provision a new agent
	resp, body := provisioningPost(srv.URL+"/ops/agents", map[string]any{
		"name": "new-agent",
	}, cfg.AgentKey)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d (body: %v)", resp.StatusCode, http.StatusCreated, body)
	}

	returnedKey, ok := body["apiKey"].(string)
	if !ok || returnedKey == "" {
		t.Fatal("expected apiKey in response")
	}
	if body["name"] != "new-agent" {
		t.Errorf("name = %v, want new-agent", body["name"])
	}

	// Verify the agent appears in listing (use the newly provisioned key)
	listResp, listBody := agentGet(srv.URL+"/ops/agents", returnedKey)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listResp.StatusCode, http.StatusOK)
	}

	agents := listBody["agents"].([]any)
	found := false
	for _, a := range agents {
		agent := a.(map[string]any)
		if agent["name"] == "new-agent" {
			found = true
			break
		}
	}
	if !found {
		t.Error("new-agent not found in agent listing")
	}
}

func TestAgentProvisioning_BadSecret(t *testing.T) {
	srv, _ := setupOpsServer(t)

	resp, _ := provisioningPost(srv.URL+"/ops/agents", map[string]any{
		"name": "bad-secret-agent",
	}, "wrong-secret")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestAgentProvisioning_Duplicate(t *testing.T) {
	srv, _ := setupOpsServer(t)

	// First creation
	resp1, _ := provisioningPost(srv.URL+"/ops/agents", map[string]any{
		"name": "dup-agent",
	}, cfg.AgentKey)
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("first create status = %d, want %d", resp1.StatusCode, http.StatusCreated)
	}

	// Duplicate
	resp2, body2 := provisioningPost(srv.URL+"/ops/agents", map[string]any{
		"name": "dup-agent",
	}, cfg.AgentKey)
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want %d", resp2.StatusCode, http.StatusConflict)
	}
	if code, _ := body2["code"].(string); code != "AGENT_EXISTS" {
		t.Errorf("code = %v, want AGENT_EXISTS", code)
	}
}

func TestAgentRevocation(t *testing.T) {
	srv, _ := setupOpsServer(t)

	// Provision first
	provisioningPost(srv.URL+"/ops/agents", map[string]any{
		"name": "revoke-me",
	}, cfg.AgentKey)

	// Revoke
	resp, body := provisioningDelete(srv.URL+"/ops/agents/revoke-me", cfg.AgentKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %v)", resp.StatusCode, http.StatusOK, body)
	}

	success, _ := body["success"].(bool)
	if !success {
		t.Error("expected success=true")
	}
}

func TestAgentRevocation_NotFound(t *testing.T) {
	srv, _ := setupOpsServer(t)

	resp, body := provisioningDelete(srv.URL+"/ops/agents/nonexistent-agent", cfg.AgentKey)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if code, _ := body["code"].(string); code != "NOT_FOUND" {
		t.Errorf("code = %v, want NOT_FOUND", code)
	}
}

func TestNodeList(t *testing.T) {
	srv, apiKey := setupOpsServer(t)

	// Insert a node
	_, err := store.Exec(
		`INSERT INTO node (label, wg_pubkey, wg_endpoint, allowed_ips, agent_credential_id)
		 VALUES (?, ?, ?, ?, NULL)`,
		"test-node-01", "dGVzdHB1YmtleXRoYXRpczMyYnl0ZXNsb25nISE=", "1.2.3.4:51820", "10.0.0.2/32",
	)
	if err != nil {
		t.Fatalf("insert node: %v", err)
	}

	resp, body := agentGet(srv.URL+"/ops/nodes", apiKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	nodes, ok := body["nodes"].([]any)
	if !ok {
		t.Fatalf("nodes is not a list: %T", body["nodes"])
	}

	found := false
	for _, n := range nodes {
		node := n.(map[string]any)
		if node["label"] == "test-node-01" {
			found = true
			if node["wg_endpoint"] != "1.2.3.4:51820" {
				t.Errorf("wg_endpoint = %v, want 1.2.3.4:51820", node["wg_endpoint"])
			}
			if node["allowed_ips"] != "10.0.0.2/32" {
				t.Errorf("allowed_ips = %v, want 10.0.0.2/32", node["allowed_ips"])
			}
			break
		}
	}
	if !found {
		t.Error("test-node-01 not found in node listing")
	}
}
