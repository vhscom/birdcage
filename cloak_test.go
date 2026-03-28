package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// resetCloakState resets package-level cloak globals and registers cleanup.
func resetCloakState(t *testing.T) {
	t.Helper()
	disableCloak()
	wgNet = nil
	cloakTriggerLast.Range(func(k, v any) bool {
		cloakTriggerLast.Delete(k)
		return true
	})
	t.Cleanup(func() {
		disableCloak()
		wgNet = nil
		cloakTriggerLast.Range(func(k, v any) bool {
			cloakTriggerLast.Delete(k)
			return true
		})
	})
}

// --- isInternalIP ---

func TestIsInternalIP_Loopback(t *testing.T) {
	resetCloakState(t)
	for _, ip := range []string{"127.0.0.1", "::1"} {
		if !isInternalIP(ip) {
			t.Errorf("%s should be internal (loopback)", ip)
		}
	}
}

func TestIsInternalIP_External(t *testing.T) {
	resetCloakState(t)
	for _, ip := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		if isInternalIP(ip) {
			t.Errorf("%s should not be internal", ip)
		}
	}
}

func TestIsInternalIP_Invalid(t *testing.T) {
	resetCloakState(t)
	for _, ip := range []string{"", "not-an-ip"} {
		if isInternalIP(ip) {
			t.Errorf("%q should not be internal (invalid)", ip)
		}
	}
}

func TestIsInternalIP_WGSubnet(t *testing.T) {
	resetCloakState(t)
	initWGSubnet("10.0.0.0/24")
	if !isInternalIP("10.0.0.1") {
		t.Error("10.0.0.1 should be internal (WG subnet)")
	}
	if !isInternalIP("10.0.0.254") {
		t.Error("10.0.0.254 should be internal (WG subnet)")
	}
	if isInternalIP("10.0.1.1") {
		t.Error("10.0.1.1 should not be internal (outside WG subnet)")
	}
}

func TestIsInternalIP_NoWGSubnet(t *testing.T) {
	resetCloakState(t)
	// wgNet is nil — only loopback should be internal
	if isInternalIP("10.0.0.1") {
		t.Error("10.0.0.1 should not be internal when no WG subnet configured")
	}
}

// --- initWGSubnet ---

func TestInitWGSubnet_Empty(t *testing.T) {
	resetCloakState(t)
	initWGSubnet("")
	if wgNet != nil {
		t.Error("wgNet should be nil for empty CIDR")
	}
}

func TestInitWGSubnet_Invalid(t *testing.T) {
	resetCloakState(t)
	initWGSubnet("not-a-cidr")
	if wgNet != nil {
		t.Error("wgNet should be nil for invalid CIDR")
	}
}

func TestInitWGSubnet_Valid(t *testing.T) {
	resetCloakState(t)
	initWGSubnet("10.10.0.0/16")
	if wgNet == nil {
		t.Fatal("wgNet should be set for valid CIDR")
	}
	_, expected, _ := net.ParseCIDR("10.10.0.0/16")
	if wgNet.String() != expected.String() {
		t.Errorf("wgNet = %v, want %v", wgNet, expected)
	}
}

// --- cloak state ---

func TestCloakState_InitiallyDisabled(t *testing.T) {
	resetCloakState(t)
	if isCloaked() {
		t.Error("cloak should be inactive initially")
	}
}

func TestCloakState_EnableDisable(t *testing.T) {
	resetCloakState(t)
	enableCloak(time.Hour)
	if !isCloaked() {
		t.Error("cloak should be active after enableCloak")
	}
	if !cloakUntil().After(time.Now()) {
		t.Error("cloakUntil should be in the future")
	}
	disableCloak()
	if isCloaked() {
		t.Error("cloak should be inactive after disableCloak")
	}
}

func TestCloakState_Expiry(t *testing.T) {
	resetCloakState(t)
	enableCloak(time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if isCloaked() {
		t.Error("cloak should have expired")
	}
}

// --- cloakMiddleware ---

func TestCloakMiddleware_Uncloaked(t *testing.T) {
	resetCloakState(t)
	var reached bool
	handler := cloakMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if !reached {
		t.Error("handler should be reached when cloak is inactive")
	}
}

func TestCloakMiddleware_CloakedPublicIP(t *testing.T) {
	resetCloakState(t)
	enableCloak(time.Hour)
	var reached bool
	handler := cloakMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:9999" // TEST-NET-3 per RFC 5737
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if reached {
		t.Error("public IP should be blocked when cloaked")
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestCloakMiddleware_CloakedLoopback(t *testing.T) {
	resetCloakState(t)
	enableCloak(time.Hour)
	var reached bool
	handler := cloakMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if !reached {
		t.Error("loopback should always pass through cloakMiddleware")
	}
}

func TestCloakMiddleware_CloakedWGMesh(t *testing.T) {
	resetCloakState(t)
	initWGSubnet("10.0.0.0/24")
	enableCloak(time.Hour)
	var reached bool
	handler := cloakMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if !reached {
		t.Error("WG mesh IP should always pass through cloakMiddleware")
	}
}

// --- checkCloakTrigger ---

func setupCloakTriggerEnv(t *testing.T) {
	t.Helper()
	initDB(":memory:")
	cfg = &Config{
		AgentKey:         "test-agent-key-that-is-32-chars!!",
		AccessSecret:     "test-access-secret-that-is-32-chars!!",
		RefreshSecret:    "test-refresh-secret-that-is-32-chars!",
		CloakDurationMin: 15,
		CloakOnAttack:    true,
	}
	resetCloakState(t)
}

func TestCheckCloakTrigger_UnknownType(t *testing.T) {
	setupCloakTriggerEnv(t)
	checkCloakTrigger("some.random.event")
	if isCloaked() {
		t.Error("unknown event type should not trigger cloak")
	}
}

func TestCheckCloakTrigger_BelowThreshold(t *testing.T) {
	setupCloakTriggerEnv(t)
	for i := 0; i < cloakTLSThreshold-1; i++ {
		store.Exec(
			"INSERT INTO security_event (type, ip_address, user_agent, status) VALUES ('tls.rejected', '1.2.3.4', 'UA', 0)",
		)
	}
	checkCloakTrigger("tls.rejected")
	if isCloaked() {
		t.Error("cloak should not be triggered below threshold")
	}
}

func TestCheckCloakTrigger_AtThreshold(t *testing.T) {
	setupCloakTriggerEnv(t)
	for i := 0; i < cloakTLSThreshold; i++ {
		store.Exec(
			"INSERT INTO security_event (type, ip_address, user_agent, status) VALUES ('tls.rejected', '1.2.3.4', 'UA', 0)",
		)
	}
	checkCloakTrigger("tls.rejected")
	if !isCloaked() {
		t.Error("cloak should be triggered at threshold")
	}
}

func TestCheckCloakTrigger_AuthFailureThreshold(t *testing.T) {
	setupCloakTriggerEnv(t)
	for i := 0; i < cloakAuthThreshold; i++ {
		store.Exec(
			"INSERT INTO security_event (type, ip_address, user_agent, status) VALUES ('agent.auth_failure', '1.2.3.4', 'UA', 0)",
		)
	}
	checkCloakTrigger("agent.auth_failure")
	if !isCloaked() {
		t.Error("cloak should be triggered at auth_failure threshold")
	}
}

func TestCheckCloakTrigger_Debounce(t *testing.T) {
	setupCloakTriggerEnv(t)
	for i := 0; i < cloakTLSThreshold; i++ {
		store.Exec(
			"INSERT INTO security_event (type, ip_address, user_agent, status) VALUES ('tls.rejected', '1.2.3.4', 'UA', 0)",
		)
	}
	checkCloakTrigger("tls.rejected")
	if !isCloaked() {
		t.Fatal("first call should have triggered cloak")
	}
	// Disable and call again immediately — second call should be debounced
	disableCloak()
	checkCloakTrigger("tls.rejected")
	if isCloaked() {
		t.Error("immediate second call should be debounced, not re-trigger")
	}
}

// --- ops cloak endpoints ---

func setupCloakOpsServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	initDB(":memory:")
	cfg = &Config{
		AgentKey:         "test-agent-key-that-is-32-chars!!",
		AccessSecret:     "test-access-secret-that-is-32-chars!!",
		RefreshSecret:    "test-refresh-secret-that-is-32-chars!",
		CloakDurationMin: 15,
		WSAllowedOrigins: "",
	}
	ensureAgentCredential()
	resetCloakState(t)

	mux := http.NewServeMux()
	mux.Handle("GET /ops/cloak", cloakMiddleware(requireAgentKey(http.HandlerFunc(handleOpsCloakStatus))))
	mux.Handle("POST /ops/cloak", cloakMiddleware(requireAgentKey(http.HandlerFunc(handleOpsCloakEnable))))
	mux.Handle("DELETE /ops/cloak", cloakMiddleware(requireAgentKey(http.HandlerFunc(handleOpsCloakDisable))))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, cfg.AgentKey
}

func agentDelete(url, apiKey string) (*http.Response, map[string]any) {
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
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

func TestOpsCloakStatus_Uncloaked(t *testing.T) {
	srv, apiKey := setupCloakOpsServer(t)
	resp, body := agentGet(srv.URL+"/ops/cloak", apiKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if active, _ := body["active"].(bool); active {
		t.Error("active should be false when cloak is off")
	}
	if _, hasUntil := body["until"]; hasUntil {
		t.Error("until should not be present when cloak is inactive")
	}
}

func TestOpsCloakStatus_Active(t *testing.T) {
	srv, apiKey := setupCloakOpsServer(t)
	enableCloak(time.Hour)
	// httptest requests come from 127.0.0.1, which passes through cloakMiddleware
	resp, body := agentGet(srv.URL+"/ops/cloak", apiKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if active, _ := body["active"].(bool); !active {
		t.Error("active should be true when cloak is on")
	}
	if _, hasUntil := body["until"]; !hasUntil {
		t.Error("until should be present when cloak is active")
	}
	if remaining, _ := body["remaining_sec"].(float64); remaining <= 0 {
		t.Errorf("remaining_sec = %v, want > 0", remaining)
	}
}

func TestOpsCloakEnable_DefaultDuration(t *testing.T) {
	srv, apiKey := setupCloakOpsServer(t)
	resp, body := agentPost(srv.URL+"/ops/cloak", map[string]any{}, apiKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if active, _ := body["active"].(bool); !active {
		t.Error("active should be true after enable")
	}
	if dur, _ := body["duration_min"].(float64); dur != float64(cfg.CloakDurationMin) {
		t.Errorf("duration_min = %v, want %v", dur, cfg.CloakDurationMin)
	}
	if !isCloaked() {
		t.Error("isCloaked() should be true after POST /ops/cloak")
	}
}

func TestOpsCloakEnable_CustomDuration(t *testing.T) {
	srv, apiKey := setupCloakOpsServer(t)
	resp, body := agentPost(srv.URL+"/ops/cloak", map[string]any{"duration_min": 30}, apiKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if dur, _ := body["duration_min"].(float64); dur != 30 {
		t.Errorf("duration_min = %v, want 30", dur)
	}
}

func TestOpsCloakEnable_ExceedsMax(t *testing.T) {
	srv, apiKey := setupCloakOpsServer(t)
	// 1441 > 1440 cap, should fall back to default
	resp, body := agentPost(srv.URL+"/ops/cloak", map[string]any{"duration_min": 1441}, apiKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if dur, _ := body["duration_min"].(float64); dur != float64(cfg.CloakDurationMin) {
		t.Errorf("duration_min = %v, want %v (default, 1441 exceeds cap)", dur, cfg.CloakDurationMin)
	}
}

func TestOpsCloakDisable(t *testing.T) {
	srv, apiKey := setupCloakOpsServer(t)
	enableCloak(time.Hour)
	resp, body := agentDelete(srv.URL+"/ops/cloak", apiKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if active, _ := body["active"].(bool); active {
		t.Error("active should be false after DELETE /ops/cloak")
	}
	if isCloaked() {
		t.Error("isCloaked() should be false after disable")
	}
}
