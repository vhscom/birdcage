package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSecurityHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := securityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	checks := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Frame-Options":          "DENY",
		"X-Content-Type-Options":   "nosniff",
	}
	for header, want := range checks {
		got := rec.Header().Get(header)
		if got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Errorf("Content-Security-Policy header is empty")
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP missing default-src 'self', got %q", csp)
	}
}

func TestAccessLog(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	})
	handler := accessLog(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	if body != "hello" {
		t.Errorf("body = %q, want %q", body, "hello")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMaxBody(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	handler := maxBody(inner)

	// Send a body larger than 1MB (maxBodySize).
	bigBody := strings.NewReader(strings.Repeat("x", 1<<20+1))
	req := httptest.NewRequest(http.MethodPost, "/upload", bigBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestRequireAgentKey_Valid(t *testing.T) {
	initDB(":memory:")
	cfg = &Config{
		AgentKey:      "test-agent-key-that-is-32-chars!!",
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}

	_, err := store.Exec("INSERT INTO agent_credential (name, key_hash) VALUES (?, ?)", "test", hashAPIKey("test-key"))
	if err != nil {
		t.Fatalf("insert credential: %v", err)
	}

	var gotCred *AgentCredential
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCred = getAgentCred(r)
		w.WriteHeader(http.StatusOK)
	})
	handler := requireAgentKey(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/agent", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotCred == nil {
		t.Fatalf("agent credential not set in context")
	}
	if gotCred.Name != "test" {
		t.Errorf("credential name = %q, want %q", gotCred.Name, "test")
	}
}

func TestRequireAgentKey_Missing(t *testing.T) {
	initDB(":memory:")
	cfg = &Config{
		AgentKey:      "test-agent-key-that-is-32-chars!!",
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := requireAgentKey(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/agent", nil)
	// No Authorization header.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireAgentKey_Invalid(t *testing.T) {
	initDB(":memory:")
	cfg = &Config{
		AgentKey:      "test-agent-key-that-is-32-chars!!",
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}

	_, err := store.Exec("INSERT INTO agent_credential (name, key_hash) VALUES (?, ?)", "test", hashAPIKey("test-key"))
	if err != nil {
		t.Fatalf("insert credential: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := requireAgentKey(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/agent", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireAgentKey_Revoked(t *testing.T) {
	initDB(":memory:")
	cfg = &Config{
		AgentKey:      "test-agent-key-that-is-32-chars!!",
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}

	_, err := store.Exec(
		"INSERT INTO agent_credential (name, key_hash, revoked_at) VALUES (?, ?, datetime('now'))",
		"revoked-agent", hashAPIKey("revoked-key"),
	)
	if err != nil {
		t.Fatalf("insert revoked credential: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := requireAgentKey(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/agent", nil)
	req.Header.Set("Authorization", "Bearer revoked-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireProvisioningSecret_Valid(t *testing.T) {
	cfg = &Config{
		AgentKey:      "test-agent-key-that-is-32-chars!!",
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := requireProvisioningSecret(inner)

	req := httptest.NewRequest(http.MethodPost, "/api/provision", nil)
	req.Header.Set("X-Provisioning-Secret", cfg.AgentKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRequireProvisioningSecret_Wrong(t *testing.T) {
	cfg = &Config{
		AgentKey:      "test-agent-key-that-is-32-chars!!",
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := requireProvisioningSecret(inner)

	req := httptest.NewRequest(http.MethodPost, "/api/provision", nil)
	req.Header.Set("X-Provisioning-Secret", "wrong-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireProvisioningSecret_Unconfigured(t *testing.T) {
	cfg = &Config{
		AgentKey:      "",
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := requireProvisioningSecret(inner)

	req := httptest.NewRequest(http.MethodPost, "/api/provision", nil)
	req.Header.Set("X-Provisioning-Secret", "anything")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestRateLimit(t *testing.T) {
	initDB(":memory:")
	cfg = &Config{
		AgentKey:      "test-agent-key-that-is-32-chars!!",
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}

	// Reset rate limiter state so other tests don't interfere.
	limiter.mu.Lock()
	limiter.windows = make(map[string]*window)
	limiter.mu.Unlock()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rc := rateConfig{
		Max:    2,
		Window: time.Minute,
		Prefix: "test-rl",
	}
	handler := rateLimit(rc)(inner)

	ts := httptest.NewServer(handler)
	defer ts.Close()

	for i := 0; i < 3; i++ {
		resp, err := http.Get(ts.URL + "/test")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()

		if i < 2 && resp.StatusCode != http.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i, resp.StatusCode, http.StatusOK)
		}
		if i == 2 && resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("request %d: status = %d, want %d", i, resp.StatusCode, http.StatusTooManyRequests)
		}
	}
}
