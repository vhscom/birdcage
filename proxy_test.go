package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxy_HeaderStripping(t *testing.T) {
	// Backend that echoes received headers as JSON.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdrs := make(map[string]string)
		for _, name := range []string{"Cookie", "Authorization"} {
			if v := r.Header.Get(name); v != "" {
				hdrs[name] = v
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hdrs)
	}))
	defer backend.Close()

	cfg = &Config{GatewayURL: backend.URL}
	proxy := newProxy()

	req := httptest.NewRequest("GET", "/control/test", nil)
	req.Header.Set("Cookie", "session=abc123")
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var received map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&received); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if v, ok := received["Cookie"]; ok {
		t.Errorf("backend received Cookie header: %q", v)
	}
	if v, ok := received["Authorization"]; ok {
		t.Errorf("backend received Authorization header: %q", v)
	}
}

func TestProxy_PathRewriting(t *testing.T) {
	// Backend that echoes the request path.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.Path))
	}))
	defer backend.Close()

	cfg = &Config{GatewayURL: backend.URL}
	proxy := newProxy()

	req := httptest.NewRequest("GET", "/control/foo", nil)
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if body != "/foo" {
		t.Errorf("backend path = %q, want %q", body, "/foo")
	}
}

func TestProxy_BadGateway(t *testing.T) {
	cfg = &Config{GatewayURL: "http://127.0.0.1:1"}
	proxy := newProxy()

	req := httptest.NewRequest("GET", "/control/anything", nil)
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadGateway)
	}
}
