package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWantsJSON(t *testing.T) {
	cases := []struct {
		accept string
		want   bool
	}{
		{"application/json", true},
		{"text/html", false},
		{"", false},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		if tc.accept != "" {
			r.Header.Set("Accept", tc.accept)
		}
		got := wantsJSON(r)
		if got != tc.want {
			t.Errorf("wantsJSON(Accept: %q) = %v, want %v", tc.accept, got, tc.want)
		}
	}
}

func TestJsonOK(t *testing.T) {
	w := httptest.NewRecorder()
	jsonOK(w, map[string]string{"key": "value"})

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if body["key"] != "value" {
		t.Errorf("body[\"key\"] = %q, want %q", body["key"], "value")
	}
}

func TestJsonError(t *testing.T) {
	w := httptest.NewRecorder()
	jsonError(w, http.StatusBadRequest, "BAD_INPUT", "invalid request")

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if body["error"] != "invalid request" {
		t.Errorf("body[\"error\"] = %q, want %q", body["error"], "invalid request")
	}
	if body["code"] != "BAD_INPUT" {
		t.Errorf("body[\"code\"] = %q, want %q", body["code"], "BAD_INPUT")
	}
}

func TestJsonCreated(t *testing.T) {
	w := httptest.NewRecorder()
	jsonCreated(w, map[string]string{"id": "123"})

	resp := w.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if body["id"] != "123" {
		t.Errorf("body[\"id\"] = %q, want %q", body["id"], "123")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	got := clientIP(r)
	if got != "1.2.3.4" {
		t.Errorf("clientIP = %q, want %q", got, "1.2.3.4")
	}
}

func TestHandleHealth(t *testing.T) {
	initDB(":memory:")
	cfg = &Config{
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/health", nil)
	handleHealth(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("body[\"status\"] = %v, want %q", body["status"], "ok")
	}
}
