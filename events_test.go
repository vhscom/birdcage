package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestEmitEvent(t *testing.T) {
	initDB(":memory:")
	cfg = &Config{
		AgentKey:      "test-agent-key-that-is-32-chars!!",
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}

	emitEvent("login.success", "10.0.0.1", 1, "TestAgent/1.0", 200, nil)

	var evType, ip string
	err := store.QueryRow("SELECT type, ip_address FROM security_event ORDER BY id DESC LIMIT 1").Scan(&evType, &ip)
	if err != nil {
		t.Fatalf("query security_event: %v", err)
	}
	if evType != "login.success" {
		t.Errorf("type = %q, want %q", evType, "login.success")
	}
	if ip != "10.0.0.1" {
		t.Errorf("ip_address = %q, want %q", ip, "10.0.0.1")
	}
}

func TestEmitEventWithDetail(t *testing.T) {
	initDB(":memory:")
	cfg = &Config{
		AgentKey:      "test-agent-key-that-is-32-chars!!",
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}

	detail := map[string]any{"reason": "bad_password", "attempts": float64(3)}
	emitEvent("login.failure", "10.0.0.2", 0, "TestAgent/1.0", 401, detail)

	var raw string
	err := store.QueryRow("SELECT detail FROM security_event ORDER BY id DESC LIMIT 1").Scan(&raw)
	if err != nil {
		t.Fatalf("query detail: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("unmarshal detail: %v", err)
	}
	if got["reason"] != "bad_password" {
		t.Errorf("detail[reason] = %v, want %q", got["reason"], "bad_password")
	}
	if got["attempts"] != float64(3) {
		t.Errorf("detail[attempts] = %v, want 3", got["attempts"])
	}
}

func TestComputeChallenge_BelowThreshold(t *testing.T) {
	initDB(":memory:")
	cfg = &Config{
		AgentKey:      "test-agent-key-that-is-32-chars!!",
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}

	ch := computeChallenge("192.168.1.100", cfg.AccessSecret)
	if ch != nil {
		t.Errorf("expected nil challenge for fresh IP, got %+v", ch)
	}
}

func TestComputeChallenge_AboveThreshold(t *testing.T) {
	initDB(":memory:")
	cfg = &Config{
		AgentKey:      "test-agent-key-that-is-32-chars!!",
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}

	ip := "192.168.1.200"
	for i := 0; i < 4; i++ {
		emitEvent("login.failure", ip, 0, "TestAgent/1.0", 401, nil)
	}

	ch := computeChallenge(ip, cfg.AccessSecret)
	if ch == nil {
		t.Fatalf("expected non-nil challenge after 4 failures")
	}
	if ch.Difficulty < 1 {
		t.Errorf("difficulty = %d, want >= 1", ch.Difficulty)
	}
	if ch.Type != "pow" {
		t.Errorf("type = %q, want %q", ch.Type, "pow")
	}
	if ch.Nonce == "" {
		t.Errorf("nonce is empty")
	}
}

func TestBuildAndVerifySignedNonce(t *testing.T) {
	secret := "test-access-secret-that-is-32-chars!!"
	ip := "10.0.0.1"

	nonce := buildSignedNonce(secret, ip)
	if nonce == "" {
		t.Fatalf("buildSignedNonce returned empty string")
	}
	if !verifySignedNonce(nonce, secret, ip) {
		t.Errorf("verifySignedNonce returned false for valid nonce")
	}
}

func TestVerifySignedNonce_WrongIP(t *testing.T) {
	secret := "test-access-secret-that-is-32-chars!!"

	nonce := buildSignedNonce(secret, "10.0.0.1")
	if verifySignedNonce(nonce, secret, "10.0.0.99") {
		t.Errorf("verifySignedNonce should return false for wrong IP")
	}
}

func TestVerifySolution(t *testing.T) {
	nonce := buildSignedNonce("test-secret", "10.0.0.1")
	difficulty := 1 // 1 leading hex zero

	// Brute-force a valid solution.
	var solution string
	for i := 0; i < 1_000_000; i++ {
		candidate := fmt.Sprintf("%d", i)
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(nonce+candidate)))
		if strings.HasPrefix(hash, "0") {
			solution = candidate
			break
		}
	}
	if solution == "" {
		t.Fatalf("could not find solution for difficulty=%d", difficulty)
	}
	if !verifySolution(nonce, solution, difficulty) {
		t.Errorf("verifySolution returned false for valid solution %q", solution)
	}
}

func TestVerifySolution_Wrong(t *testing.T) {
	nonce := buildSignedNonce("test-secret", "10.0.0.1")
	if verifySolution(nonce, "wrong", 1) {
		t.Errorf("verifySolution should return false for invalid solution")
	}
}

func TestPruneEvents(t *testing.T) {
	initDB(":memory:")
	cfg = &Config{
		AgentKey:      "test-agent-key-that-is-32-chars!!",
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}

	emitEvent("login.success", "10.0.0.1", 0, "TestAgent/1.0", 200, nil)

	// Backdate the event to 91 days ago so it exceeds the retention window.
	_, err := store.Exec("UPDATE security_event SET created_at = datetime('now', '-91 days')")
	if err != nil {
		t.Fatalf("backdate event: %v", err)
	}

	pruneEvents()

	var count int
	err = store.QueryRow("SELECT COUNT(*) FROM security_event").Scan(&count)
	if err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 events after prune, got %d", count)
	}
}

func TestEventSignal(t *testing.T) {
	// Reset the broadcast channel for a clean test.
	eventBroadcast.mu.Lock()
	eventBroadcast.ch = make(chan struct{})
	eventBroadcast.mu.Unlock()

	ch := eventSignal()
	select {
	case <-ch:
		t.Fatalf("channel should not be closed before notifySubscribers")
	default:
	}

	notifySubscribers()

	select {
	case <-ch:
		// success: channel was closed
	default:
		t.Errorf("channel should be closed after notifySubscribers")
	}
}
