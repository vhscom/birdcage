package main

import (
	"testing"
)

func sessionTestSetup(t *testing.T) {
	t.Helper()
	initDB(":memory:")
	cfg = &Config{
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
	}
	_, err := store.Exec("INSERT INTO account (email, password_data) VALUES (?, ?)", "test@test.com", "hash")
	if err != nil {
		t.Fatalf("failed to insert test account: %v", err)
	}
}

func TestCreateAndGetSession(t *testing.T) {
	sessionTestSetup(t)

	sid, err := createSession(1, "TestAgent/1.0", "10.0.0.1")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	if sid == "" {
		t.Fatalf("createSession returned empty session ID")
	}

	sess, err := getSession(sid)
	if err != nil {
		t.Fatalf("getSession: %v", err)
	}
	if sess == nil {
		t.Fatalf("getSession returned nil for valid session")
	}
	if sess.ID != sid {
		t.Errorf("session ID = %q, want %q", sess.ID, sid)
	}
	if sess.UserID != 1 {
		t.Errorf("session UserID = %d, want 1", sess.UserID)
	}
	if sess.UserAgent != "TestAgent/1.0" {
		t.Errorf("session UserAgent = %q, want %q", sess.UserAgent, "TestAgent/1.0")
	}
	if sess.IPAddress != "10.0.0.1" {
		t.Errorf("session IPAddress = %q, want %q", sess.IPAddress, "10.0.0.1")
	}
	if sess.ExpiresAt.IsZero() {
		t.Errorf("session ExpiresAt is zero")
	}
	if sess.CreatedAt.IsZero() {
		t.Errorf("session CreatedAt is zero")
	}
}

func TestSessionExpiry(t *testing.T) {
	sessionTestSetup(t)

	sid, err := createSession(1, "TestAgent/1.0", "10.0.0.1")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Manually set expires_at to the past.
	_, err = store.Exec("UPDATE session SET expires_at = datetime('now', '-1 hour') WHERE id = ?", sid)
	if err != nil {
		t.Fatalf("failed to set expires_at to past: %v", err)
	}

	sess, err := getSession(sid)
	if err != nil {
		t.Fatalf("getSession: %v", err)
	}
	if sess != nil {
		t.Errorf("getSession returned non-nil for expired session")
	}
}

func TestEnforceSessionLimit(t *testing.T) {
	sessionTestSetup(t)

	var ids []string
	for i := 0; i < 4; i++ {
		sid, err := createSession(1, "TestAgent/1.0", "10.0.0.1")
		if err != nil {
			t.Fatalf("createSession #%d: %v", i+1, err)
		}
		ids = append(ids, sid)
	}

	// Count active sessions (expires_at in the future).
	var active int
	err := store.QueryRow(
		"SELECT COUNT(*) FROM session WHERE user_id = 1 AND expires_at > datetime('now')",
	).Scan(&active)
	if err != nil {
		t.Fatalf("count query: %v", err)
	}
	if active != maxSessions {
		t.Errorf("active sessions = %d, want %d", active, maxSessions)
	}
}

func TestEndSession(t *testing.T) {
	sessionTestSetup(t)

	sid, err := createSession(1, "TestAgent/1.0", "10.0.0.1")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	endSession(sid)

	sess, err := getSession(sid)
	if err != nil {
		t.Fatalf("getSession: %v", err)
	}
	if sess != nil {
		t.Errorf("getSession returned non-nil after endSession")
	}
}

func TestEndAllSessions(t *testing.T) {
	sessionTestSetup(t)

	sid1, err := createSession(1, "TestAgent/1.0", "10.0.0.1")
	if err != nil {
		t.Fatalf("createSession #1: %v", err)
	}
	sid2, err := createSession(1, "TestAgent/2.0", "10.0.0.2")
	if err != nil {
		t.Fatalf("createSession #2: %v", err)
	}

	endAllSessions(1)

	sess1, err := getSession(sid1)
	if err != nil {
		t.Fatalf("getSession #1: %v", err)
	}
	if sess1 != nil {
		t.Errorf("session 1 still active after endAllSessions")
	}

	sess2, err := getSession(sid2)
	if err != nil {
		t.Fatalf("getSession #2: %v", err)
	}
	if sess2 != nil {
		t.Errorf("session 2 still active after endAllSessions")
	}
}

func TestBumpRefreshGen(t *testing.T) {
	sessionTestSetup(t)

	sid, err := createSession(1, "TestAgent/1.0", "10.0.0.1")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	gen1, err := bumpRefreshGen(sid)
	if err != nil {
		t.Fatalf("bumpRefreshGen #1: %v", err)
	}
	if gen1 != 1 {
		t.Errorf("gen after first bump = %d, want 1", gen1)
	}

	gen2, err := bumpRefreshGen(sid)
	if err != nil {
		t.Fatalf("bumpRefreshGen #2: %v", err)
	}
	if gen2 != 2 {
		t.Errorf("gen after second bump = %d, want 2", gen2)
	}
}

func TestRevokeSessions_All(t *testing.T) {
	sessionTestSetup(t)

	_, err := createSession(1, "TestAgent/1.0", "10.0.0.1")
	if err != nil {
		t.Fatalf("createSession #1: %v", err)
	}
	_, err = createSession(1, "TestAgent/2.0", "10.0.0.2")
	if err != nil {
		t.Fatalf("createSession #2: %v", err)
	}

	count, code, msg := revokeSessions("all", nil)
	if code != "" {
		t.Errorf("revokeSessions(all) code = %q, msg = %q; want empty", code, msg)
	}
	if count != 2 {
		t.Errorf("revokeSessions(all) revoked = %d, want 2", count)
	}
}

func TestRevokeSessions_Session(t *testing.T) {
	sessionTestSetup(t)

	sid, err := createSession(1, "TestAgent/1.0", "10.0.0.1")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	count, code, msg := revokeSessions("session", sid)
	if code != "" {
		t.Errorf("revokeSessions(session) code = %q, msg = %q; want empty", code, msg)
	}
	if count != 1 {
		t.Errorf("revokeSessions(session) revoked = %d, want 1", count)
	}
}

func TestRevokeSessions_InvalidScope(t *testing.T) {
	sessionTestSetup(t)

	_, code, _ := revokeSessions("invalid", nil)
	if code == "" {
		t.Errorf("revokeSessions(invalid) should return non-empty error code")
	}
	if code != "INVALID_SCOPE" {
		t.Errorf("revokeSessions(invalid) code = %q, want %q", code, "INVALID_SCOPE")
	}
}
