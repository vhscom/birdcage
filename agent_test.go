package main

import "testing"

// --- ensureAgentCredential ---

func TestEnsureAgentCredential_Create(t *testing.T) {
	initDB(":memory:")
	cfg = &Config{AgentKey: "test-agent-key-that-is-32-chars!!"}
	ensureAgentCredential()

	var name string
	err := store.QueryRow(
		"SELECT name FROM agent_credential WHERE key_hash = ? AND revoked_at IS NULL",
		hashAPIKey(cfg.AgentKey),
	).Scan(&name)
	if err != nil {
		t.Fatalf("credential not found: %v", err)
	}
	if name != "home" {
		t.Errorf("name = %q, want %q", name, "home")
	}
}

func TestEnsureAgentCredential_NoOp(t *testing.T) {
	initDB(":memory:")
	cfg = &Config{AgentKey: "test-agent-key-that-is-32-chars!!"}
	ensureAgentCredential()
	ensureAgentCredential() // second call with same key — should be a no-op

	var count int
	store.QueryRow("SELECT COUNT(*) FROM agent_credential").Scan(&count)
	if count != 1 {
		t.Errorf("credential count = %d, want 1", count)
	}
}

func TestEnsureAgentCredential_Rotate(t *testing.T) {
	initDB(":memory:")
	cfg = &Config{AgentKey: "old-agent-key-that-is-32-chars!!"}
	ensureAgentCredential()

	cfg = &Config{AgentKey: "new-agent-key-that-is-32-chars!!"}
	ensureAgentCredential()

	// "home" should now carry the new key hash
	var name string
	err := store.QueryRow(
		"SELECT name FROM agent_credential WHERE key_hash = ? AND revoked_at IS NULL",
		hashAPIKey(cfg.AgentKey),
	).Scan(&name)
	if err != nil {
		t.Fatalf("new key not found: %v", err)
	}
	if name != "home" {
		t.Errorf("name = %q, want %q", name, "home")
	}

	// Old key should no longer match any active credential
	var count int
	store.QueryRow(
		"SELECT COUNT(*) FROM agent_credential WHERE key_hash = ? AND revoked_at IS NULL",
		hashAPIKey("old-agent-key-that-is-32-chars!!"),
	).Scan(&count)
	if count != 0 {
		t.Errorf("old key still active: count = %d, want 0", count)
	}
}

func TestEnsureAgentCredential_RevokedKeyExists(t *testing.T) {
	// Key hash exists on a revoked credential (the scenario that triggered the bug).
	// ensureAgentCredential should still rotate "home" to the new key.
	initDB(":memory:")
	cfg = &Config{AgentKey: "old-agent-key-that-is-32-chars!!"}
	ensureAgentCredential() // creates "home" with old key

	newKey := "new-agent-key-that-is-32-chars!!"
	newHash := hashAPIKey(newKey)

	// Simulate old behavior: new key was registered as a separate credential,
	// then revoked.
	store.Exec(
		"INSERT INTO agent_credential (name, key_hash, revoked_at) VALUES ('agent-orphan', ?, datetime('now'))",
		newHash,
	)

	cfg = &Config{AgentKey: newKey}
	ensureAgentCredential()

	// "home" should now carry the new key hash
	var name string
	err := store.QueryRow(
		"SELECT name FROM agent_credential WHERE key_hash = ? AND revoked_at IS NULL",
		newHash,
	).Scan(&name)
	if err != nil {
		t.Fatalf("new key not active: %v", err)
	}
	if name != "home" {
		t.Errorf("name = %q, want %q", name, "home")
	}
}

func TestEnsureAgentCredential_HomeRevoked(t *testing.T) {
	// If "home" has been intentionally revoked, a new key should not resurrect it.
	initDB(":memory:")
	cfg = &Config{AgentKey: "old-agent-key-that-is-32-chars!!"}
	ensureAgentCredential()
	store.Exec("UPDATE agent_credential SET revoked_at = datetime('now') WHERE name = 'home'")

	cfg = &Config{AgentKey: "new-agent-key-that-is-32-chars!!"}
	ensureAgentCredential()

	var count int
	store.QueryRow(
		"SELECT COUNT(*) FROM agent_credential WHERE revoked_at IS NULL",
	).Scan(&count)
	if count != 0 {
		t.Errorf("active credential count = %d, want 0", count)
	}
}
