package main

import (
	"testing"

	"birdcage/internal/wgkey"
)

func nodeTestSetup(t *testing.T) {
	t.Helper()
	initDB(":memory:")
	cfg = &Config{}
}

func TestLookupNodeForAgent_Creates(t *testing.T) {
	nodeTestSetup(t)

	// Insert an agent credential.
	_, err := store.Exec("INSERT INTO agent_credential (name, key_hash) VALUES (?, ?)", "test-agent", "fakehash")
	if err != nil {
		t.Fatalf("insert agent_credential: %v", err)
	}

	nodeID := lookupNodeForAgent(1)
	if nodeID == 0 {
		t.Fatalf("lookupNodeForAgent returned 0, expected a new node ID")
	}

	// Verify the node was created with the expected mesh IP.
	var allowedIPs string
	err = store.QueryRow("SELECT allowed_ips FROM node WHERE id = ?", nodeID).Scan(&allowedIPs)
	if err != nil {
		t.Fatalf("query node: %v", err)
	}
	if allowedIPs != "10.0.0.2/32" {
		t.Errorf("allowed_ips = %q, want %q", allowedIPs, "10.0.0.2/32")
	}
}

func TestNextMeshIP(t *testing.T) {
	nodeTestSetup(t)

	// Insert two nodes occupying .2 and .3.
	_, err := store.Exec(
		"INSERT INTO agent_credential (name, key_hash) VALUES (?, ?)", "a1", "h1",
	)
	if err != nil {
		t.Fatalf("insert agent_credential: %v", err)
	}
	_, err = store.Exec(
		"INSERT INTO agent_credential (name, key_hash) VALUES (?, ?)", "a2", "h2",
	)
	if err != nil {
		t.Fatalf("insert agent_credential: %v", err)
	}

	_, err = store.Exec(
		"INSERT INTO node (label, wg_pubkey, allowed_ips, agent_credential_id) VALUES (?, ?, ?, ?)",
		"node-a", "pending", "10.0.0.2/32", 1,
	)
	if err != nil {
		t.Fatalf("insert node 1: %v", err)
	}
	_, err = store.Exec(
		"INSERT INTO node (label, wg_pubkey, allowed_ips, agent_credential_id) VALUES (?, ?, ?, ?)",
		"node-b", "pending", "10.0.0.3/32", 2,
	)
	if err != nil {
		t.Fatalf("insert node 2: %v", err)
	}

	got := nextMeshIP()
	if got != "10.0.0.4/32" {
		t.Errorf("nextMeshIP() = %q, want %q", got, "10.0.0.4/32")
	}
}

func TestNextMeshIP_SkipsServer(t *testing.T) {
	nodeTestSetup(t)

	// No nodes in the database yet. First call should skip .1 (server) and return .2.
	got := nextMeshIP()
	if got != "10.0.0.2/32" {
		t.Errorf("nextMeshIP() = %q, want %q", got, "10.0.0.2/32")
	}
}

func TestDeriveWGPublicKey(t *testing.T) {
	privKey, pubKey, err := wgkey.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	derived := deriveWGPublicKey(privKey)
	if derived == "" {
		t.Fatalf("deriveWGPublicKey returned empty string")
	}
	if derived != pubKey {
		t.Errorf("deriveWGPublicKey = %q, want %q", derived, pubKey)
	}
}
