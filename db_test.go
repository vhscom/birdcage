package main

import (
	"errors"
	"testing"
)

func TestInitDBMemory(t *testing.T) {
	initDB(":memory:")
	if store == nil {
		t.Fatalf("store is nil after initDB")
	}
	if err := store.Ping(); err != nil {
		t.Fatalf("store.Ping failed: %v", err)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	initDB(":memory:")
	// migrate() is already called by initDB; call it again to verify idempotency.
	migrate()
	if err := store.Ping(); err != nil {
		t.Fatalf("store.Ping failed after second migrate: %v", err)
	}
}

func TestSchemaVerification(t *testing.T) {
	initDB(":memory:")

	expected := []string{"account", "session", "security_event", "agent_credential", "node"}
	for _, table := range expected {
		var name string
		err := store.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q not found in sqlite_master: %v", table, err)
			continue
		}
		if name != table {
			t.Errorf("expected table name %q, got %q", table, name)
		}
	}
}

func TestIsUniqueViolation(t *testing.T) {
	if isUniqueViolation(nil) {
		t.Errorf("isUniqueViolation(nil) = true, want false")
	}
	if isUniqueViolation(errors.New("some generic error")) {
		t.Errorf("isUniqueViolation(generic error) = true, want false")
	}

	// Insert a duplicate email to trigger a real UNIQUE constraint violation.
	initDB(":memory:")
	_, err := store.Exec("INSERT INTO account (email, password_data) VALUES (?, ?)", "dup@test.com", "hash")
	if err != nil {
		t.Fatalf("first insert failed: %v", err)
	}
	_, err = store.Exec("INSERT INTO account (email, password_data) VALUES (?, ?)", "dup@test.com", "hash")
	if err == nil {
		t.Fatalf("expected error on duplicate insert, got nil")
	}
	if !isUniqueViolation(err) {
		t.Errorf("isUniqueViolation(duplicate email error) = false, want true; error was: %v", err)
	}
}
