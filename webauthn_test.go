package main

import (
	"net/http"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// --- DB helper tests ---

func TestInsertAndListPasskeys(t *testing.T) {
	initDB(":memory:")
	store.Exec("INSERT INTO account (email, password_data) VALUES (?, ?)", "test@example.com", "hash")

	cred := &webauthn.Credential{
		ID:        []byte("cred-id-1"),
		PublicKey: []byte("pubkey-1"),
		Transport: []protocol.AuthenticatorTransport{"internal"},
		Authenticator: webauthn.Authenticator{
			AAGUID:    []byte("aaguid-1234567890"),
			SignCount: 0,
		},
	}

	id, err := insertPasskey(1, cred, "Test Key")
	if err != nil {
		t.Fatalf("insertPasskey: %v", err)
	}
	if id <= 0 {
		t.Fatalf("expected positive id, got %d", id)
	}

	keys, err := listPasskeys(1)
	if err != nil {
		t.Fatalf("listPasskeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 passkey, got %d", len(keys))
	}
	if keys[0].Name != "Test Key" {
		t.Errorf("name = %q, want %q", keys[0].Name, "Test Key")
	}
	if keys[0].LastUsedAt != nil {
		t.Errorf("lastUsedAt should be nil for a fresh passkey")
	}
}

func TestListPasskeysEmpty(t *testing.T) {
	initDB(":memory:")
	store.Exec("INSERT INTO account (email, password_data) VALUES (?, ?)", "test@example.com", "hash")

	keys, err := listPasskeys(1)
	if err != nil {
		t.Fatalf("listPasskeys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 passkeys, got %d", len(keys))
	}
}

func TestDeletePasskey(t *testing.T) {
	initDB(":memory:")
	store.Exec("INSERT INTO account (email, password_data) VALUES (?, ?)", "test@example.com", "hash")

	cred := &webauthn.Credential{
		ID:        []byte("cred-id-1"),
		PublicKey: []byte("pubkey-1"),
		Authenticator: webauthn.Authenticator{
			AAGUID: []byte("aaguid-1234567890"),
		},
	}

	id, _ := insertPasskey(1, cred, "To Delete")

	ok, err := deletePasskey(1, int(id))
	if err != nil {
		t.Fatalf("deletePasskey: %v", err)
	}
	if !ok {
		t.Fatalf("deletePasskey returned false")
	}

	keys, _ := listPasskeys(1)
	if len(keys) != 0 {
		t.Fatalf("expected 0 passkeys after delete, got %d", len(keys))
	}
}

func TestDeletePasskey_WrongUser(t *testing.T) {
	initDB(":memory:")
	store.Exec("INSERT INTO account (email, password_data) VALUES (?, ?)", "user1@example.com", "hash")
	store.Exec("INSERT INTO account (email, password_data) VALUES (?, ?)", "user2@example.com", "hash")

	cred := &webauthn.Credential{
		ID:        []byte("cred-id-1"),
		PublicKey: []byte("pubkey-1"),
		Authenticator: webauthn.Authenticator{
			AAGUID: []byte("aaguid-1234567890"),
		},
	}

	id, _ := insertPasskey(1, cred, "User1 Key")

	// User 2 should not be able to delete user 1's passkey
	ok, err := deletePasskey(2, int(id))
	if err != nil {
		t.Fatalf("deletePasskey: %v", err)
	}
	if ok {
		t.Fatalf("user 2 was able to delete user 1's passkey")
	}

	// Verify it still exists for user 1
	keys, _ := listPasskeys(1)
	if len(keys) != 1 {
		t.Fatalf("expected 1 passkey for user 1, got %d", len(keys))
	}
}

func TestUpdatePasskeySignCount(t *testing.T) {
	initDB(":memory:")
	store.Exec("INSERT INTO account (email, password_data) VALUES (?, ?)", "test@example.com", "hash")

	credID := []byte("cred-id-sign-count")
	cred := &webauthn.Credential{
		ID:        credID,
		PublicKey: []byte("pubkey-1"),
		Authenticator: webauthn.Authenticator{
			AAGUID:    []byte("aaguid-1234567890"),
			SignCount: 0,
		},
	}

	insertPasskey(1, cred, "Counter Test")

	if err := updatePasskeySignCount(credID, 42); err != nil {
		t.Fatalf("updatePasskeySignCount: %v", err)
	}

	creds, err := loadCredentialsByUser(1)
	if err != nil {
		t.Fatalf("loadCredentialsByUser: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Authenticator.SignCount != 42 {
		t.Errorf("sign count = %d, want 42", creds[0].Authenticator.SignCount)
	}

	// Verify last_used_at was set
	keys, _ := listPasskeys(1)
	if len(keys) != 1 {
		t.Fatalf("expected 1 passkey, got %d", len(keys))
	}
	if keys[0].LastUsedAt == nil {
		t.Errorf("last_used_at should be set after sign count update")
	}
}

func TestLoadCredentialsByUser(t *testing.T) {
	initDB(":memory:")
	store.Exec("INSERT INTO account (email, password_data) VALUES (?, ?)", "test@example.com", "hash")

	cred := &webauthn.Credential{
		ID:        []byte("cred-id-load"),
		PublicKey: []byte("pubkey-load"),
		Transport: []protocol.AuthenticatorTransport{"internal", "hybrid"},
		Authenticator: webauthn.Authenticator{
			AAGUID:    []byte("aaguid-1234567890"),
			SignCount: 5,
		},
	}

	insertPasskey(1, cred, "Load Test")

	creds, err := loadCredentialsByUser(1)
	if err != nil {
		t.Fatalf("loadCredentialsByUser: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if string(creds[0].ID) != "cred-id-load" {
		t.Errorf("credential ID mismatch")
	}
	if string(creds[0].PublicKey) != "pubkey-load" {
		t.Errorf("public key mismatch")
	}
	if len(creds[0].Transport) != 2 {
		t.Errorf("expected 2 transports, got %d", len(creds[0].Transport))
	}
	if creds[0].Authenticator.SignCount != 5 {
		t.Errorf("sign count = %d, want 5", creds[0].Authenticator.SignCount)
	}
}

// --- Transport serialization tests ---

func TestSerializeTransports(t *testing.T) {
	tests := []struct {
		name   string
		input  []protocol.AuthenticatorTransport
		expect string
	}{
		{"nil", nil, ""},
		{"empty", []protocol.AuthenticatorTransport{}, ""},
		{"single", []protocol.AuthenticatorTransport{"internal"}, "internal"},
		{"multiple", []protocol.AuthenticatorTransport{"internal", "hybrid", "usb"}, "internal,hybrid,usb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serializeTransports(tt.input)
			if got != tt.expect {
				t.Errorf("serializeTransports = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestDeserializeTransports(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect int
	}{
		{"empty", "", 0},
		{"single", "internal", 1},
		{"multiple", "internal,hybrid,usb", 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deserializeTransports(tt.input)
			if len(got) != tt.expect {
				t.Errorf("len(deserializeTransports) = %d, want %d", len(got), tt.expect)
			}
		})
	}
}

// --- HTTP handler tests ---

func TestPasskeyLoginBegin_ReturnsChallenge(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, result := jsonPost(ts.URL+"/auth/passkey/begin", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if result["publicKey"] == nil {
		t.Errorf("response missing publicKey field")
	}
}

func TestPasskeyLoginFinish_NoPendingChallenge(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Clear any pending challenge
	challenges.Lock()
	challenges.login = nil
	challenges.Unlock()

	resp, result := jsonPost(ts.URL+"/auth/passkey/finish", map[string]any{}, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if code, ok := result["code"].(string); !ok || code != "NO_CHALLENGE" {
		t.Errorf("code = %v, want NO_CHALLENGE", result["code"])
	}
}

func TestPasskeyRegisterBegin_Unauthenticated(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, _ := jsonPost(ts.URL+"/account/passkey/begin", nil, nil)
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestPasskeyRegisterFinish_Unauthenticated(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, _ := jsonPost(ts.URL+"/account/passkey/finish", nil, nil)
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestPasskeyList_Unauthenticated(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, _ := jsonGet(ts.URL+"/account/passkeys", nil)
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestPasskeyList_Empty(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Register and login to get cookies
	jsonPost(ts.URL+"/auth/register", map[string]any{
		"email": "test@example.com", "password": "testpass123",
	}, nil)
	resp, _ := jsonPost(ts.URL+"/auth/login", map[string]any{
		"email": "test@example.com", "password": "testpass123",
	}, nil)

	resp, result := jsonGet(ts.URL+"/account/passkeys", resp.Cookies())
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	passkeys, ok := result["passkeys"].([]any)
	if !ok {
		t.Fatalf("passkeys field is not an array: %T", result["passkeys"])
	}
	if len(passkeys) != 0 {
		t.Errorf("expected 0 passkeys, got %d", len(passkeys))
	}
}

func TestPasskeyRegisterBegin_Authenticated(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Register and login
	jsonPost(ts.URL+"/auth/register", map[string]any{
		"email": "test@example.com", "password": "testpass123",
	}, nil)
	loginResp, _ := jsonPost(ts.URL+"/auth/login", map[string]any{
		"email": "test@example.com", "password": "testpass123",
	}, nil)

	resp, result := jsonPost(ts.URL+"/account/passkey/begin", nil, loginResp.Cookies())
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if result["publicKey"] == nil {
		t.Errorf("response missing publicKey field")
	}
}

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com", "example.com"},
		{"https://example.com:8443", "example.com"},
		{"http://localhost:3000", "localhost"},
		{"https://birdcage.example.com/path", "birdcage.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractHostname(tt.input)
			if got != tt.want {
				t.Errorf("extractHostname(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestWebAuthnUser_Interface(t *testing.T) {
	u := &webAuthnUser{id: 42, email: "test@example.com", credentials: nil}

	id := u.WebAuthnID()
	if len(id) != 8 {
		t.Fatalf("WebAuthnID length = %d, want 8", len(id))
	}
	if u.WebAuthnName() != "test@example.com" {
		t.Errorf("WebAuthnName = %q, want %q", u.WebAuthnName(), "test@example.com")
	}
	if u.WebAuthnDisplayName() != "test@example.com" {
		t.Errorf("WebAuthnDisplayName = %q, want %q", u.WebAuthnDisplayName(), "test@example.com")
	}
	if u.WebAuthnCredentials() != nil {
		t.Errorf("WebAuthnCredentials should be nil for user with no creds")
	}
}

func TestHasPasskeys(t *testing.T) {
	initDB(":memory:")
	store.Exec("INSERT INTO account (email, password_data) VALUES (?, ?)", "test@example.com", "hash")

	if hasPasskeys() {
		t.Errorf("hasPasskeys() = true before any passkeys registered")
	}

	cred := &webauthn.Credential{
		ID:        []byte("cred-id-hp"),
		PublicKey: []byte("pubkey-hp"),
		Authenticator: webauthn.Authenticator{
			AAGUID: []byte("aaguid-1234567890"),
		},
	}
	insertPasskey(1, cred, "test")

	if !hasPasskeys() {
		t.Errorf("hasPasskeys() = false after passkey registered")
	}
}

func TestAuthStatus_IncludesPasskeys(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Before registration, passkeys field should not be present
	_, result := jsonGet(ts.URL+"/auth/status", nil)
	if _, exists := result["passkeys"]; exists {
		t.Errorf("passkeys field should not be present when not registered")
	}

	// Register
	jsonPost(ts.URL+"/auth/register", map[string]any{
		"email": "test@example.com", "password": "testpass123",
	}, nil)

	// After registration, passkeys should be false
	_, result = jsonGet(ts.URL+"/auth/status", nil)
	if pk, ok := result["passkeys"].(bool); !ok || pk {
		t.Errorf("passkeys = %v, want false", result["passkeys"])
	}
}

func TestPasskeyNameFromRequest(t *testing.T) {
	tests := []struct {
		query string
		want  string
	}{
		{"", "Passkey"},
		{"?name=MyKey", "MyKey"},
		{"?name=", "Passkey"},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			r, _ := http.NewRequest("POST", "/finish"+tt.query, nil)
			got := passkeyNameFromRequest(r)
			if got != tt.want {
				t.Errorf("passkeyNameFromRequest = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMigrateIdempotent_WithPasskey(t *testing.T) {
	initDB(":memory:")
	migrate()
	// Verify passkey table exists after double migrate
	var name string
	err := store.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='passkey'").Scan(&name)
	if err != nil {
		t.Errorf("passkey table not found after double migrate: %v", err)
	}
}
