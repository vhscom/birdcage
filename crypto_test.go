package main

import (
	"encoding/hex"
	"testing"
	"time"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := hashPassword("correcthorse")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !verifyPassword("correcthorse", hash) {
		t.Errorf("verifyPassword returned false for correct password")
	}
	if verifyPassword("wrongpassword", hash) {
		t.Errorf("verifyPassword returned true for wrong password")
	}
}

func TestPasswordNormalization(t *testing.T) {
	hash, err := hashPassword("  hello   world  ")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !verifyPassword("hello world", hash) {
		t.Errorf("normalized password should verify against hash created with extra whitespace")
	}
	if !verifyPassword("  hello   world  ", hash) {
		t.Errorf("password with extra whitespace should verify against its own hash")
	}
}

func TestVerifyPasswordBadFormat(t *testing.T) {
	cases := []string{
		"",
		"not-a-hash",
		"$pbkdf2-sha384$v1$short",
		"$$$$$$",
		"random garbage 123!@#",
	}
	for _, bad := range cases {
		if verifyPassword("anything", bad) {
			t.Errorf("verifyPassword should return false for bad format %q", bad)
		}
	}
}

func TestRejectConstantTime(t *testing.T) {
	// rejectConstantTime should complete without panic.
	rejectConstantTime("somepassword")
}

func TestSignAndVerifyToken(t *testing.T) {
	secret := "test-secret-key"
	tok, err := signToken(42, "sess-abc", "access", secret, 15*time.Minute)
	if err != nil {
		t.Fatalf("signToken: %v", err)
	}
	claims, err := verifyToken(tok, secret, "access")
	if err != nil {
		t.Fatalf("verifyToken: %v", err)
	}
	if claims.UID != 42 {
		t.Errorf("UID = %d, want 42", claims.UID)
	}
	if claims.SID != "sess-abc" {
		t.Errorf("SID = %q, want %q", claims.SID, "sess-abc")
	}
	if claims.Typ != "access" {
		t.Errorf("Typ = %q, want %q", claims.Typ, "access")
	}
}

func TestVerifyTokenWrongType(t *testing.T) {
	secret := "test-secret-key"
	tok, err := signRefreshToken(1, "sess-1", secret, 1)
	if err != nil {
		t.Fatalf("signRefreshToken: %v", err)
	}
	_, err = verifyToken(tok, secret, "access")
	if err == nil {
		t.Errorf("verifyToken should fail when expected type does not match")
	}
}

func TestVerifyTokenWrongSecret(t *testing.T) {
	tok, err := signToken(1, "sess-1", "access", "secret-one", 15*time.Minute)
	if err != nil {
		t.Fatalf("signToken: %v", err)
	}
	_, err = verifyToken(tok, "secret-two", "access")
	if err == nil {
		t.Errorf("verifyToken should fail when secret does not match")
	}
}

func TestSignRefreshToken(t *testing.T) {
	secret := "refresh-secret"
	tok, err := signRefreshToken(7, "sess-r", secret, 5)
	if err != nil {
		t.Fatalf("signRefreshToken: %v", err)
	}
	claims, err := verifyToken(tok, secret, "refresh")
	if err != nil {
		t.Fatalf("verifyToken: %v", err)
	}
	if claims.Gen != 5 {
		t.Errorf("Gen = %d, want 5", claims.Gen)
	}
	if claims.UID != 7 {
		t.Errorf("UID = %d, want 7", claims.UID)
	}
	if claims.Typ != "refresh" {
		t.Errorf("Typ = %q, want %q", claims.Typ, "refresh")
	}
}

func TestHashAPIKey(t *testing.T) {
	h := hashAPIKey("my-api-key")
	if len(h) != 64 {
		t.Errorf("hashAPIKey length = %d, want 64", len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		t.Errorf("hashAPIKey output is not valid hex: %v", err)
	}
	// Deterministic: same input produces same output.
	if h2 := hashAPIKey("my-api-key"); h2 != h {
		t.Errorf("hashAPIKey is not deterministic: %q != %q", h, h2)
	}
}

func TestRandomHex(t *testing.T) {
	t.Run("16 bytes", func(t *testing.T) {
		out := randomHex(16)
		if len(out) != 32 {
			t.Errorf("randomHex(16) length = %d, want 32", len(out))
		}
		if _, err := hex.DecodeString(out); err != nil {
			t.Errorf("randomHex(16) output is not valid hex: %v", err)
		}
	})
	t.Run("32 bytes", func(t *testing.T) {
		out := randomHex(32)
		if len(out) != 64 {
			t.Errorf("randomHex(32) length = %d, want 64", len(out))
		}
		if _, err := hex.DecodeString(out); err != nil {
			t.Errorf("randomHex(32) output is not valid hex: %v", err)
		}
	})
	t.Run("uniqueness", func(t *testing.T) {
		a := randomHex(16)
		b := randomHex(16)
		if a == b {
			t.Errorf("two calls to randomHex returned identical values: %q", a)
		}
	})
}
