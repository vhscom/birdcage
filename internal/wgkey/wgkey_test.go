package wgkey

import (
	"encoding/base64"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	for _, tc := range []struct {
		name string
		key  string
	}{
		{"private", priv},
		{"public", pub},
	} {
		if len(tc.key) != 44 {
			t.Errorf("%s key length = %d, want 44", tc.name, len(tc.key))
		}
		if tc.key[len(tc.key)-1] != '=' {
			t.Errorf("%s key should end with '=', got %q", tc.name, tc.key[len(tc.key)-1:])
		}
		if _, err := base64.StdEncoding.DecodeString(tc.key); err != nil {
			t.Errorf("%s key is not valid base64: %v", tc.name, err)
		}
	}
}

func TestGenerateKeypairUniqueness(t *testing.T) {
	priv1, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (1): %v", err)
	}
	priv2, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (2): %v", err)
	}
	if priv1 == priv2 {
		t.Error("two generated private keys should differ")
	}
}
