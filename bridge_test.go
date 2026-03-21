package main

import (
	"encoding/json"
	"testing"
)

func TestInjectToken_ConnectFrame(t *testing.T) {
	input := `{"type":"req","method":"connect","params":{}}`
	result := injectToken([]byte(input), "mytoken")

	var f map[string]any
	if err := json.Unmarshal(result, &f); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	params, ok := f["params"].(map[string]any)
	if !ok {
		t.Fatalf("params is not a map")
	}
	auth, ok := params["auth"].(map[string]any)
	if !ok {
		t.Fatalf("params.auth is not a map")
	}
	tok, ok := auth["token"].(string)
	if !ok {
		t.Fatalf("params.auth.token is not a string")
	}
	if tok != "mytoken" {
		t.Errorf("params.auth.token = %q, want %q", tok, "mytoken")
	}
}

func TestInjectToken_ScopesInjected(t *testing.T) {
	input := `{"type":"req","method":"connect","params":{}}`
	result := injectToken([]byte(input), "mytoken")

	var f map[string]any
	if err := json.Unmarshal(result, &f); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	params := f["params"].(map[string]any)

	scopes, ok := params["scopes"].([]any)
	if !ok {
		t.Fatalf("params.scopes is not an array: %T", params["scopes"])
	}
	if len(scopes) != 1 || scopes[0] != "operator.admin" {
		t.Errorf("params.scopes = %v, want [operator.admin]", scopes)
	}
}

func TestInjectToken_ScopesPreserved(t *testing.T) {
	input := `{"type":"req","method":"connect","params":{"scopes":["operator.read","operator.write"]}}`
	result := injectToken([]byte(input), "mytoken")

	var f map[string]any
	if err := json.Unmarshal(result, &f); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	params := f["params"].(map[string]any)

	scopes, ok := params["scopes"].([]any)
	if !ok {
		t.Fatalf("params.scopes is not an array: %T", params["scopes"])
	}
	if len(scopes) != 2 {
		t.Errorf("params.scopes = %v, want [operator.read operator.write] (preserved)", scopes)
	}
}

func TestInjectToken_EmptyTokenPassthrough(t *testing.T) {
	input := `{"type":"req","method":"connect","params":{}}`
	result := injectToken([]byte(input), "")

	if string(result) != input {
		t.Errorf("empty token should pass through unchanged")
	}
}

func TestInjectToken_NonConnectFrame(t *testing.T) {
	input := `{"type":"ping"}`
	result := injectToken([]byte(input), "mytoken")

	// Output should be unchanged from the input.
	var orig, got map[string]any
	json.Unmarshal([]byte(input), &orig)
	if err := json.Unmarshal(result, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if got["type"] != "ping" {
		t.Errorf("type = %v, want %q", got["type"], "ping")
	}
	if _, exists := got["params"]; exists {
		t.Errorf("non-connect frame should not have params added")
	}
}

func TestInjectToken_InvalidJSON(t *testing.T) {
	input := "not json"
	result := injectToken([]byte(input), "mytoken")

	if string(result) != input {
		t.Errorf("result = %q, want %q (unchanged)", string(result), input)
	}
}

func TestToWS(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://localhost", "ws://localhost"},
		{"https://localhost", "wss://localhost"},
		{"http://example.com:8080/path", "ws://example.com:8080/path"},
		{"https://example.com/path", "wss://example.com/path"},
	}

	for _, tt := range tests {
		got := toWS(tt.input)
		if got != tt.want {
			t.Errorf("toWS(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
