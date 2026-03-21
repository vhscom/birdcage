package api

import (
	"testing"
)

func TestNewClient(t *testing.T) {
	c := NewClient("http://localhost:8080", "agent-key-123", "prov-secret-456")

	if c.baseURL != "http://localhost:8080" {
		t.Errorf("baseURL = %q, want %q", c.baseURL, "http://localhost:8080")
	}
	if c.agentKey != "agent-key-123" {
		t.Errorf("agentKey = %q, want %q", c.agentKey, "agent-key-123")
	}
	if c.provSecret != "prov-secret-456" {
		t.Errorf("provSecret = %q, want %q", c.provSecret, "prov-secret-456")
	}
	if c.http == nil {
		t.Error("http client should not be nil")
	}
}

func TestHTTPToWS(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "http to ws",
			input: "http://localhost",
			want:  "ws://localhost",
		},
		{
			name:  "https to wss with port",
			input: "https://localhost:8080",
			want:  "wss://localhost:8080",
		},
		{
			name:    "invalid scheme",
			input:   "ftp://localhost",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := httpToWS(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error for invalid URL scheme")
				}
				return
			}
			if err != nil {
				t.Fatalf("httpToWS(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("httpToWS(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
