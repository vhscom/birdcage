package main

import (
	"strings"
	"testing"
)

func TestValidEmail(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid address", "user@example.com", true},
		{"empty string", "", false},
		{"no at sign", "noat", false},
		{"no dot in domain", "no@dot", false},
		{"over 254 chars", strings.Repeat("a", 243) + "@example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validEmail(tt.input); got != tt.want {
				t.Errorf("validEmail(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"normal address", "user@example.com", "*@example.com"},
		{"no at sign", "noat", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskEmail(tt.input); got != tt.want {
				t.Errorf("maskEmail(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidPassword(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"too short", "short", false},
		{"valid 9 chars", "validpass", true},
		{"valid 8 digits", "12345678", true},
		{"too long 65 chars", strings.Repeat("a", 65), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validPassword(tt.input); got != tt.want {
				t.Errorf("validPassword(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidLabel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid hyphenated", "my-host", true},
		{"empty string", "", false},
		{"has space", "has space", false},
		{"has underscore", "has_underscore", false},
		{"has dot", "has.dot", false},
		{"too long 33 chars", strings.Repeat("a", 33), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validLabel(tt.input); got != tt.want {
				t.Errorf("validLabel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidEndpoint(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid ip:port", "1.2.3.4:51820", true},
		{"no port", "noport", false},
		{"empty string", "", false},
		{"too long 254 chars", strings.Repeat("a", 254), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validEndpoint(tt.input); got != tt.want {
				t.Errorf("validEndpoint(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidAllowedIPs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"single host /32", "10.0.0.2/32", true},
		{"subnet /24", "10.0.0.0/24", true},
		{"not CIDR", "notcidr", false},
		{"missing prefix length", "10.0.0.2", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validAllowedIPs(tt.input); got != tt.want {
				t.Errorf("validAllowedIPs(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidWGPubkey(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid base64 key", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=", true},
		{"too short", "short", false},
		{"44 chars no trailing =", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validWGPubkey(tt.input); got != tt.want {
				t.Errorf("validWGPubkey(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
