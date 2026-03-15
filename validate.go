package main

import (
	"net"
	"strings"
	"unicode/utf8"
)

func validEmail(email string) bool {
	if len(email) == 0 || len(email) > 254 {
		return false
	}
	parts := strings.SplitN(email, "@", 2)
	return len(parts) == 2 && len(parts[0]) > 0 && strings.Contains(parts[1], ".")
}

// maskEmail returns "*@domain" for event logging (never log full addresses).
func maskEmail(email string) string {
	if i := strings.LastIndex(email, "@"); i >= 0 {
		return "*@" + email[i+1:]
	}
	return ""
}

func validPassword(password string) bool {
	n := utf8.RuneCountInString(normalizePassword(password))
	return n >= 8 && n <= 64
}

func validLabel(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

func validEndpoint(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	i := strings.LastIndex(s, ":")
	return i > 0 && i < len(s)-1
}

func validAllowedIPs(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func validWGPubkey(s string) bool {
	if len(s) != 44 || s[43] != '=' {
		return false
	}
	for _, c := range s[:43] {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/') {
			return false
		}
	}
	return true
}
