package main

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

var cloakState struct {
	mu    sync.RWMutex
	until time.Time
}

var wgNet *net.IPNet

// initWGSubnet parses WG_SUBNET at startup. Must be called after cfg is set.
func initWGSubnet(cidr string) {
	if cidr == "" {
		return
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		slog.Warn("invalid WG_SUBNET, mesh IP allowlist disabled", "value", cidr, "error", err)
		return
	}
	wgNet = n
	slog.Info("cloak mesh subnet configured", "subnet", cidr)
}

// isInternalIP returns true for loopback and WireGuard mesh addresses.
// Handles IPv4 and IPv6. Does NOT consult X-Forwarded-For by design.
func isInternalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if wgNet != nil && wgNet.Contains(ip) {
		return true
	}
	return false
}

func isCloaked() bool {
	cloakState.mu.RLock()
	defer cloakState.mu.RUnlock()
	return time.Now().Before(cloakState.until)
}

func enableCloak(d time.Duration) {
	cloakState.mu.Lock()
	cloakState.until = time.Now().Add(d)
	cloakState.mu.Unlock()
}

func disableCloak() {
	cloakState.mu.Lock()
	cloakState.until = time.Time{}
	cloakState.mu.Unlock()
}

func cloakUntil() time.Time {
	cloakState.mu.RLock()
	defer cloakState.mu.RUnlock()
	return cloakState.until
}

// cloakMiddleware returns a plain 404 to public IPs when cloak is active.
// WG mesh and loopback always pass through. No special headers or log lines
// on blocked requests to avoid fingerprinting the ops surface.
func cloakMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isCloaked() && !isInternalIP(clientIP(r)) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Auto-trigger thresholds for CLOAK_ON_ATTACK mode ---

const (
	cloakAttackWindow    = 5 * time.Minute
	cloakTriggerDebounce = 30 * time.Second // min interval between DB threshold checks per event type
	cloakTLSThreshold    = 5                // tls.rejected events in window
	cloakAuthThreshold   = 3                // agent.auth_failure events in window
	cloakRLThreshold     = 5                // rate_limit.reject events in window
)

var cloakTriggerLast sync.Map // eventType → time.Time

// checkCloakTrigger auto-enables cloak when an attack threshold is exceeded.
// Debounced per event type to avoid a DB query on every individual attack event.
// Safe to call from emitEvent: "cloak.enabled" is not an attack type, and
// isCloaked() is true after enableCloak, so the recursive emitEvent call exits early.
func checkCloakTrigger(eventType string) {
	threshold := 0
	switch eventType {
	case "tls.rejected":
		threshold = cloakTLSThreshold
	case "agent.auth_failure":
		threshold = cloakAuthThreshold
	case "rate_limit.reject":
		threshold = cloakRLThreshold
	default:
		return
	}

	now := time.Now()
	if last, ok := cloakTriggerLast.Load(eventType); ok && now.Sub(last.(time.Time)) < cloakTriggerDebounce {
		return
	}
	cloakTriggerLast.Store(eventType, now)

	since := now.Add(-cloakAttackWindow).UTC().Format("2006-01-02 15:04:05")
	var count int
	if err := store.QueryRow(
		"SELECT COUNT(*) FROM security_event WHERE type = ? AND created_at >= ?",
		eventType, since,
	).Scan(&count); err != nil {
		return
	}

	if count >= threshold {
		durMin := cfg.CloakDurationMin
		enableCloak(time.Duration(durMin) * time.Minute)
		slog.Warn("cloak auto-enabled", "trigger", eventType, "count", count, "minutes", durMin)
		emitEvent("cloak.enabled", "", 0, "", 0, map[string]any{
			"trigger": eventType, "count": count, "duration_min": durMin, "auto": true,
		})
	}
}
