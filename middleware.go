package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Context keys ---

type ctxKey int

const (
	ctxClaims ctxKey = iota
	ctxAgentCredential
)

func getClaims(r *http.Request) *TokenClaims {
	v, _ := r.Context().Value(ctxClaims).(*TokenClaims)
	return v
}

type AgentCredential struct {
	ID   int
	Name string
}

func getAgentCred(r *http.Request) *AgentCredential {
	v, _ := r.Context().Value(ctxAgentCredential).(*AgentCredential)
	return v
}

// --- Auth middleware (JWT dual-token with auto-refresh) ---

func requireAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := tryAccessToken(r)
		if err != nil {
			claims, err = tryRefreshAndRotate(w, r)
		}
		if err != nil || claims == nil {
			jsonError(w, http.StatusUnauthorized, "TOKEN_EXPIRED", "Authentication required")
			return
		}
		sess, _ := getSession(claims.SID)
		if sess == nil {
			jsonError(w, http.StatusForbidden, "SESSION_REVOKED", "Session expired")
			return
		}
		ctx := context.WithValue(r.Context(), ctxClaims, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func tryAccessToken(r *http.Request) (*TokenClaims, error) {
	c, err := r.Cookie("access_token")
	if err != nil {
		return nil, err
	}
	return verifyToken(c.Value, cfg.AccessSecret, "access")
}

func tryRefreshAndRotate(w http.ResponseWriter, r *http.Request) (*TokenClaims, error) {
	c, err := r.Cookie("refresh_token")
	if err != nil {
		return nil, err
	}
	refresh, err := verifyToken(c.Value, cfg.RefreshSecret, "refresh")
	if err != nil {
		return nil, err
	}
	sess, _ := getSession(refresh.SID)
	if sess == nil {
		return nil, errSessionRevoked
	}

	// Reuse detection: a rotated-out token was replayed → revoke session
	if refresh.Gen != sess.RefreshGen {
		endSession(refresh.SID)
		emitEvent("session.refresh_reuse", clientIP(r), refresh.UID, r.UserAgent(), 401, map[string]any{
			"sessionId": refresh.SID, "tokenGen": refresh.Gen, "sessionGen": sess.RefreshGen,
		})
		return nil, errSessionRevoked
	}

	newGen, err := bumpRefreshGen(refresh.SID)
	if err != nil {
		return nil, err
	}

	access, err := signToken(refresh.UID, refresh.SID, "access", cfg.AccessSecret, accessExpiry)
	if err != nil {
		return nil, err
	}
	newRefresh, err := signRefreshToken(refresh.UID, refresh.SID, cfg.RefreshSecret, newGen)
	if err != nil {
		return nil, err
	}
	setAuthCookie(w, "access_token", access, accessExpiry)
	setAuthCookie(w, "refresh_token", newRefresh, refreshExpiry)
	return verifyToken(access, cfg.AccessSecret, "access")
}

var errSessionRevoked = &authError{"SESSION_REVOKED"}

type authError struct{ code string }

func (e *authError) Error() string { return e.code }

// --- Agent key middleware (Bearer token → agent credential) ---

func requireAgentKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			jsonError(w, http.StatusUnauthorized, "MISSING_KEY", "Bearer token required")
			return
		}
		raw := auth[7:]
		keyHash := hashAPIKey(raw)

		var cred AgentCredential
		err := store.QueryRow(
			"SELECT id, name FROM agent_credential WHERE key_hash = ? AND revoked_at IS NULL",
			keyHash,
		).Scan(&cred.ID, &cred.Name)
		if err != nil {
			emitEvent("agent.auth_failure", clientIP(r), 0, r.UserAgent(), 401, nil)
			jsonError(w, http.StatusUnauthorized, "INVALID_KEY", "Invalid API key")
			return
		}
		ctx := context.WithValue(r.Context(), ctxAgentCredential, &cred)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- Access logging ---

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		slog.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status, "duration", time.Since(start).Round(time.Microsecond))
	})
}

// --- Security headers (OWASP) ---

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Permitted-Cross-Domain-Policies", "none")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'; upgrade-insecure-requests")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("Permissions-Policy", "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(self), usb=(), web-share=(), xr-spatial-tracking=()")
		h.Set("Cache-Control", "no-store, max-age=0")
		h.Del("Server")
		h.Del("X-Powered-By")
		next.ServeHTTP(w, r)
	})
}

// --- In-memory fixed-window rate limiter ---

type rateLimiter struct {
	mu      sync.Mutex
	windows map[string]*window
}

type window struct {
	count   int
	resetAt time.Time
}

const maxRateLimitKeys = 10_000

var limiter = &rateLimiter{windows: make(map[string]*window)}

type rateConfig struct {
	Window  time.Duration
	Max     int
	Prefix  string
	KeyFunc func(*http.Request) string
}

func rateLimit(rc rateConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := rc.Prefix + ":"
			if rc.KeyFunc != nil {
				key += rc.KeyFunc(r)
			} else {
				key += clientIP(r)
			}

			limiter.mu.Lock()
			win, ok := limiter.windows[key]
			now := time.Now()
			if !ok || now.After(win.resetAt) {
				if !ok && len(limiter.windows) >= maxRateLimitKeys {
					limiter.mu.Unlock()
					w.Header().Set("Retry-After", "60")
					jsonError(w, http.StatusTooManyRequests, "RATE_LIMIT", "Too many requests")
					return
				}
				win = &window{count: 0, resetAt: now.Add(rc.Window)}
				limiter.windows[key] = win
			}
			win.count++
			exceeded := win.count > rc.Max
			limiter.mu.Unlock()

			if exceeded {
				emitEvent("rate_limit.reject", clientIP(r), 0, r.UserAgent(), 429, map[string]any{"prefix": rc.Prefix})
				w.Header().Set("Retry-After", "60")
				jsonError(w, http.StatusTooManyRequests, "RATE_LIMIT", "Too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Periodic cleanup of expired rate limit windows.
func init() {
	go func() {
		for range time.Tick(5 * time.Minute) {
			limiter.mu.Lock()
			now := time.Now()
			for k, w := range limiter.windows {
				if now.After(w.resetAt) {
					delete(limiter.windows, k)
				}
			}
			limiter.mu.Unlock()
		}
	}()
}

func userKey(r *http.Request) string {
	if claims := getClaims(r); claims != nil {
		return strconv.Itoa(claims.UID)
	}
	return clientIP(r)
}

// --- Global request body limit ---

func maxBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		next.ServeHTTP(w, r)
	})
}

// --- Agent provisioning secret ---

func requireProvisioningSecret(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.AgentKey == "" {
			http.NotFound(w, r)
			return
		}
		got := r.Header.Get("X-Provisioning-Secret")
		if subtle.ConstantTimeCompare([]byte(cfg.AgentKey), []byte(got)) != 1 {
			jsonError(w, http.StatusUnauthorized, "INVALID_SECRET", "Invalid provisioning secret")
			return
		}
		next.ServeHTTP(w, r)
	})
}
