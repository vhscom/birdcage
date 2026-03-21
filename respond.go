package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// --- Content negotiation ---

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

func respondSuccess(w http.ResponseWriter, r *http.Request, status int, msg, redirect string) {
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"success": true, "message": msg})
	} else {
		http.Redirect(w, r, redirect, http.StatusFound)
	}
}

func respondError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	if wantsJSON(r) {
		jsonError(w, status, code, msg)
	} else {
		http.Redirect(w, r, "/#error", http.StatusFound)
	}
}

func jsonError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg, "code": code})
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonCreated(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(v)
}

// --- Request parsing ---

const maxBodySize = 1 << 20 // 1 MB

func parseRegistration(r *http.Request) (email, password, token string) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodySize)
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var body struct {
			Email             string `json:"email"`
			Password          string `json:"password"`
			RegistrationToken string `json:"registrationToken"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		return strings.ToLower(strings.TrimSpace(body.Email)), body.Password, body.RegistrationToken
	}
	r.ParseForm()
	return strings.ToLower(strings.TrimSpace(r.FormValue("email"))), r.FormValue("password"), r.FormValue("registrationToken")
}

func parsePasswordChange(r *http.Request) (current, next string) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodySize)
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var body struct {
			CurrentPassword string `json:"currentPassword"`
			NewPassword     string `json:"newPassword"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		return body.CurrentPassword, body.NewPassword
	}
	r.ParseForm()
	return r.FormValue("currentPassword"), r.FormValue("newPassword")
}

// GET /health
func handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	if err := store.Ping(); err != nil {
		status = "degraded"
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	jsonOK(w, map[string]any{"status": status, "timestamp": nowUnix()})
}

// --- Cookie helpers ---

func setAuthCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure set dynamically via cfg.CookieSecure
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func deleteAuthCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- deletion cookie; Secure set dynamically
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func setTokenCookies(w http.ResponseWriter, uid int, sid string) error {
	access, err := signToken(uid, sid, "access", cfg.AccessSecret, accessExpiry)
	if err != nil {
		return err
	}
	refresh, err := signToken(uid, sid, "refresh", cfg.RefreshSecret, refreshExpiry)
	if err != nil {
		return err
	}
	setAuthCookie(w, "access_token", access, accessExpiry)
	setAuthCookie(w, "refresh_token", refresh, refreshExpiry)
	return nil
}

func clearTokenCookies(w http.ResponseWriter) {
	deleteAuthCookie(w, "access_token")
	deleteAuthCookie(w, "refresh_token")
}

// --- IP helpers ---

func connIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host
}

func clientIP(r *http.Request) string {
	return connIP(r)
}

// --- Error logging ---

func logError(op string, err error) {
	if err != nil {
		slog.Error(op, "error", err)
	}
}
