package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
)

// POST /auth/register — single-user registration (only one account allowed).
func handleRegister(w http.ResponseWriter, r *http.Request) {
	email, password, token := parseRegistration(r)

	if cfg.RegistrationToken != "" {
		if subtle.ConstantTimeCompare([]byte(cfg.RegistrationToken), []byte(token)) != 1 {
			respondError(w, r, http.StatusForbidden, "INVALID_TOKEN", "Invalid registration token")
			return
		}
	}

	if !validEmail(email) || !validPassword(password) {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid email or password")
		return
	}
	hash, err := hashPassword(password)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Registration failed")
		return
	}
	domain := maskEmail(email)
	// Atomic single-user enforcement: only insert if no account exists
	result, err := store.Exec("INSERT INTO account (email, password_data) SELECT ?,? WHERE (SELECT COUNT(*) FROM account) = 0", email, hash)
	if err != nil {
		if isUniqueViolation(err) {
			emitEvent("registration.failure", clientIP(r), 0, r.UserAgent(), 409, map[string]any{"email": domain})
		} else {
			logError("registration.insert", err)
		}
		// Identical response to prevent enumeration
		respondSuccess(w, r, http.StatusCreated, "Registration successful", "/#registered")
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		// Account already exists — return identical response to prevent enumeration
		respondSuccess(w, r, http.StatusCreated, "Registration successful", "/#registered")
		return
	}
	emitEvent("registration.success", clientIP(r), 0, r.UserAgent(), 201, map[string]any{"email": domain})
	respondSuccess(w, r, http.StatusCreated, "Registration successful", "/#registered")
}

// POST /auth/login
func handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	// Parse all login fields from the body once
	email, password, challengeNonce, challengeSolution := parseLoginRequest(r)

	// Adaptive PoW challenge
	ch := computeChallenge(ip, cfg.AccessSecret)
	if ch != nil {
		if challengeNonce == "" || challengeSolution == "" {
			emitEvent("challenge.issued", ip, 0, r.UserAgent(), 403, map[string]any{"difficulty": ch.Difficulty})
			jsonChallenge(w, "CHALLENGE_REQUIRED", "Proof of work required", ch)
			return
		}
		if !verifySignedNonce(challengeNonce, cfg.AccessSecret, ip) || !verifySolution(challengeNonce, challengeSolution, ch.Difficulty) {
			emitEvent("challenge.failed", ip, 0, r.UserAgent(), 403, nil)
			jsonChallenge(w, "CHALLENGE_FAILED", "Invalid proof of work", ch)
			return
		}
	}
	domain := maskEmail(email)

	var userID int
	var storedHash string
	err := store.QueryRow("SELECT id, password_data FROM account WHERE email = ?", email).Scan(&userID, &storedHash)
	if err != nil {
		rejectConstantTime(password)
		emitEvent("login.failure", ip, 0, r.UserAgent(), 401, map[string]any{"email": domain})
		respondError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password")
		return
	}
	if !verifyPassword(password, storedHash) {
		emitEvent("login.failure", ip, userID, r.UserAgent(), 401, map[string]any{"email": domain})
		respondError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password")
		return
	}

	sid, err := createSession(userID, r.UserAgent(), ip)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Login failed")
		return
	}
	if err := setTokenCookies(w, userID, sid); err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Login failed")
		return
	}
	emitEvent("login.success", ip, userID, r.UserAgent(), 200, map[string]any{"sessionId": sid})
	respondSuccess(w, r, http.StatusOK, "Login successful", "/#logged-in")
}

// POST /auth/logout
func handleLogout(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	endSession(claims.SID)
	clearTokenCookies(w)
	emitEvent("session.revoke", clientIP(r), claims.UID, r.UserAgent(), 200, map[string]any{"sessionId": claims.SID})
	respondSuccess(w, r, http.StatusOK, "Logged out", "/#logged-out")
}

// POST /account/password
func handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	current, newPw := parsePasswordChange(r)
	if !validPassword(current) || !validPassword(newPw) {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid password")
		return
	}
	if normalizePassword(current) == normalizePassword(newPw) {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "New password must differ from current")
		return
	}

	var storedHash string
	err := store.QueryRow("SELECT password_data FROM account WHERE id = ?", claims.UID).Scan(&storedHash)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Password change failed")
		return
	}
	if !verifyPassword(current, storedHash) {
		respondError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Current password is incorrect")
		return
	}

	hash, err := hashPassword(newPw)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Password change failed")
		return
	}
	if _, err = store.Exec("UPDATE account SET password_data = ? WHERE id = ?", hash, claims.UID); err != nil {
		logError("account.password_update", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Password change failed")
		return
	}

	endAllSessions(claims.UID)
	clearTokenCookies(w)
	emitEvent("password.change", clientIP(r), claims.UID, r.UserAgent(), 200, map[string]any{"sessionId": claims.SID})
	emitEvent("session.revoke_all", clientIP(r), claims.UID, r.UserAgent(), 200, nil)
	respondSuccess(w, r, http.StatusOK, "Password changed", "/#password-changed")
}

// GET /account/me
func handleMe(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)

	var email string
	if err := store.QueryRow("SELECT email FROM account WHERE id = ?", claims.UID).Scan(&email); err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Account lookup failed")
		return
	}

	// Check if gateway (claw) is reachable
	gatewayStatus := "unconfigured"
	if cfg.GatewayURL != "" {
		gatewayStatus = "configured"
	}

	jsonOK(w, map[string]any{
		"userId":  claims.UID,
		"email":   email,
		"gateway": gatewayStatus,
	})
}

// GET /auth/status — public endpoint to check if registration is needed.
func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	var count int
	if err := store.QueryRow("SELECT COUNT(*) FROM account").Scan(&count); err != nil {
		logError("auth.status", err)
		count = 1 // fail closed: assume registered
	}
	resp := map[string]any{"registered": count > 0}
	if count == 0 && cfg.RegistrationToken != "" {
		resp["requiresToken"] = true
	}
	jsonOK(w, resp)
}

func jsonChallenge(w http.ResponseWriter, code, msg string, ch *Challenge) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]any{
		"error": msg, "code": code, "challenge": ch,
	})
}

func parseLoginRequest(r *http.Request) (email, password, challengeNonce, challengeSolution string) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodySize)
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var body struct {
			Email             string `json:"email"`
			Password          string `json:"password"`
			ChallengeNonce    string `json:"challengeNonce"`
			ChallengeSolution string `json:"challengeSolution"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		return strings.ToLower(strings.TrimSpace(body.Email)), body.Password, body.ChallengeNonce, body.ChallengeSolution
	}
	r.ParseForm()
	return strings.ToLower(strings.TrimSpace(r.FormValue("email"))), r.FormValue("password"), r.FormValue("challengeNonce"), r.FormValue("challengeSolution")
}

func nowUnix() int64 {
	return timeNow().Unix()
}
