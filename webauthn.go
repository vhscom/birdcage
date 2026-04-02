package main

import (
	"encoding/binary"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var wan *webauthn.WebAuthn

func initWebAuthn() error {
	host := extractHostname(cfg.BaseURL)
	var err error
	wan, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "birdcage",
		RPID:          host,
		RPOrigins:     []string{cfg.BaseURL},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
	})
	return err
}

func extractHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}

// --- WebAuthn User interface ---

type webAuthnUser struct {
	id          int
	email       string
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte {
	b := make([]byte, 8)
	if u.id < 0 {
		return b
	}
	binary.BigEndian.PutUint64(b, uint64(u.id))
	return b
}
func (u *webAuthnUser) WebAuthnName() string                         { return u.email }
func (u *webAuthnUser) WebAuthnDisplayName() string                  { return u.email }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential   { return u.credentials }

func loadWebAuthnUser(userID int) (*webAuthnUser, error) {
	var email string
	if err := store.QueryRow("SELECT email FROM account WHERE id = ?", userID).Scan(&email); err != nil {
		return nil, err
	}
	creds, err := loadCredentialsByUser(userID)
	if err != nil {
		return nil, err
	}
	return &webAuthnUser{id: userID, email: email, credentials: creds}, nil
}

func loadWebAuthnUserByHandle(userHandle []byte) (*webAuthnUser, error) {
	if len(userHandle) < 8 {
		return nil, errNotFound
	}
	raw := binary.BigEndian.Uint64(userHandle)
	if raw > math.MaxInt {
		return nil, errNotFound
	}
	return loadWebAuthnUser(int(raw))
}

// --- In-memory challenge store (single-user, single-process) ---

var challenges struct {
	sync.Mutex
	reg   *webauthn.SessionData
	login *webauthn.SessionData
}

// --- Handlers ---

// POST /account/passkey/begin — start passkey registration (authenticated).
func handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	ip := clientIP(r)

	user, err := loadWebAuthnUser(claims.UID)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load account")
		return
	}

	options, session, err := wan.BeginRegistration(user)
	if err != nil {
		logError("passkey.register_begin", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to start registration")
		return
	}

	challenges.Lock()
	challenges.reg = session
	challenges.Unlock()

	emitEvent("passkey.register_begin", ip, claims.UID, r.UserAgent(), 200, nil)
	jsonOK(w, options)
}

// POST /account/passkey/finish — complete passkey registration (authenticated).
func handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	ip := clientIP(r)

	challenges.Lock()
	session := challenges.reg
	challenges.reg = nil
	challenges.Unlock()

	if session == nil {
		respondError(w, r, http.StatusBadRequest, "NO_CHALLENGE", "No registration challenge pending")
		return
	}

	user, err := loadWebAuthnUser(claims.UID)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load account")
		return
	}

	cred, err := wan.FinishRegistration(user, *session, r)
	if err != nil {
		emitEvent("passkey.register_failure", ip, claims.UID, r.UserAgent(), 400, map[string]any{"error": err.Error()})
		respondError(w, r, http.StatusBadRequest, "REGISTRATION_FAILED", "Passkey registration failed")
		return
	}

	// Parse optional name from a wrapper object; the browser sends the attestation
	// fields directly, so we also accept a "name" field alongside them.
	name := passkeyNameFromRequest(r)

	id, err := insertPasskey(claims.UID, cred, name)
	if err != nil {
		logError("passkey.insert", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save passkey")
		return
	}

	emitEvent("passkey.register_success", ip, claims.UID, r.UserAgent(), 201, map[string]any{"passkeyId": id, "name": name})
	jsonCreated(w, map[string]any{"id": id, "name": name})
}

// POST /auth/passkey/begin — start passkey login (public).
func handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	options, session, err := wan.BeginDiscoverableLogin()
	if err != nil {
		logError("passkey.login_begin", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to start passkey login")
		return
	}

	challenges.Lock()
	challenges.login = session
	challenges.Unlock()

	emitEvent("passkey.login_begin", ip, 0, r.UserAgent(), 200, nil)
	jsonOK(w, options)
}

// POST /auth/passkey/finish — complete passkey login (public).
func handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	challenges.Lock()
	session := challenges.login
	challenges.login = nil
	challenges.Unlock()

	if session == nil {
		respondError(w, r, http.StatusBadRequest, "NO_CHALLENGE", "No login challenge pending")
		return
	}

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		return loadWebAuthnUserByHandle(userHandle)
	}

	user, cred, err := wan.FinishPasskeyLogin(handler, *session, r)
	if err != nil {
		emitEvent("passkey.login_failure", ip, 0, r.UserAgent(), 401, map[string]any{"error": err.Error()})
		respondError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIAL", "Passkey authentication failed")
		return
	}

	wau := user.(*webAuthnUser)
	_ = updatePasskeySignCount(cred.ID, cred.Authenticator.SignCount)

	sid, err := createSession(wau.id, r.UserAgent(), ip)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Login failed")
		return
	}
	if err := setTokenCookies(w, wau.id, sid); err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Login failed")
		return
	}

	emitEvent("passkey.login_success", ip, wau.id, r.UserAgent(), 200, map[string]any{"sessionId": sid})
	respondSuccess(w, r, http.StatusOK, "Login successful", "/#logged-in")
}

// GET /account/passkeys — list registered passkeys (authenticated).
func handlePasskeyList(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	keys, err := listPasskeys(claims.UID)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list passkeys")
		return
	}
	jsonOK(w, map[string]any{"passkeys": keys})
}

// DELETE /account/passkeys/{id} — delete a passkey (authenticated).
func handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	ip := clientIP(r)

	idStr := r.PathValue("id")
	pkID, err := strconv.Atoi(idStr)
	if err != nil {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid passkey ID")
		return
	}

	ok, err := deletePasskey(claims.UID, pkID)
	if err != nil {
		logError("passkey.delete", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete passkey")
		return
	}
	if !ok {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Passkey not found")
		return
	}

	emitEvent("passkey.delete", ip, claims.UID, r.UserAgent(), 200, map[string]any{"passkeyId": pkID})
	jsonOK(w, map[string]any{"success": true})
}

// --- DB helpers ---

var errNotFound = errors.New("not found")

func insertPasskey(userID int, cred *webauthn.Credential, name string) (int64, error) {
	transports := serializeTransports(cred.Transport)
	result, err := store.Exec(
		"INSERT INTO passkey (user_id, credential_id, public_key, aaguid, sign_count, name, transports) VALUES (?,?,?,?,?,?,?)",
		userID, cred.ID, cred.PublicKey, cred.Authenticator.AAGUID, cred.Authenticator.SignCount, name, transports,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

type passkeyInfo struct {
	ID         int     `json:"id"`
	Name       string  `json:"name"`
	LastUsedAt *string `json:"lastUsedAt"`
	CreatedAt  string  `json:"createdAt"`
}

func listPasskeys(userID int) ([]passkeyInfo, error) {
	rows, err := store.Query("SELECT id, name, last_used_at, created_at FROM passkey WHERE user_id = ? ORDER BY created_at", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []passkeyInfo
	for rows.Next() {
		var pk passkeyInfo
		if err := rows.Scan(&pk.ID, &pk.Name, &pk.LastUsedAt, &pk.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, pk)
	}
	if keys == nil {
		keys = []passkeyInfo{}
	}
	return keys, rows.Err()
}

func deletePasskey(userID, passkeyID int) (bool, error) {
	result, err := store.Exec("DELETE FROM passkey WHERE id = ? AND user_id = ?", passkeyID, userID)
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

func updatePasskeySignCount(credentialID []byte, count uint32) error {
	_, err := store.Exec("UPDATE passkey SET sign_count = ?, last_used_at = datetime('now') WHERE credential_id = ?", count, credentialID)
	return err
}

func loadCredentialsByUser(userID int) ([]webauthn.Credential, error) {
	rows, err := store.Query("SELECT credential_id, public_key, aaguid, sign_count, transports FROM passkey WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var creds []webauthn.Credential
	for rows.Next() {
		var (
			credID, pubKey, aaguid []byte
			signCount              uint32
			transports             string
		)
		if err := rows.Scan(&credID, &pubKey, &aaguid, &signCount, &transports); err != nil {
			return nil, err
		}
		creds = append(creds, webauthn.Credential{
			ID:        credID,
			PublicKey: pubKey,
			Transport: deserializeTransports(transports),
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguid,
				SignCount: signCount,
			},
		})
	}
	return creds, rows.Err()
}

// --- Helpers ---

func serializeTransports(ts []protocol.AuthenticatorTransport) string {
	if len(ts) == 0 {
		return ""
	}
	parts := make([]string, len(ts))
	for i, t := range ts {
		parts[i] = string(t)
	}
	return strings.Join(parts, ",")
}

func deserializeTransports(s string) []protocol.AuthenticatorTransport {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	ts := make([]protocol.AuthenticatorTransport, len(parts))
	for i, p := range parts {
		ts[i] = protocol.AuthenticatorTransport(p)
	}
	return ts
}

// passkeyNameFromRequest tries to extract a "name" field from the request body.
// The go-webauthn library reads the attestation from r.Body, so we check the
// URL query parameter instead to avoid consuming the body twice.
func passkeyNameFromRequest(r *http.Request) string {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

// --- Auth status extension ---

func passkeyCount() int {
	var count int
	if err := store.QueryRow("SELECT COUNT(*) FROM passkey").Scan(&count); err != nil {
		return 0
	}
	return count
}

// hasPasskeys returns true if any passkeys are registered.
func hasPasskeys() bool {
	return passkeyCount() > 0
}

