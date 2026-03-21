package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	initDB(":memory:")
	cfg = &Config{
		AccessSecret:  "test-access-secret-that-is-32-chars!!",
		RefreshSecret: "test-refresh-secret-that-is-32-chars!",
		CookieSecure:  false,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/status", handleAuthStatus)
	mux.Handle("POST /auth/register", http.HandlerFunc(handleRegister))
	mux.Handle("POST /auth/login", http.HandlerFunc(handleLogin))
	mux.Handle("POST /auth/logout", requireAuthMiddleware(http.HandlerFunc(handleLogout)))
	mux.Handle("POST /account/password", requireAuthMiddleware(http.HandlerFunc(handlePasswordChange)))
	mux.Handle("GET /account/me", requireAuthMiddleware(http.HandlerFunc(handleMe)))
	mux.HandleFunc("GET /health", handleHealth)
	return httptest.NewServer(mux)
}

func jsonPost(url string, body any, cookies []*http.Cookie) (*http.Response, map[string]any) {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return resp, result
}

func jsonGet(url string, cookies []*http.Cookie) (*http.Response, map[string]any) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Accept", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return resp, result
}

func TestRegisterAndLogin(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Register
	resp, body := jsonPost(ts.URL+"/auth/register", map[string]any{
		"email":    "user@example.com",
		"password": "securepassword123",
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	if body["success"] != true {
		t.Fatalf("register: success = %v, want true", body["success"])
	}

	// Login
	resp, body = jsonPost(ts.URL+"/auth/login", map[string]any{
		"email":    "user@example.com",
		"password": "securepassword123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if body["success"] != true {
		t.Fatalf("login: success = %v, want true", body["success"])
	}

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("login: no cookies set")
	}

	// GET /account/me with cookies
	resp, body = jsonGet(ts.URL+"/account/me", cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	email, _ := body["email"].(string)
	if email != "user@example.com" {
		t.Errorf("me: email = %q, want %q", email, "user@example.com")
	}
}

func TestRegisterDuplicate(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	payload := map[string]any{
		"email":    "dup@example.com",
		"password": "securepassword123",
	}

	// First registration
	resp, _ := jsonPost(ts.URL+"/auth/register", payload, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first register: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	// Second registration with same email — still 201 (anti-enumeration)
	resp, body := jsonPost(ts.URL+"/auth/register", payload, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("second register: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	if body["success"] != true {
		t.Errorf("second register: success = %v, want true", body["success"])
	}
}

func TestRegisterInvalidEmail(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, body := jsonPost(ts.URL+"/auth/register", map[string]any{
		"email":    "not-an-email",
		"password": "securepassword123",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("register invalid email: status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	code, _ := body["code"].(string)
	if code != "VALIDATION_ERROR" {
		t.Errorf("register invalid email: code = %q, want %q", code, "VALIDATION_ERROR")
	}
}

func TestRegisterRequiresToken(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	cfg.RegistrationToken = "my-secret-token"

	// Register without token — 403
	resp, body := jsonPost(ts.URL+"/auth/register", map[string]any{
		"email":    "token@example.com",
		"password": "securepassword123",
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("register without token: status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	code, _ := body["code"].(string)
	if code != "INVALID_TOKEN" {
		t.Errorf("register without token: code = %q, want %q", code, "INVALID_TOKEN")
	}

	// Register with correct token — 201
	resp, body = jsonPost(ts.URL+"/auth/register", map[string]any{
		"email":             "token@example.com",
		"password":          "securepassword123",
		"registrationToken": "my-secret-token",
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register with token: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	if body["success"] != true {
		t.Errorf("register with token: success = %v, want true", body["success"])
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Register first
	resp, _ := jsonPost(ts.URL+"/auth/register", map[string]any{
		"email":    "cred@example.com",
		"password": "correctpassword1",
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	// Login with wrong password
	resp, body := jsonPost(ts.URL+"/auth/login", map[string]any{
		"email":    "cred@example.com",
		"password": "wrongpassword12",
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login wrong pw: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	code, _ := body["code"].(string)
	if code != "INVALID_CREDENTIALS" {
		t.Errorf("login wrong pw: code = %q, want %q", code, "INVALID_CREDENTIALS")
	}
}

func TestLoginNonexistentUser(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, body := jsonPost(ts.URL+"/auth/login", map[string]any{
		"email":    "nobody@example.com",
		"password": "somepassword12",
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login nonexistent: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	code, _ := body["code"].(string)
	if code != "INVALID_CREDENTIALS" {
		t.Errorf("login nonexistent: code = %q, want %q", code, "INVALID_CREDENTIALS")
	}
}

func TestLogout(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Register
	jsonPost(ts.URL+"/auth/register", map[string]any{
		"email":    "logout@example.com",
		"password": "securepassword123",
	}, nil)

	// Login
	resp, _ := jsonPost(ts.URL+"/auth/login", map[string]any{
		"email":    "logout@example.com",
		"password": "securepassword123",
	}, nil)
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("login: no cookies set")
	}

	// Logout
	resp, body := jsonPost(ts.URL+"/auth/logout", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if body["success"] != true {
		t.Errorf("logout: success = %v, want true", body["success"])
	}

	// /account/me should now return 401 or 403 (session revoked)
	resp, _ = jsonGet(ts.URL+"/account/me", cookies)
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("me after logout: status = %d, want 401 or 403", resp.StatusCode)
	}
}

func TestPasswordChange(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Register and login
	jsonPost(ts.URL+"/auth/register", map[string]any{
		"email":    "pwchange@example.com",
		"password": "oldpassword1234",
	}, nil)
	resp, _ := jsonPost(ts.URL+"/auth/login", map[string]any{
		"email":    "pwchange@example.com",
		"password": "oldpassword1234",
	}, nil)
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("login: no cookies set")
	}

	// Change password
	resp, body := jsonPost(ts.URL+"/account/password", map[string]any{
		"currentPassword": "oldpassword1234",
		"newPassword":     "newpassword5678",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password change: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if body["success"] != true {
		t.Errorf("password change: success = %v, want true", body["success"])
	}

	// Old cookies should no longer work (all sessions revoked)
	resp, _ = jsonGet(ts.URL+"/account/me", cookies)
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("me after pw change: status = %d, want 401 or 403", resp.StatusCode)
	}
}

func TestPasswordChangeSamePassword(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Register and login
	jsonPost(ts.URL+"/auth/register", map[string]any{
		"email":    "samepw@example.com",
		"password": "thepassword1234",
	}, nil)
	resp, _ := jsonPost(ts.URL+"/auth/login", map[string]any{
		"email":    "samepw@example.com",
		"password": "thepassword1234",
	}, nil)
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("login: no cookies set")
	}

	// Try to change to the same password
	resp, body := jsonPost(ts.URL+"/account/password", map[string]any{
		"currentPassword": "thepassword1234",
		"newPassword":     "thepassword1234",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("same password: status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	code, _ := body["code"].(string)
	if code != "VALIDATION_ERROR" {
		t.Errorf("same password: code = %q, want %q", code, "VALIDATION_ERROR")
	}
}

func TestAuthStatus_Unregistered(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, body := jsonGet(ts.URL+"/auth/status", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("auth status: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	registered, _ := body["registered"].(bool)
	if registered {
		t.Errorf("auth status: registered = %v, want false", registered)
	}
}

func TestAuthStatus_Registered(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Register
	resp, _ := jsonPost(ts.URL+"/auth/register", map[string]any{
		"email":    "status@example.com",
		"password": "securepassword123",
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	// Check status
	resp, body := jsonGet(ts.URL+"/auth/status", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("auth status: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	registered, _ := body["registered"].(bool)
	if !registered {
		t.Errorf("auth status: registered = %v, want true", registered)
	}
}
