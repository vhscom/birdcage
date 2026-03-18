# Threat Model

STRIDE analysis for Birdcage. This document maps each threat to the specific mitigation in the codebase (or flags the gap).

> **Prerequisite reading:** [flows.md](flows.md) for authentication sequence diagrams.

---

## STRIDE Threat Analysis

### Core Auth Surface

| # | Category | Threat | Component | Mitigation | Residual Risk |
|---|----------|--------|-----------|------------|---------------|
| 1 | **Spoofing** | JWT forgery via `alg: "none"` | `crypto.go:119` | `verifyToken()` called with explicit `jwt.SigningMethodHS256` — rejects any other algorithm | None if `golang-jwt` library is kept up to date |
| 2 | **Spoofing** | JWT forgery via algorithm confusion (RSA/HMAC) | `crypto.go:121-124` | `verifyToken()` checks `t.Method != jwt.SigningMethodHS256` before returning the secret — rejects mismatched algorithms | None with current design |
| 3 | **Spoofing** | Timing-based user enumeration | `crypto.go:67-70` | `rejectConstantTime()` runs full PBKDF2-SHA384 (210K iterations) against a dummy hash when the user doesn't exist, equalizing response time | Statistical analysis with many requests may still detect small differences |
| 4 | **Spoofing** | User enumeration via error messages | `auth.go:80-88` | Both "user not found" and "wrong password" return the same `"Invalid email or password"` string | None — identical error paths |
| 5 | **Spoofing** | User enumeration via registration response | `auth.go:30-42` | All registration outcomes (success, duplicate, closed) return identical `201 "Registration successful"` | `/auth/status` intentionally reveals whether registration is open |
| 6 | **Spoofing** | Token type confusion (refresh as access) | `crypto.go:130-134` | `verifyToken()` checks `c.Typ != expectedTyp`; access and refresh tokens use separate signing secrets (`JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`) | None with current design |
| 7 | **Spoofing** | Bootstrap race — attacker registers first | `auth.go:14-19`, `internal/cli/init.go:61` | `REGISTRATION_TOKEN` required for registration when configured; `birdcage init` generates a 256-bit token; verified with `subtle.ConstantTimeCompare` | If `REGISTRATION_TOKEN` is unset (manual `.env`), registration is open to anyone |
| 8 | **Tampering** | JWT payload modification | `crypto.go:119-134` | HMAC-SHA256 signature verification — any payload change invalidates the signature | None — HMAC provides integrity |
| 9 | **Tampering** | Cookie manipulation | `respond.go:93-103` | Cookies set with `HttpOnly: true`, `Secure: true` (HTTPS mode), `SameSite: Strict`, `Path: "/"` | In HTTP dev mode, `Secure` is false — never deploy HTTP in production |
| 10 | **Tampering** | Password hash tampering in database | `crypto.go:46-63` | `verifyPassword()` performs both PBKDF2 hash comparison and SHA-384 integrity digest verification via `hmac.Equal`; both must pass | An attacker with direct DB write access could replace both hash and digest consistently |
| 11 | **Tampering** | Refresh token replay after rotation | `middleware.go:84-91` | `refresh_gen` counter in session table; token's `Gen` must match session's `RefreshGen`; mismatch revokes the entire session and emits `session.refresh_reuse` event | None — replay of a rotated-out token immediately kills the session |
| 12 | **Repudiation** | No audit trail for auth events | `events.go:58-78` | `emitEvent()` persists security events (`login.success/failure`, `registration.*`, `session.revoke`, `password.change`, `challenge.*`, `rate_limit.reject`, etc.) to the `security_event` table; events older than 90 days pruned on startup and daily | Fire-and-forget semantics — a failed write logs the error but never blocks auth |
| 13 | **Information Disclosure** | Error message leakage | `auth.go`, `respond.go:27-33` | Generic error messages; no stack traces in JSON responses; password change returns same error for wrong password and missing user | None in current error paths |
| 14 | **Information Disclosure** | Server header fingerprinting | `middleware.go:188-189` | `Server` and `X-Powered-By` headers explicitly deleted | None — headers removed on every response |
| 15 | **Information Disclosure** | Secrets in JWT payload | `crypto.go:93-104` | Payload contains only `uid`, `sid`, `typ`, `gen`, `exp`, `iat` — no email, role, or sensitive data | None — minimal claims |
| 16 | **Information Disclosure** | Email address exposure in logs | `validate.go:18-24` | `maskEmail()` logs only the domain portion (`*@example.com`) in security events | None — full email never logged |
| 17 | **Denial of Service** | Brute-force / credential stuffing on login | `middleware.go:217-254`, `events.go:82-120` | Fixed-window rate limiting (5 login/5min, IP-keyed). Adaptive PoW challenges escalate from 3 to 5 leading hex zeros after 3+ failures in 15 minutes. PoW nonces are HMAC-signed and time-limited (5 min). Rate limiter capped at 10K keys — fail closed on exhaustion. | PoW raises cost but does not stop well-resourced attackers; distributed attacks below per-IP threshold are not challenged |
| 18 | **Denial of Service** | PoW bypass via DB failure | `events.go:103-107` | `computeChallenge()` fails closed — issues PoW challenge when security_event query fails | None — DB unavailability does not weaken brute-force protection |
| 19 | **Denial of Service** | Session exhaustion | `session.go:48-71` | `enforceSessionLimit()` caps sessions at 3 per user; oldest sessions expired first | An attacker with valid credentials can only hold 3 sessions |
| 20 | **Denial of Service** | Request body exhaustion | `middleware.go:280-285` | Global `maxBody` middleware wraps every request body with `MaxBytesReader` (1 MB limit) | None — applied to all routes |
| 21 | **Elevation of Privilege** | Cross-secret token acceptance | `crypto.go:93-104`, `middleware.go:62-68` | Access tokens verified with `JWT_ACCESS_SECRET`, refresh tokens with `JWT_REFRESH_SECRET` — separate secrets | None — secrets are isolated per token type |
| 22 | **Elevation of Privilege** | Weak JWT secrets accepted | `main.go:510-521` | `mustEnv()` rejects secrets shorter than 32 characters at startup | No entropy validation — a 32-char repeating string would pass |
| 23 | **Tampering** | SQL injection | `auth.go`, `session.go`, `events.go`, `node.go` | All SQL uses parameterized queries (`?` placeholders) — no string concatenation or interpolation in any query | None — parameterized queries are the standard defense |

### Browser Surface

| # | Category | Threat | Component | Mitigation | Residual Risk |
|---|----------|--------|-----------|------------|---------------|
| 24 | **Spoofing** | Cross-site request forgery (CSRF) on auth endpoints | `respond.go:93-103` | All auth cookies set with `SameSite=Strict` — browsers will not attach cookies to cross-origin requests regardless of method | None with current browser support; legacy browsers without SameSite support are not targeted |
| 25 | **Tampering** | Cross-site scripting (XSS) / script injection | `main.go:142-147`, `middleware.go:181`, `public/index.html` | Per-request CSP nonce for the inline script (`script-src 'nonce-...'`); default CSP blocks all inline scripts on non-HTML responses; all dynamic content rendered via `textContent` (never `innerHTML`); auth cookies are `HttpOnly` (inaccessible to JavaScript) | `style-src 'unsafe-inline'` remains for embedded CSS — style injection is low-risk but not fully mitigated |
| 26 | **Tampering** | Clickjacking | `middleware.go:178`, `main.go:145` | `X-Frame-Options: DENY` and `frame-ancestors 'none'` in CSP set on all responses | None — both legacy and modern browsers covered |

### Control Proxy Surface

| # | Category | Threat | Component | Mitigation | Residual Risk |
|---|----------|--------|-----------|------------|---------------|
| 27 | **Spoofing** | Credential leakage to gateway | `proxy.go:46-47` | Reverse proxy strips `Cookie` and `Authorization` headers before forwarding to gateway | None — credentials never reach downstream |
| 28 | **Tampering** | Header injection via proxy | `proxy.go:46-55` | Birdcage strips `Cookie`, `Authorization`, and all `X-Forwarded-*` / `Forwarded` headers before rebuilding `X-Forwarded-*` via `SetXForwarded()`; hop-by-hop header semantics handled by Go's `httputil.ReverseProxy` | None — headers rebuilt from scratch |
| 29 | **Tampering** | Gateway token injection in non-connect frames | `bridge.go:177-201` | `injectToken()` only modifies JSON messages where `type=="req"` and `method=="connect"` and `params` exists; binary messages rejected | None — narrow injection criteria |
| 30 | **Information Disclosure** | Response header leakage from gateway | `proxy.go:57-62` | `ModifyResponse` strips `Set-Cookie`, `Server`, `X-Powered-By` from gateway responses | None — sensitive headers removed |
| 31 | **Denial of Service** | WebSocket bridge flooding | `bridge.go:149-162` | Rate limit: 100 messages per 1-second sliding window; binary messages rejected with close code 1003 | None — both text and binary abuse paths covered |
| 32 | **Denial of Service** | Bridge session persistence after revocation | `bridge.go:96-116` | Heartbeat timer checks session validity in DB every 25 seconds; revoked sessions receive close code 4010 | Up to 25-second window between revocation and forced disconnect |

### Agent WebSocket Surface

| # | Category | Threat | Component | Mitigation | Residual Risk |
|---|----------|--------|-----------|------------|---------------|
| 33 | **Spoofing** | Agent key compromise | `middleware.go:119-142` | Keys are 256-bit random, SHA-256 hashed before storage, looked up via parameterized query; `revoked_at IS NULL` filter rejects revoked keys; auth failures emit `agent.auth_failure` events | Keys are long-lived — exposure window is unbounded until explicit revocation |
| 34 | **Spoofing** | Browser-initiated WebSocket CSRF | `ws.go:32-46` | Origin validation rejects connections with an `Origin` header unless it matches the `WS_ALLOWED_ORIGINS` allowlist (empty by default — all browser origins rejected) | Non-browser clients that omit `Origin` are allowed through (by design — agent clients) |
| 35 | **Spoofing** | Revoked agent persists on open WebSocket | `ws.go:216-248` | Heartbeat timer re-validates agent credential against DB every 25 seconds; revoked agents receive close code `4010` | Up to 25-second window between revocation and forced disconnect |
| 36 | **Tampering** | Capability escalation over WebSocket | `ws.go:166-214` | Capabilities are immutable after negotiation; each message checked against `granted` map before dispatch | None — capabilities fixed at connection time |
| 37 | **Tampering** | WireGuard key injection via agent message | `ws.go:359-397`, `node.go:392-400` | `validWGPubkey()` validates key format before DB write; `serverUpdatePeer()` re-validates pubkey, endpoint, and allowed_ips before passing to `wg` CLI | None — defense-in-depth validation at both layers |
| 38 | **Denial of Service** | Agent message flooding | `ws.go:128-155` | Per-connection rate limit: 60 messages per 60-second window; exceeding closes connection with code 4008 | None — rate limit enforced before message dispatch |
| 39 | **Denial of Service** | Relay bandwidth abuse | `relay.go:109-117` | Byte-rate limit: 10 MB per 60-second window per source node; relay bindings require both nodes connected | None — bandwidth and binding constraints prevent amplification |

### TLS and Network Surface

| # | Category | Threat | Component | Mitigation | Residual Risk |
|---|----------|--------|-----------|------------|---------------|
| 40 | **Spoofing** | IP spoofing via X-Forwarded-For | `respond.go:146-148` | `clientIP()` always returns `RemoteAddr` — no proxy trust headers evaluated; auto-TLS eliminates the need for a reverse proxy | None — spoofing surface eliminated by design |
| 41 | **Spoofing** | Certificate issuance for wrong domain | `main.go:239-243` | `autocert.HostWhitelist(host)` restricts cert issuance to the exact hostname from `BASE_URL` | None — only configured hostname accepted |
| 42 | **Information Disclosure** | Plaintext traffic interception | `main.go:231-278` | Auto-TLS via Let's Encrypt when `BASE_URL` uses `https://`; HSTS header (`max-age=31536000; includeSubDomains`) set on all responses | HTTP dev mode has no encryption — never expose to the internet |
| 43 | **Denial of Service** | TLS cert exhaustion via random hostnames | `main.go:239-243` | `HostWhitelist` rejects certificate requests for any hostname not matching BASE_URL | None — rate limits on Let's Encrypt API are an external safeguard |

---

## JWT Pitfalls — Naive vs Birdcage

| Pitfall | Naive Approach | Birdcage | Reference |
|---------|---------------|----------|-----------|
| **Algorithm confusion** | Accept whatever `alg` the token header says, including `"none"` | Explicit `jwt.SigningMethodHS256` check — rejects any other algorithm | `crypto.go:121-124`, [RFC 8725 &sect;2.1](https://datatracker.ietf.org/doc/html/rfc8725#section-2.1) |
| **Shared secret for all token types** | One `JWT_SECRET` for everything | Separate `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET`; `typ` claim validated in `verifyToken()` | `crypto.go:93-134` |
| **No token type discrimination** | Accept any valid JWT in any context | `payload.Typ` must match expected type (`"access"` or `"refresh"`) or request is rejected | `crypto.go:130` |
| **Irrevocable tokens** | Stateless JWTs with no server-side check | Every token contains `sid` (session ID); `getSession()` checks the session exists and is valid before granting access | `middleware.go:52-56`, `session.go:73-95` |
| **No refresh token rotation** | Reuse same refresh token forever | Refresh tokens rotated on every use; `refresh_gen` counter with reuse detection — replay revokes the entire session | `middleware.go:70-109`, `session.go:109-118` |
| **Long-lived access tokens** | 24h or 7d access tokens | 15-minute access tokens; 7-day refresh tokens with automatic rotation | `crypto.go:22-23` |
| **Secrets in payload** | Store email, role, permissions in JWT claims | Minimal payload: `uid`, `sid`, `typ`, `gen`, `exp`, `iat` only — all other data fetched server-side | `crypto.go:85-90` |
| **Missing expiration** | No `exp` claim; tokens valid forever | `exp` set on both access and refresh tokens; `golang-jwt` rejects expired tokens automatically | `crypto.go:99-100` |
| **Tokens in localStorage** | `localStorage.setItem("token", jwt)` — accessible to any XSS | HTTP-only, Secure, SameSite=Strict cookies — JavaScript cannot read them; CSP nonce blocks inline script injection | `respond.go:93-103`, `main.go:140-150` |

---

## References

- [OWASP ASVS v5.0](https://github.com/OWASP/ASVS/tree/v5.0.0) — Application Security Verification Standard
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) — Digital Identity Guidelines: Authentication and Lifecycle Management
- [STRIDE Threat Model](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) — Microsoft Threat Modeling methodology
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) — JSON Web Token (JWT)
- [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) — JSON Web Token Best Current Practices
- [NIST SP 800-132](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf) — Recommendation for Password-Based Key Derivation
