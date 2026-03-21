package api

import "time"

// APIError represents an error response from the ops API.
type APIError struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// --- Agents ---

// Agent represents an agent credential.
type Agent struct {
	Name      string  `json:"name"`
	CreatedAt string  `json:"created_at"`
	RevokedAt *string `json:"revoked_at,omitempty"`
}

// ListAgentsResponse is the response from GET /ops/agents.
type ListAgentsResponse struct {
	Agents []Agent `json:"agents"`
}

// CreateAgentRequest is the request body for POST /ops/agents.
type CreateAgentRequest struct {
	Name string `json:"name"`
}

// CreateAgentResponse is the response from POST /ops/agents.
type CreateAgentResponse struct {
	Name   string `json:"name"`
	APIKey string `json:"apiKey"`
}

// DeleteAgentResponse is the response from DELETE /ops/agents/:name.
type DeleteAgentResponse struct {
	Success bool `json:"success"`
}

// --- Events ---

// Event represents a security event.
type Event struct {
	ID        int     `json:"id"`
	Type      string  `json:"type"`
	IPAddress string  `json:"ip_address"`
	UserID    *int    `json:"user_id"`
	Detail    *string `json:"detail"`
	CreatedAt string  `json:"created_at"`
	ActorID   string  `json:"actor_id"`
}

// ListEventsResponse is the response from GET /ops/events.
type ListEventsResponse struct {
	Events []Event `json:"events"`
}

// EventsParams holds query parameters for GET /ops/events.
type EventsParams struct {
	Type   string
	UserID string
	IP     string
	Since  string
	Limit  int
	Offset int
}

// EventStatsResponse is the response from GET /ops/events/stats.
type EventStatsResponse struct {
	Stats map[string]int `json:"stats"`
	Since string         `json:"since"`
}

// --- Sessions ---

// Session represents a user session.
type Session struct {
	ID        string `json:"id"`
	UserID    int    `json:"user_id"`
	UserAgent string `json:"user_agent"`
	IPAddress string `json:"ip_address"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

// ListSessionsResponse is the response from GET /ops/sessions.
type ListSessionsResponse struct {
	Sessions []Session `json:"sessions"`
}

// SessionsParams holds query parameters for GET /ops/sessions.
type SessionsParams struct {
	Limit  int
	Offset int
}

// RevokeSessionsRequest is the request body for POST /ops/sessions/revoke.
type RevokeSessionsRequest struct {
	Scope string      `json:"scope"`
	ID    interface{} `json:"id,omitempty"`
}

// RevokeSessionsResponse is the response from POST /ops/sessions/revoke.
type RevokeSessionsResponse struct {
	Success bool  `json:"success"`
	Revoked int64 `json:"revoked"`
}

// --- Nodes ---

// Node represents a WireGuard mesh node.
type Node struct {
	ID         int     `json:"id"`
	Label      string  `json:"label"`
	WGPubkey   string  `json:"wg_pubkey"`
	WGEndpoint *string `json:"wg_endpoint,omitempty"`
	AllowedIPs string  `json:"allowed_ips"`
	LastSeenAt *string `json:"last_seen_at,omitempty"`
	CreatedAt  string  `json:"created_at"`
}

// ListNodesResponse is the response from GET /ops/nodes.
type ListNodesResponse struct {
	Nodes []Node `json:"nodes"`
}

// DefaultSince returns the ISO 8601 timestamp for 24 hours ago.
func DefaultSince() string {
	return time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
}
