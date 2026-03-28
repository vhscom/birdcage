package api

import (
	"context"
	"net/http"
)

// GetCloakStatus returns the current cloak state.
func (c *Client) GetCloakStatus(ctx context.Context) (*CloakStatusResponse, error) {
	var out CloakStatusResponse
	if err := c.do(ctx, http.MethodGet, "/ops/cloak", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EnableCloak activates cloak mode.
func (c *Client) EnableCloak(ctx context.Context, req EnableCloakRequest) (*EnableCloakResponse, error) {
	var out EnableCloakResponse
	if err := c.do(ctx, http.MethodPost, "/ops/cloak", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DisableCloak deactivates cloak mode.
func (c *Client) DisableCloak(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/ops/cloak", nil, nil)
}
