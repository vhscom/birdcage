package api

import (
	"context"
	"net/http"
)

// ListNodes returns all nodes in the mesh.
func (c *Client) ListNodes(ctx context.Context) (*ListNodesResponse, error) {
	var out ListNodesResponse
	if err := c.do(ctx, http.MethodGet, "/ops/nodes", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
