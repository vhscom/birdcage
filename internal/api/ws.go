package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/coder/websocket"
)

// ConnectWS opens a WebSocket connection to /ops/ws with agent auth.
// The caller is responsible for closing the returned connection.
func (c *Client) ConnectWS(ctx context.Context) (*websocket.Conn, error) {
	wsURL, err := httpToWS(c.baseURL)
	if err != nil {
		return nil, err
	}
	wsURL += "/ops/ws"

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + c.agentKey},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("ws dial: %w", err)
	}
	return conn, nil
}

// httpToWS converts an HTTP(S) URL to a WS(S) URL.
func httpToWS(rawURL string) (string, error) {
	switch {
	case strings.HasPrefix(rawURL, "https://"):
		return "wss://" + strings.TrimPrefix(rawURL, "https://"), nil
	case strings.HasPrefix(rawURL, "http://"):
		return "ws://" + strings.TrimPrefix(rawURL, "http://"), nil
	default:
		return "", fmt.Errorf("unsupported URL scheme: %s", rawURL)
	}
}
