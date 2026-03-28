package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	maxMessageSize = 1 << 20 // 1 MB
	bridgeRateMax  = 100     // messages per 1-second window
	idleTimeout    = 30 * time.Minute
	dialTimeout    = 5 * time.Second
	writeWait      = 10 * time.Second
	heartbeatIvl   = 25 * time.Second
)

const (
	codeBackendDown    = 4502
	codeSuperseded     = 4012
	codeRateLimited    = 4029
	codeSessionRevoked = 4010
)

var (
	activeBridge   *wsConn
	activeBridgeMu sync.Mutex
)

func newBridge() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.GatewayURL == "" {
			http.NotFound(w, r)
			return
		}

		if !checkWSOrigin(r) {
			http.Error(w, "Origin not allowed", http.StatusForbidden)
			return
		}

		opts := &websocket.AcceptOptions{}
		if cfg.WSAllowedOrigins != "" {
			for _, o := range strings.Split(cfg.WSAllowedOrigins, ",") {
				if o = strings.TrimSpace(o); o != "" {
					opts.OriginPatterns = append(opts.OriginPatterns, o)
				}
			}
		}
		c, err := websocket.Accept(w, r, opts)
		if err != nil {
			return
		}
		client := &wsConn{Conn: c, remoteAddr: r.RemoteAddr}
		client.SetReadLimit(maxMessageSize)

		claims := getClaims(r)

		// Supersede existing connection
		activeBridgeMu.Lock()
		if prev := activeBridge; prev != nil {
			closeBridgeWS(prev, codeSuperseded, "Superseded")
			if claims != nil {
				emitEvent("bridge.superseded", clientIP(r), claims.UID, r.UserAgent(), 0, map[string]any{
					"session_id":  claims.SID,
					"previous_ip": prev.remoteAddr,
				})
			}
		}
		activeBridge = client
		activeBridgeMu.Unlock()

		defer func() {
			activeBridgeMu.Lock()
			if activeBridge == client {
				activeBridge = nil
			}
			activeBridgeMu.Unlock()
			client.CloseNow()
		}()

		// Dial backend (claw gateway)
		wsURL := toWS(cfg.GatewayURL)
		hdr := http.Header{}
		if o := r.Header.Get("Origin"); o != "" {
			hdr.Set("Origin", o)
		}
		dialCtx, dialCancel := context.WithTimeout(r.Context(), dialTimeout)
		defer dialCancel()
		backend, _, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
			HTTPHeader: hdr,
		})
		if err != nil {
			logError("bridge.dial", err)
			closeBridgeWS(client, codeBackendDown, "Backend unavailable")
			return
		}
		defer backend.CloseNow()
		backend.SetReadLimit(maxMessageSize)

		done := make(chan struct{}, 3)

		// Session heartbeat — close if session revoked
		if claims != nil {
			go func() {
				ticker := time.NewTicker(heartbeatIvl)
				defer ticker.Stop()
				for {
					select {
					case <-done:
						return
					case <-ticker.C:
						var count int
						err := store.QueryRow(
							"SELECT COUNT(*) FROM session WHERE id = ? AND expires_at > datetime('now')", claims.SID,
						).Scan(&count)
						if err != nil || count == 0 {
							closeBridgeWS(client, codeSessionRevoked, "Session revoked")
							done <- struct{}{}
							return
						}
					}
				}
			}()
		}

		// backend → client
		go func() {
			defer func() { done <- struct{}{} }()
			for {
				readCtx, readCancel := context.WithTimeout(r.Context(), idleTimeout)
				mt, msg, err := backend.Read(readCtx)
				readCancel()
				if err != nil {
					return
				}
				if err := client.safeWrite(mt, msg); err != nil {
					return
				}
			}
		}()

		// client → backend (token injection + rate limiting)
		go func() {
			defer func() { done <- struct{}{} }()
			var count int
			win := time.Now()
			for {
				readCtx, readCancel := context.WithTimeout(r.Context(), idleTimeout)
				mt, msg, err := client.Read(readCtx)
				readCancel()
				if err != nil {
					return
				}
				if mt == websocket.MessageBinary {
					closeBridgeWS(client, 1003, "Binary not supported")
					return
				}
				now := time.Now()
				if now.Sub(win) > time.Second {
					win = now
					count = 0
				}
				count++
				if count > bridgeRateMax {
					closeBridgeWS(client, codeRateLimited, "Rate limited")
					return
				}
				if mt == websocket.MessageText {
					msg = injectToken(msg, cfg.GatewayToken)
				}
				wctx, wcancel := context.WithTimeout(r.Context(), writeWait)
				werr := backend.Write(wctx, mt, msg)
				wcancel()
				if werr != nil {
					return
				}
			}
		}()

		<-done
	})
}

func injectToken(raw []byte, token string) []byte {
	if token == "" {
		return raw
	}
	var f map[string]any
	if json.Unmarshal(raw, &f) != nil {
		return raw
	}
	if f["type"] != "req" || f["method"] != "connect" {
		return raw
	}
	params, _ := f["params"].(map[string]any)
	if params == nil {
		return raw
	}
	if _, exists := params["auth"]; exists {
		slog.Warn("bridge connect frame already contains auth field, overwriting")
	}
	params["auth"] = map[string]string{"token": token}
	if params["scopes"] == nil {
		params["scopes"] = []string{"operator.admin"}
	}
	out, err := json.Marshal(f)
	if err != nil {
		return raw
	}
	return out
}

func toWS(u string) string {
	return strings.NewReplacer("https://", "wss://", "http://", "ws://").Replace(u)
}

func closeBridgeWS(c *wsConn, code int, reason string) {
	c.Close(websocket.StatusCode(code), reason)
}
