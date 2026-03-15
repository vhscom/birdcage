package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
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
	bridgeUpgrader = websocket.Upgrader{
		CheckOrigin: checkWSOrigin,
	}
)

func newBridge() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.GatewayURL == "" {
			http.NotFound(w, r)
			return
		}

		raw, err := bridgeUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		client := &wsConn{Conn: raw}
		client.SetReadLimit(maxMessageSize)

		claims := getClaims(r)

		// Supersede existing connection
		activeBridgeMu.Lock()
		if prev := activeBridge; prev != nil {
			closeBridgeWS(prev, codeSuperseded, "Superseded")
			if claims != nil {
				emitEvent("bridge.superseded", clientIP(r), claims.UID, r.UserAgent(), 0, map[string]any{
					"session_id":  claims.SID,
					"previous_ip": prev.RemoteAddr().String(),
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
			client.Close()
		}()

		// Dial backend (claw gateway)
		wsURL := toWS(cfg.GatewayURL)
		hdr := http.Header{}
		if o := r.Header.Get("Origin"); o != "" {
			hdr.Set("Origin", o)
		}
		dialer := websocket.Dialer{HandshakeTimeout: dialTimeout}
		backend, _, err := dialer.Dial(wsURL, hdr)
		if err != nil {
			logError("bridge.dial", err)
			closeBridgeWS(client, codeBackendDown, "Backend unavailable")
			return
		}
		defer backend.Close()
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
				backend.SetReadDeadline(time.Now().Add(idleTimeout))
				mt, msg, err := backend.ReadMessage()
				if err != nil {
					return
				}
				client.wmu.Lock()
				client.Conn.SetWriteDeadline(time.Now().Add(writeWait))
				werr := client.Conn.WriteMessage(mt, msg)
				client.wmu.Unlock()
				if werr != nil {
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
				client.SetReadDeadline(time.Now().Add(idleTimeout))
				mt, msg, err := client.ReadMessage()
				if err != nil {
					return
				}
				if mt == websocket.BinaryMessage {
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
				if mt == websocket.TextMessage {
					msg = injectToken(msg, cfg.GatewayToken)
				}
				backend.SetWriteDeadline(time.Now().Add(writeWait))
				if err := backend.WriteMessage(mt, msg); err != nil {
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
	msg := websocket.FormatCloseMessage(code, reason)
	c.safeWriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second))
	c.Close()
}
