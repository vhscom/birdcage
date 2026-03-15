package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
)

type config struct {
	Server    string `json:"server"`
	Token     string `json:"token"`
	Interface string `json:"interface"`
}

// Run is the entry point for "birdcage agent".
func Run() {
	var ifaceOverride string
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "init":
			runInit()
			return
		case "install":
			runInstall()
			return
		case "uninstall":
			runUninstall()
			return
		case "--help", "-h", "help":
			printAgentHelp()
			return
		}
		for i := 1; i < len(os.Args); i++ {
			if os.Args[i] == "--interface" && i+1 < len(os.Args) {
				i++
				ifaceOverride = os.Args[i]
			}
		}
	}

	checkWireGuardTools()

	cfg := loadConfig()
	if ifaceOverride != "" {
		cfg.Interface = ifaceOverride
	}

	slog.Info("birdcage agent starting", "server", cfg.Server, "interface", cfg.Interface)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	connectLoop(ctx, cfg)
}

func printAgentHelp() {
	fmt.Println("birdcage agent — WireGuard mesh agent")
	fmt.Println()
	fmt.Println("Usage")
	fmt.Printf("  %-42s %s\n", "birdcage agent", "Connect and sync WireGuard config")
	fmt.Printf("  %-42s %s\n", "birdcage agent init <server> <key> [iface]", "Write config from server URL and API key")
	fmt.Printf("  %-42s %s\n", "birdcage agent install", "Install as system service (launchd/systemd)")
	fmt.Printf("  %-42s %s\n", "birdcage agent uninstall", "Remove system service")
	fmt.Println()
	fmt.Println("Environment")
	fmt.Printf("  %-28s %s\n", "BIRDCAGE_AGENT_SERVER", "Server URL (overrides config file)")
	fmt.Printf("  %-28s %s\n", "BIRDCAGE_AGENT_TOKEN", "API key (overrides config file)")
	fmt.Printf("  %-28s %s\n", "BIRDCAGE_AGENT_INTERFACE", "WireGuard interface (default: wg0)")
	fmt.Printf("  %-28s %s\n", "BIRDCAGE_AGENT_CONFIG_DIR", "Config directory (default: ~/.config/birdcage)")
}

func runInit() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: birdcage agent init <server-url> <api-key> [interface]\n")
		fmt.Fprintf(os.Stderr, "Example: birdcage agent init https://birdcage.example.com abc123 wg0\n")
		os.Exit(1)
	}

	iface := DefaultInterface()
	if len(os.Args) > 4 {
		iface = os.Args[4]
	}

	cfg := config{
		Server:    os.Args[2],
		Token:     os.Args[3],
		Interface: iface,
	}

	dir := configDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatalf("Failed to create config dir: %v", err)
	}

	data, _ := json.MarshalIndent(cfg, "", "  ")
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		log.Fatalf("Failed to write config: %v", err)
	}
	fmt.Printf("Config written to %s\n", path)
	fmt.Printf("Run 'sudo birdcage agent' to connect.\n")
}

func configDir() string {
	if d := os.Getenv("BIRDCAGE_AGENT_CONFIG_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "birdcage")
}

func loadConfig() *config {
	server := os.Getenv("BIRDCAGE_AGENT_SERVER")
	token := os.Getenv("BIRDCAGE_AGENT_TOKEN")
	iface := os.Getenv("BIRDCAGE_AGENT_INTERFACE")

	if server != "" && token != "" {
		if iface == "" {
			iface = DefaultInterface()
		}
		return &config{Server: server, Token: token, Interface: iface}
	}

	path := filepath.Join(configDir(), "config.json")
	data, err := os.ReadFile(path) // #nosec G304 — path constructed from fixed prefix + "config.json"
	if err != nil {
		fmt.Fprintf(os.Stderr, "No config found. Run 'birdcage agent init <server> <key>' first.\n")
		os.Exit(1)
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}
	if cfg.Interface == "" {
		cfg.Interface = DefaultInterface()
	}
	return &cfg
}

func connectLoop(ctx context.Context, cfg *config) {
	backoff := time.Second

	for {
		err := runSession(ctx, cfg)
		if ctx.Err() != nil {
			return
		}

		reason := "unknown"
		if err != nil {
			reason = err.Error()
		}
		slog.Warn("disconnected, reconnecting", "reason", reason, "backoff", backoff)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
	}
}

func runSession(ctx context.Context, cfg *config) error {
	iface := cfg.Interface
	wsURL := cfg.Server + "/ws"
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: map[string][]string{
			"Authorization": {"Bearer " + cfg.Token},
		},
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseNow()

	slog.Info("connected to server")

	// Negotiate capabilities
	capReq := map[string]any{
		"type":         "capability.request",
		"capabilities": []string{"wg_sync", "wg_status", "endpoint_discovery", "key_rotate"},
	}
	data, _ := json.Marshal(capReq)
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		return fmt.Errorf("capability request: %w", err)
	}

	_, resp, err := conn.Read(ctx)
	if err != nil {
		return fmt.Errorf("capability response: %w", err)
	}

	var granted struct {
		Type    string   `json:"type"`
		Granted []string `json:"granted"`
	}
	if err := json.Unmarshal(resp, &granted); err != nil {
		return fmt.Errorf("parse capabilities: %w", err)
	}

	caps := map[string]bool{}
	for _, c := range granted.Granted {
		caps[c] = true
	}

	if !caps["wg_sync"] {
		return fmt.Errorf("server did not grant wg_sync capability")
	}

	slog.Info("capabilities granted", "caps", granted.Granted)

	// Session state
	keyRotateAck := make(chan bool, 1)
	rm := newRelayManager(ctx, conn, iface, getListenPort(nil))
	defer rm.close()

	sess := &session{
		ctx:          ctx,
		conn:         conn,
		iface:        iface,
		rm:           rm,
		keyRotateAck: keyRotateAck,
	}

	// Send initial status
	wgStatus, err := wgShow(sess.iface)
	if err != nil {
		slog.Info("wg interface not yet provisioned")
	} else {
		sess.sendStatus(wgStatus)
	}

	// STUN endpoint discovery
	if caps["endpoint_discovery"] {
		go sess.sendEndpointDiscovery(getListenPort(wgStatus))
	}

	// Main loop
	statusTicker := time.NewTicker(60 * time.Second)
	defer statusTicker.Stop()

	stunTicker := time.NewTicker(30 * time.Minute)
	defer stunTicker.Stop()

	keyRotateTicker := time.NewTicker(1 * time.Hour)
	defer keyRotateTicker.Stop()

	msgCh := make(chan wsMessage, 16)
	errCh := make(chan error, 1)

	go func() {
		for {
			msgType, data, err := conn.Read(ctx)
			if err != nil {
				errCh <- err
				return
			}
			msgCh <- wsMessage{msgType: msgType, data: data}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "shutdown")
			return nil
		case err := <-errCh:
			return err
		case msg := <-msgCh:
			if msg.msgType == websocket.MessageBinary {
				rm.injectPacket(msg.data)
				continue
			}
			if err := sess.handleMessage(msg.data); err != nil {
				slog.Error("message handler", "error", err)
			}
		case <-statusTicker.C:
			wgStatus, err := wgShow(sess.iface)
			if err != nil {
				continue
			}
			sess.sendStatus(wgStatus)
			rm.evaluatePeers(wgStatus)
		case <-stunTicker.C:
			if caps["endpoint_discovery"] {
				listenPort := 51820
				if s, err := wgShow(sess.iface); err == nil {
					listenPort = getListenPort(s)
				}
				sess.sendEndpointDiscovery(listenPort)
			}
		case <-keyRotateTicker.C:
			if caps["key_rotate"] && needsRotation() {
				if err := rotateKey(ctx, conn, sess.iface, keyRotateAck); err != nil {
					slog.Error("key rotation failed", "error", err)
				} else {
					slog.Info("key rotated successfully")
				}
			}
		}
	}
}

type wsMessage struct {
	msgType websocket.MessageType
	data    []byte
}

type session struct {
	ctx          context.Context
	conn         *websocket.Conn
	iface        string
	rm           *relayManager
	keyRotateAck chan<- bool
}

func (s *session) sendEndpointDiscovery(listenPort int) {
	ep, err := discoverEndpoint(s.ctx, listenPort)
	if err != nil {
		slog.Warn("stun discovery failed", "error", err)
		return
	}
	slog.Info("endpoint discovered", "endpoint", ep)
	msg := map[string]any{
		"type": "endpoint.discovered",
		"payload": map[string]any{
			"endpoint": ep,
		},
	}
	data, _ := json.Marshal(msg)
	s.conn.Write(s.ctx, websocket.MessageText, data)
}

func getListenPort(status *interfaceStatus) int {
	if status != nil && status.ListenPort > 0 {
		return status.ListenPort
	}
	return 51820
}

func (s *session) sendStatus(status *interfaceStatus) {
	msg := map[string]any{
		"type":    "wg.status",
		"payload": status,
	}
	data, _ := json.Marshal(msg)
	s.conn.Write(s.ctx, websocket.MessageText, data)
}

func (s *session) handleMessage(raw []byte) error {
	var msg struct {
		Type    string          `json:"type"`
		ID      string          `json:"id"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil
	}

	switch msg.Type {
	case "heartbeat", "pong":
		// no-op
	case "wg.sync":
		return s.handleSync(msg.ID, msg.Payload)
	case "relay.bind.result":
		var p struct {
			Success bool `json:"success"`
		}
		json.Unmarshal(msg.Payload, &p)
		if !p.Success {
			slog.Warn("relay bind denied")
		}
	case "key.rotate.result":
		var p struct {
			Success bool `json:"success"`
		}
		json.Unmarshal(msg.Payload, &p)
		select {
		case s.keyRotateAck <- p.Success:
		default:
		}
	case "endpoint.discovered.result":
		// acknowledgement
	}
	return nil
}

func (s *session) handleSync(msgID string, payload json.RawMessage) error {
	var p struct {
		Action string `json:"action"`
		Self   *struct {
			NodeID     int    `json:"node_id"`
			MeshIP     string `json:"mesh_ip"`
			ListenPort int    `json:"listen_port"`
		} `json:"self"`
		Peers  []peerConfig `json:"peers"`
		Peer   *peerConfig  `json:"peer"`
		Pubkey string       `json:"public_key"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("parse sync payload: %w", err)
	}

	var syncErr error
	switch p.Action {
	case "full_sync":
		if p.Self != nil && p.Self.MeshIP != "" {
			slog.Info("mesh identity", "ip", p.Self.MeshIP, "port", p.Self.ListenPort)
			if actualIface, err := ensureInterface(s.iface, p.Self.ListenPort, p.Self.MeshIP); err != nil {
				errMsg := err.Error()
				if strings.Contains(errMsg, "not permitted") {
					slog.Error("creating network interface requires elevated privileges — run: sudo birdcage agent")
				} else if strings.Contains(errMsg, "Address already in use") {
					slog.Error("listen port already in use (stale wireguard-go process?)")
				} else {
					slog.Error("interface setup failed", "error", errMsg)
				}
				os.Exit(1)
			} else if actualIface != s.iface {
				s.iface = actualIface
				slog.Info("using interface", "iface", actualIface)
			}
		}
		syncErr = wgSyncFull(s.iface, p.Peers)
		if syncErr == nil {
			slog.Info("mesh synced", "peers", len(p.Peers))
		}
		if err := updateHosts(p.Peers); err != nil {
			slog.Warn("dns update failed", "error", err)
		}
		if s.rm != nil {
			nodeMap := make(map[string]int)
			for _, peer := range p.Peers {
				if peer.NodeID > 0 {
					nodeMap[peer.PublicKey] = peer.NodeID
				}
			}
			s.rm.updateNodeMap(nodeMap)
		}
	case "add_peer":
		if p.Peer != nil {
			syncErr = wgSetPeer(s.iface, *p.Peer)
		}
	case "remove_peer":
		if p.Pubkey != "" {
			syncErr = wgRemovePeer(s.iface, p.Pubkey)
		}
	default:
		return nil
	}

	if syncErr != nil {
		slog.Error("sync failed", "action", p.Action, "error", syncErr)
	}

	result := map[string]any{
		"type": "wg.sync.result",
		"payload": map[string]any{
			"success": syncErr == nil,
		},
	}
	if msgID != "" {
		result["id"] = msgID
	}
	if syncErr != nil {
		result["payload"].(map[string]any)["error"] = syncErr.Error()
	}
	data, _ := json.Marshal(result)
	return s.conn.Write(s.ctx, websocket.MessageText, data)
}
