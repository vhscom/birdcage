package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/curve25519"
)

// --- Connected node registry ---

type connectedNode struct {
	conn    *wsConn
	agentID int
	nodeID  int
}

var nodeRegistry struct {
	mu   sync.RWMutex
	byID map[int]*connectedNode
}

func init() {
	nodeRegistry.byID = make(map[int]*connectedNode)
}

func registerNode(n *connectedNode) {
	nodeRegistry.mu.Lock()
	defer nodeRegistry.mu.Unlock()
	nodeRegistry.byID[n.nodeID] = n
}

func unregisterNode(nodeID int) {
	nodeRegistry.mu.Lock()
	defer nodeRegistry.mu.Unlock()
	delete(nodeRegistry.byID, nodeID)
}

// lookupNodeForAgent returns the node ID for an agent credential, or 0 if none.
// If no node exists, it auto-creates one with the next available mesh IP.
func lookupNodeForAgent(agentCredID int) int {
	var nodeID int
	err := store.QueryRow("SELECT id FROM node WHERE agent_credential_id = ?", agentCredID).Scan(&nodeID)
	if err == nil {
		return nodeID
	}

	// Auto-create: find agent name for label
	var name string
	store.QueryRow("SELECT name FROM agent_credential WHERE id = ?", agentCredID).Scan(&name)
	if name == "" {
		name = fmt.Sprintf("node-%d", agentCredID)
	}

	meshIP := nextMeshIP()
	_, err = store.Exec(
		"INSERT INTO node (label, wg_pubkey, allowed_ips, agent_credential_id) VALUES (?,?,?,?)",
		name, "pending", meshIP, agentCredID,
	)
	if err != nil {
		slog.Error("auto-create node failed", "error", err)
		return 0
	}

	store.QueryRow("SELECT id FROM node WHERE agent_credential_id = ?", agentCredID).Scan(&nodeID)
	slog.Info("node auto-created", "id", nodeID, "label", name, "mesh_ip", meshIP)
	return nodeID
}

// nextMeshIP finds the next available IP in the 10.0.0.0/24 mesh.
// 10.0.0.1 is reserved for the server.
func nextMeshIP() string {
	var maxOctet int
	rows, err := store.Query("SELECT allowed_ips FROM node")
	if err != nil {
		return "10.0.0.2/32"
	}
	defer rows.Close()

	for rows.Next() {
		var ips string
		if err := rows.Scan(&ips); err != nil {
			continue
		}
		// Parse "10.0.0.X/32"
		ip := strings.TrimSuffix(ips, "/32")
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			var oct int
			fmt.Sscanf(parts[3], "%d", &oct)
			if oct > maxOctet {
				maxOctet = oct
			}
		}
	}

	next := maxOctet + 1
	if next < 2 {
		next = 2 // 10.0.0.1 is the server
	}
	if next > 254 {
		next = 254
	}
	return fmt.Sprintf("10.0.0.%d/32", next)
}

// handleWGStatus processes a wg.status message from a node agent.
// On first status, updates the node's public key.
func handleWGStatus(cred *AgentCredential, payload json.RawMessage, nodeID int) {
	if nodeID == 0 {
		return
	}

	var status struct {
		PublicKey  string `json:"public_key"`
		ListenPort int    `json:"listen_port"`
		Interface  string `json:"interface"`
	}
	if err := json.Unmarshal(payload, &status); err != nil {
		return
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05")

	// Update node record with latest status + public key if it was pending
	if status.PublicKey != "" && validWGPubkey(status.PublicKey) {
		if _, err := store.Exec(
			"UPDATE node SET wg_pubkey = ?, wg_listen_port = ?, interface_name = ?, last_status = ?, last_seen_at = ?, updated_at = ? WHERE id = ? AND wg_pubkey = 'pending'",
			status.PublicKey, status.ListenPort, status.Interface, string(payload), now, now, nodeID,
		); err != nil {
			logError("node.update_pubkey", err)
		}
	}

	if _, err := store.Exec(
		"UPDATE node SET last_status = ?, last_seen_at = ?, updated_at = ? WHERE id = ?",
		string(payload), now, now, nodeID,
	); err != nil {
		logError("node.update_status", err)
	}

	// If pubkey was updated, sync WireGuard peers
	if status.PublicKey != "" {
		serverUpdatePeer(nodeID)
	}
}

// notifyNodeSync pushes the mesh peer set to all connected node agents.
func notifyNodeSync() {
	nodeRegistry.mu.RLock()
	var targets []*connectedNode
	for _, n := range nodeRegistry.byID {
		targets = append(targets, n)
	}
	nodeRegistry.mu.RUnlock()

	if len(targets) == 0 {
		return
	}

	// Fetch all nodes
	type meshNode struct {
		ID         int
		Label      string
		Pubkey     string
		Endpoint   *string
		AllowedIPs string
		ListenPort int
		Keepalive  int
	}
	rows, err := store.Query(
		"SELECT id, label, wg_pubkey, wg_endpoint, allowed_ips, wg_listen_port, persistent_keepalive FROM node WHERE wg_pubkey != 'pending'",
	)
	if err != nil {
		slog.Error("notifyNodeSync: query nodes", "error", err)
		return
	}
	defer rows.Close()

	var allNodes []meshNode
	for rows.Next() {
		var n meshNode
		if err := rows.Scan(&n.ID, &n.Label, &n.Pubkey, &n.Endpoint, &n.AllowedIPs, &n.ListenPort, &n.Keepalive); err != nil {
			continue
		}
		allNodes = append(allNodes, n)
	}

	// Build server peer info from config
	var serverPeer *syncPeer
	if cfg.WGPrivateKey != "" {
		pubKey := deriveWGPublicKey(cfg.WGPrivateKey)
		if pubKey != "" {
			serverPeer = &syncPeer{
				NodeID:     0, // server is not a DB node
				Label:      "server",
				PublicKey:  pubKey,
				Endpoint:   cfg.WGEndpoint,
				AllowedIPs: "10.0.0.1/32",
				Keepalive:  25,
			}
		}
	}

	type syncSelf struct {
		NodeID     int    `json:"node_id"`
		MeshIP     string `json:"mesh_ip"`
		ListenPort int    `json:"listen_port"`
	}

	for _, target := range targets {
		peers := make([]syncPeer, 0)
		var self *syncSelf

		// Always include self info, even if pubkey is still pending
		var selfIP string
		var selfPort int
		if err := store.QueryRow(
			"SELECT allowed_ips, wg_listen_port FROM node WHERE id = ?", target.nodeID,
		).Scan(&selfIP, &selfPort); err == nil {
			self = &syncSelf{
				NodeID:     target.nodeID,
				MeshIP:     selfIP,
				ListenPort: selfPort,
			}
		}

		// Add server as peer
		if serverPeer != nil {
			peers = append(peers, *serverPeer)
		}

		for _, n := range allNodes {
			if n.ID == target.nodeID {
				continue
			}
			ep := ""
			if n.Endpoint != nil {
				ep = *n.Endpoint
			}
			peers = append(peers, syncPeer{
				NodeID:     n.ID,
				Label:      n.Label,
				PublicKey:  n.Pubkey,
				Endpoint:   ep,
				AllowedIPs: n.AllowedIPs,
				Keepalive:  n.Keepalive,
			})
		}

		msg := map[string]any{
			"type": "wg.sync",
			"payload": map[string]any{
				"action": "full_sync",
				"self":   self,
				"peers":  peers,
			},
		}
		data, _ := json.Marshal(msg)
		target.conn.safeWrite(websocket.TextMessage, data)
	}
}

type syncPeer struct {
	NodeID     int    `json:"node_id"`
	Label      string `json:"label,omitempty"`
	PublicKey  string `json:"public_key"`
	Endpoint   string `json:"endpoint,omitempty"`
	AllowedIPs string `json:"allowed_ips"`
	Keepalive  int    `json:"persistent_keepalive,omitempty"`
}

// deriveWGPublicKey derives the WireGuard public key from a base64-encoded private key.
func deriveWGPublicKey(privKeyB64 string) string {
	privBytes, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil || len(privBytes) != 32 {
		return ""
	}
	pub, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// --- Server-side WireGuard management ---

// serverEnsureWG provisions the server's WireGuard interface.
func serverEnsureWG() {
	if cfg.WGPrivateKey == "" {
		return
	}

	iface := cfg.WGInterface
	listenPort := cfg.WGListenPort

	switch runtime.GOOS {
	case "linux":
		if exec.Command("ip", "link", "show", iface).Run() != nil {
			out, err := exec.Command("ip", "link", "add", iface, "type", "wireguard").CombinedOutput()
			if err != nil {
				slog.Error("failed to create WG interface", "error", err, "output", string(out))
				return
			}
		}
		// Set private key via stdin
		cmd := exec.Command("wg", "set", iface, "private-key", "/dev/stdin", "listen-port", fmt.Sprint(listenPort))
		cmd.Stdin = strings.NewReader(cfg.WGPrivateKey)
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Error("wg set failed", "error", err, "output", string(out))
			return
		}
		if out, err := exec.Command("ip", "addr", "flush", "dev", iface).CombinedOutput(); err != nil { // #nosec G204
			slog.Warn("ip addr flush failed", "error", err, "output", string(out))
		}
		if out, err := exec.Command("ip", "addr", "add", "10.0.0.1/32", "dev", iface).CombinedOutput(); err != nil { // #nosec G204
			slog.Warn("ip addr add failed", "error", err, "output", string(out))
		}
		if out, err := exec.Command("ip", "link", "set", iface, "up").CombinedOutput(); err != nil { // #nosec G204
			slog.Error("ip link set up failed", "error", err, "output", string(out))
			return
		}

	case "darwin":
		if exec.Command("wg", "show", iface).Run() != nil {
			if _, err := exec.LookPath("wireguard-go"); err != nil {
				slog.Warn("wireguard-go not found, WireGuard disabled")
				return
			}

			// Try requested interface, then scan for available utun
			candidates := []string{iface}
			if strings.HasPrefix(iface, "utun") {
				for i := 3; i <= 15; i++ {
					name := fmt.Sprintf("utun%d", i)
					if name != iface {
						candidates = append(candidates, name)
					}
				}
			}

			requested := iface
			created := false
			for _, name := range candidates {
				os.Remove(fmt.Sprintf("/var/run/wireguard/%s.sock", name))
				out, err := exec.Command("wireguard-go", name).CombinedOutput()
				if err == nil {
					iface = name
					cfg.WGInterface = name
					created = true
					if name != requested {
						slog.Info("requested interface unavailable, using alternative", "requested", requested, "using", name)
					}
					break
				}
				if strings.Contains(string(out), "not permitted") {
					slog.Error("wireguard requires elevated privileges", "hint", "run: sudo birdcage serve")
					return
				}
			}
			if !created {
				slog.Error("no available utun device (utun3-utun15 all in use)")
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		cmd := exec.Command("wg", "set", iface, "private-key", "/dev/stdin", "listen-port", fmt.Sprint(listenPort))
		cmd.Stdin = strings.NewReader(cfg.WGPrivateKey)
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Error("wg set failed", "error", err, "output", string(out))
			return
		}
		if out, err := exec.Command("ifconfig", iface, "inet", "10.0.0.1/32", "10.0.0.1").CombinedOutput(); err != nil { // #nosec G204
			slog.Warn("ifconfig inet failed", "error", err, "output", string(out))
		}
		if out, err := exec.Command("ifconfig", iface, "up").CombinedOutput(); err != nil { // #nosec G204
			slog.Error("ifconfig up failed", "error", err, "output", string(out))
			return
		}

	default:
		slog.Warn("WireGuard not supported on this platform", "os", runtime.GOOS)
		return
	}

	pubKey := deriveWGPublicKey(cfg.WGPrivateKey)
	slog.Info("wireguard interface ready", "interface", iface, "listen_port", listenPort, "pubkey", pubKey)
}

// serverUpdatePeer updates a single node's WireGuard peer on the server interface.
func serverUpdatePeer(nodeID int) {
	if cfg.WGPrivateKey == "" {
		return
	}

	var pubkey string
	var endpoint *string
	var allowedIPs string
	var keepalive int

	err := store.QueryRow(
		"SELECT wg_pubkey, wg_endpoint, allowed_ips, persistent_keepalive FROM node WHERE id = ?",
		nodeID,
	).Scan(&pubkey, &endpoint, &allowedIPs, &keepalive)
	if err != nil || pubkey == "pending" {
		return
	}

	// Defense-in-depth: validate before passing to wg CLI
	if !validWGPubkey(pubkey) || !validAllowedIPs(allowedIPs) {
		slog.Warn("server peer update: invalid data in DB", "node", nodeID)
		return
	}
	if endpoint != nil && *endpoint != "" && !validEndpoint(*endpoint) {
		slog.Warn("server peer update: invalid endpoint in DB", "node", nodeID)
		return
	}

	iface := cfg.WGInterface
	args := []string{"set", iface, "peer", pubkey, "allowed-ips", allowedIPs}
	if endpoint != nil && *endpoint != "" {
		args = append(args, "endpoint", *endpoint)
	}
	if keepalive > 0 {
		args = append(args, "persistent-keepalive", fmt.Sprint(keepalive))
	}

	if out, err := exec.Command("wg", args...).CombinedOutput(); err != nil {
		slog.Error("wg set peer failed", "error", err, "output", string(out), "node", nodeID)
	} else {
		slog.Info("peer updated", "node", nodeID, "pubkey", pubkey[:8]+"...")
	}
}
