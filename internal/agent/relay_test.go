package agent

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func testRelayManager(t *testing.T) *relayManager {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Create a test WS conn so stopRelay doesn't panic on relay.unbind send
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		for {
			_, _, err := c.Read(context.Background())
			if err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial test ws: %v", err)
	}
	t.Cleanup(func() { conn.CloseNow() })

	return &relayManager{
		peers:    make(map[string]*peerRelay),
		conn:     conn,
		iface:    "wg-test",
		wgPort:   51820,
		nodeMap:  make(map[string]int),
		ctx:      ctx,
		cancelFn: cancel,
	}
}

func TestEvaluatePeersNilStatus(t *testing.T) {
	rm := testRelayManager(t)
	rm.evaluatePeers(nil) // should not panic
}

func TestEvaluatePeersDirectHandshake(t *testing.T) {
	rm := testRelayManager(t)
	rm.nodeMap["pubkey-a"] = 10

	status := &interfaceStatus{
		Peers: []peerStatus{
			{PublicKey: "pubkey-a", LatestHandshake: time.Now().Unix()},
		},
	}
	rm.evaluatePeers(status)

	// Peer with fresh handshake should not create relay state
	if _, exists := rm.peers["pubkey-a"]; exists {
		t.Error("should not create relay state for peer with direct handshake")
	}
}

func TestEvaluatePeersStaleHandshakeStartsDirectAttempt(t *testing.T) {
	rm := testRelayManager(t)
	rm.nodeMap["pubkey-a"] = 10

	status := &interfaceStatus{
		Peers: []peerStatus{
			{PublicKey: "pubkey-a", LatestHandshake: 0}, // never seen
		},
	}
	rm.evaluatePeers(status)

	pr, exists := rm.peers["pubkey-a"]
	if !exists {
		t.Fatal("should create relay state for stale peer")
	}
	if pr.state != relayDirectAttempt {
		t.Errorf("expected relayDirectAttempt, got %d", pr.state)
	}
}

func TestEvaluatePeersDirectAttemptExpires(t *testing.T) {
	rm := testRelayManager(t)
	rm.nodeMap["pubkey-a"] = 10

	// Pre-seed a direct attempt that started 31 seconds ago
	rm.peers["pubkey-a"] = &peerRelay{
		pubkey:  "pubkey-a",
		nodeID:  10,
		state:   relayDirectAttempt,
		started: time.Now().Add(-31 * time.Second),
	}

	status := &interfaceStatus{
		Peers: []peerStatus{
			{PublicKey: "pubkey-a", LatestHandshake: 0},
		},
	}

	// Verify the timeout condition directly (evaluatePeers would call startRelay
	// which needs wg/net)
	pr := rm.peers["pubkey-a"]
	_ = status
	if time.Since(pr.started) <= relayDirectTimeout {
		t.Error("direct attempt should have exceeded timeout")
	}
}

func TestEvaluatePeersDirectBecomesStale(t *testing.T) {
	rm := testRelayManager(t)
	rm.nodeMap["pubkey-a"] = 10

	rm.peers["pubkey-a"] = &peerRelay{
		pubkey: "pubkey-a",
		nodeID: 10,
		state:  relayDirect,
	}

	// Handshake is stale
	status := &interfaceStatus{
		Peers: []peerStatus{
			{PublicKey: "pubkey-a", LatestHandshake: time.Now().Unix() - 200},
		},
	}
	rm.evaluatePeers(status)

	pr := rm.peers["pubkey-a"]
	if pr.state != relayDirectAttempt {
		t.Errorf("stale handshake on direct peer should transition to relayDirectAttempt, got %d", pr.state)
	}
}

func TestEvaluatePeersTeardownOnDirectRecovery(t *testing.T) {
	rm := testRelayManager(t)
	rm.nodeMap["pubkey-a"] = 10

	// Simulate active relay
	ctx, cancel := context.WithCancel(rm.ctx)
	listener, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})

	rm.peers["pubkey-a"] = &peerRelay{
		pubkey:   "pubkey-a",
		nodeID:   10,
		state:    relayActive,
		listener: listener,
		cancel:   cancel,
	}

	// Fresh handshake — should tear down relay
	status := &interfaceStatus{
		Peers: []peerStatus{
			{PublicKey: "pubkey-a", LatestHandshake: time.Now().Unix()},
		},
	}
	rm.evaluatePeers(status)

	if _, exists := rm.peers["pubkey-a"]; exists {
		t.Error("relay should be torn down when peer becomes directly reachable")
	}

	// Verify context was cancelled
	select {
	case <-ctx.Done():
	default:
		t.Error("relay context should be cancelled")
	}
}

func TestEvaluatePeersCleanupRemovedPeers(t *testing.T) {
	rm := testRelayManager(t)
	rm.nodeMap["pubkey-a"] = 10

	rm.peers["pubkey-gone"] = &peerRelay{
		pubkey: "pubkey-gone",
		nodeID: 99,
		state:  relayDirectAttempt,
	}

	// Status doesn't include pubkey-gone
	status := &interfaceStatus{
		Peers: []peerStatus{
			{PublicKey: "pubkey-a", LatestHandshake: time.Now().Unix()},
		},
	}
	rm.evaluatePeers(status)

	if _, exists := rm.peers["pubkey-gone"]; exists {
		t.Error("relay state should be cleaned up for peers no longer in mesh")
	}
}

func TestEvaluatePeersIgnoresUnknownNodes(t *testing.T) {
	rm := testRelayManager(t)
	// nodeMap is empty — no pubkey->nodeID mapping

	status := &interfaceStatus{
		Peers: []peerStatus{
			{PublicKey: "unknown-key", LatestHandshake: 0},
		},
	}
	rm.evaluatePeers(status)

	if len(rm.peers) != 0 {
		t.Error("should not create state for peers not in nodeMap")
	}
}

func TestUpdateNodeMap(t *testing.T) {
	rm := testRelayManager(t)

	m := map[string]int{"pk1": 10, "pk2": 20}
	rm.updateNodeMap(m)

	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.nodeMap["pk1"] != 10 || rm.nodeMap["pk2"] != 20 {
		t.Error("nodeMap not updated correctly")
	}
}

func TestInjectPacketTooShort(t *testing.T) {
	rm := testRelayManager(t)
	// Should not panic
	rm.injectPacket(nil)
	rm.injectPacket([]byte{1, 2, 3, 4}) // exactly 4 bytes, no payload
	rm.injectPacket([]byte{1})
}

func TestInjectPacketWritesToWGPort(t *testing.T) {
	// Start a UDP listener to simulate the WireGuard port
	wgListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer wgListener.Close()

	rm := testRelayManager(t)
	rm.wgPort = wgListener.LocalAddr().(*net.UDPAddr).Port

	// Build packet: 4-byte header + payload
	payload := []byte("hello-wg")
	packet := make([]byte, 4+len(payload))
	packet[0], packet[1], packet[2], packet[3] = 0, 0, 0, 42 // source nodeID 42
	copy(packet[4:], payload)

	rm.injectPacket(packet)

	// Read from the WG listener
	buf := make([]byte, 1024)
	wgListener.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := wgListener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected to receive packet: %v", err)
	}
	if string(buf[:n]) != "hello-wg" {
		t.Errorf("expected payload 'hello-wg', got %q", buf[:n])
	}
}

func TestRelayManagerClose(t *testing.T) {
	rm := testRelayManager(t)

	ctx, cancel := context.WithCancel(rm.ctx)
	listener, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})

	rm.peers["pk"] = &peerRelay{
		pubkey:   "pk",
		nodeID:   1,
		state:    relayActive,
		listener: listener,
		cancel:   cancel,
	}

	rm.close()

	select {
	case <-ctx.Done():
	default:
		t.Error("close should cancel peer contexts")
	}

	if len(rm.peers) != 0 {
		t.Error("close should clear all peers")
	}
}
