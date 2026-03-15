package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
)

type relayState int

const (
	relayDirectAttempt relayState = iota
	relayBinding
	relayActive
	relayDirect
)

const (
	relayDirectTimeout = 30 * time.Second
	relayHandshakeMax  = 120
)

type peerRelay struct {
	pubkey   string
	nodeID   int
	state    relayState
	listener *net.UDPConn
	cancel   context.CancelFunc
	started  time.Time
}

type relayManager struct {
	mu         sync.Mutex
	peers      map[string]*peerRelay
	conn       *websocket.Conn
	iface      string
	wgPort     int
	nodeMap    map[string]int
	injectConn *net.UDPConn
	ctx        context.Context
	cancelFn   context.CancelFunc
}

func newRelayManager(ctx context.Context, conn *websocket.Conn, iface string, wgPort int) *relayManager {
	rctx, cancel := context.WithCancel(ctx)
	return &relayManager{
		peers:    make(map[string]*peerRelay),
		conn:     conn,
		iface:    iface,
		wgPort:   wgPort,
		nodeMap:  make(map[string]int),
		ctx:      rctx,
		cancelFn: cancel,
	}
}

func (rm *relayManager) close() {
	rm.cancelFn()
	rm.mu.Lock()
	defer rm.mu.Unlock()
	for _, pr := range rm.peers {
		if pr.cancel != nil {
			pr.cancel()
		}
		if pr.listener != nil {
			pr.listener.Close()
		}
	}
	rm.peers = make(map[string]*peerRelay)
	if rm.injectConn != nil {
		rm.injectConn.Close()
		rm.injectConn = nil
	}
}

func (rm *relayManager) updateNodeMap(m map[string]int) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.nodeMap = m
}

func (rm *relayManager) evaluatePeers(status *interfaceStatus) {
	if status == nil {
		return
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	now := time.Now()
	activePubkeys := map[string]bool{}

	for _, peer := range status.Peers {
		activePubkeys[peer.PublicKey] = true
		nodeID, ok := rm.nodeMap[peer.PublicKey]
		if !ok {
			continue
		}

		pr, exists := rm.peers[peer.PublicKey]
		handshakeStale := peer.LatestHandshake == 0 ||
			now.Unix()-peer.LatestHandshake > relayHandshakeMax

		if !handshakeStale {
			if exists && pr.state != relayDirect {
				slog.Info("peer reachable directly, tearing down relay", "peer", peer.PublicKey[:8])
				rm.stopRelay(peer.PublicKey)
			}
			continue
		}

		if !exists {
			rm.peers[peer.PublicKey] = &peerRelay{
				pubkey:  peer.PublicKey,
				nodeID:  nodeID,
				state:   relayDirectAttempt,
				started: now,
			}
			continue
		}

		switch pr.state {
		case relayDirectAttempt:
			if now.Sub(pr.started) > relayDirectTimeout {
				rm.startRelay(pr)
			}
		case relayDirect:
			pr.state = relayDirectAttempt
			pr.started = now
		}
	}

	for pubkey := range rm.peers {
		if !activePubkeys[pubkey] {
			rm.stopRelay(pubkey)
		}
	}
}

func (rm *relayManager) startRelay(pr *peerRelay) {
	pr.state = relayBinding

	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	listener, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		slog.Error("relay listen failed", "peer", pr.pubkey[:8], "error", err)
		return
	}
	pr.listener = listener

	localPort := listener.LocalAddr().(*net.UDPAddr).Port

	if err := wgSetPeer(rm.iface, peerConfig{
		PublicKey: pr.pubkey,
		Endpoint:  fmt.Sprintf("127.0.0.1:%d", localPort),
	}); err != nil {
		slog.Error("relay set peer endpoint failed", "peer", pr.pubkey[:8], "error", err)
		listener.Close()
		return
	}

	bind := map[string]any{
		"type": "relay.bind",
		"payload": map[string]any{
			"peer_node_id": pr.nodeID,
		},
	}
	data, _ := json.Marshal(bind)
	if err := rm.conn.Write(rm.ctx, websocket.MessageText, data); err != nil {
		slog.Error("relay bind send failed", "peer", pr.pubkey[:8], "error", err)
		listener.Close()
		return
	}

	ctx, cancel := context.WithCancel(rm.ctx) // #nosec G118 — cancel stored in pr.cancel, called in stopRelay
	pr.cancel = cancel
	pr.state = relayActive

	slog.Info("relay started", "peer", pr.pubkey[:8], "port", localPort)

	go rm.udpToWS(ctx, listener, pr.nodeID)
}

func (rm *relayManager) stopRelay(pubkey string) {
	pr, ok := rm.peers[pubkey]
	if !ok {
		return
	}
	if pr.cancel != nil {
		pr.cancel()
	}
	if pr.listener != nil {
		pr.listener.Close()
	}
	delete(rm.peers, pubkey)

	unbind := map[string]any{
		"type": "relay.unbind",
		"payload": map[string]any{
			"peer_node_id": pr.nodeID,
		},
	}
	data, _ := json.Marshal(unbind)
	rm.conn.Write(rm.ctx, websocket.MessageText, data)
}

func (rm *relayManager) udpToWS(ctx context.Context, listener *net.UDPConn, destNodeID int) {
	buf := make([]byte, 4+65536)
	binary.BigEndian.PutUint32(buf[0:4], uint32(destNodeID)) // #nosec G115 — node IDs are small positive integers

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		listener.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := listener.ReadFromUDP(buf[4:])
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}

		if err := rm.conn.Write(ctx, websocket.MessageBinary, buf[:4+n]); err != nil {
			return
		}
	}
}

func (rm *relayManager) injectPacket(data []byte) {
	if len(data) < 5 {
		return
	}

	rm.mu.Lock()
	if rm.injectConn == nil {
		wgAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: rm.wgPort}
		c, err := net.DialUDP("udp4", nil, wgAddr)
		if err != nil {
			rm.mu.Unlock()
			return
		}
		rm.injectConn = c
	}
	c := rm.injectConn
	rm.mu.Unlock()

	c.Write(data[4:])
}
