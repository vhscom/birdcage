package main

import (
	"encoding/binary"
	"log/slog"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	relayByteRateWindow = 60 * time.Second
	relayByteRateMax    = 10 * 1024 * 1024
)

type relayNodeState struct {
	peerNodeIDs []int
	byteCount   int
	windowStart time.Time
}

var relayRouter struct {
	mu     sync.RWMutex
	byNode map[int]*relayNodeState
}

func init() {
	relayRouter.byNode = make(map[int]*relayNodeState)
}

func registerRelayBinding(sourceNodeID, peerNodeID int) bool {
	// Validate both nodes are connected
	nodeRegistry.mu.RLock()
	sourceNode := nodeRegistry.byID[sourceNodeID]
	peerNode := nodeRegistry.byID[peerNodeID]
	nodeRegistry.mu.RUnlock()

	if sourceNode == nil || peerNode == nil {
		return false
	}

	relayRouter.mu.Lock()
	defer relayRouter.mu.Unlock()

	state, ok := relayRouter.byNode[sourceNodeID]
	if !ok {
		state = &relayNodeState{windowStart: time.Now()}
		relayRouter.byNode[sourceNodeID] = state
	}

	for _, id := range state.peerNodeIDs {
		if id == peerNodeID {
			return true
		}
	}

	state.peerNodeIDs = append(state.peerNodeIDs, peerNodeID)
	slog.Info("relay bound", "source", sourceNodeID, "peer", peerNodeID)
	return true
}

func unregisterRelayBinding(sourceNodeID, peerNodeID int) {
	relayRouter.mu.Lock()
	defer relayRouter.mu.Unlock()

	state, ok := relayRouter.byNode[sourceNodeID]
	if !ok {
		return
	}

	for i, id := range state.peerNodeIDs {
		if id == peerNodeID {
			state.peerNodeIDs = append(state.peerNodeIDs[:i], state.peerNodeIDs[i+1:]...)
			break
		}
	}

	if len(state.peerNodeIDs) == 0 {
		delete(relayRouter.byNode, sourceNodeID)
	}
}

func cleanupRelayBindings(nodeID int) {
	relayRouter.mu.Lock()
	defer relayRouter.mu.Unlock()
	delete(relayRouter.byNode, nodeID)
}

// handleRelayPacket routes a binary frame from sourceNodeID to the destination.
// Binary frame format: [4-byte destNodeID][raw WireGuard packet]
// Note: the relay layer does not authenticate inner packet content — WireGuard's
// own Noise protocol handles peer authentication at the tunnel layer.
func handleRelayPacket(sourceNodeID int, raw []byte) {
	if len(raw) < 5 || sourceNodeID < 0 {
		return
	}

	destNodeID := int(binary.BigEndian.Uint32(raw[0:4]))

	relayRouter.mu.Lock()
	state, ok := relayRouter.byNode[sourceNodeID]
	if !ok {
		relayRouter.mu.Unlock()
		return
	}

	now := time.Now()
	if now.Sub(state.windowStart) > relayByteRateWindow {
		state.windowStart = now
		state.byteCount = 0
	}
	state.byteCount += len(raw)
	if state.byteCount > relayByteRateMax {
		relayRouter.mu.Unlock()
		return
	}

	bound := false
	for _, id := range state.peerNodeIDs {
		if id == destNodeID {
			bound = true
			break
		}
	}
	relayRouter.mu.Unlock()

	if !bound {
		return
	}

	nodeRegistry.mu.RLock()
	destNode := nodeRegistry.byID[destNodeID]
	nodeRegistry.mu.RUnlock()

	if destNode == nil {
		return
	}

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(sourceNodeID)) // #nosec G115 — node IDs are small positive integers from SQLite autoincrement
	packet := append(header, raw[4:]...)

	destNode.conn.safeWrite(websocket.BinaryMessage, packet)
}
