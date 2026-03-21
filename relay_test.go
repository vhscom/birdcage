package main

import (
	"testing"
)

func relayTestSetup(t *testing.T) {
	t.Helper()

	// Clear the global registries.
	nodeRegistry.mu.Lock()
	nodeRegistry.byID = make(map[int]*connectedNode)
	nodeRegistry.mu.Unlock()

	relayRouter.mu.Lock()
	relayRouter.byNode = make(map[int]*relayNodeState)
	relayRouter.mu.Unlock()
}

func TestRegisterRelayBinding(t *testing.T) {
	relayTestSetup(t)

	// Register two mock nodes (conn can be nil since we don't send data).
	registerNode(&connectedNode{conn: nil, agentID: 1, nodeID: 10})
	registerNode(&connectedNode{conn: nil, agentID: 2, nodeID: 20})

	ok := registerRelayBinding(10, 20)
	if !ok {
		t.Errorf("registerRelayBinding(10, 20) = false, want true")
	}

	// Verify the binding exists in relayRouter.
	relayRouter.mu.RLock()
	state, exists := relayRouter.byNode[10]
	relayRouter.mu.RUnlock()

	if !exists {
		t.Fatalf("relayRouter.byNode[10] does not exist")
	}
	if len(state.peerNodeIDs) != 1 || state.peerNodeIDs[0] != 20 {
		t.Errorf("peerNodeIDs = %v, want [20]", state.peerNodeIDs)
	}
}

func TestRegisterRelayBinding_PeerDisconnected(t *testing.T) {
	relayTestSetup(t)

	// Only register source node; peer is not connected.
	registerNode(&connectedNode{conn: nil, agentID: 1, nodeID: 10})

	ok := registerRelayBinding(10, 20)
	if ok {
		t.Errorf("registerRelayBinding(10, 20) = true, want false (peer not connected)")
	}
}

func TestUnregisterRelayBinding(t *testing.T) {
	relayTestSetup(t)

	registerNode(&connectedNode{conn: nil, agentID: 1, nodeID: 10})
	registerNode(&connectedNode{conn: nil, agentID: 2, nodeID: 20})

	registerRelayBinding(10, 20)

	unregisterRelayBinding(10, 20)

	relayRouter.mu.RLock()
	_, exists := relayRouter.byNode[10]
	relayRouter.mu.RUnlock()

	if exists {
		t.Errorf("relayRouter.byNode[10] still exists after unregister, want deleted (no remaining peers)")
	}
}

func TestCleanupRelayBindings(t *testing.T) {
	relayTestSetup(t)

	registerNode(&connectedNode{conn: nil, agentID: 1, nodeID: 10})
	registerNode(&connectedNode{conn: nil, agentID: 2, nodeID: 20})
	registerNode(&connectedNode{conn: nil, agentID: 3, nodeID: 30})

	registerRelayBinding(10, 20)
	registerRelayBinding(10, 30)

	// Verify bindings exist.
	relayRouter.mu.RLock()
	state := relayRouter.byNode[10]
	relayRouter.mu.RUnlock()

	if state == nil || len(state.peerNodeIDs) != 2 {
		t.Fatalf("expected 2 peer bindings before cleanup, got %v", state)
	}

	cleanupRelayBindings(10)

	relayRouter.mu.RLock()
	_, exists := relayRouter.byNode[10]
	relayRouter.mu.RUnlock()

	if exists {
		t.Errorf("relayRouter.byNode[10] still exists after cleanupRelayBindings")
	}
}
