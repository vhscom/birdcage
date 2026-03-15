package agent

import (
	"encoding/base64"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

type peerConfig struct {
	NodeID              int    `json:"node_id,omitempty"`
	Label               string `json:"label,omitempty"`
	PublicKey           string `json:"public_key"`
	Endpoint            string `json:"endpoint,omitempty"`
	AllowedIPs          string `json:"allowed_ips"`
	PersistentKeepalive int    `json:"persistent_keepalive,omitempty"`
}

type interfaceStatus struct {
	Interface  string       `json:"interface"`
	PublicKey  string       `json:"public_key"`
	ListenPort int          `json:"listen_port"`
	Peers      []peerStatus `json:"peers"`
}

type peerStatus struct {
	PublicKey           string `json:"public_key"`
	Endpoint            string `json:"endpoint,omitempty"`
	AllowedIPs          string `json:"allowed_ips,omitempty"`
	LatestHandshake     int64  `json:"latest_handshake"`
	TransferRx          int64  `json:"transfer_rx"`
	TransferTx          int64  `json:"transfer_tx"`
	PersistentKeepalive int    `json:"persistent_keepalive,omitempty"`
}

func wgShow(iface string) (*interfaceStatus, error) {
	out, err := exec.Command("wg", "show", iface, "dump").Output()
	if err != nil {
		return nil, fmt.Errorf("wg show %s dump: %w", iface, err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("wg show: empty output")
	}

	ifields := strings.Split(lines[0], "\t")
	if len(ifields) < 3 {
		return nil, fmt.Errorf("wg show: unexpected interface line format")
	}

	port, _ := strconv.Atoi(ifields[2])
	status := &interfaceStatus{
		Interface:  iface,
		PublicKey:  ifields[1],
		ListenPort: port,
	}

	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			continue
		}
		handshake, _ := strconv.ParseInt(fields[4], 10, 64)
		rx, _ := strconv.ParseInt(fields[5], 10, 64)
		tx, _ := strconv.ParseInt(fields[6], 10, 64)
		keepalive, _ := strconv.Atoi(fields[7])

		status.Peers = append(status.Peers, peerStatus{
			PublicKey:           fields[0],
			Endpoint:            fields[2],
			AllowedIPs:          fields[3],
			LatestHandshake:     handshake,
			TransferRx:          rx,
			TransferTx:          tx,
			PersistentKeepalive: keepalive,
		})
	}

	return status, nil
}

func validatePeer(peer peerConfig) error {
	// Public key must be 32 bytes base64-encoded (44 chars ending with =)
	if b, err := base64.StdEncoding.DecodeString(peer.PublicKey); err != nil || len(b) != 32 {
		return fmt.Errorf("invalid public key")
	}
	if peer.Endpoint != "" {
		host, port, err := net.SplitHostPort(peer.Endpoint)
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("invalid endpoint: %s", peer.Endpoint)
		}
	}
	if peer.AllowedIPs != "" {
		for _, cidr := range strings.Split(peer.AllowedIPs, ",") {
			if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
				return fmt.Errorf("invalid allowed-ips: %s", peer.AllowedIPs)
			}
		}
	}
	return nil
}

func wgSetPeer(iface string, peer peerConfig) error {
	if err := validatePeer(peer); err != nil {
		return fmt.Errorf("wg set peer: %w", err)
	}

	args := []string{"set", iface, "peer", peer.PublicKey}
	if peer.Endpoint != "" {
		args = append(args, "endpoint", peer.Endpoint)
	}
	if peer.AllowedIPs != "" {
		args = append(args, "allowed-ips", peer.AllowedIPs)
	}
	if peer.PersistentKeepalive > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(peer.PersistentKeepalive))
	}

	out, err := exec.Command("wg", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg set peer %s: %w: %s", peer.PublicKey[:8], err, out)
	}
	return nil
}

func wgRemovePeer(iface, pubkey string) error {
	if b, err := base64.StdEncoding.DecodeString(pubkey); err != nil || len(b) != 32 {
		return fmt.Errorf("wg remove peer: invalid public key")
	}
	out, err := exec.Command("wg", "set", iface, "peer", pubkey, "remove").CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg remove peer %s: %w: %s", pubkey[:8], err, out)
	}
	return nil
}

func wgSyncFull(iface string, desired []peerConfig) error {
	current, err := wgShow(iface)
	if err != nil {
		for _, p := range desired {
			if err := wgSetPeer(iface, p); err != nil {
				return err
			}
		}
		return nil
	}

	want := map[string]peerConfig{}
	for _, p := range desired {
		want[p.PublicKey] = p
	}

	for _, p := range current.Peers {
		if _, ok := want[p.PublicKey]; !ok {
			if err := wgRemovePeer(iface, p.PublicKey); err != nil {
				return err
			}
		}
	}

	for _, p := range desired {
		if err := wgSetPeer(iface, p); err != nil {
			return err
		}
	}

	return nil
}
