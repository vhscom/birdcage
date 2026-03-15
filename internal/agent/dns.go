package agent

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	hostsPath  = "/etc/hosts"
	hostsBegin = "# birdcage:begin"
	hostsEnd   = "# birdcage:end"
)

func updateHosts(peers []peerConfig) error {
	var lines []string
	for _, p := range peers {
		if p.Label == "" || p.AllowedIPs == "" {
			continue
		}
		// Validate label: alphanumeric + hyphen only, no whitespace or newlines
		safe := true
		for _, c := range p.Label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				safe = false
				break
			}
		}
		if !safe || len(p.Label) > 63 {
			continue
		}
		// Validate IP from CIDR
		ip, _, err := net.ParseCIDR(p.AllowedIPs)
		if err != nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s %s", ip.String(), p.Label))
	}

	var b strings.Builder
	b.WriteString(hostsBegin)
	b.WriteByte('\n')
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	b.WriteString(hostsEnd)
	block := b.String()

	data, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", hostsPath, err)
	}
	content := string(data)

	beginIdx := strings.Index(content, hostsBegin)
	endIdx := strings.Index(content, hostsEnd)

	var newContent string
	if beginIdx >= 0 && endIdx >= 0 {
		newContent = content[:beginIdx] + block + content[endIdx+len(hostsEnd):]
	} else {
		newContent = strings.TrimRight(content, "\n") + "\n\n" + block + "\n"
	}

	if newContent == content {
		return nil
	}

	tmp, err := os.CreateTemp(filepath.Dir(hostsPath), ".hosts-birdcage-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(newContent); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0644); err != nil { // #nosec G302 — /etc/hosts must be world-readable
		os.Remove(tmpName)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, hostsPath); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename %s → %s: %w", tmpName, hostsPath, err)
	}

	slog.Info("updated /etc/hosts", "entries", len(lines))
	return nil
}
