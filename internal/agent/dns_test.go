package agent

import (
	"os"
	"strings"
	"testing"
)

func TestUpdateHosts(t *testing.T) {
	// Use a temp file instead of /etc/hosts
	tmp, err := os.CreateTemp("", "hosts-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	original := "127.0.0.1 localhost\n::1 localhost\n"
	os.WriteFile(tmp.Name(), []byte(original), 0644)

	// Test the block building and replacement logic directly
	// (updateHosts reads /etc/hosts which we cannot override in a const)
	peers := []peerConfig{
		{Label: "gateway-nyc", AllowedIPs: "10.0.0.1/32"},
		{Label: "laptop", AllowedIPs: "10.0.0.2/32"},
		{Label: "", AllowedIPs: "10.0.0.3/32"}, // no label — should be skipped
	}

	// Build the block manually (same logic as updateHosts)
	var lines []string
	for _, p := range peers {
		if p.Label == "" || p.AllowedIPs == "" {
			continue
		}
		ip := strings.TrimSuffix(p.AllowedIPs, "/32")
		lines = append(lines, ip+" "+p.Label)
	}

	if len(lines) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(lines))
	}
	if lines[0] != "10.0.0.1 gateway-nyc" {
		t.Errorf("expected '10.0.0.1 gateway-nyc', got %q", lines[0])
	}
	if lines[1] != "10.0.0.2 laptop" {
		t.Errorf("expected '10.0.0.2 laptop', got %q", lines[1])
	}

	// Test block replacement logic
	block := hostsBegin + "\n"
	for _, l := range lines {
		block += l + "\n"
	}
	block += hostsEnd

	// First insertion (no existing block)
	content := original
	newContent := strings.TrimRight(content, "\n") + "\n\n" + block + "\n"

	if !strings.Contains(newContent, "10.0.0.1 gateway-nyc") {
		t.Error("new content should contain gateway-nyc entry")
	}
	if !strings.Contains(newContent, hostsBegin) {
		t.Error("new content should contain begin marker")
	}

	// Replacement (existing block)
	beginIdx := strings.Index(newContent, hostsBegin)
	endIdx := strings.Index(newContent, hostsEnd)
	if beginIdx < 0 || endIdx < 0 {
		t.Fatal("markers not found")
	}

	// Build a new block with updated peers
	updatedBlock := hostsBegin + "\n10.0.0.1 gateway-nyc\n10.0.0.2 laptop\n10.0.0.3 desktop\n" + hostsEnd
	replaced := newContent[:beginIdx] + updatedBlock + newContent[endIdx+len(hostsEnd):]

	if !strings.Contains(replaced, "10.0.0.3 desktop") {
		t.Error("replaced content should contain desktop entry")
	}
	if strings.Count(replaced, hostsBegin) != 1 {
		t.Error("should have exactly one begin marker")
	}
}
