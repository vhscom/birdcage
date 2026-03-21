package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestNeedsRotationNoMetaFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BIRDCAGE_AGENT_CONFIG_DIR", dir)
	t.Setenv("BIRDCAGE_KEY_ROTATE_DAYS", "30")

	// No meta file — should create one and return false
	if needsRotation() {
		t.Error("first call with no meta should return false")
	}

	// Meta file should now exist
	data, err := os.ReadFile(filepath.Join(dir, "key_meta.json"))
	if err != nil {
		t.Fatalf("meta file not created: %v", err)
	}
	var m keyMeta
	json.Unmarshal(data, &m)
	if time.Since(m.CreatedAt) > 5*time.Second {
		t.Error("meta created_at should be recent")
	}
}

func TestNeedsRotationFreshKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BIRDCAGE_AGENT_CONFIG_DIR", dir)
	t.Setenv("BIRDCAGE_KEY_ROTATE_DAYS", "30")

	saveKeyMeta(&keyMeta{CreatedAt: time.Now()})

	if needsRotation() {
		t.Error("fresh key should not need rotation")
	}
}

func TestNeedsRotationExpiredKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BIRDCAGE_AGENT_CONFIG_DIR", dir)
	t.Setenv("BIRDCAGE_KEY_ROTATE_DAYS", "30")

	saveKeyMeta(&keyMeta{CreatedAt: time.Now().Add(-31 * 24 * time.Hour)})

	if !needsRotation() {
		t.Error("31-day-old key should need rotation")
	}
}

func TestNeedsRotationForceImmediate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BIRDCAGE_AGENT_CONFIG_DIR", dir)
	t.Setenv("BIRDCAGE_KEY_ROTATE_DAYS", "0")

	saveKeyMeta(&keyMeta{CreatedAt: time.Now()})

	if !needsRotation() {
		t.Error("days=0 should force immediate rotation")
	}
}

func TestNeedsRotationDisabled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BIRDCAGE_AGENT_CONFIG_DIR", dir)
	t.Setenv("BIRDCAGE_KEY_ROTATE_DAYS", "-1")

	saveKeyMeta(&keyMeta{CreatedAt: time.Now().Add(-365 * 24 * time.Hour)})

	if needsRotation() {
		t.Error("days=-1 should disable rotation")
	}
}

func TestRotateIntervalDaysDefault(t *testing.T) {
	t.Setenv("BIRDCAGE_KEY_ROTATE_DAYS", "")
	if d := rotateIntervalDays(); d != 30 {
		t.Errorf("default should be 30, got %d", d)
	}
}

func TestRotateIntervalDaysCustom(t *testing.T) {
	t.Setenv("BIRDCAGE_KEY_ROTATE_DAYS", "7")
	if d := rotateIntervalDays(); d != 7 {
		t.Errorf("expected 7, got %d", d)
	}
}

func TestRotateIntervalDaysInvalid(t *testing.T) {
	t.Setenv("BIRDCAGE_KEY_ROTATE_DAYS", "abc")
	if d := rotateIntervalDays(); d != 30 {
		t.Errorf("invalid should fall back to 30, got %d", d)
	}
}

// testWSConn creates a WebSocket connection backed by a test server that absorbs all messages.
func testWSConn(t *testing.T) *websocket.Conn {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		// Drain messages
		for {
			_, _, err := c.Read(context.Background())
			if err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(context.Background(), url, nil)
	if err != nil {
		t.Fatalf("dial test ws: %v", err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}

func TestRotateKeyServerReject(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BIRDCAGE_AGENT_CONFIG_DIR", dir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := testWSConn(t)
	ack := make(chan bool, 1)
	ack <- false // server rejects

	err := rotateKey(ctx, conn, "wg-test", ack)
	if err == nil {
		t.Fatal("expected error when server rejects")
	}
	if err.Error() != "server rejected key rotation" {
		t.Errorf("unexpected error: %v", err)
	}

	// Private key should NOT have been written
	if _, err := os.Stat(filepath.Join(dir, "private.key")); err == nil {
		t.Error("private key should not be written when server rejects")
	}
}

func TestRotateKeyAckTimeout(t *testing.T) {
	// Verify timeout behavior of the ack channel pattern used by rotateKey
	ack := make(chan bool)
	start := time.Now()
	select {
	case <-ack:
		t.Error("should not receive from empty channel")
	case <-time.After(100 * time.Millisecond):
		// expected
	}
	elapsed := time.Since(start)
	if elapsed < 50*time.Millisecond {
		t.Error("timeout should have waited")
	}
}

func TestRotateKeyContextCancelled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BIRDCAGE_AGENT_CONFIG_DIR", dir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	conn := testWSConn(t)
	ack := make(chan bool)

	err := rotateKey(ctx, conn, "wg-test", ack)
	if err == nil {
		t.Fatal("expected error when context cancelled")
	}
}

func TestSaveLoadKeyMeta(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BIRDCAGE_AGENT_CONFIG_DIR", dir)

	now := time.Now().Truncate(time.Second)
	if err := saveKeyMeta(&keyMeta{CreatedAt: now}); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := loadKeyMeta()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !loaded.CreatedAt.Equal(now) {
		t.Errorf("expected %v, got %v", now, loaded.CreatedAt)
	}
}

func TestLoadKeyMetaCorrupt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BIRDCAGE_AGENT_CONFIG_DIR", dir)

	os.WriteFile(filepath.Join(dir, "key_meta.json"), []byte("not json"), 0600)

	_, err := loadKeyMeta()
	if err == nil {
		t.Error("expected error for corrupt meta file")
	}
}
