package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"birdcage/internal/wgkey"

	"github.com/coder/websocket"
)

const defaultRotateDays = 30

type keyMeta struct {
	CreatedAt time.Time `json:"created_at"`
}

func rotateIntervalDays() int {
	if v := os.Getenv("BIRDCAGE_KEY_ROTATE_DAYS"); v != "" {
		if d, err := strconv.Atoi(v); err == nil {
			return d
		}
	}
	return defaultRotateDays
}

func keyMetaPath() string {
	return filepath.Join(configDir(), "key_meta.json")
}

func loadKeyMeta() (*keyMeta, error) {
	data, err := os.ReadFile(keyMetaPath())
	if err != nil {
		return nil, err
	}
	var m keyMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func saveKeyMeta(m *keyMeta) error {
	data, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(keyMetaPath(), data, 0600)
}

func needsRotation() bool {
	days := rotateIntervalDays()
	if days < 0 {
		return false
	}

	meta, err := loadKeyMeta()
	if err != nil {
		saveKeyMeta(&keyMeta{CreatedAt: time.Now()})
		return false
	}

	if days == 0 {
		return true
	}

	age := time.Since(meta.CreatedAt)
	return age >= time.Duration(days)*24*time.Hour
}

func rotateKey(ctx context.Context, conn *websocket.Conn, iface string, ack <-chan bool) error {
	privKey, pubKey, err := wgkey.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	msg := map[string]any{
		"type": "key.rotate",
		"payload": map[string]any{
			"public_key": pubKey,
		},
	}
	data, _ := json.Marshal(msg)
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		return fmt.Errorf("send key.rotate: %w", err)
	}

	select {
	case ok := <-ack:
		if !ok {
			return fmt.Errorf("server rejected key rotation")
		}
	case <-time.After(10 * time.Second):
		return fmt.Errorf("key rotation timed out waiting for server")
	case <-ctx.Done():
		return ctx.Err()
	}

	cmd := exec.CommandContext(ctx, "wg", "set", iface, "private-key", "/dev/stdin")
	cmd.Stdin = strings.NewReader(privKey)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg set private-key: %w: %s", err, out)
	}

	dir := configDir()
	keyPath := filepath.Join(dir, "private.key")
	if err := os.WriteFile(keyPath, []byte(privKey+"\n"), 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	if err := saveKeyMeta(&keyMeta{CreatedAt: time.Now()}); err != nil {
		return fmt.Errorf("write key meta: %w", err)
	}

	slog.Info("key rotated", "pubkey", pubKey[:8]+"..."+pubKey[len(pubKey)-4:])
	return nil
}
