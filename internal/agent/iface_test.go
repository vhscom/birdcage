package agent

import (
	"runtime"
	"testing"
)

func TestDefaultInterface(t *testing.T) {
	got := DefaultInterface()
	switch runtime.GOOS {
	case "darwin":
		if got != "utun3" {
			t.Errorf("DefaultInterface() = %q on darwin, want utun3", got)
		}
	case "linux":
		if got != "wg0" {
			t.Errorf("DefaultInterface() = %q on linux, want wg0", got)
		}
	default:
		if got != "wg0" {
			t.Errorf("DefaultInterface() = %q, want wg0", got)
		}
	}
}

func TestGetListenPort(t *testing.T) {
	if p := getListenPort(nil); p != 51820 {
		t.Errorf("getListenPort(nil) = %d, want 51820", p)
	}

	s := &interfaceStatus{ListenPort: 0}
	if p := getListenPort(s); p != 51820 {
		t.Errorf("getListenPort(port=0) = %d, want 51820", p)
	}

	s.ListenPort = 12345
	if p := getListenPort(s); p != 12345 {
		t.Errorf("getListenPort(port=12345) = %d, want 12345", p)
	}
}
