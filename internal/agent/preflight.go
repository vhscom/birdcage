package agent

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func checkWireGuardTools() {
	if _, err := exec.LookPath("wg"); err != nil {
		fmt.Fprintln(os.Stderr, "Error: 'wg' command not found")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Install WireGuard tools:")
		switch runtime.GOOS {
		case "darwin":
			fmt.Fprintln(os.Stderr, "  brew install wireguard-tools")
		case "linux":
			fmt.Fprintln(os.Stderr, "  Ubuntu/Debian:  sudo apt install wireguard-tools")
			fmt.Fprintln(os.Stderr, "  Fedora/RHEL:    sudo dnf install wireguard-tools")
		default:
			fmt.Fprintln(os.Stderr, "  Install the 'wireguard-tools' package for your platform")
		}
		os.Exit(1)
	}

	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("wireguard-go"); err != nil {
			fmt.Fprintln(os.Stderr, "Error: 'wireguard-go' not found (required on macOS)")
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "Install it:")
			fmt.Fprintln(os.Stderr, "  brew install wireguard-go")
			os.Exit(1)
		}
	}
}
