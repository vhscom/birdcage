package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"text/template"
)

const launchdLabel = "com.birdcage.agent"

var launchdPlist = template.Must(template.New("plist").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{.Label}}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.Binary}}</string>
        <string>agent</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>BIRDCAGE_AGENT_CONFIG_DIR</key>
        <string>{{.ConfigDir}}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{{.LogDir}}/birdcage-agent.log</string>
    <key>StandardErrorPath</key>
    <string>{{.LogDir}}/birdcage-agent.log</string>
</dict>
</plist>
`))

const systemdUnit = `[Unit]
Description=Birdcage WireGuard Mesh Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={{.Binary}} agent
Environment=BIRDCAGE_AGENT_CONFIG_DIR={{.ConfigDir}}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`

var systemdTemplate = template.Must(template.New("unit").Parse(systemdUnit))

type serviceParams struct {
	Label     string
	Binary    string
	ConfigDir string
	LogDir    string
}

func runInstall() {
	for _, a := range os.Args[1:] {
		if a == "--help" || a == "-h" {
			fmt.Println("birdcage agent install — install the agent as a system service (launchd/systemd)")
			fmt.Println()
			fmt.Println("Requires agent config. Run 'birdcage agent init <server> <key>' first.")
			return
		}
	}

	binary, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding binary path: %v\n", err)
		os.Exit(1)
	}
	binary, _ = filepath.Abs(binary)

	cfgPath := filepath.Join(configDir(), "config.json")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "No agent config found. Run 'birdcage agent init <server> <key>' first.")
		os.Exit(1)
	}

	params := serviceParams{
		Label:     launchdLabel,
		Binary:    binary,
		ConfigDir: configDir(),
	}

	switch runtime.GOOS {
	case "darwin":
		installLaunchd(params)
	case "linux":
		installSystemd(params)
	default:
		fmt.Fprintf(os.Stderr, "Service install not supported on %s\n", runtime.GOOS)
		os.Exit(1)
	}
}

func installLaunchd(params serviceParams) {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not determine home directory: %v\n", err)
		os.Exit(1)
	}
	params.LogDir = filepath.Join(home, "Library", "Logs")
	os.MkdirAll(params.LogDir, 0755) // #nosec G301 — macOS requires 0755 for ~/Library/Logs

	plistDir := filepath.Join(home, "Library", "LaunchAgents")
	os.MkdirAll(plistDir, 0755) // #nosec G301 — macOS requires 0755 for ~/Library/LaunchAgents
	plistPath := filepath.Join(plistDir, launchdLabel+".plist")

	f, err := os.Create(plistPath) // #nosec G304 — path constructed from fixed prefix + constant label
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing plist: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	if err := launchdPlist.Execute(f, params); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing plist: %v\n", err)
		os.Exit(1)
	}

	out, err := exec.Command("launchctl", "load", plistPath).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading service: %v\n%s\n", err, out)
		fmt.Fprintf(os.Stderr, "Plist written to %s — load manually with:\n", plistPath)
		fmt.Fprintf(os.Stderr, "  launchctl load %s\n", plistPath)
		os.Exit(1)
	}

	fmt.Printf("Agent installed and started\n")
	fmt.Printf("  Service: %s\n", launchdLabel)
	fmt.Printf("  Plist:   %s\n", plistPath)
	fmt.Printf("  Logs:    %s/birdcage-agent.log\n", params.LogDir)
	fmt.Printf("  Uninstall: birdcage agent uninstall\n")
}

func installSystemd(params serviceParams) {
	unitPath := "/etc/systemd/system/birdcage-agent.service"

	f, err := os.Create(unitPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing unit file (try with sudo): %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	if err := systemdTemplate.Execute(f, params); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing unit file: %v\n", err)
		os.Exit(1)
	}

	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "birdcage-agent"},
		{"systemctl", "start", "birdcage-agent"},
	}
	for _, args := range cmds {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error running %v: %v\n%s\n", args, err, out)
			os.Exit(1)
		}
	}

	fmt.Printf("Agent installed and started\n")
	fmt.Printf("  Unit:      %s\n", unitPath)
	fmt.Printf("  Status:    systemctl status birdcage-agent\n")
	fmt.Printf("  Logs:      journalctl -u birdcage-agent -f\n")
	fmt.Printf("  Uninstall: birdcage agent uninstall\n")
}

func runUninstall() {
	for _, a := range os.Args[1:] {
		if a == "--help" || a == "-h" {
			fmt.Println("birdcage agent uninstall — remove the agent system service")
			return
		}
	}

	switch runtime.GOOS {
	case "darwin":
		uninstallLaunchd()
	case "linux":
		uninstallSystemd()
	default:
		fmt.Fprintf(os.Stderr, "Service uninstall not supported on %s\n", runtime.GOOS)
		os.Exit(1)
	}
}

func uninstallLaunchd() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not determine home directory: %v\n", err)
		os.Exit(1)
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")

	exec.Command("launchctl", "unload", plistPath).Run()
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error removing plist: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Agent service removed.")
}

func uninstallSystemd() {
	unitPath := "/etc/systemd/system/birdcage-agent.service"

	exec.Command("systemctl", "stop", "birdcage-agent").Run()
	exec.Command("systemctl", "disable", "birdcage-agent").Run()

	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error removing unit file: %v\n", err)
		os.Exit(1)
	}

	exec.Command("systemctl", "daemon-reload").Run()

	fmt.Println("Agent service removed.")
}
