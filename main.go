package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/acme/autocert"

	"birdcage/internal/agent"
	"birdcage/internal/cli"
	"birdcage/internal/ctl"
)

//go:embed public
var publicFS embed.FS

type Config struct {
	Addr              string
	DBPath            string
	AccessSecret      string
	RefreshSecret     string
	AgentKey          string // raw API key for the home agent
	RegistrationToken string
	GatewayURL        string
	GatewayToken      string
	CookieSecure      bool
	WSAllowedOrigins  string
	BaseURL           string
	CertDir           string
	WGPrivateKey      string
	WGListenPort      int
	WGEndpoint        string
	WGInterface       string
	WGSubnet          string
	CloakDurationMin  int
	CloakOnAttack     bool
}

var cfg *Config
var version = "dev"
var timeNow = time.Now

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "init":
			os.Args = os.Args[1:]
			cli.RunInit()
			return
		case "serve":
			os.Args = os.Args[1:]
			if len(os.Args) > 1 {
				switch os.Args[1] {
				case "install":
					runServeInstall()
					return
				case "uninstall":
					runServeUninstall()
					return
				}
			}
			runServe()
			return
		case "agent":
			os.Args = os.Args[1:]
			agent.Run()
			return
		case "ctl":
			os.Args = os.Args[1:]
			ctl.Run()
			return
		case "--version", "-v", "version":
			fmt.Println("birdcage " + version)
			return
		case "--help", "-h", "help":
			printHelp()
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown command: %s\n\nRun 'birdcage --help' for usage.\n", os.Args[1])
			os.Exit(1)
		}
	}
	runServe()
}

func printHelp() {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5")).Render
	heading := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Render
	cmd := lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render
	dim := lipgloss.NewStyle().Faint(true).Render

	fmt.Printf("%s %s\n\n", title("birdcage"), dim("— secure remote access for personal AI"))

	fmt.Println(heading("Usage"))
	fmt.Printf("  %s\n\n", cmd("birdcage <command> [flags]"))

	fmt.Println(heading("Server"))
	fmt.Printf("  %s  %s\n", cmd(fmt.Sprintf("%-28s", "init")), dim("Generate server config (.env)"))
	fmt.Printf("  %s  %s\n", cmd(fmt.Sprintf("%-28s", "serve")), dim("Start the birdcage server"))
	fmt.Printf("  %s  %s\n", cmd(fmt.Sprintf("%-28s", "serve install")), dim("Install as system service"))
	fmt.Printf("  %s  %s\n\n", cmd(fmt.Sprintf("%-28s", "serve uninstall")), dim("Remove system service"))

	fmt.Println(heading("Agent"))
	fmt.Printf("  %s  %s\n", cmd(fmt.Sprintf("%-28s", "agent")), dim("Run the WireGuard mesh agent"))
	fmt.Printf("  %s  %s\n", cmd(fmt.Sprintf("%-28s", "agent init <server> <key>")), dim("Save agent config"))
	fmt.Printf("  %s  %s\n", cmd(fmt.Sprintf("%-28s", "agent install")), dim("Install as system service"))
	fmt.Printf("  %s  %s\n\n", cmd(fmt.Sprintf("%-28s", "agent uninstall")), dim("Remove system service"))

	fmt.Println(heading("Management"))
	fmt.Printf("  %s  %s\n\n", cmd(fmt.Sprintf("%-28s", "ctl")), dim("Open the management TUI"))

	fmt.Printf("  %s\n", dim("Run 'birdcage <command> --help' for command-specific help."))
}

func runServe() {
	for _, a := range os.Args[1:] {
		if a == "--help" || a == "-h" {
			fmt.Println("birdcage serve — start the birdcage server")
			fmt.Println()
			fmt.Println("Reads configuration from .env in the current directory.")
			fmt.Println("Run 'birdcage init' first to generate it.")
			return
		}
	}

	cfg = loadConfig()
	initDB(cfg.DBPath)
	startEventPruner()

	// Ensure agent credential exists for AGENT_KEY
	ensureAgentCredential()

	// Provision server WireGuard interface
	serverEnsureWG()
	initWGSubnet(cfg.WGSubnet)

	mux := http.NewServeMux()

	// --- Static files (embedded, CSP nonce injected per request) ---
	indexTpl, _ := publicFS.ReadFile("public/index.html")
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		nonce := randomHex(16)
		page := bytes.Replace(indexTpl, []byte("__CSP_NONCE__"), []byte(nonce), 1)
		w.Header().Set("Content-Security-Policy", fmt.Sprintf(
			"default-src 'self'; script-src 'nonce-%s'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'; upgrade-insecure-requests",
			nonce,
		))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	})

	faviconData, _ := publicFS.ReadFile("public/favicon.ico")
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Cache-Control", "public, max-age=604800")
		w.Write(faviconData)
	})

	// --- Public ---
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /auth/status", handleAuthStatus)

	// --- Auth lifecycle (rate-limited) ---
	loginRL := rateLimit(rateConfig{Window: 5 * time.Minute, Max: 5, Prefix: "rl:login"})
	registerRL := rateLimit(rateConfig{Window: 5 * time.Minute, Max: 5, Prefix: "rl:register"})
	logoutRL := rateLimit(rateConfig{Window: 5 * time.Minute, Max: 5, Prefix: "rl:logout", KeyFunc: userKey})
	passwordRL := rateLimit(rateConfig{Window: time.Hour, Max: 3, Prefix: "rl:password", KeyFunc: userKey})

	mux.Handle("POST /auth/register", registerRL(http.HandlerFunc(handleRegister)))
	mux.Handle("POST /auth/login", loginRL(http.HandlerFunc(handleLogin)))
	mux.Handle("POST /auth/logout", logoutRL(requireAuthMiddleware(http.HandlerFunc(handleLogout))))

	// --- Account management (authenticated) ---
	mux.Handle("POST /account/password", passwordRL(requireAuthMiddleware(http.HandlerFunc(handlePasswordChange))))
	mux.Handle("GET /account/me", requireAuthMiddleware(http.HandlerFunc(handleMe)))

	// --- Agent WebSocket (bearer token auth, cloaked from public IPs) ---
	mux.Handle("GET /ws", cloakMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			requireAgentKey(http.HandlerFunc(handleAgentWS)).ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})))

	// --- Control proxy (authenticated) — bridge to claw ---
	proxy := newProxy()
	mux.Handle("/control", requireAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			newBridge().ServeHTTP(w, r)
			return
		}
		u := r.URL
		u.Path += "/"
		http.Redirect(w, r, u.Path, http.StatusPermanentRedirect)
	})))
	mux.Handle("/control/", requireAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			newBridge().ServeHTTP(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})))

	// --- Ops API (cloaked from public IPs; agent key for reads/actions, provisioning secret for credential lifecycle) ---
	mux.Handle("GET /ops/sessions", cloakMiddleware(requireAgentKey(http.HandlerFunc(handleOpsSessions))))
	mux.Handle("POST /ops/sessions/revoke", cloakMiddleware(requireAgentKey(http.HandlerFunc(handleOpsSessionRevoke))))
	mux.Handle("GET /ops/agents", cloakMiddleware(requireAgentKey(http.HandlerFunc(handleOpsAgentList))))
	mux.Handle("POST /ops/agents", cloakMiddleware(requireProvisioningSecret(http.HandlerFunc(handleOpsAgentCreate))))
	mux.Handle("DELETE /ops/agents/{name}", cloakMiddleware(requireProvisioningSecret(http.HandlerFunc(handleOpsAgentRevoke))))
	mux.Handle("GET /ops/events", cloakMiddleware(requireAgentKey(http.HandlerFunc(handleOpsEvents))))
	mux.Handle("GET /ops/events/stats", cloakMiddleware(requireAgentKey(http.HandlerFunc(handleOpsEventStats))))
	mux.Handle("GET /ops/nodes", cloakMiddleware(requireAgentKey(http.HandlerFunc(handleOpsNodeList))))
	mux.Handle("GET /ops/cloak", cloakMiddleware(requireAgentKey(http.HandlerFunc(handleOpsCloakStatus))))
	mux.Handle("POST /ops/cloak", cloakMiddleware(requireAgentKey(http.HandlerFunc(handleOpsCloakEnable))))
	mux.Handle("DELETE /ops/cloak", cloakMiddleware(requireAgentKey(http.HandlerFunc(handleOpsCloakDisable))))

	// Global middleware: access log → security headers → body limit → routes
	handler := accessLog(securityHeaders(maxBody(mux)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if strings.HasPrefix(cfg.BaseURL, "https://") {
		serveTLS(ctx, handler)
	} else {
		servePlain(ctx, handler)
	}
}

func servePlain(ctx context.Context, handler http.Handler) {
	srv := &http.Server{Addr: cfg.Addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}

	go func() {
		slog.Info("birdcage starting", "addr", cfg.Addr, "db", cfg.DBPath)
		logStartupInfo()
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
	store.Close()
}

func serveTLS(ctx context.Context, handler http.Handler) {
	host := extractHost(cfg.BaseURL)

	if err := os.MkdirAll(cfg.CertDir, 0700); err != nil {
		slog.Error("failed to create cert directory", "path", cfg.CertDir, "error", err)
		os.Exit(1)
	}

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      loggingCache{autocert.DirCache(cfg.CertDir)},
		HostPolicy: autocert.HostWhitelist(host),
	}

	tlsCfg := m.TLSConfig()
	inner := tlsCfg.GetCertificate

	var tlsRejectSeen sync.Map // ip → time.Time
	const tlsRejectCooldown = time.Minute

	tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "" || net.ParseIP(hello.ServerName) != nil {
			rawAddr := hello.Conn.RemoteAddr().String()
			ip, _, _ := net.SplitHostPort(rawAddr)
			if ip == "" {
				ip = rawAddr
			}
			slog.Warn("tls rejected", "reason", "missing or IP-based SNI", "ip", rawAddr, "sni", hello.ServerName)
			now := time.Now()
			if last, ok := tlsRejectSeen.Load(ip); !ok || now.Sub(last.(time.Time)) >= tlsRejectCooldown {
				tlsRejectSeen.Store(ip, now)
				emitEvent("tls.rejected", ip, 0, "", 0, map[string]any{
					"reason": "no_sni",
					"sni":    hello.ServerName,
				})
			}
			return nil, fmt.Errorf("rejected: no SNI or bare IP")
		}
		cert, err := inner(hello)
		if err != nil {
			rawAddr := hello.Conn.RemoteAddr().String()
			ip, _, _ := net.SplitHostPort(rawAddr)
			if ip == "" {
				ip = rawAddr
			}
			now := time.Now()
			if last, ok := tlsRejectSeen.Load(ip); !ok || now.Sub(last.(time.Time)) >= tlsRejectCooldown {
				tlsRejectSeen.Store(ip, now)
				emitEvent("tls.rejected", ip, 0, "", 0, map[string]any{
					"reason": "wrong_host",
					"sni":    hello.ServerName,
				})
			}
		}
		return cert, err
	}

	tlsSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}

	httpSrv := &http.Server{
		Addr:              ":80",
		Handler:           m.HTTPHandler(httpsRedirectHandler(host)),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		slog.Info("birdcage starting", "addr", cfg.Addr, "host", host, "tls", true, "certDir", cfg.CertDir)
		logStartupInfo()
		if err := tlsSrv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			slog.Error("HTTPS server failed", "error", err)
			os.Exit(1)
		}
	}()

	go func() {
		if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
			slog.Warn("HTTP listener failed (ACME will use TLS-ALPN-01)", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tlsSrv.Shutdown(shutdownCtx)
	httpSrv.Shutdown(shutdownCtx)
	store.Close()
}

func logStartupInfo() {
	if cfg.GatewayURL != "" {
		slog.Info("control proxy enabled", "gateway", cfg.GatewayURL)
	}
	if cfg.WGPrivateKey != "" {
		slog.Info("wireguard enabled", "interface", cfg.WGInterface, "port", cfg.WGListenPort)
	}
}

func addrFromURL(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return ":8080"
	}
	if p := u.Port(); p != "" {
		return ":" + p
	}
	if u.Scheme == "https" {
		return ":443"
	}
	return ":80"
}

func extractHost(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		slog.Error("invalid BASE_URL", "url", baseURL, "error", err)
		os.Exit(1)
	}
	host := u.Hostname()
	if host == "" {
		slog.Error("BASE_URL must include a hostname", "url", baseURL)
		os.Exit(1)
	}
	if net.ParseIP(host) != nil {
		slog.Error("HTTPS requires a domain name (Let's Encrypt does not issue certificates for IP addresses)", "host", host)
		os.Exit(1)
	}
	if host == "localhost" {
		slog.Error("HTTPS requires a public domain (use http:// for local development)", "host", host)
		os.Exit(1)
	}
	return host
}

func httpsRedirectHandler(host string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

type loggingCache struct {
	autocert.Cache
}

func (c loggingCache) Put(ctx context.Context, name string, data []byte) error {
	slog.Info("TLS certificate cached", "name", name)
	return c.Cache.Put(ctx, name, data)
}

// --- Server service install/uninstall ---

const serverServiceName = "birdcage"

var serverSystemdUnit = template.Must(template.New("unit").Parse(`[Unit]
Description=Birdcage Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={{.Binary}} serve
WorkingDirectory={{.WorkDir}}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`))

func runServeInstall() {
	for _, a := range os.Args[1:] {
		if a == "--help" || a == "-h" {
			fmt.Println("birdcage serve install — install the server as a system service")
			fmt.Println()
			fmt.Println("Requires .env in the current directory. Run 'birdcage init' first.")
			return
		}
	}

	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "No .env found in current directory. Run 'birdcage init' first.")
		os.Exit(1)
	}

	binary, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding binary path: %v\n", err)
		os.Exit(1)
	}
	binary, _ = filepath.Abs(binary)

	workDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting working directory: %v\n", err)
		os.Exit(1)
	}

	switch runtime.GOOS {
	case "linux":
		installServerSystemd(binary, workDir)
	default:
		fmt.Fprintf(os.Stderr, "Server service install not supported on %s (use systemd on Linux)\n", runtime.GOOS)
		os.Exit(1)
	}
}

func installServerSystemd(binary, workDir string) {
	unitPath := "/etc/systemd/system/" + serverServiceName + ".service"

	f, err := os.Create(unitPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing unit file (try with sudo): %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	if err := serverSystemdUnit.Execute(f, struct{ Binary, WorkDir string }{binary, workDir}); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing unit file: %v\n", err)
		os.Exit(1)
	}

	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", serverServiceName},
		{"systemctl", "start", serverServiceName},
	}
	for _, args := range cmds {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error running %v: %v\n%s\n", args, err, out)
			os.Exit(1)
		}
	}

	fmt.Println("Server installed and started")
	fmt.Printf("  Unit:      %s\n", unitPath)
	fmt.Printf("  WorkDir:   %s\n", workDir)
	fmt.Printf("  Status:    systemctl status %s\n", serverServiceName)
	fmt.Printf("  Logs:      journalctl -u %s -f\n", serverServiceName)
	fmt.Printf("  Uninstall: birdcage serve uninstall\n")
}

func runServeUninstall() {
	for _, a := range os.Args[1:] {
		if a == "--help" || a == "-h" {
			fmt.Println("birdcage serve uninstall — remove the server system service")
			return
		}
	}

	switch runtime.GOOS {
	case "linux":
		uninstallServerSystemd()
	default:
		fmt.Fprintf(os.Stderr, "Server service uninstall not supported on %s\n", runtime.GOOS)
		os.Exit(1)
	}
}

func uninstallServerSystemd() {
	unitPath := "/etc/systemd/system/" + serverServiceName + ".service"

	exec.Command("systemctl", "stop", serverServiceName).Run()    // #nosec G104 — best effort
	exec.Command("systemctl", "disable", serverServiceName).Run() // #nosec G104 — best effort

	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error removing unit file: %v\n", err)
		os.Exit(1)
	}

	exec.Command("systemctl", "daemon-reload").Run() // #nosec G104 — best effort

	fmt.Println("Server service removed.")
}

func loadConfig() *Config {
	godotenv.Load(".env") // #nosec G104 — .env is optional

	baseURL := envOr("BASE_URL", "http://localhost:8080")
	isHTTPS := strings.HasPrefix(baseURL, "https://")

	defaultAddr := addrFromURL(baseURL)

	wgPort := envInt("WG_LISTEN_PORT", 51820)

	defaultIface := "wg0"
	if runtime.GOOS == "darwin" {
		defaultIface = "utun3"
	}
	wgIface := envOr("WG_INTERFACE", defaultIface)

	return &Config{
		Addr:              envOr("ADDR", defaultAddr),
		DBPath:            envOr("DB_PATH", "birdcage.db"),
		AccessSecret:      mustEnv("JWT_ACCESS_SECRET"),
		RefreshSecret:     mustEnv("JWT_REFRESH_SECRET"),
		AgentKey:          os.Getenv("AGENT_KEY"),
		RegistrationToken: os.Getenv("REGISTRATION_TOKEN"),
		GatewayURL:        os.Getenv("GATEWAY_URL"),
		GatewayToken:      os.Getenv("GATEWAY_TOKEN"),
		CookieSecure:      isHTTPS,
		WSAllowedOrigins:  os.Getenv("WS_ALLOWED_ORIGINS"),
		BaseURL:           baseURL,
		CertDir:           envOr("CERT_DIR", "certs"),
		WGPrivateKey:      os.Getenv("WG_PRIVATE_KEY"),
		WGListenPort:      wgPort,
		WGEndpoint:        os.Getenv("WG_ENDPOINT"),
		WGInterface:       wgIface,
		WGSubnet:          envOr("WG_SUBNET", "10.0.0.0/24"),
		CloakDurationMin:  envInt("CLOAK_DURATION_MIN", 60),
		CloakOnAttack:     os.Getenv("CLOAK_ON_ATTACK") != "false",
	}
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		slog.Error("required env var missing", "key", k)
		os.Exit(1)
	}
	if len(v) < 32 {
		slog.Error("env var too short (minimum 32 characters)", "key", k, "length", len(v))
		os.Exit(1)
	}
	return v
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// ensureAgentCredential creates the agent credential from AGENT_KEY if it doesn't exist.
func ensureAgentCredential() {
	if cfg.AgentKey == "" {
		return
	}

	keyHash := hashAPIKey(cfg.AgentKey)

	var exists int
	if err := store.QueryRow("SELECT COUNT(*) FROM agent_credential WHERE key_hash = ?", keyHash).Scan(&exists); err != nil {
		logError("agent_credential.check", err)
	}
	if exists > 0 {
		return
	}

	_, err := store.Exec(
		"INSERT INTO agent_credential (name, key_hash) VALUES (?, ?)",
		"home", keyHash,
	)
	if err != nil {
		if isUniqueViolation(err) {
			// Name "home" already taken, try with suffix
			_, err = store.Exec(
				"INSERT INTO agent_credential (name, key_hash) VALUES (?, ?)",
				fmt.Sprintf("agent-%s", keyHash[:8]), keyHash,
			)
		}
		if err != nil {
			slog.Error("failed to create agent credential", "error", err)
		}
	} else {
		slog.Info("agent credential created", "name", "home")
	}
}
