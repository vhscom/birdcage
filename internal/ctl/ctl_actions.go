package ctl

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/coder/websocket"

	tea "github.com/charmbracelet/bubbletea"
	"birdcage/internal/api"
	"birdcage/internal/ui"
)

func (m model) dispatchAction() (model, tea.Cmd) {
	switch m.action {
	// Direct fetches (no input needed)
	case actionViewSessions:
		m.sessions = nil
		return m, m.fetchSessions()
	case actionViewEvents:
		m.events = nil
		return m, m.fetchEvents()
	case actionViewEventStats:
		m.eventStats = nil
		return m, m.fetchEventStats()
	case actionTailEvents:
		m.tailEvents = nil
		m.tailFilter = nil
		m.tailErr = nil
		m.tailConn = nil
		m.startInput([]string{"Type filter (optional)"})
		m.inputHint = "  Examples:  login.*, session.revoke, ws.*\n" +
			"  Available: login.*, password.*, session.*, agent.*, challenge.*, ws.*, registration.*, rate_limit.*\n" +
			"  Combine:   login.*,session.revoke"
	case actionViewNodes:
		m.nodeList = nil
		return m, m.fetchNodes()
	case actionListAgents:
		m.agents = nil
		return m, m.fetchAgents()

	// Single input
	case actionRevokeAll:
		m.state = stateConfirm
	case actionRevokeSession:
		m.startInput([]string{"Session ID"})
	case actionRevokeAgent:
		m.startInput([]string{"Agent name"})

	// Single-field input
	case actionProvisionAgent:
		m.startInput([]string{"Agent name"})
	}
	return m, nil
}

func (m model) afterInputComplete() (model, tea.Cmd) {
	switch m.action {
	// Actions that need confirmation before executing
	case actionRevokeSession, actionRevokeAgent:
		m.state = stateConfirm
		return m, nil

	// Actions that execute immediately after input
	case actionTailEvents:
		filter := strings.TrimSpace(m.inputs[0])
		if filter != "" {
			m.tailFilter = strings.Split(filter, ",")
			for i := range m.tailFilter {
				m.tailFilter[i] = strings.TrimSpace(m.tailFilter[i])
			}
		}
		m.state = stateTailEvents
		return m, m.dialAndSubscribe()
	case actionProvisionAgent:
		m.state = stateConfirm
		return m, nil
	}

	m.state = stateMenu
	return m, nil
}

func (m model) executeAction() tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()

		switch m.action {
		case actionRevokeAll:
			resp, err := m.client.RevokeSessions(ctx, api.RevokeSessionsRequest{Scope: "all"})
			if err != nil {
				return resultMsg{err: err}
			}
			return resultMsg{message: fmt.Sprintf("Done. %d session(s) revoked.", resp.Revoked)}

		case actionRevokeSession:
			resp, err := m.client.RevokeSessions(ctx, api.RevokeSessionsRequest{Scope: "session", ID: m.inputs[0]})
			if err != nil {
				return resultMsg{err: err}
			}
			return resultMsg{message: fmt.Sprintf("Done. %d session(s) revoked.", resp.Revoked)}

		case actionProvisionAgent:
			resp, err := m.client.CreateAgent(ctx, api.CreateAgentRequest{Name: m.inputs[0]})
			if err != nil {
				return resultMsg{err: err}
			}
			return resultMsg{message: fmt.Sprintf("Agent '%s' provisioned.\nAPI Key: %s\n\nSave this key -- it will not be shown again.", resp.Name, resp.APIKey)}

		case actionRevokeAgent:
			_, err := m.client.DeleteAgent(ctx, m.inputs[0])
			if err != nil {
				return resultMsg{err: err}
			}
			return resultMsg{message: fmt.Sprintf("Agent '%s' revoked.", m.inputs[0])}
		}

		return resultMsg{err: fmt.Errorf("unknown action")}
	}
}

// --- Commands (fetch data from API) ---

func (m model) fetchSessions() tea.Cmd {
	return func() tea.Msg {
		resp, err := m.client.ListSessions(context.Background(), api.SessionsParams{})
		if err != nil {
			return sessionsMsg{err: err}
		}
		return sessionsMsg{sessions: resp.Sessions}
	}
}

func (m model) fetchEvents() tea.Cmd {
	return func() tea.Msg {
		resp, err := m.client.ListEvents(context.Background(), api.EventsParams{})
		if err != nil {
			return eventsMsg{err: err}
		}
		return eventsMsg{events: resp.Events}
	}
}

func (m model) fetchEventStats() tea.Cmd {
	return func() tea.Msg {
		resp, err := m.client.GetEventStats(context.Background(), "")
		if err != nil {
			return eventStatsMsg{err: err}
		}
		return eventStatsMsg{stats: resp.Stats, since: resp.Since}
	}
}

func (m model) fetchAgents() tea.Cmd {
	return func() tea.Msg {
		resp, err := m.client.ListAgents(context.Background())
		if err != nil {
			return agentsMsg{err: err}
		}
		return agentsMsg{agents: resp.Agents}
	}
}

func (m model) fetchNodes() tea.Cmd {
	return func() tea.Msg {
		resp, err := m.client.ListNodes(context.Background())
		if err != nil {
			return nodesMsg{err: err}
		}
		return nodesMsg{nodes: resp.Nodes}
	}
}

// --- WebSocket subscription ---

func (m model) dialAndSubscribe() tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		var frames []wsFrame

		conn, err := m.client.ConnectWS(ctx)
		if err != nil {
			return tailConnectedMsg{err: err}
		}

		// Send capability.request
		capReq := api.WSCapabilitiesRequest{
			Type:         "capability.request",
			Capabilities: []string{"subscribe_events"},
		}
		data, _ := json.Marshal(capReq)
		frames = append(frames, wsFrame{Dir: ">", Type: "capability.request", Raw: string(data), Time: time.Now()})
		if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
			conn.Close(websocket.StatusNormalClosure, "")
			return tailConnectedMsg{err: fmt.Errorf("write capabilities: %w", err)}
		}

		// Read capability.granted
		_, capResp, err := conn.Read(ctx)
		if err != nil {
			conn.Close(websocket.StatusNormalClosure, "")
			return tailConnectedMsg{err: fmt.Errorf("read capabilities: %w", err)}
		}
		frames = append(frames, wsFrame{Dir: "<", Type: "capability.granted", Raw: string(capResp), Time: time.Now()})
		var granted api.WSCapabilitiesGranted
		if err := json.Unmarshal(capResp, &granted); err != nil {
			conn.Close(websocket.StatusNormalClosure, "")
			return tailConnectedMsg{err: fmt.Errorf("decode capabilities: %w", err)}
		}
		hasSubscribe := false
		for _, c := range granted.Granted {
			if c == "subscribe_events" {
				hasSubscribe = true
				break
			}
		}
		if !hasSubscribe {
			conn.Close(websocket.StatusNormalClosure, "")
			return tailConnectedMsg{err: fmt.Errorf("subscribe_events capability denied")}
		}

		// Send subscribe_events
		subReq := api.WSSubscribeRequest{
			Type:    "subscribe_events",
			ID:      "tail-1",
			Payload: api.WSSubscribePayload{Types: m.tailFilter},
		}
		data, _ = json.Marshal(subReq)
		frames = append(frames, wsFrame{Dir: ">", Type: "subscribe_events", Raw: string(data), Time: time.Now()})
		if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
			conn.Close(websocket.StatusNormalClosure, "")
			return tailConnectedMsg{err: fmt.Errorf("write subscribe: %w", err)}
		}

		// Read subscribe ack
		_, subResp, err := conn.Read(ctx)
		if err != nil {
			conn.Close(websocket.StatusNormalClosure, "")
			return tailConnectedMsg{err: fmt.Errorf("read subscribe ack: %w", err)}
		}
		frames = append(frames, wsFrame{Dir: "<", Type: "subscribe_events.result", Raw: string(subResp), Time: time.Now()})
		var envelope api.WSEnvelope
		if err := json.Unmarshal(subResp, &envelope); err != nil || (envelope.OK != nil && !*envelope.OK) {
			conn.Close(websocket.StatusNormalClosure, "")
			return tailConnectedMsg{err: fmt.Errorf("subscribe rejected")}
		}

		return tailConnectedMsg{conn: conn, frames: frames}
	}
}

func (m model) readNextEvent() tea.Cmd {
	return func() tea.Msg {
		if m.tailConn == nil {
			return tailErrorMsg{err: fmt.Errorf("no connection")}
		}
		_, data, err := m.tailConn.Read(context.Background())
		if err != nil {
			return tailErrorMsg{err: err}
		}
		var envelope api.WSEnvelope
		if err := json.Unmarshal(data, &envelope); err != nil {
			return tailErrorMsg{err: fmt.Errorf("decode message: %w", err)}
		}
		frame := wsFrame{Dir: "<", Type: envelope.Type, Raw: string(data), Time: time.Now()}
		switch envelope.Type {
		case "credential.revoked":
			return tailErrorMsg{err: fmt.Errorf("agent credential revoked")}
		case "event":
			var wsEvt api.WSEvent
			if err := json.Unmarshal(data, &wsEvt); err != nil {
				return tailErrorMsg{err: fmt.Errorf("decode event: %w", err)}
			}
			p := wsEvt.Payload
			var detail *string
			if p.Detail != nil {
				s := string(*p.Detail)
				detail = &s
			}
			return tailEventMsg{
				event: api.Event{
					ID:        p.EventID,
					Type:      p.EventType,
					IPAddress: p.IPAddress,
					UserID:    p.UserID,
					Detail:    detail,
					CreatedAt: p.CreatedAt,
					ActorID:   p.ActorID,
				},
				frame: frame,
			}
		default:
			// Protocol messages (heartbeat, pong) — captured in frame inspector
			return tailEventMsg{event: api.Event{Type: ""}, frame: frame}
		}
	}
}

func (m *model) closeTail() {
	if m.tailKeepaliveStop != nil {
		close(m.tailKeepaliveStop)
		m.tailKeepaliveStop = nil
	}
	if m.tailConn != nil {
		unsub := api.WSUnsubscribeRequest{Type: "unsubscribe_events", ID: "tail-2"}
		data, _ := json.Marshal(unsub)
		_ = m.tailConn.Write(context.Background(), websocket.MessageText, data)
		m.tailConn.Close(websocket.StatusNormalClosure, "client disconnected")
		m.tailConn = nil
	}
}

// keepAlive sends application-level ping messages to prevent ping timeout.
func keepAlive(conn *websocket.Conn, stop <-chan struct{}) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	seq := 0
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			seq++
			ping := api.WSPingRequest{
				Type: "ping",
				ID:   fmt.Sprintf("keepalive-%d", seq),
			}
			data, _ := json.Marshal(ping)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = conn.Write(ctx, websocket.MessageText, data)
			cancel()
		}
	}
}

// --- Entry point & usage ---

func printUsage() {
	title := ui.TitleStyle.Render
	heading := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Render
	cmd := lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render
	flag := lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Render
	dim := ui.DimStyle.Render

	fmt.Printf("%s %s\n\n", title("birdcage ctl"), dim("— ops control TUI"))

	fmt.Println(heading("Usage"))
	fmt.Printf("  %s\n\n", cmd("birdcage ctl [flags]"))

	fmt.Println(heading("Flags"))
	fmt.Printf("  %s  %s\n", flag(fmt.Sprintf("%-20s", "--addr <url>")), dim("Ops endpoint (overrides BIRDCAGE_CTL_ADDR)"))
	fmt.Printf("  %s  %s\n\n", flag(fmt.Sprintf("%-20s", "--help")), dim("Show this help"))

	fmt.Println(heading("Environment"))
	fmt.Printf("  %s  %s\n", flag(fmt.Sprintf("%-28s", "BIRDCAGE_CTL_ADDR")), dim("Ops endpoint URL (required)"))
	fmt.Printf("  %s  %s\n", flag(fmt.Sprintf("%-28s", "BIRDCAGE_CTL_API_KEY")), dim("Agent API key for Bearer auth (required)"))
	fmt.Printf("  %s  %s\n\n", flag(fmt.Sprintf("%-28s", "BIRDCAGE_CTL_PROVISIONING_SECRET")), dim("Provisioning secret (optional)"))

	fmt.Println(heading("Interactive Commands"))
	fmt.Println()
	fmt.Printf("  %s\n", title("Sessions"))
	fmt.Printf("    %s  %s\n", cmd(fmt.Sprintf("%-32s", "View active sessions")), dim("List all active sessions"))
	fmt.Printf("    %s  %s\n", cmd(fmt.Sprintf("%-32s", "Revoke all sessions")), dim("Expire every active session"))
	fmt.Printf("    %s  %s\n\n", cmd(fmt.Sprintf("%-32s", "Revoke specific session")), dim("Expire by session ID"))

	fmt.Printf("  %s\n", title("Events"))
	fmt.Printf("    %s  %s\n", cmd(fmt.Sprintf("%-32s", "View recent events")), dim("Security events (last 24h)"))
	fmt.Printf("    %s  %s\n", cmd(fmt.Sprintf("%-32s", "View event stats")), dim("Aggregate counts by type"))
	fmt.Printf("    %s  %s\n\n", cmd(fmt.Sprintf("%-32s", "Tail events (live)")), dim("Stream in real time"))

	fmt.Printf("  %s\n", title("Nodes"))
	fmt.Printf("    %s  %s\n\n", cmd(fmt.Sprintf("%-32s", "View all nodes")), dim("List all mesh nodes"))

	fmt.Printf("  %s\n", title("Agents"))
	fmt.Printf("    %s  %s\n", cmd(fmt.Sprintf("%-32s", "List agents")), dim("Show agent credentials"))
	fmt.Printf("    %s  %s\n", cmd(fmt.Sprintf("%-32s", "Provision agent")), dim("Create a new credential"))
	fmt.Printf("    %s  %s\n", cmd(fmt.Sprintf("%-32s", "Revoke agent")), dim("Revoke a credential"))
}

// Run is the entry point for "birdcage ctl".
func Run() {
	var addr string
	var help bool
	for i := 1; i < len(os.Args); i++ {
		switch {
		case os.Args[i] == "--help" || os.Args[i] == "-h":
			help = true
		case os.Args[i] == "--addr" && i+1 < len(os.Args):
			i++
			addr = os.Args[i]
		case strings.HasPrefix(os.Args[i], "--addr="):
			addr = strings.TrimPrefix(os.Args[i], "--addr=")
		}
	}

	if help {
		printUsage()
		os.Exit(0)
	}

	apiURL := addr
	if apiURL == "" {
		apiURL = os.Getenv("BIRDCAGE_CTL_ADDR")
	}
	apiKey := os.Getenv("BIRDCAGE_CTL_API_KEY")
	provSecret := os.Getenv("BIRDCAGE_CTL_PROVISIONING_SECRET")
	if provSecret == "" {
		provSecret = os.Getenv("AGENT_PROVISIONING_SECRET")
	}

	if apiURL == "" || apiKey == "" {
		fmt.Fprintln(os.Stderr, "BIRDCAGE_CTL_ADDR and BIRDCAGE_CTL_API_KEY environment variables are required")
		fmt.Fprintln(os.Stderr, "Run 'birdcage ctl --help' for usage information")
		os.Exit(1)
	}

	client := api.NewClient(apiURL, apiKey, provSecret)

	p := tea.NewProgram(initialModel(client))
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
