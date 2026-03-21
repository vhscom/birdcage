package ctl

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"

	"birdcage/internal/api"
	"birdcage/internal/ui"
)

func buildEventsTable(events []api.Event) table.Model {
	columns := []table.Column{
		{Title: "ID", Width: 6},
		{Title: "Type", Width: 24},
		{Title: "IP", Width: 16},
		{Title: "User", Width: 8},
		{Title: "Actor", Width: 28},
		{Title: "Time", Width: 20},
	}

	rows := make([]table.Row, len(events))
	for i, e := range events {
		userID := "-"
		if e.UserID != nil {
			userID = fmt.Sprintf("%d", *e.UserID)
		}
		rows[i] = table.Row{
			fmt.Sprintf("%d", e.ID),
			e.Type,
			e.IPAddress,
			userID,
			e.ActorID,
			e.CreatedAt,
		}
	}

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("8")).
		BorderBottom(true).
		Bold(true).
		Foreground(lipgloss.Color("5"))
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("0")).
		Background(lipgloss.Color("2")).
		Bold(false)

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithHeight(15),
		table.WithFocused(true),
		table.WithStyles(s),
	)

	return t
}

func buildFramesTable(frames []wsFrame) table.Model {
	columns := []table.Column{
		{Title: "Dir", Width: 3},
		{Title: "Type", Width: 28},
		{Title: "Time", Width: 12},
		{Title: "Size", Width: 6},
	}

	rows := make([]table.Row, len(frames))
	for i, f := range frames {
		ts := f.Time.Format("15:04:05.000")
		rows[i] = table.Row{
			f.Dir,
			f.Type,
			ts,
			fmt.Sprintf("%d", len(f.Raw)),
		}
	}

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("8")).
		BorderBottom(true).
		Bold(true).
		Foreground(lipgloss.Color("5"))
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("0")).
		Background(lipgloss.Color("6")).
		Bold(false)

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithHeight(20),
		table.WithFocused(true),
		table.WithStyles(s),
	)

	return t
}

// --- View rendering ---

func (m model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder
	b.WriteString(ui.TitleStyle.Render("birdcagectl"))
	b.WriteString("\n\n")

	switch m.state {
	case stateMenu:
		b.WriteString(m.viewMenu())
	case stateInput:
		b.WriteString(m.viewInput())
	case stateConfirm:
		b.WriteString(m.viewConfirm())
	case stateResult:
		b.WriteString(m.viewResult())
	case stateSessions:
		b.WriteString(m.viewSessions())
	case stateEvents:
		b.WriteString(m.viewEvents())
	case stateEventDetail:
		b.WriteString(m.viewEventDetail())
	case stateEventStats:
		b.WriteString(m.viewEventStats())
	case stateNodes:
		b.WriteString(m.viewNodes())
	case stateAgents:
		b.WriteString(m.viewAgents())
	case stateTailEvents:
		b.WriteString(m.viewTailEvents())
	case stateFrameInspector:
		b.WriteString(m.viewFrameInspector())
	case stateFrameDetail:
		b.WriteString(m.viewFrameDetail())
	}

	b.WriteString("\n")
	return b.String()
}

func (m model) viewMenu() string {
	var b strings.Builder

	for i, item := range menuItems {
		if item.isHeader {
			if i > 0 {
				b.WriteString("\n")
			}
			b.WriteString("  ")
			b.WriteString(ui.HeaderStyle.Render(item.label))
			b.WriteString("\n")
			continue
		}

		cursor := "  "
		style := ui.DimStyle
		if i == m.cursor {
			cursor = "> "
			style = ui.ActiveStyle
		}
		b.WriteString(style.Render(cursor + item.label))
		b.WriteString("\n")
	}

	b.WriteString(ui.DimStyle.Render("\nj/k navigate | enter select | q quit"))
	return b.String()
}

func (m model) viewInput() string {
	var b strings.Builder

	for i := 0; i < len(m.inputs); i++ {
		b.WriteString(ui.DimStyle.Render(fmt.Sprintf("  %s: %s", m.inputLabels[i], m.inputs[i])))
		b.WriteString("\n")
	}

	label := m.inputLabels[m.inputField]
	b.WriteString(ui.PromptStyle.Render(fmt.Sprintf("Enter %s: ", label)))
	b.WriteString(m.input.Value)
	b.WriteString("_")
	if m.inputHint != "" {
		b.WriteString("\n\n")
		b.WriteString(ui.DimStyle.Render(m.inputHint))
	}
	b.WriteString(ui.DimStyle.Render("\n\nenter confirm | esc back"))
	return b.String()
}

func (m model) viewConfirm() string {
	var b strings.Builder
	var target string

	switch m.action {
	case actionRevokeAll:
		target = "ALL active sessions"
	case actionRevokeSession:
		target = fmt.Sprintf("session %s", m.inputs[0])
	case actionProvisionAgent:
		target = fmt.Sprintf("agent '%s'", m.inputs[0])
	case actionRevokeAgent:
		target = fmt.Sprintf("agent '%s'", m.inputs[0])
	}

	verb := "Execute"
	switch m.action {
	case actionRevokeAll, actionRevokeSession, actionRevokeAgent:
		verb = "Revoke"
	case actionProvisionAgent:
		verb = "Provision"
	}

	b.WriteString(ui.ErrorStyle.Render(fmt.Sprintf("%s %s?", verb, target)))
	b.WriteString(ui.DimStyle.Render("\n\ny confirm | n cancel"))
	return b.String()
}

func (m model) viewResult() string {
	var b strings.Builder
	if m.resultErr != nil {
		b.WriteString(ui.ErrorStyle.Render(fmt.Sprintf("Error: %v", m.resultErr)))
	} else {
		b.WriteString(ui.SuccessStyle.Render(m.resultMessage))
	}
	b.WriteString(ui.DimStyle.Render("\n\nenter continue | q quit"))
	return b.String()
}

func (m model) viewSessions() string {
	var b strings.Builder

	if m.dataErr != nil {
		b.WriteString(ui.ErrorStyle.Render(fmt.Sprintf("Error: %v", m.dataErr)))
		b.WriteString(ui.DimStyle.Render("\n\nenter continue | q quit"))
		return b.String()
	}

	if m.sessions == nil {
		b.WriteString(ui.DimStyle.Render("Loading..."))
		return b.String()
	}

	if len(m.sessions) == 0 {
		b.WriteString(ui.DimStyle.Render("No active sessions."))
		b.WriteString(ui.DimStyle.Render("\n\nenter continue | q quit"))
		return b.String()
	}

	b.WriteString(fmt.Sprintf("Active Sessions (%d)\n\n", len(m.sessions)))

	columns := []ui.Column{
		{Header: "ID", Width: 24},
		{Header: "User", Width: 8},
		{Header: "IP", Width: 16},
		{Header: "User Agent", Width: 30},
		{Header: "Expires", Width: 20},
	}

	rows := make([][]string, len(m.sessions))
	for i, s := range m.sessions {
		rows[i] = []string{
			s.ID,
			fmt.Sprintf("%d", s.UserID),
			s.IPAddress,
			s.UserAgent,
			s.ExpiresAt,
		}
	}

	b.WriteString(ui.RenderTable(columns, rows))
	b.WriteString(ui.DimStyle.Render("\nenter continue | q quit"))
	return b.String()
}

func (m model) viewEvents() string {
	var b strings.Builder

	if m.dataErr != nil {
		b.WriteString(ui.ErrorStyle.Render(fmt.Sprintf("Error: %v", m.dataErr)))
		b.WriteString(ui.DimStyle.Render("\n\nenter continue | q quit"))
		return b.String()
	}

	if m.events == nil {
		b.WriteString(ui.DimStyle.Render("Loading..."))
		return b.String()
	}

	if len(m.events) == 0 {
		b.WriteString(ui.DimStyle.Render("No events found."))
		b.WriteString(ui.DimStyle.Render("\n\nenter continue | q quit"))
		return b.String()
	}

	b.WriteString(fmt.Sprintf("Security Events (%d)\n\n", len(m.events)))
	b.WriteString(m.eventsTable.View())
	b.WriteString(ui.DimStyle.Render("\nj/k navigate | enter detail | esc back | q quit"))
	return b.String()
}

func (m model) viewEventDetail() string {
	var b strings.Builder

	idx := m.eventsTable.Cursor()
	if idx < 0 || idx >= len(m.events) {
		b.WriteString(ui.DimStyle.Render("No event selected."))
		b.WriteString(ui.DimStyle.Render("\n\nesc back | q quit"))
		return b.String()
	}

	e := m.events[idx]

	b.WriteString(fmt.Sprintf("Event #%d\n\n", e.ID))

	userID := "-"
	if e.UserID != nil {
		userID = fmt.Sprintf("%d", *e.UserID)
	}
	ip := e.IPAddress
	if ip == "" {
		ip = "-"
	}
	labels := []string{"Type", "IP", "User", "Actor", "Time"}
	values := []string{e.Type, ip, userID, e.ActorID, e.CreatedAt}

	for i, label := range labels {
		b.WriteString(fmt.Sprintf("  %s  %s\n", ui.HeaderStyle.Render(fmt.Sprintf("%-10s", label)), values[i]))
	}

	detail := "-"
	if e.Detail != nil {
		detail = *e.Detail
	}
	const labelWidth = 15
	maxDetail := m.width - labelWidth
	if maxDetail < 20 {
		maxDetail = 80
	}
	prefix := fmt.Sprintf("  %s  ", ui.HeaderStyle.Render(fmt.Sprintf("%-10s", "Detail")))
	pad := strings.Repeat(" ", labelWidth)
	for i := 0; i < len(detail); i += maxDetail {
		end := min(i+maxDetail, len(detail))
		if i == 0 {
			b.WriteString(prefix)
		} else {
			b.WriteString(pad)
		}
		b.WriteString(detail[i:end])
		b.WriteString("\n")
	}

	b.WriteString(ui.DimStyle.Render("\nesc back | q quit"))
	return b.String()
}

func (m model) viewEventStats() string {
	var b strings.Builder

	if m.dataErr != nil {
		b.WriteString(ui.ErrorStyle.Render(fmt.Sprintf("Error: %v", m.dataErr)))
		b.WriteString(ui.DimStyle.Render("\n\nenter continue | q quit"))
		return b.String()
	}

	if m.eventStats == nil {
		b.WriteString(ui.DimStyle.Render("Loading..."))
		return b.String()
	}

	if len(m.eventStats) == 0 {
		b.WriteString(ui.DimStyle.Render("No events in time window."))
		b.WriteString(ui.DimStyle.Render("\n\nenter continue | q quit"))
		return b.String()
	}

	b.WriteString(fmt.Sprintf("Event Stats (since %s)\n\n", m.eventSince))

	keys := make([]string, 0, len(m.eventStats))
	for k := range m.eventStats {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	columns := []ui.Column{
		{Header: "Event Type", Width: 30},
		{Header: "Count", Width: 8},
	}

	rows := make([][]string, len(keys))
	for i, k := range keys {
		rows[i] = []string{k, fmt.Sprintf("%d", m.eventStats[k])}
	}

	b.WriteString(ui.RenderTable(columns, rows))
	b.WriteString(ui.DimStyle.Render("\nenter continue | q quit"))
	return b.String()
}

func (m model) viewAgents() string {
	var b strings.Builder

	if m.dataErr != nil {
		b.WriteString(ui.ErrorStyle.Render(fmt.Sprintf("Error: %v", m.dataErr)))
		b.WriteString(ui.DimStyle.Render("\n\nenter continue | q quit"))
		return b.String()
	}

	if m.agents == nil {
		b.WriteString(ui.DimStyle.Render("Loading..."))
		return b.String()
	}

	if len(m.agents) == 0 {
		b.WriteString(ui.DimStyle.Render("No agents."))
		b.WriteString(ui.DimStyle.Render("\n\nenter continue | q quit"))
		return b.String()
	}

	b.WriteString(fmt.Sprintf("Agents (%d)\n\n", len(m.agents)))

	columns := []ui.Column{
		{Header: "Name", Width: 20},
		{Header: "Created", Width: 20},
	}

	rows := make([][]string, len(m.agents))
	for i, a := range m.agents {
		rows[i] = []string{a.Name, a.CreatedAt}
	}

	b.WriteString(ui.RenderTable(columns, rows))
	b.WriteString(ui.DimStyle.Render("\nenter continue | q quit"))
	return b.String()
}

func (m model) viewNodes() string {
	var b strings.Builder

	if m.dataErr != nil {
		b.WriteString(ui.ErrorStyle.Render(fmt.Sprintf("Error: %v", m.dataErr)))
		b.WriteString(ui.DimStyle.Render("\n\nenter continue | q quit"))
		return b.String()
	}

	if m.nodeList == nil {
		b.WriteString(ui.DimStyle.Render("Loading..."))
		return b.String()
	}

	if len(m.nodeList) == 0 {
		b.WriteString(ui.DimStyle.Render("No nodes found."))
		b.WriteString(ui.DimStyle.Render("\n\nenter continue | q quit"))
		return b.String()
	}

	b.WriteString(fmt.Sprintf("Nodes (%d)\n\n", len(m.nodeList)))

	columns := []ui.Column{
		{Header: "ID", Width: 6},
		{Header: "Label", Width: 16},
		{Header: "Pubkey", Width: 20},
		{Header: "Endpoint", Width: 22},
		{Header: "Allowed IPs", Width: 18},
		{Header: "Last Seen", Width: 20},
	}

	rows := make([][]string, len(m.nodeList))
	for i, n := range m.nodeList {
		endpoint := "-"
		if n.WGEndpoint != nil {
			endpoint = *n.WGEndpoint
		}
		lastSeen := "-"
		if n.LastSeenAt != nil {
			lastSeen = *n.LastSeenAt
		}
		pubkey := n.WGPubkey
		if len(pubkey) > 18 {
			pubkey = pubkey[:16] + ".."
		}
		rows[i] = []string{
			fmt.Sprintf("%d", n.ID),
			n.Label,
			pubkey,
			endpoint,
			n.AllowedIPs,
			lastSeen,
		}
	}

	b.WriteString(ui.RenderTable(columns, rows))
	b.WriteString(ui.DimStyle.Render("\nenter continue | q quit"))
	return b.String()
}

func (m model) viewTailEvents() string {
	var b strings.Builder

	if m.tailErr != nil {
		b.WriteString(ui.ErrorStyle.Render(fmt.Sprintf("Error: %v", m.tailErr)))
		b.WriteString(ui.DimStyle.Render("\n\nesc back | q quit"))
		return b.String()
	}

	if m.tailConn == nil {
		b.WriteString(ui.DimStyle.Render("Connecting..."))
		return b.String()
	}

	header := "Tailing events (live)"
	if len(m.tailFilter) > 0 {
		header += fmt.Sprintf("  [%s]", strings.Join(m.tailFilter, ", "))
	}
	b.WriteString(ui.HeaderStyle.Render(header))
	if len(m.tailEvents) > 0 {
		b.WriteString(ui.DimStyle.Render(fmt.Sprintf("  %d event(s)", len(m.tailEvents))))
	}
	b.WriteString("\n\n")

	if len(m.tailEvents) == 0 {
		b.WriteString(ui.DimStyle.Render("Waiting for events..."))
	} else {
		start := 0
		if len(m.tailEvents) > 20 {
			start = len(m.tailEvents) - 20
		}
		for _, e := range m.tailEvents[start:] {
			ts := e.CreatedAt
			if len(ts) >= 19 {
				ts = ts[11:19]
			}
			userID := "-"
			if e.UserID != nil {
				userID = fmt.Sprintf("user:%d", *e.UserID)
			}
			line := fmt.Sprintf("  %s  %-24s  %-16s  %-10s  %s",
				ts, e.Type, e.IPAddress, userID, e.ActorID)
			if m.width > 0 && len(line) > m.width {
				line = line[:m.width]
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
	}

	frameHint := ""
	if len(m.frames) > 0 {
		frameHint = fmt.Sprintf(" | f frames (%d)", len(m.frames))
	}
	b.WriteString(ui.DimStyle.Render(fmt.Sprintf("\nesc stop%s | q quit", frameHint)))
	return b.String()
}

func (m model) viewFrameInspector() string {
	var b strings.Builder

	b.WriteString(ui.HeaderStyle.Render(fmt.Sprintf("WebSocket Frames (%d)", len(m.frames))))
	b.WriteString("\n\n")
	b.WriteString(m.framesTable.View())
	b.WriteString(ui.DimStyle.Render("\nj/k navigate | enter detail | f back | q quit"))
	return b.String()
}

func (m model) viewFrameDetail() string {
	var b strings.Builder

	idx := m.framesTable.Cursor()
	if idx < 0 || idx >= len(m.frames) {
		b.WriteString(ui.DimStyle.Render("No frame selected."))
		b.WriteString(ui.DimStyle.Render("\n\nesc back | q quit"))
		return b.String()
	}

	f := m.frames[idx]

	b.WriteString(ui.HeaderStyle.Render(fmt.Sprintf("Frame #%d", idx+1)))
	b.WriteString("\n\n")

	labels := []string{"Dir", "Type", "Time", "Size"}
	values := []string{
		f.Dir,
		f.Type,
		f.Time.Format("15:04:05.000"),
		fmt.Sprintf("%d bytes", len(f.Raw)),
	}

	for i, label := range labels {
		b.WriteString(fmt.Sprintf("  %s  %s\n", ui.HeaderStyle.Render(fmt.Sprintf("%-6s", label)), values[i]))
	}

	// Pretty-print JSON payload
	b.WriteString(fmt.Sprintf("\n  %s\n", ui.HeaderStyle.Render("Payload")))
	var pretty json.RawMessage
	if err := json.Unmarshal([]byte(f.Raw), &pretty); err == nil {
		indented, err := json.MarshalIndent(pretty, "  ", "  ")
		if err == nil {
			b.WriteString("  ")
			b.WriteString(string(indented))
		} else {
			b.WriteString("  ")
			b.WriteString(f.Raw)
		}
	} else {
		b.WriteString("  ")
		b.WriteString(f.Raw)
	}
	b.WriteString("\n")

	b.WriteString(ui.DimStyle.Render("\nesc back | q quit"))
	return b.String()
}
