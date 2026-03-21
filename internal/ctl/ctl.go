package ctl

import (
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/coder/websocket"

	"birdcage/internal/api"
	"birdcage/internal/ui"
)

// states
type state int

const (
	stateMenu state = iota
	stateInput
	stateConfirm
	stateResult
	stateSessions
	stateEvents
	stateEventDetail
	stateEventStats
	stateAgents
	stateNodes
	stateTailEvents
	stateFrameInspector
	stateFrameDetail
)

type action int

const (
	// Sessions
	actionViewSessions action = iota
	actionRevokeAll
	actionRevokeSession
	// Events
	actionViewEvents
	actionViewEventStats
	actionTailEvents
	// Nodes
	actionViewNodes
	// Agents
	actionListAgents
	actionProvisionAgent
	actionRevokeAgent
)

type wsFrame struct {
	Dir  string // ">" send, "<" recv
	Type string
	Raw  string
	Time time.Time
}

type menuItem struct {
	label    string
	action   action
	isHeader bool
}

var menuItems = []menuItem{
	{label: "SESSIONS", isHeader: true},
	{label: "View active sessions", action: actionViewSessions},
	{label: "Revoke all sessions", action: actionRevokeAll},
	{label: "Revoke specific session", action: actionRevokeSession},

	{label: "EVENTS", isHeader: true},
	{label: "View recent events", action: actionViewEvents},
	{label: "View event stats", action: actionViewEventStats},
	{label: "Tail events (live)", action: actionTailEvents},

	{label: "NODES", isHeader: true},
	{label: "View all nodes", action: actionViewNodes},

	{label: "AGENTS", isHeader: true},
	{label: "List agents", action: actionListAgents},
	{label: "Provision agent", action: actionProvisionAgent},
	{label: "Revoke agent", action: actionRevokeAgent},
}

// messages
type resultMsg struct {
	message string
	err     error
}

type sessionsMsg struct {
	sessions []api.Session
	err      error
}

type eventsMsg struct {
	events []api.Event
	err    error
}

type eventStatsMsg struct {
	stats map[string]int
	since string
	err   error
}

type agentsMsg struct {
	agents []api.Agent
	err    error
}

type nodesMsg struct {
	nodes []api.Node
	err   error
}

type tailConnectedMsg struct {
	conn   *websocket.Conn
	err    error
	frames []wsFrame
}

type tailEventMsg struct {
	event api.Event
	frame wsFrame
}

type tailErrorMsg struct {
	err error
}

type model struct {
	client   *api.Client
	state    state
	cursor   int
	action   action
	input    ui.InputBuffer
	quitting bool

	// multi-field input
	inputField  int
	inputLabels []string
	inputs      []string
	inputHint   string

	// result state
	resultMessage string
	resultErr     error

	// data states
	sessions    []api.Session
	events      []api.Event
	eventsTable table.Model
	eventStats  map[string]int
	eventSince  string
	agents      []api.Agent
	nodeList    []api.Node
	dataErr     error

	// tail events state
	tailEvents        []api.Event
	tailFilter        []string
	tailErr           error
	tailConn          *websocket.Conn
	tailKeepaliveStop chan struct{}

	// frame inspector state
	frames      []wsFrame
	framesTable table.Model

	// terminal dimensions
	width int
}

func initialModel(client *api.Client) model {
	m := model{client: client, state: stateMenu}
	m.cursor = firstSelectableIndex()
	return m
}

func firstSelectableIndex() int {
	for i, item := range menuItems {
		if !item.isHeader {
			return i
		}
	}
	return 0
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	case resultMsg:
		m.resultMessage = msg.message
		m.resultErr = msg.err
		m.state = stateResult
		return m, nil
	case sessionsMsg:
		m.sessions = msg.sessions
		m.dataErr = msg.err
		m.state = stateSessions
		return m, nil
	case eventsMsg:
		m.events = msg.events
		m.dataErr = msg.err
		m.state = stateEvents
		if msg.err == nil && len(msg.events) > 0 {
			m.eventsTable = buildEventsTable(msg.events)
		}
		return m, nil
	case eventStatsMsg:
		m.eventStats = msg.stats
		m.eventSince = msg.since
		m.dataErr = msg.err
		m.state = stateEventStats
		return m, nil
	case agentsMsg:
		m.agents = msg.agents
		m.dataErr = msg.err
		m.state = stateAgents
		return m, nil
	case nodesMsg:
		m.nodeList = msg.nodes
		m.dataErr = msg.err
		m.state = stateNodes
		return m, nil
	case tailConnectedMsg:
		if msg.err != nil {
			m.tailErr = msg.err
			m.state = stateTailEvents
			return m, nil
		}
		m.tailConn = msg.conn
		m.frames = append(m.frames, msg.frames...)
		m.tailKeepaliveStop = make(chan struct{})
		go keepAlive(m.tailConn, m.tailKeepaliveStop)
		m.state = stateTailEvents
		return m, m.readNextEvent()
	case tailEventMsg:
		m.frames = append(m.frames, msg.frame)
		if len(m.frames) > 500 {
			m.frames = m.frames[len(m.frames)-500:]
		}
		if m.state == stateFrameInspector {
			cursor := m.framesTable.Cursor()
			m.framesTable = buildFramesTable(m.frames)
			m.framesTable.SetCursor(cursor)
		}
		if msg.event.Type != "" {
			m.tailEvents = append(m.tailEvents, msg.event)
			if len(m.tailEvents) > 100 {
				m.tailEvents = m.tailEvents[len(m.tailEvents)-100:]
			}
		}
		return m, m.readNextEvent()
	case tailErrorMsg:
		if m.tailConn == nil {
			return m, nil
		}
		m.tailErr = msg.err
		return m, nil
	}
	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	if key == "ctrl+c" {
		m.quitting = true
		return m, tea.Quit
	}

	switch m.state {
	case stateMenu:
		return m.handleMenu(key)
	case stateInput:
		return m.handleInput(key, msg)
	case stateConfirm:
		return m.handleConfirm(key)
	case stateEvents:
		return m.handleEventsView(msg)
	case stateEventDetail:
		return m.handleEventDetail(msg)
	case stateTailEvents:
		return m.handleTailView(key)
	case stateFrameInspector:
		return m.handleFrameInspector(msg)
	case stateFrameDetail:
		return m.handleFrameDetail(msg)
	case stateResult, stateSessions, stateEventStats, stateAgents, stateNodes:
		return m.handleDataView(key)
	}
	return m, nil
}

func (m model) handleMenu(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		m.cursor = m.prevSelectable(m.cursor)
	case "down", "j":
		m.cursor = m.nextSelectable(m.cursor)
	case "enter":
		item := menuItems[m.cursor]
		if item.isHeader {
			return m, nil
		}
		m.action = item.action
		return m.dispatchAction()
	case "q":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) prevSelectable(from int) int {
	for i := from - 1; i >= 0; i-- {
		if !menuItems[i].isHeader {
			return i
		}
	}
	return from
}

func (m model) nextSelectable(from int) int {
	for i := from + 1; i < len(menuItems); i++ {
		if !menuItems[i].isHeader {
			return i
		}
	}
	return from
}

func (m *model) startInput(labels []string) {
	m.state = stateInput
	m.inputField = 0
	m.inputLabels = labels
	m.inputs = make([]string, 0, len(labels))
	m.inputHint = ""
	m.input.Clear()
}

func (m model) handleInput(key string, msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key {
	case "enter":
		val := strings.TrimSpace(m.input.Value)
		optional := strings.HasSuffix(m.inputLabels[m.inputField], "(optional)")
		if val == "" && !optional {
			return m, nil
		}
		m.inputs = append(m.inputs, val)
		m.inputField++
		m.input.Clear()

		if m.inputField >= len(m.inputLabels) {
			return m.afterInputComplete()
		}
	case "backspace":
		m.input.Backspace()
	case "esc":
		m.state = stateMenu
		m.input.Clear()
	default:
		m.input.Append(msg.Runes)
	}
	return m, nil
}

func (m model) handleConfirm(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "y", "Y":
		return m, m.executeAction()
	case "n", "N", "esc":
		m.state = stateMenu
		m.input.Clear()
	}
	return m, nil
}

func (m model) handleDataView(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "enter", "esc":
		m.state = stateMenu
		m.input.Clear()
		m.dataErr = nil
	case "q":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) handleEventsView(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "enter":
		if len(m.events) > 0 && m.eventsTable.SelectedRow() != nil {
			m.state = stateEventDetail
			return m, nil
		}
		m.state = stateMenu
		m.dataErr = nil
		return m, nil
	case "esc":
		m.state = stateMenu
		m.dataErr = nil
		return m, nil
	case "q":
		m.quitting = true
		return m, tea.Quit
	}
	var cmd tea.Cmd
	m.eventsTable, cmd = m.eventsTable.Update(msg)
	return m, cmd
}

func (m model) handleEventDetail(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter":
		m.state = stateEvents
	case "q":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) handleTailView(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "f":
		if len(m.frames) > 0 {
			m.framesTable = buildFramesTable(m.frames)
			m.state = stateFrameInspector
		}
		return m, nil
	case "esc":
		m.closeTail()
		m.state = stateMenu
		m.tailEvents = nil
		m.tailErr = nil
		m.frames = nil
		return m, nil
	case "q":
		m.closeTail()
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) handleFrameInspector(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "enter":
		if len(m.frames) > 0 && m.framesTable.SelectedRow() != nil {
			m.state = stateFrameDetail
			return m, nil
		}
	case "f", "esc":
		m.state = stateTailEvents
		return m, nil
	case "q":
		m.closeTail()
		m.quitting = true
		return m, tea.Quit
	}
	var cmd tea.Cmd
	m.framesTable, cmd = m.framesTable.Update(msg)
	return m, cmd
}

func (m model) handleFrameDetail(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter":
		m.state = stateFrameInspector
	case "q":
		m.closeTail()
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}
