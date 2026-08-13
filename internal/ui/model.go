package ui

import (
	"context"
	"errors"
	"io"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

const (
	defaultRefreshInterval = 2 * time.Second
	statusRequestTimeout   = 10 * time.Second
)

var ErrInvalidModelOptions = errors.New("ui: invalid model options")

type ConnectionState string

const (
	ConnectionLoading     ConnectionState = "loading"
	ConnectionLive        ConnectionState = "live"
	ConnectionStale       ConnectionState = "stale"
	ConnectionUnavailable ConnectionState = "unavailable"
)

// SnapshotSource is the operator client boundary consumed by the TUI.
type SnapshotSource interface {
	Status(context.Context) (Snapshot, error)
}

type ModelOptions struct {
	Context         context.Context
	Source          SnapshotSource
	Clock           func() time.Time
	RefreshInterval time.Duration
}

// Model is the minimum Phase 2 status TUI.
type Model struct {
	ctx             context.Context
	source          SnapshotSource
	clock           func() time.Time
	refreshInterval time.Duration

	snapshot    Snapshot
	hasSnapshot bool
	connection  ConnectionState
	lastGoodAt  time.Time
	refreshing  bool
	width       int
	height      int
}

func NewModel(options ModelOptions) (Model, error) {
	if options.Context == nil || options.Source == nil {
		return Model{}, ErrInvalidModelOptions
	}
	if options.RefreshInterval < 0 {
		return Model{}, ErrInvalidModelOptions
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	refreshInterval := options.RefreshInterval
	if refreshInterval == 0 {
		refreshInterval = defaultRefreshInterval
	}
	return Model{
		ctx:             options.Context,
		source:          options.Source,
		clock:           clock,
		refreshInterval: refreshInterval,
		connection:      ConnectionLoading,
		refreshing:      true,
	}, nil
}

func (model Model) Init() tea.Cmd {
	return model.loadStatus()
}

func (model Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.KeyMsg:
		if message.Type == tea.KeyCtrlC ||
			message.Type == tea.KeyEsc ||
			message.String() == "q" {
			return model, tea.Quit
		}
	case tea.WindowSizeMsg:
		model.width = message.Width
		model.height = message.Height
		return model, nil
	case statusResultMsg:
		model.refreshing = false
		if message.err == nil {
			if err := message.snapshot.Validate(); err == nil {
				model.snapshot = message.snapshot
				model.hasSnapshot = true
				model.connection = ConnectionLive
				model.lastGoodAt = model.clock()
			} else {
				message.err = err
			}
		}
		if message.err != nil {
			if model.hasSnapshot {
				model.connection = ConnectionStale
			} else {
				model.connection = ConnectionUnavailable
			}
		}
		return model, model.scheduleRefresh()
	case refreshStatusMsg:
		if model.refreshing {
			return model, nil
		}
		model.refreshing = true
		return model, model.loadStatus()
	}
	return model, nil
}

type statusResultMsg struct {
	snapshot Snapshot
	err      error
}

type refreshStatusMsg struct{}

func (model Model) loadStatus() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(
			model.ctx,
			statusRequestTimeout,
		)
		defer cancel()
		snapshot, err := model.source.Status(ctx)
		return statusResultMsg{
			snapshot: snapshot,
			err:      err,
		}
	}
}

func (model Model) scheduleRefresh() tea.Cmd {
	return tea.Tick(model.refreshInterval, func(time.Time) tea.Msg {
		return refreshStatusMsg{}
	})
}

// Run starts the full-screen minimum status TUI.
func Run(
	ctx context.Context,
	source SnapshotSource,
	input io.Reader,
	output io.Writer,
) error {
	if ctx == nil || source == nil || input == nil || output == nil {
		return ErrInvalidModelOptions
	}
	model, err := NewModel(ModelOptions{
		Context: ctx,
		Source:  source,
	})
	if err != nil {
		return err
	}
	_, err = tea.NewProgram(
		model,
		tea.WithContext(ctx),
		tea.WithInput(input),
		tea.WithOutput(output),
		tea.WithAltScreen(),
	).Run()
	return err
}
