package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func TestModelRetainsLastGoodStatusAsExplicitlyStale(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	model, err := NewModel(ModelOptions{
		Context: context.Background(),
		Source: snapshotSourceFunc(func(context.Context) (Snapshot, error) {
			return Snapshot{}, errors.New("not called directly")
		}),
		Clock:           func() time.Time { return now },
		RefreshInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("NewModel(): %v", err)
	}
	model.width = 80
	model.height = 24
	updated, command := model.Update(statusResultMsg{
		snapshot: snapshotFromCoordination(uiTestStatusSnapshot(t)),
	})
	live := updated.(Model)
	if live.connection != ConnectionLive ||
		!live.hasSnapshot ||
		command == nil {
		t.Fatalf("live model = %#v, command nil = %t", live, command == nil)
	}

	now = now.Add(65 * time.Second)
	updated, command = live.Update(statusResultMsg{
		err: errors.New("daemon unavailable"),
	})
	stale := updated.(Model)
	if stale.connection != ConnectionStale ||
		!stale.hasSnapshot ||
		stale.snapshot.TaskTotal != live.snapshot.TaskTotal ||
		command == nil ||
		!strings.Contains(stale.View(), "[STALE 1m05s]") {
		t.Fatalf("stale model = %#v\n%s", stale, stale.View())
	}

	empty, err := NewModel(ModelOptions{
		Context: context.Background(),
		Source: snapshotSourceFunc(func(context.Context) (Snapshot, error) {
			return Snapshot{}, errors.New("unavailable")
		}),
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, _ = empty.Update(statusResultMsg{err: errors.New("unavailable")})
	unavailable := updated.(Model)
	if unavailable.connection != ConnectionUnavailable ||
		unavailable.hasSnapshot ||
		!strings.Contains(unavailable.View(), "[UNAVAILABLE]") {
		t.Fatalf("unavailable model = %#v\n%s", unavailable, unavailable.View())
	}
}

func TestModelViewFitsTerminalAndSanitizesUntrustedText(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	snapshot := snapshotFromCoordination(uiTestStatusSnapshot(t))
	for _, width := range []int{40, 80, 120} {
		t.Run(fmt.Sprintf("%d_columns", width), func(t *testing.T) {
			model := Model{
				snapshot:    snapshot,
				hasSnapshot: true,
				connection:  ConnectionLive,
				lastGoodAt:  time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC),
				clock:       func() time.Time { return time.Date(2026, 8, 12, 12, 0, 1, 0, time.UTC) },
				width:       width,
				height:      24,
			}
			view := model.View()
			golden, err := os.ReadFile(filepath.Join(
				"testdata",
				fmt.Sprintf("status_%d.golden", width),
			))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if view != string(golden) {
				t.Fatalf("view differs from golden:\n%s", view)
			}
			if strings.ContainsAny(view, "\x1b\x07") {
				t.Fatalf("view retained terminal control sequence:\n%q", view)
			}
			if !strings.Contains(view, "DEGRADED: 1 voter") ||
				!strings.Contains(view, "no voter loss") ||
				!strings.Contains(view, "tolerated") {
				t.Fatalf("view omitted one-voter warning:\n%s", view)
			}
			lines := strings.Split(strings.TrimSuffix(view, "\n"), "\n")
			if len(lines) > model.height {
				t.Fatalf("view has %d lines, height %d", len(lines), model.height)
			}
			for index, line := range lines {
				if got := ansi.StringWidth(line); got > width {
					t.Fatalf(
						"line %d width = %d, want <= %d: %q",
						index,
						got,
						width,
						line,
					)
				}
			}
		})
	}
}

func TestAbbreviateIDsExtendsCollidingPrefixes(t *testing.T) {
	values := []string{
		"018f47de-89ab-7def-8123-111111111111",
		"018f47de-89ab-7def-8123-222222222222",
		"018f47df-89ab-7def-8123-333333333333",
	}
	got := abbreviateIDs(values, 8, 20)
	if len(got) != len(values) {
		t.Fatalf("abbreviations = %#v", got)
	}
	seen := make(map[string]struct{}, len(got))
	for _, value := range values {
		short := got[value]
		if len(short) < 8 || len(short) > 20 {
			t.Fatalf("abbreviation %q has invalid length", short)
		}
		if _, duplicate := seen[short]; duplicate {
			t.Fatalf("duplicate abbreviation %q in %#v", short, got)
		}
		seen[short] = struct{}{}
	}
}

func TestModelRefreshQuitAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sourceCalls := 0
	model, err := NewModel(ModelOptions{
		Context: ctx,
		Source: snapshotSourceFunc(func(ctx context.Context) (Snapshot, error) {
			sourceCalls++
			return Snapshot{}, ctx.Err()
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	message := model.Init()()
	result, ok := message.(statusResultMsg)
	if !ok || !errors.Is(result.err, context.Canceled) || sourceCalls != 1 {
		t.Fatalf("Init() message = %#v, source calls = %d", message, sourceCalls)
	}

	updated, _ := model.Update(result)
	updated, command := updated.(Model).Update(refreshStatusMsg{})
	refreshing := updated.(Model)
	if !refreshing.refreshing || command == nil {
		t.Fatalf("refresh update = %#v, command nil = %t", refreshing, command == nil)
	}
	_, command = refreshing.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if command == nil {
		t.Fatal("Ctrl-C did not return a quit command")
	}
	if _, ok := command().(tea.QuitMsg); !ok {
		t.Fatalf("quit command message = %T", command())
	}
}

func TestRunExitsCleanlyOnQuitInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var output bytes.Buffer
	err := Run(
		ctx,
		snapshotSourceFunc(func(context.Context) (Snapshot, error) {
			return snapshotFromCoordination(uiTestStatusSnapshot(t)), nil
		}),
		strings.NewReader("q"),
		&output,
	)
	if err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

type snapshotSourceFunc func(context.Context) (Snapshot, error)

func (function snapshotSourceFunc) Status(
	ctx context.Context,
) (Snapshot, error) {
	return function(ctx)
}
