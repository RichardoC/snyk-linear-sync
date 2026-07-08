package main

import (
	"testing"
	"time"

	"github.com/RichardoC/snyk-linear-sync/internal/config"
	"github.com/RichardoC/snyk-linear-sync/internal/linear"
	"github.com/RichardoC/snyk-linear-sync/internal/model"
)

func TestDetectReopensFlagsTerminalToNonTerminal(t *testing.T) {
	iss := model.ExistingIssue{
		ID:          "uuid-1",
		Identifier:  "SNYK-6582",
		Title:       "Snyk: [low] path traversal",
		StateName:   "In Progress",
		Fingerprint: "snyk:proj:issue-1",
	}
	history := []linear.HistoryEntry{
		{CreatedAt: parseTime("2026-01-10T00:00:00Z"), FromStateType: "backlog", ToStateType: "started"},   // open→open: ignored
		{CreatedAt: parseTime("2026-02-01T00:00:00Z"), FromStateType: "started", ToStateType: "completed"}, // close: ignored
		{CreatedAt: parseTime("2026-06-01T00:00:00Z"), FromStateType: "completed", ToStateType: "started", UpdatedDescription: true}, // REOPEN
		{CreatedAt: parseTime("2026-06-05T00:00:00Z"), FromStateType: "started", ToStateType: "completed"}, // close again: ignored
	}

	terminalNames := terminalStateNames(config.StateConfig{Done: "Done", Cancelled: "Canceled"})
	events := detectReopens(iss, history, 0, terminalNames)

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	e := events[0]
	if e.Identifier != "SNYK-6582" {
		t.Errorf("Identifier = %q", e.Identifier)
	}
	if e.ReopenedAt != parseTime("2026-06-01T00:00:00Z") {
		t.Errorf("ReopenedAt = %v", e.ReopenedAt)
	}
	if !e.SyncRewroteDescription {
		t.Error("SyncRewroteDescription = false, want true")
	}
	if !e.CurrentOpen {
		t.Error("CurrentOpen = false, want true (In Progress is non-terminal)")
	}
}

func TestDetectReopensIgnoresOpenToTerminalAndSameType(t *testing.T) {
	iss := model.ExistingIssue{Identifier: "SNYK-1", StateName: "Done"}
	history := []linear.HistoryEntry{
		{CreatedAt: parseTime("2026-01-01T00:00:00Z"), FromStateType: "completed", ToStateType: "canceled"}, // terminal→terminal: ignored
		{CreatedAt: parseTime("2026-01-02T00:00:00Z"), FromStateType: "backlog", ToStateType: "started"},     // open→open: ignored
	}
	events := detectReopens(iss, history, 0, terminalStateNames(config.StateConfig{Done: "Done"}))
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0: %+v", len(events), events)
	}
}

func TestDetectReopensRespectsSinceCutoff(t *testing.T) {
	iss := model.ExistingIssue{Identifier: "SNYK-2", StateName: "Backlog"}
	history := []linear.HistoryEntry{
		{CreatedAt: time.Now().Add(-48 * time.Hour), FromStateType: "completed", ToStateType: "backlog"},
		{CreatedAt: time.Now().Add(-200 * time.Hour), FromStateType: "completed", ToStateType: "backlog"},
	}
	// since = 72h: only the 48h-old reopen should be reported.
	events := detectReopens(iss, history, 72*time.Hour, terminalStateNames(config.StateConfig{Done: "Done"}))
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
}

func parseTime(s string) time.Time {
	out, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return out
}
