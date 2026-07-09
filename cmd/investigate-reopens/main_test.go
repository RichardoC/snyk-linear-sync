package main

import (
	"testing"
	"time"

	"github.com/RichardoC/snyk-linear-sync/internal/config"
	linearclient "github.com/RichardoC/snyk-linear-sync/internal/linear"
)

func TestDetectReopensFlagsTerminalToNonTerminal(t *testing.T) {
	iss := linearclient.IssueWithHistory{
		ID:          "uuid-1",
		Identifier:  "SNYK-6582",
		Title:       "Snyk: [low] path traversal",
		StateName:   "In Progress",
		Description: "<!-- snyk-linear-sync fingerprint: snyk:proj:issue-1 -->",
		History: []linearclient.HistoryEntry{
			{CreatedAt: parseTime("2026-01-10T00:00:00Z"), FromStateType: "backlog", ToStateType: "started"},                             // open→open: ignored
			{CreatedAt: parseTime("2026-02-01T00:00:00Z"), FromStateType: "started", ToStateType: "completed"},                           // close: ignored
			{CreatedAt: parseTime("2026-06-01T00:00:00Z"), FromStateType: "completed", ToStateType: "started", UpdatedDescription: true}, // REOPEN
			{CreatedAt: parseTime("2026-06-05T00:00:00Z"), FromStateType: "started", ToStateType: "completed"},                           // close again: ignored
		},
	}

	terminalNames := terminalStateNames(config.StateConfig{Done: "Done", Cancelled: "Canceled"})
	events := detectReopensFromHistory(iss, 0, terminalNames)

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
	if e.Fingerprint != "snyk:proj:issue-1" {
		t.Errorf("Fingerprint = %q, want snyk:proj:issue-1", e.Fingerprint)
	}
}

func TestDetectReopensIgnoresOpenToTerminalAndSameType(t *testing.T) {
	iss := linearclient.IssueWithHistory{Identifier: "SNYK-1", StateName: "Done"}
	history := []linearclient.HistoryEntry{
		{CreatedAt: parseTime("2026-01-01T00:00:00Z"), FromStateType: "completed", ToStateType: "canceled"}, // terminal→terminal: ignored
		{CreatedAt: parseTime("2026-01-02T00:00:00Z"), FromStateType: "backlog", ToStateType: "started"},    // open→open: ignored
	}
	iss.History = history
	events := detectReopensFromHistory(iss, 0, terminalStateNames(config.StateConfig{Done: "Done"}))
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0: %+v", len(events), events)
	}
}

func TestDetectReopensRespectsSinceCutoff(t *testing.T) {
	iss := linearclient.IssueWithHistory{Identifier: "SNYK-2", StateName: "Backlog"}
	iss.History = []linearclient.HistoryEntry{
		{CreatedAt: time.Now().Add(-48 * time.Hour), FromStateType: "completed", ToStateType: "backlog"},
		{CreatedAt: time.Now().Add(-200 * time.Hour), FromStateType: "completed", ToStateType: "backlog"},
	}
	// since = 72h: only the 48h-old reopen should be reported.
	events := detectReopensFromHistory(iss, 72*time.Hour, terminalStateNames(config.StateConfig{Done: "Done"}))
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
}

func TestExtractFingerprint(t *testing.T) {
	tests := []struct {
		name string
		desc string
		want string
	}{
		{"present", "<!-- snyk-linear-sync\nfingerprint: snyk:proj:issue-1:file.py\n-->", "snyk:proj:issue-1:file.py"},
		{"inline", "blah fingerprint: snyk:proj:issue-2 blah", "snyk:proj:issue-2"},
		{"missing", "no fingerprint here", ""},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractFingerprint(tc.desc)
			if got != tc.want {
				t.Errorf("extractFingerprint(%q) = %q, want %q", tc.desc, got, tc.want)
			}
		})
	}
}

func parseTime(s string) time.Time {
	out, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return out
}
