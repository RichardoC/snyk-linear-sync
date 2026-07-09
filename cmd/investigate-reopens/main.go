// Command investigate-reopens scans Snyk-managed Linear issues for tickets
// that were moved from a terminal state (Done/Cancelled) back to a
// non-terminal state (Backlog/Triage/Started/...). Such a terminal→non-terminal
// transition is the signature of the reopen bug described in
// REOPEN_INVESTIGATION.md: when Snyk re-reports an issue ID that matches an
// already-closed ticket's fingerprint, the sync reopens the closed ticket
// instead of creating a new one.
//
// Usage:
//
//	investigate-reopens [--env-file FILE] [--json] [--since 720h]
//
// It uses the same configuration/env vars as snyk-linear-sync (LINEAR_API_KEY,
// LINEAR_TEAM_ID, etc.). It only reads from Linear; it never mutates.
//
// Optimization: history is fetched INLINE with the issues query (one paginated
// pass), not per-ticket. This eliminates the thousands of per-ticket history
// API calls that made the original approach impractical at scale.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/RichardoC/snyk-linear-sync/internal/config"
	linearclient "github.com/RichardoC/snyk-linear-sync/internal/linear"
	"github.com/RichardoC/snyk-linear-sync/internal/logx"
)

// Linear WorkflowState.Type values. Terminal states are completed/canceled;
// everything else is non-terminal. We classify by Linear's own state type
// rather than the sync's configured state names so detection is robust even
// if the config doesn't list every team state.
func isTerminalStateType(t string) bool {
	t = strings.ToLower(strings.TrimSpace(t))
	return t == "completed" || t == "canceled"
}

// ReopenEvent is one terminal→non-terminal transition found in a ticket's
// history. A ticket can appear more than once if it was reopened repeatedly.
type ReopenEvent struct {
	Identifier    string    `json:"identifier"`
	URL           string    `json:"url"`
	Title         string    `json:"title"`
	Fingerprint   string    `json:"fingerprint"`
	CurrentState  string    `json:"current_state"`
	CurrentOpen   bool      `json:"current_open"`
	ReopenedAt    time.Time `json:"reopened_at"`
	Actor         string    `json:"actor"`
	FromStateName string    `json:"from_state"`
	ToStateName   string    `json:"to_state"`
	// SyncRewroteDescription is true when the reopen entry also rewrote the
	// description — the fingerprint of a snyk-linear-sync update (it rewrites
	// the description on every update batch), as opposed to a manual human
	// drag back to an open column.
	SyncRewroteDescription bool `json:"sync_rewrote_description"`
}

func main() {
	var (
		envFile       = flag.String("env-file", "", "load configuration from a dotenv-style file before reading the process environment")
		jsonOut       = flag.Bool("json", false, "emit JSON instead of human-readable text")
		since         = flag.Duration("since", 0, "only report reopens within this duration from now (e.g. 720h = last 30 days; 0 = no limit)")
		includeClosed = flag.Bool("include-closed", false, "also report reopens on currently-closed tickets (reopened-then-closed-again case). Default: only report currently-open tickets, which is where the bug's damage is visible.")
	)
	flag.Parse()

	// --since drives the server-side updatedAt filter (which issues we even
	// download) and the client-side reopen-event cutoff. A reopen is an
	// update, so any ticket reopened within the window has updatedAt within
	// the window. Default 30d keeps the candidate set small; widen it (e.g.
	// 2160h = 90d, 0 = all time) to look further back.
	if *since == 0 {
		*since = 30 * 24 * time.Hour
	}
	sinceCutoff := time.Now().Add(-*since)

	args := []string(nil)
	if strings.TrimSpace(*envFile) != "" {
		args = append(args, "--env-file", strings.TrimSpace(*envFile))
	}
	cfg, err := config.Load(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load config: %v\n", err)
		os.Exit(1)
	}

	terminalStateNames := terminalStateNames(cfg.Linear.States)

	logger := slog.New(logx.NewMultiHandler(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}),
	))
	linear := linearclient.New(cfg.Linear, 4, logger.With("service", "linear"))

	ctx := context.Background()
	fmt.Fprintf(os.Stderr, "loading Snyk-managed Linear issues for team %s updated since %s (%.0f days)\n",
		cfg.Linear.TeamID, sinceCutoff.Format("2006-01-02"), -sinceCutoff.Sub(time.Now()).Hours()/24)
	fmt.Fprintf(os.Stderr, "fetching issues with inline history (optimized: single paginated pass)...\n")

	issues, err := linear.LoadSnapshotWithHistorySince(ctx, sinceCutoff)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load Linear snapshot+history: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "loaded %d issues with history\n", len(issues))

	// Detect reopens from the inlined history — no per-ticket API calls.
	var reopens []ReopenEvent
	openCount, closedCount := 0, 0
	for _, iss := range issues {
		isOpen := !isTerminalStateName(iss.StateName, terminalStateNames)
		if isOpen {
			openCount++
		} else {
			closedCount++
		}
		events := detectReopensFromHistory(iss, *since, terminalStateNames)
		if len(events) == 0 {
			continue
		}
		// By default, only report currently-open tickets (the actionable
		// case). --include-closed also reports reopened-then-closed-again.
		if !*includeClosed && !isOpen {
			continue
		}
		reopens = append(reopens, events...)
	}

	fmt.Fprintf(os.Stderr, "scan complete: %d open / %d closed issues, %d reopen events (%d currently-open affected)\n",
		openCount, closedCount, len(reopens), countOpenReopens(reopens, terminalStateNames))

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reopens); err != nil {
			fmt.Fprintf(os.Stderr, "error: encode json: %v\n", err)
			os.Exit(1)
		}
		return
	}

	printHuman(reopens)
}

// detectReopensFromHistory walks an issue's history (oldest-first as Linear
// returns it) and records every terminal→non-terminal state transition.
func detectReopensFromHistory(iss linearclient.IssueWithHistory, since time.Duration, terminalNames map[string]struct{}) []ReopenEvent {
	var out []ReopenEvent
	cutoff := time.Time{}
	if since > 0 {
		cutoff = time.Now().Add(-since)
	}
	for _, h := range iss.History {
		if !isTerminalStateType(h.FromStateType) || isTerminalStateType(h.ToStateType) {
			continue
		}
		if h.ToStateType == "" {
			continue // not a state-transition entry
		}
		if !cutoff.IsZero() && h.CreatedAt.Before(cutoff) {
			continue
		}
		fp := extractFingerprint(iss.Description)
		out = append(out, ReopenEvent{
			Identifier:             iss.Identifier,
			URL:                    iss.URL,
			Title:                  iss.Title,
			Fingerprint:            fp,
			CurrentState:           iss.StateName,
			CurrentOpen:            !isTerminalStateName(iss.StateName, terminalNames),
			ReopenedAt:             h.CreatedAt,
			Actor:                  h.ActorName,
			FromStateName:          h.FromStateName,
			ToStateName:            h.ToStateName,
			SyncRewroteDescription: h.UpdatedDescription,
		})
	}
	return out
}

// extractFingerprint pulls the snyk-linear-sync fingerprint from a Linear
// issue description. The fingerprint is embedded in the metadata block:
// <!-- snyk-linear-sync ... fingerprint: snyk:proj:issue:loc ... -->
func extractFingerprint(description string) string {
	const marker = "fingerprint:"
	_, after, ok := strings.Cut(description, marker)
	if !ok {
		return ""
	}
	rest := strings.TrimSpace(after)
	end := strings.IndexAny(rest, "\n\r\t ]")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func countOpenReopens(reopens []ReopenEvent, terminalNames map[string]struct{}) int {
	seen := map[string]bool{}
	for _, r := range reopens {
		if r.CurrentOpen {
			seen[r.Identifier] = true
		}
	}
	return len(seen)
}

func terminalStateNames(states config.StateConfig) map[string]struct{} {
	out := map[string]struct{}{}
	for _, n := range []string{states.Done, states.Cancelled} {
		if n = strings.TrimSpace(n); n != "" {
			out[n] = struct{}{}
			// Also add common spelling variants — Linear uses "Canceled"
			// (American, one l) while many configs use "Cancelled" (British,
			// two l's). Without this, tickets in the Canceled state are
			// misclassified as currently open.
			if strings.EqualFold(n, "Cancelled") {
				out["Canceled"] = struct{}{}
			}
			if strings.EqualFold(n, "Canceled") {
				out["Cancelled"] = struct{}{}
			}
		}
	}
	// Always include Linear's canonical terminal state names.
	out["Canceled"] = struct{}{}
	out["Done"] = struct{}{}
	return out
}

func isTerminalStateName(name string, terminalNames map[string]struct{}) bool {
	_, ok := terminalNames[strings.TrimSpace(name)]
	return ok
}

func printHuman(reopens []ReopenEvent) {
	if len(reopens) == 0 {
		fmt.Println("No terminal→non-terminal reopens found among Snyk-managed tickets.")
		return
	}
	// Count unique affected tickets.
	unique := map[string]bool{}
	for _, r := range reopens {
		unique[r.Identifier] = true
	}
	fmt.Printf("Found %d reopen event(s) across %d unique ticket(s):\n\n", len(reopens), len(unique))
	for _, r := range reopens {
		fmt.Printf("  %s  %s\n", r.Identifier, r.Title)
		fmt.Printf("    url:         %s\n", r.URL)
		fmt.Printf("    fingerprint: %s\n", r.Fingerprint)
		fmt.Printf("    reopened:    %s   %s -> %s\n", r.ReopenedAt.Format("2006-01-02 15:04:05"), r.FromStateName, r.ToStateName)
		if r.Actor != "" {
			fmt.Printf("    actor:       %s\n", r.Actor)
		}
		fmt.Printf("    now:         %s (%s)\n", r.CurrentState, openClosed(r.CurrentOpen))
		if r.SyncRewroteDescription {
			fmt.Printf("    note:        description rewritten in same history entry (likely snyk-linear-sync reopen)\n")
		}
		fmt.Println()
	}
}

func openClosed(open bool) string {
	if open {
		return "currently open"
	}
	return "currently closed"
}
