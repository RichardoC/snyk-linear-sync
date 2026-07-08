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
//	investigate-reopens [--env-file FILE] [--json] [--since 720h] [--workers N]
//
// It uses the same configuration/env vars as snyk-linear-sync (LINEAR_API_KEY,
// LINEAR_TEAM_ID, etc.). It only reads from Linear; it never mutates.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RichardoC/snyk-linear-sync/internal/config"
	linearclient "github.com/RichardoC/snyk-linear-sync/internal/linear"
	"github.com/RichardoC/snyk-linear-sync/internal/logx"
	"github.com/RichardoC/snyk-linear-sync/internal/model"
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
		envFile = flag.String("env-file", "", "load configuration from a dotenv-style file before reading the process environment")
		jsonOut = flag.Bool("json", false, "emit JSON instead of human-readable text")
		since   = flag.Duration("since", 0, "only report reopens within this duration from now (e.g. 720h = last 30 days; 0 = no limit)")
		workers       = flag.Int("workers", 4, "number of concurrent Linear history fetches")
		includeClosed = flag.Bool("include-closed", false, "also fetch history for currently-closed tickets (reopened-then-closed-again case). Default: only scan currently-open tickets, which is where the bug's damage is visible.")
	)
	flag.Parse()

	// --since drives both the server-side updatedAt filter (which issues we
	// even download) and the client-side reopen-event cutoff. A reopen is an
	// update, so any ticket reopened within the window has updatedAt within
	// the window. Default 30d keeps the candidate set small enough to stay
	// under Linear's hourly rate limit; widen it (e.g. 720h, 2160h) to look
	// further back. Pass 0 to scan the full snapshot (slow, rate-limited).
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
	linear := linearclient.New(cfg.Linear, *workers, logger.With("service", "linear"))

	ctx := context.Background()
	fmt.Fprintf(os.Stderr, "loading Snyk-managed Linear issues for team %s updated since %s (%.0f days)\n", cfg.Linear.TeamID, sinceCutoff.Format("2006-01-02"), -sinceCutoff.Sub(time.Now()).Hours()/24)
	issues, err := linear.LoadSnapshotUpdatedSince(ctx, sinceCutoff)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load Linear snapshot: %v\n", err)
		os.Exit(1)
	}
	// Narrow to the candidate set. An affected ticket that is still sitting
	// open (the actionable case, e.g. SNYK-6582) is currently non-terminal.
	// Tickets currently closed were either never reopened or reopened-then-
	// closed-again; the latter is rare and far less actionable, so by default
	// we skip them and avoid ~80% of the history calls that trigger Linear's
	// rate limiting.
	candidates := issues
	if !*includeClosed {
		filtered := issues[:0]
		for _, iss := range issues {
			if !isTerminalStateName(iss.StateName, terminalStateNames) {
				filtered = append(filtered, iss)
			}
		}
		candidates = filtered
		fmt.Fprintf(os.Stderr, "narrowed to %d currently-open tickets (use --include-closed to scan all %d)\n", len(candidates), len(issues))
	}

	fmt.Fprintf(os.Stderr, "fetching history with %d workers...\n", *workers)

	var (
		mu       sync.Mutex
		reopens  []ReopenEvent
		done     int64
		errCount int64
	)

	sem := make(chan struct{}, *workers)
	var wg sync.WaitGroup
	for _, iss := range candidates {
		wg.Add(1)
		go func(iss model.ExistingIssue) {
			defer wg.Done()
			// Acquire the semaphore before doing any work so we don't spawn
			// thousands of idle goroutines for large candidate sets.
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

				history, hErr := linear.LoadIssueHistory(ctx, iss.ID)
				n := atomic.AddInt64(&done, 1)
				if hErr != nil {
					atomic.AddInt64(&errCount, 1)
					if n%200 == 0 || n <= 3 {
						fmt.Fprintf(os.Stderr, "[%d/%d] %d errors | warn: history for %s: %v\n", n, len(candidates), atomic.LoadInt64(&errCount), iss.Identifier, hErr)
					}
					return
				}

				events := detectReopens(iss, history, *since, terminalStateNames)
				if n%200 == 0 {
					fmt.Fprintf(os.Stderr, "[%d/%d] %d errors | scanned %s\n", n, len(candidates), atomic.LoadInt64(&errCount), iss.Identifier)
				}
				if len(events) == 0 {
					return
				}
				mu.Lock()
				reopens = append(reopens, events...)
				mu.Unlock()
			}(iss)
	}
	wg.Wait()
	fmt.Fprintf(os.Stderr, "scan complete: %d candidates scanned, %d history errors, %d reopen events\n", len(candidates), atomic.LoadInt64(&errCount), len(reopens))

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

// detectReopens walks an issue's history (oldest-first as Linear returns it)
// and records every terminal→non-terminal state transition.
func detectReopens(iss model.ExistingIssue, history []linearclient.HistoryEntry, since time.Duration, terminalNames map[string]struct{}) []ReopenEvent {
	var out []ReopenEvent
	cutoff := time.Time{}
	if since > 0 {
		cutoff = time.Now().Add(-since)
	}
	for _, h := range history {
		if !isTerminalStateType(h.FromStateType) || isTerminalStateType(h.ToStateType) {
			continue
		}
		if h.ToStateType == "" {
			continue // not a state-transition entry
		}
		if !cutoff.IsZero() && h.CreatedAt.Before(cutoff) {
			continue
		}
		out = append(out, ReopenEvent{
			Identifier:             iss.Identifier,
			URL:                    iss.URL,
			Title:                  iss.Title,
			Fingerprint:            iss.Fingerprint,
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

func terminalStateNames(states config.StateConfig) map[string]struct{} {
	out := map[string]struct{}{}
	for _, n := range []string{states.Done, states.Cancelled} {
		if n = strings.TrimSpace(n); n != "" {
			out[n] = struct{}{}
		}
	}
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
	fmt.Printf("Found %d reopen event(s):\n\n", len(reopens))
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
