// Command remediate-reopens closes Linear tickets that were reopened by the
// snyk-linear-sync zombie-ticket bug. It reads a list of ticket identifiers
// (one per line) from a file or stdin, fetches each ticket, and transitions
// it to Cancelled.
//
// This is Phase 1 of the cleanup: after closing the contaminated tickets,
// the fixed sync (Phase 2) creates fresh tickets with fine-grained
// fingerprints for any still-current Snyk findings.
//
// Usage:
//
//	remediate-reopens --env-file .env --from-file REMEDIATION_TARGETS.md [--dry-run] [--batch-size 50]
//
// The input file format is flexible: any line containing a SNYK-NNNNN
// identifier is parsed. This allows feeding REMEDIATION_TARGETS.md directly.
//
// --dry-run lists what would be closed without making any API calls.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/RichardoC/snyk-linear-sync/internal/config"
	linearclient "github.com/RichardoC/snyk-linear-sync/internal/linear"
	"github.com/RichardoC/snyk-linear-sync/internal/logx"
	"github.com/RichardoC/snyk-linear-sync/internal/model"
)

var identifierRe = regexp.MustCompile(`SNYK-\d+`)

func main() {
	var (
		envFile   = flag.String("env-file", "", "load configuration from a dotenv-style file before reading the process environment")
		fromFile  = flag.String("from-file", "", "read ticket identifiers from this file (use - for stdin)")
		dryRun    = flag.Bool("dry-run", false, "list what would be closed without mutating Linear")
		batchSize = flag.Int("batch-size", 50, "number of issues to update per Linear API call")
	)
	flag.Parse()

	if *fromFile == "" {
		fmt.Fprintln(os.Stderr, "error: --from-file is required (use - for stdin)")
		os.Exit(1)
	}

	// Load identifiers.
	identifiers, err := loadIdentifiers(*fromFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load identifiers: %v\n", err)
		os.Exit(1)
	}
	if len(identifiers) == 0 {
		fmt.Fprintln(os.Stderr, "no ticket identifiers found")
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "loaded %d ticket identifiers\n", len(identifiers))

	// Load config.
	args := []string(nil)
	if strings.TrimSpace(*envFile) != "" {
		args = append(args, "--env-file", strings.TrimSpace(*envFile))
	}
	cfg, err := config.Load(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load config: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(logx.NewMultiHandler(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}),
	))
	linear := linearclient.New(cfg.Linear, 4, logger.With("service", "linear"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if *dryRun {
		fmt.Fprintf(os.Stderr, "DRY RUN — no changes will be made\n\n")
		for _, id := range identifiers {
			fmt.Printf("would close %s -> %s\n", id, cfg.Linear.States.Cancelled)
		}
		fmt.Fprintf(os.Stderr, "\nTotal: %d tickets would be closed\n", len(identifiers))
		return
	}

	// Fetch each issue and build update batches.
	var updates []model.IssueUpdate
	failed := 0
	for i, id := range identifiers {
		issue, err := linear.LoadIssueByIdentifier(ctx, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: fetch %s: %v\n", id, err)
			failed++
			continue
		}
		// Skip if already terminal.
		if issue.StateName == cfg.Linear.States.Done || issue.StateName == cfg.Linear.States.Cancelled {
			fmt.Fprintf(os.Stderr, "skip %s — already %s\n", id, issue.StateName)
			continue
		}
		updates = append(updates, model.IssueUpdate{
			Existing: issue,
			Desired: model.DesiredIssue{
				Fingerprint:   issue.Fingerprint,
				Title:         issue.Title,
				Description:   issue.Description,
				State:         model.StateCancelled,
				PreserveState: false,
				ManagedLabels: issue.ManagedLabels,
				Priority:      issue.Priority,
			},
		})
		if (i+1)%100 == 0 {
			fmt.Fprintf(os.Stderr, "fetched %d/%d...\n", i+1, len(identifiers))
		}
	}
	fmt.Fprintf(os.Stderr, "fetched %d issues (%d skipped as already terminal, %d failed)\n",
		len(updates), len(identifiers)-len(updates)-failed, failed)

	if len(updates) == 0 {
		fmt.Fprintln(os.Stderr, "no non-terminal tickets to close")
		return
	}

	// Send update batches.
	closed := 0
	for i := 0; i < len(updates); i += *batchSize {
		end := i + *batchSize
		if end > len(updates) {
			end = len(updates)
		}
		batch := updates[i:end]
		if err := linear.UpdateIssues(ctx, batch); err != nil {
			fmt.Fprintf(os.Stderr, "error: close batch %d-%d: %v\n", i, end, err)
			// Retry individually on batch failure.
			for _, u := range batch {
				if err := linear.UpdateIssues(ctx, []model.IssueUpdate{u}); err != nil {
					fmt.Fprintf(os.Stderr, "error: close %s: %v\n", u.Existing.Identifier, err)
				} else {
					closed++
				}
			}
			continue
		}
		closed += len(batch)
		fmt.Fprintf(os.Stderr, "closed %d/%d...\n", closed, len(updates))
	}

	fmt.Fprintf(os.Stderr, "\nremediation complete: %d/%d tickets closed to %s\n",
		closed, len(updates), cfg.Linear.States.Cancelled)
}

// loadIdentifiers reads a file (or stdin) and extracts all SNYK-NNNNN
// identifiers, deduplicated and sorted.
func loadIdentifiers(path string) ([]string, error) {
	var r *os.File
	var err error
	if path == "-" {
		r = os.Stdin
	} else {
		r, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		defer r.Close()
	}

	seen := map[string]bool{}
	var out []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		for _, match := range identifierRe.FindAllString(scanner.Text(), -1) {
			if !seen[match] {
				seen[match] = true
				out = append(out, match)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
