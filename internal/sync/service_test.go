package sync

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RichardoC/snyk-linear-sync/internal/cache"
	"github.com/RichardoC/snyk-linear-sync/internal/config"
	"github.com/RichardoC/snyk-linear-sync/internal/model"
)

type fakeSnyk struct {
	snapshot model.SnykSnapshot
}

func (f fakeSnyk) LoadSnapshot(context.Context) (model.SnykSnapshot, error) {
	return f.snapshot, nil
}

type fakeLinear struct {
	snapshot []model.ExistingIssue
	created  []model.DesiredIssue
	updated  []model.DesiredIssue
	updates  []model.IssueUpdate
	comments []model.IssueUpdate
}

type fakeCache struct {
	snapshot cache.Snapshot
	saved    cache.Snapshot
}

func (f *fakeLinear) LoadSnapshot(context.Context) ([]model.ExistingIssue, error) {
	return f.snapshot, nil
}

func (f *fakeLinear) CreateIssues(_ context.Context, desired []model.DesiredIssue) error {
	f.created = append(f.created, desired...)
	return nil
}

func (f *fakeLinear) UpdateIssues(_ context.Context, updates []model.IssueUpdate) error {
	for _, update := range updates {
		f.updated = append(f.updated, update.Desired)
		f.updates = append(f.updates, update)
	}
	return nil
}

func (f *fakeLinear) PostComments(_ context.Context, updates []model.IssueUpdate) error {
	f.comments = append(f.comments, updates...)
	return nil
}

func (f *fakeCache) Load(context.Context) (cache.Snapshot, error) {
	return f.snapshot, nil
}

func (f *fakeCache) Save(_ context.Context, snapshot cache.Snapshot) error {
	f.saved = snapshot
	return nil
}

func TestRunPlansCreateUpdateAndResolve(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{
			Workers: 1,
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "Outdated package",
					PackageName: "github.com/example/pkg",
					Severity:    "high",
					Status:      model.FindingOpen,
					IssueURL:    "https://example.test/issue-1",
					CreatedAt:   time.Date(2026, time.August, 1, 14, 0, 0, 0, time.UTC),
				},
				{
					Fingerprint: "snyk:project-b:issue-2",
					SnykIssueID: "issue-2",
					ProjectID:   "project-b",
					ProjectName: "Project B",
					IssueTitle:  "Ignored issue",
					Severity:    "low",
					Status:      model.FindingIgnored,
					IssueURL:    "https://example.test/issue-2",
					CreatedAt:   time.Date(2026, time.August, 1, 9, 0, 0, 0, time.UTC),
				},
			},
			ProjectIDs: map[string]struct{}{
				"project-a": {},
				"project-b": {},
				"project-z": {},
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
			},
			{
				ID:          "existing-2",
				Identifier:  "SEC-2",
				Title:       "old resolved issue",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-z:issue-9",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)

	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedCreates != 1 {
		t.Fatalf("PlannedCreates = %d, want 1", result.PlannedCreates)
	}
	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.created) != 1 {
		t.Fatalf("created = %d, want 1", len(linear.created))
	}
	if len(linear.updated) != 2 {
		t.Fatalf("updated = %d, want 2", len(linear.updated))
	}
	if linear.created[0].DueDate != "2026-10-30" {
		t.Fatalf("created due date = %q, want %q", linear.created[0].DueDate, "2026-10-30")
	}
	if !containsDesiredState(linear.updated, model.StateDone) {
		t.Fatalf("updated states = %#v, want one %q", desiredStates(linear.updated), model.StateDone)
	}
}

func TestRunSkipsCachedUnchangedIssue(t *testing.T) {
	cfg := config.Config{
		Cache: config.CacheConfig{},
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{
			Workers: 1,
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:  "snyk:project-a:issue-1",
					SnykIssueID:  "issue-1",
					SnykIssueKey: "SNYK-ISSUE-1",
					ProjectID:    "project-a",
					ProjectName:  "Project A",
					IssueTitle:   "Outdated package",
					PackageName:  "github.com/example/pkg",
					Severity:     "high",
					Status:       model.FindingOpen,
					IssueURL:     "https://app.snyk.io/org/example/project/project-a#issue-SNYK-ISSUE-1",
					IssueAPIURL:  "https://api.snyk.io/rest/orgs/example/issues/issue-1?version=2024-10-15",
					CreatedAt:    time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
			},
			ProjectIDs: map[string]struct{}{
				"project-a": {},
			},
		},
	}
	desired := desiredIssue(cfg, snyk.snapshot.Findings[0])
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       desired.Title,
		Description: desired.Description,
		DueDate:     desired.DueDate,
		StateName:   "Todo",
		Fingerprint: desired.Fingerprint,
		Priority:    desired.Priority,
	}
	cacheStore := &fakeCache{
		snapshot: cache.Snapshot{
			SchemaSignature: managedSchemaSignature(),
			SnykHashes: map[string]string{
				desired.Fingerprint: desiredIssueHash(desired),
			},
			LinearHashes: map[string]string{
				desired.Fingerprint: existingIssueHash(existing),
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{existing},
	}

	service := New(cfg, logger, snyk, linear, cacheStore)

	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

// TestRunCancelsIgnoredFindingEvenIfCached verifies that a finding which is
// ignored in Snyk (desired state Cancelled) is moved to Cancelled even when its
// ticket was manually parked in "Todo" and the cache claims nothing changed.
// Regression test: the per-finding cache fast-path previously skipped these,
// leaving wont-fix-ignored tickets stuck open indefinitely.
func TestRunCancelsIgnoredFindingEvenIfCached(t *testing.T) {
	cfg := config.Config{
		Cache: config.CacheConfig{},
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{Workers: 1},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:  "snyk:project-a:issue-1",
					SnykIssueID:  "issue-1",
					SnykIssueKey: "SNYK-ISSUE-1",
					ProjectID:    "project-a",
					ProjectName:  "Project A",
					IssueTitle:   "Base image vulnerability",
					PackageName:  "glibc/libc6",
					Severity:     "low",
					Status:       model.FindingIgnored,
					CreatedAt:    time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	// desired.State is Cancelled (ignored); the ticket was manually moved to
	// "Todo", so its state diverges from desired.
	desired := desiredIssue(cfg, snyk.snapshot.Findings[0])
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       desired.Title,
		Description: desired.Description,
		DueDate:     desired.DueDate,
		StateName:   "Todo",
		Fingerprint: desired.Fingerprint,
		Priority:    desired.Priority,
	}
	// Cache claims the issue is unchanged since last run — the masking condition
	// that previously suppressed the cancellation.
	cacheStore := &fakeCache{
		snapshot: cache.Snapshot{
			SchemaSignature: managedSchemaSignature(),
			SnykHashes: map[string]string{
				desired.Fingerprint: desiredIssueHash(desired),
			},
			LinearHashes: map[string]string{
				desired.Fingerprint: existingIssueHash(existing),
			},
		},
	}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{existing}}

	service := New(cfg, logger, snyk, linear, cacheStore)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateCancelled {
		t.Fatalf("updated state = %q, want %q", linear.updated[0].State, model.StateCancelled)
	}
}

// TestRunCacheStillSkipsNonTerminalStateDivergence locks in the narrow scope of
// the terminal-transition cache guard: an open finding whose ticket diverges
// only in a non-terminal state must still be cache-suppressed when its hashes
// are unchanged. (A broader !needsUpdate guard would incorrectly re-update it.)
func TestRunCacheStillSkipsNonTerminalStateDivergence(t *testing.T) {
	cfg := config.Config{
		Cache: config.CacheConfig{},
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{Workers: 1},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:  "snyk:project-a:issue-1",
					SnykIssueID:  "issue-1",
					SnykIssueKey: "SNYK-ISSUE-1",
					ProjectID:    "project-a",
					ProjectName:  "Project A",
					IssueTitle:   "Outdated package",
					PackageName:  "github.com/example/pkg",
					Severity:     "high",
					Status:       model.FindingOpen, // desired Todo — non-terminal
					CreatedAt:    time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	desired := desiredIssue(cfg, snyk.snapshot.Findings[0]) // State == Todo
	// Ticket is in a *different open* state; needsUpdate is true, but the
	// transition is non-terminal so the cache should keep suppressing it.
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       desired.Title,
		Description: desired.Description,
		DueDate:     desired.DueDate,
		StateName:   "Triage",
		Fingerprint: desired.Fingerprint,
		Priority:    desired.Priority,
	}
	cacheStore := &fakeCache{
		snapshot: cache.Snapshot{
			SchemaSignature: managedSchemaSignature(),
			SnykHashes: map[string]string{
				desired.Fingerprint: desiredIssueHash(desired),
			},
			LinearHashes: map[string]string{
				desired.Fingerprint: existingIssueHash(existing),
			},
		},
	}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{existing}}

	service := New(cfg, logger, snyk, linear, cacheStore)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (non-terminal divergence stays cached)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

func TestRunCancelsMissingIssueWhenProjectDeleted(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{
			Workers: 1,
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			ProjectIDs: map[string]struct{}{
				"project-a": {},
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "missing project issue",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-z:issue-9",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)

	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateCancelled {
		t.Fatalf("resolved state = %q, want %q", linear.updated[0].State, model.StateCancelled)
	}
}

func TestRunCancelsMissingIssueWhenProjectDeletedEvenIfCached(t *testing.T) {
	cfg := config.Config{
		Cache: config.CacheConfig{},
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{
			Workers: 1,
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			ProjectIDs: map[string]struct{}{
				"project-a": {},
			},
		},
	}
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       "missing project issue",
		Description: "old description",
		StateName:   "Todo",
		Fingerprint: "snyk:project-z:issue-9",
	}
	cacheStore := &fakeCache{
		snapshot: cache.Snapshot{
			SchemaSignature: managedSchemaSignature(),
			LinearHashes: map[string]string{
				existing.Fingerprint: existingIssueHash(existing),
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{existing},
	}

	service := New(cfg, logger, snyk, linear, cacheStore)

	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateCancelled {
		t.Fatalf("resolved state = %q, want %q", linear.updated[0].State, model.StateCancelled)
	}
}

func TestNeedsUpdateUsesCaseInsensitiveLabels(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-04-01",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-04-01",
		State:       model.StateTodo,
		Priority:    2,
	}

	if needsUpdate(existing, desired) {
		t.Fatal("needsUpdate() = true, want false")
	}
}

func containsDesiredState(desired []model.DesiredIssue, state model.IssueState) bool {
	for _, issue := range desired {
		if issue.State == state {
			return true
		}
	}
	return false
}

func desiredStates(desired []model.DesiredIssue) []model.IssueState {
	out := make([]model.IssueState, 0, len(desired))
	for _, issue := range desired {
		out = append(out, issue.State)
	}
	return out
}

func TestDesiredIssueDueDateUsesSnykCreatedAt(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
	}
	// Use a CreatedAt that produces a future due date so the guard against
	// past due dates does not kick in.
	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectName: "Project A",
		IssueType:   "code",
		Severity:    "critical",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.August, 11, 23, 30, 0, 0, time.FixedZone("minus0500", -5*60*60)),
	}

	desired := desiredIssue(cfg, finding)

	if desired.DueDate != "2026-08-27" {
		t.Fatalf("desired due date = %q, want %q", desired.DueDate, "2026-08-27")
	}
}

func TestDesiredIssueDueDateFloorsPastDueDateToToday(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
	}
	// CreatedAt is far in the past, so CreatedAt + 30 days would be in the past.
	// The due date should be floored to today instead.
	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectName: "Project A",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)
	today := time.Now().Format(time.DateOnly)

	if desired.DueDate != today {
		t.Fatalf("desired due date = %q, want %q (past due date must be floored to today)", desired.DueDate, today)
	}
}

func TestDesiredIssueDueDateFloorsExpiredSnoozeToToday(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
	}
	// IgnoreExpiresAt is in the past (snooze already expired),
	// so IgnoreExpiresAt + 30 days would also be in the past.
	// The due date should be floored to today instead.
	finding := model.Finding{
		Fingerprint:     "snyk:project-a:issue-1",
		SnykIssueID:     "issue-1",
		ProjectName:     "Project A",
		Severity:        "high",
		Status:          model.FindingOpen,
		CreatedAt:       time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		IgnoreExpiresAt: time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)
	today := time.Now().Format(time.DateOnly)

	if desired.DueDate != today {
		t.Fatalf("desired due date = %q, want %q (past due date from expired snooze must be floored to today)", desired.DueDate, today)
	}
}

func TestDesiredIssueAddsGitHubSourceLinksWhenConfigured(t *testing.T) {
	cfg := config.Config{
		Source: config.SourceConfig{
			Provider: "github",
		},
		Linear: config.LinearConfig{
			Labels: config.LabelConfig{
				Managed:     "snyk-automation",
				Tool:        map[string]string{"code": "snyk-code"},
				ToolDefault: "snyk-automation",
			},
		},
	}
	finding := model.Finding{
		Fingerprint:       "snyk:project-a:issue-1",
		SnykIssueID:       "issue-1",
		SnykIssueKey:      "SNYK-CODE-ISSUE-1",
		IssueType:         "code",
		ProjectID:         "project-a",
		ProjectName:       "Project A",
		IssueTitle:        "Path Traversal",
		Severity:          "high",
		Status:            model.FindingOpen,
		IssueAPIURL:       "https://api.example.test/issue-1",
		IssueURL:          "https://app.example.test/issue-1",
		Repository:        "owner/repo",
		ProjectReference:  "main",
		SourceFile:        "src/main.go",
		SourceCommitID:    "abc123",
		SourceLineStart:   10,
		SourceColumnStart: 2,
		SourceLineEnd:     12,
		SourceColumnEnd:   8,
	}

	desired := desiredIssue(cfg, finding)

	if desired.Title != "Snyk: [high] owner/repo: Path Traversal in main.go" {
		t.Fatalf("title = %q, want %q", desired.Title, "Snyk: [high] owner/repo: Path Traversal in main.go")
	}
	if !strings.Contains(desired.Description, "## Path Traversal [HIGH]") {
		t.Fatalf("description missing heading: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Repository: [owner/repo](https://github.com/owner/repo)") {
		t.Fatalf("description missing GitHub repository link: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Ref: `main` at [`abc123`](https://github.com/owner/repo/commit/abc123)") {
		t.Fatalf("description missing ref line: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "[src/main.go (line 10:2 to 12:8)](https://github.com/owner/repo/blob/abc123/src/main.go#L10-L12)") {
		t.Fatalf("description missing GitHub source file link: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Snyk: [Open issue](https://app.example.test/issue-1)") {
		t.Fatalf("description missing Snyk link: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "API: [Issue details](https://api.example.test/issue-1)") {
		t.Fatalf("description missing API link: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Status: `open`") {
		t.Fatalf("description missing status line: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "managed_labels: snyk-automation,snyk-code") {
		t.Fatalf("description missing managed labels metadata: %s", desired.Description)
	}
	if len(desired.ManagedLabels) != 2 || desired.ManagedLabels[0] != "snyk-automation" || desired.ManagedLabels[1] != "snyk-code" {
		t.Fatalf("ManagedLabels = %#v, want [snyk-automation snyk-code]", desired.ManagedLabels)
	}
}

func TestDesiredIssueAddsGitHubProjectTargetFileLinkWhenNoSourceLocationExists(t *testing.T) {
	cfg := config.Config{
		Source: config.SourceConfig{
			Provider: "github",
		},
	}
	finding := model.Finding{
		Fingerprint:       "snyk:project-a:issue-1",
		SnykIssueID:       "issue-1",
		IssueType:         "package_vulnerability",
		ProjectID:         "project-a",
		ProjectName:       "owner/repo(main):apps/backend/Dockerfile.dev",
		IssueTitle:        "Integer Overflow or Wraparound",
		Severity:          "critical",
		Status:            model.FindingOpen,
		IssueURL:          "https://app.example.test/issue-1",
		IssueAPIURL:       "https://api.example.test/issue-1",
		Repository:        "owner/repo",
		ProjectReference:  "main",
		ProjectTargetFile: "apps/backend/Dockerfile.dev",
		PackageName:       "zlib/zlib1g",
		SnykIssueKey:      "SNYK-DEBIAN-ZLIB-1",
	}

	desired := desiredIssue(cfg, finding)

	if desired.Title != "Snyk: [critical] owner/repo: Integer Overflow or Wraparound in zlib/zlib1g" {
		t.Fatalf("title = %q, want %q", desired.Title, "Snyk: [critical] owner/repo: Integer Overflow or Wraparound in zlib/zlib1g")
	}
	if !strings.Contains(desired.Description, "Repository: [owner/repo](https://github.com/owner/repo)") {
		t.Fatalf("description missing repository link: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Ref: `main`") {
		t.Fatalf("description missing ref line: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Target file: [apps/backend/Dockerfile.dev](https://github.com/owner/repo/blob/main/apps/backend/Dockerfile.dev)") {
		t.Fatalf("description missing GitHub project target file link: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Package: `zlib/zlib1g`") {
		t.Fatalf("description missing package line: %s", desired.Description)
	}
}

func TestIssueTitleUsesReferenceForNonGitHubTargetFileFindings(t *testing.T) {
	finding := model.Finding{
		IssueTitle:        "Use of Default Credentials",
		Severity:          "critical",
		ProjectOrigin:     "kubernetes",
		ProjectReference:  "ghcr.io/berriai/litellm-database",
		ProjectTargetFile: "/app/pyproject.toml",
		PackageName:       "mlflow",
	}

	title := issueTitle(finding)

	if title != "Snyk: [critical] ghcr.io/berriai/litellm-database: Use of Default Credentials in mlflow" {
		t.Fatalf("title = %q, want %q", title, "Snyk: [critical] ghcr.io/berriai/litellm-database: Use of Default Credentials in mlflow")
	}
}

func TestUpsertManagedMetadataRemovesVisibleFingerprintFooter(t *testing.T) {
	description := "Status: `open`\n\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->\nFingerprint: snyk:project-a:issue-1"

	got := upsertManagedMetadata(description, "snyk:project-a:issue-1", []string{"snyk-automation", "snyk-code"})

	if strings.Contains(got, "Fingerprint: snyk:project-a:issue-1") {
		t.Fatalf("upsertManagedMetadata() left visible fingerprint footer: %s", got)
	}
	if !strings.Contains(got, "managed_labels: snyk-automation,snyk-code") {
		t.Fatalf("upsertManagedMetadata() missing managed labels metadata: %s", got)
	}
}

func TestNeedsUpdateDetectsManagedLabelChange(t *testing.T) {
	existing := model.ExistingIssue{
		Title:         "title",
		Description:   "description",
		DueDate:       "2026-04-01",
		StateName:     "Todo",
		ManagedLabels: []string{"old-label"},
		Labels: []model.IssueLabel{
			{ID: "label-1", Name: "old-label"},
		},
		Priority: 2,
	}
	desired := model.DesiredIssue{
		Title:         "title",
		Description:   "description",
		DueDate:       "2026-04-01",
		State:         model.StateTodo,
		ManagedLabels: []string{"new-label"},
		Priority:      2,
	}

	if !needsUpdate(existing, desired) {
		t.Fatal("needsUpdate() = false, want true")
	}
}

func TestManagedLabelsUsesConfiguredToolMapping(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed:     "snyk-automation",
		Tool:        map[string]string{"code": "snyk-code"},
		ToolDefault: "snyk-automation",
	}, model.Finding{IssueType: "code"})

	if len(labels) != 2 || labels[0] != "snyk-automation" || labels[1] != "snyk-code" {
		t.Fatalf("managedLabels() = %#v, want [snyk-automation snyk-code]", labels)
	}
}

func TestManagedLabelsFallsBackToConfiguredDefault(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed:     "snyk-automation",
		ToolDefault: "snyk-fallback",
	}, model.Finding{IssueType: "custom"})

	if len(labels) != 2 || labels[0] != "snyk-automation" || labels[1] != "snyk-fallback" {
		t.Fatalf("managedLabels() = %#v, want [snyk-automation snyk-fallback]", labels)
	}
}

func TestManagedLabelsUsesConfiguredOriginMapping(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed: "snyk-automation",
		Origin:  map[string]string{"kubernetes": "snyk-kubernetes", "github": "snyk-github"},
	}, model.Finding{ProjectOrigin: "kubernetes"})

	if len(labels) != 2 || labels[0] != "snyk-automation" || labels[1] != "snyk-kubernetes" {
		t.Fatalf("managedLabels() = %#v, want [snyk-automation snyk-kubernetes]", labels)
	}
}

func TestManagedLabelsFallsBackToConfiguredOriginDefault(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed:       "snyk-automation",
		OriginDefault: "snyk-origin",
	}, model.Finding{ProjectOrigin: "github"})

	if len(labels) != 2 || labels[0] != "snyk-automation" || labels[1] != "snyk-origin" {
		t.Fatalf("managedLabels() = %#v, want [snyk-automation snyk-origin]", labels)
	}
}

func TestManagedLabelsAddsAwaitingFixLabel(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed:     "snyk-automation",
		AwaitingFix: "triage-dependency",
	}, model.Finding{Status: model.FindingAwaitingFix})

	found := false
	for _, l := range labels {
		if l == "triage-dependency" {
			found = true
		}
	}
	if !found {
		t.Fatalf("managedLabels() = %#v, want triage-dependency for awaiting-fix issue", labels)
	}
}

func TestManagedLabelsOmitsAwaitingFixLabelWhenOff(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed:     "snyk-automation",
		AwaitingFix: "", // off
	}, model.Finding{Status: model.FindingAwaitingFix})

	for _, l := range labels {
		if l == "triage-dependency" {
			t.Fatalf("managedLabels() should not include triage-dependency when AwaitingFix is off")
		}
	}
}

func TestManagedLabelsOmitsAwaitingFixLabelForOpenIssue(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed:     "snyk-automation",
		AwaitingFix: "triage-dependency",
	}, model.Finding{Status: model.FindingOpen})

	for _, l := range labels {
		if l == "triage-dependency" {
			t.Fatalf("managedLabels() should not include triage-dependency for open issues")
		}
	}
}

func TestNeedsUpdateClearsDueDateWhenDesiredIsEmpty(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-07-01",
		StateName:   "Backlog",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "", // cleared for awaiting-fix
		State:       model.StateBacklog,
		Priority:    2,
	}

	if !needsUpdate(existing, desired) {
		t.Fatal("needsUpdate() = false, want true (must clear stale due date for awaiting-fix)")
	}
}

func TestNeedsUpdateSkipsDueDateWhenBothEmpty(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "",
		StateName:   "Backlog",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "",
		State:       model.StateBacklog,
		Priority:    2,
	}

	if needsUpdate(existing, desired) {
		t.Fatal("needsUpdate() = true, want false (both due dates empty)")
	}
}

func TestNeedsUpdateIncludesDueDate(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-04-01",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-04-15",
		State:       model.StateTodo,
		Priority:    2,
	}

	if !needsUpdate(existing, desired) {
		t.Fatal("needsUpdate() = false, want true")
	}
}

func TestNeedsUpdateDetectsLinkOnlyDescriptionChange(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "Repository: owner/repo",
		DueDate:     "2026-04-01",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "Repository: [owner/repo](https://github.com/owner/repo)",
		DueDate:     "2026-04-01",
		State:       model.StateTodo,
		Priority:    2,
	}

	if !needsUpdate(existing, desired) {
		t.Fatal("needsUpdate() = false, want true")
	}
}

func TestIdentifierNum(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"SNYK-1", 1},
		{"SNYK-42", 42},
		{"SNYK-11596", 11596},
		{"SEC-999", 999},
		{"nodash", 0},
		{"", 0},
		{"SNYK-abc", 0},
	}
	for _, tc := range cases {
		if got := identifierNum(tc.input); got != tc.want {
			t.Errorf("identifierNum(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestRunCancelsDuplicateFingerprintKeepsLowerIdentifier(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "CVE-2026-1234",
					Severity:    "high",
					Status:      model.FindingOpen,
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	// SNYK-20 and SNYK-10 share the same fingerprint — concurrent-run duplicate.
	// SNYK-10 is older (lower number) and should be kept as canonical.
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "issue-a",
				Identifier:  "SNYK-20",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "old body\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
				Priority:    2,
			},
			{
				ID:          "issue-b",
				Identifier:  "SNYK-10",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "old body\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
				Priority:    2,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Conflicts != 1 {
		t.Fatalf("Conflicts = %d, want 1", result.Conflicts)
	}
	if result.CancelledDuplicates != 1 {
		t.Fatalf("CancelledDuplicates = %d, want 1", result.CancelledDuplicates)
	}

	// SNYK-20 (the higher-identifier duplicate) must be cancelled.
	cancelledIDs := cancelledIdentifiers(linear.updates)
	if len(cancelledIDs) != 1 || cancelledIDs[0] != "SNYK-20" {
		t.Fatalf("cancelled identifiers = %v, want [SNYK-20]", cancelledIDs)
	}
}

func TestRunDuplicateCancellationIsIdempotentWhenAlreadyCancelled(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "CVE-2026-1234",
					Severity:    "high",
					Status:      model.FindingOpen,
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	// SNYK-20 is already Cancelled — a previous run already cleaned it up.
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "issue-a",
				Identifier:  "SNYK-20",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "old body\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Cancelled",
				Fingerprint: "snyk:project-a:issue-1",
				Priority:    2,
			},
			{
				ID:          "issue-b",
				Identifier:  "SNYK-10",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "old body\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
				Priority:    2,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Conflicts != 1 {
		t.Fatalf("Conflicts = %d, want 1", result.Conflicts)
	}
	// No update needed since SNYK-20 is already Cancelled.
	if result.CancelledDuplicates != 0 {
		t.Fatalf("CancelledDuplicates = %d, want 0 (already cancelled)", result.CancelledDuplicates)
	}
	if len(cancelledIdentifiers(linear.updates)) != 0 {
		t.Fatalf("expected no cancel mutations, got: %v", linear.updates)
	}
}

func TestRunThreeWayDuplicateCancelsTwoKeepsLowest(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "CVE-2026-1234",
					Severity:    "high",
					Status:      model.FindingOpen,
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{ID: "issue-c", Identifier: "SNYK-30", Title: "t", Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->", StateName: "Todo", Fingerprint: "snyk:project-a:issue-1"},
			{ID: "issue-a", Identifier: "SNYK-10", Title: "t", Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->", StateName: "Todo", Fingerprint: "snyk:project-a:issue-1"},
			{ID: "issue-b", Identifier: "SNYK-20", Title: "t", Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->", StateName: "Todo", Fingerprint: "snyk:project-a:issue-1"},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Conflicts != 2 {
		t.Fatalf("Conflicts = %d, want 2", result.Conflicts)
	}
	if result.CancelledDuplicates != 2 {
		t.Fatalf("CancelledDuplicates = %d, want 2", result.CancelledDuplicates)
	}

	cancelled := cancelledIdentifiers(linear.updates)
	if len(cancelled) != 2 {
		t.Fatalf("cancelled count = %d, want 2: %v", len(cancelled), cancelled)
	}
	for _, id := range cancelled {
		if id == "SNYK-10" {
			t.Fatalf("SNYK-10 (lowest) must not be cancelled; got cancelled: %v", cancelled)
		}
	}
}

func TestRunCancelsDuplicateAndStillSyncsCanonical(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "CVE-2026-1234",
					Severity:    "high",
					Status:      model.FindingOpen,
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	// SNYK-10 is canonical with a stale title — it should be updated.
	// SNYK-20 is the duplicate — it should be cancelled.
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "issue-a",
				Identifier:  "SNYK-20",
				Title:       "stale title",
				Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
			},
			{
				ID:          "issue-b",
				Identifier:  "SNYK-10",
				Title:       "stale title",
				Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.CancelledDuplicates != 1 {
		t.Fatalf("CancelledDuplicates = %d, want 1", result.CancelledDuplicates)
	}
	// Canonical (SNYK-10) must have been updated.
	if !containsStr(updatedIdentifiers(linear.updates), "SNYK-10") {
		t.Fatalf("SNYK-10 (canonical) was not updated; updates: %v", updatedIdentifiers(linear.updates))
	}
	// Duplicate (SNYK-20) must have been cancelled.
	if !containsStr(cancelledIdentifiers(linear.updates), "SNYK-20") {
		t.Fatalf("SNYK-20 (duplicate) was not cancelled; cancelled: %v", cancelledIdentifiers(linear.updates))
	}
}

// minimalCfg returns the smallest valid Config needed to run the service in tests.
func minimalCfg() config.Config {
	return config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{Workers: 1},
	}
}

func cancelledIdentifiers(updates []model.IssueUpdate) []string {
	var out []string
	for _, u := range updates {
		if u.Desired.State == model.StateCancelled {
			out = append(out, u.Existing.Identifier)
		}
	}
	return out
}

func updatedIdentifiers(updates []model.IssueUpdate) []string {
	out := make([]string, 0, len(updates))
	for _, u := range updates {
		out = append(out, u.Existing.Identifier)
	}
	return out
}

func containsStr(slice []string, s string) bool {
	return slices.Contains(slice, s)
}

// TestRunCancelsIssuesWhenProjectBecomesInactive verifies that managed Linear
// issues are cancelled when their Snyk project is de-activated (inactive).
func TestRunCancelsIssuesWhenProjectBecomesInactive(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// project-inactive has been de-activated; it still exists in Snyk but its
	// issues must be cancelled in Linear.
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{},
			ProjectIDs: map[string]struct{}{
				"project-active": {},
			},
			InactiveProjectIDs: map[string]struct{}{
				"project-inactive": {},
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "issue from inactive project",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-inactive:issue-9",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateCancelled {
		t.Fatalf("resolved state = %q, want %q", linear.updated[0].State, model.StateCancelled)
	}
}

// TestRunCancelsIssuesWhenProjectBecomesInactiveEvenIfCached verifies that the
// cache does not prevent cancellation when a project transitions to inactive.
func TestRunCancelsIssuesWhenProjectBecomesInactiveEvenIfCached(t *testing.T) {
	cfg := config.Config{
		Cache: config.CacheConfig{},
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{Workers: 1},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{},
			ProjectIDs: map[string]struct{}{
				"project-active": {},
			},
			InactiveProjectIDs: map[string]struct{}{
				"project-inactive": {},
			},
		},
	}
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       "issue from inactive project",
		Description: "old description",
		StateName:   "Todo",
		Fingerprint: "snyk:project-inactive:issue-9",
	}
	cacheStore := &fakeCache{
		snapshot: cache.Snapshot{
			SchemaSignature: managedSchemaSignature(),
			LinearHashes: map[string]string{
				existing.Fingerprint: existingIssueHash(existing),
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{existing},
	}

	service := New(cfg, logger, snyk, linear, cacheStore)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateCancelled {
		t.Fatalf("resolved state = %q, want %q", linear.updated[0].State, model.StateCancelled)
	}
}

// TestRunDoesNotCreateIssuesForInactiveProjectFindings verifies that no new
// Linear issues are created for findings belonging to inactive Snyk projects.
// (In practice the Snyk client excludes these findings, but the service should
// not act on them even if they somehow appear in the snapshot.)
func TestRunDoesNotCreateIssuesForInactiveProjectFindings(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// A finding whose project is inactive — it must not trigger a create.
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{},
			ProjectIDs: map[string]struct{}{
				"project-active": {},
			},
			InactiveProjectIDs: map[string]struct{}{
				"project-inactive": {},
			},
		},
	}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{}}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedCreates != 0 {
		t.Fatalf("PlannedCreates = %d, want 0 (inactive project findings must not be created)", result.PlannedCreates)
	}
	if len(linear.created) != 0 {
		t.Fatalf("created = %d, want 0", len(linear.created))
	}
}

// TestRunInactiveProjectAlreadyCancelledIsIdempotent verifies that an issue
// already in the Cancelled state is not mutated again on a subsequent run.
func TestRunInactiveProjectAlreadyCancelledIsIdempotent(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{},
			ProjectIDs: map[string]struct{}{
				"project-active": {},
			},
			InactiveProjectIDs: map[string]struct{}{
				"project-inactive": {},
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "issue from inactive project",
				Description: "old description\n<!-- snyk-linear-sync\nfingerprint: snyk:project-inactive:issue-9\n-->",
				StateName:   "Cancelled",
				Fingerprint: "snyk:project-inactive:issue-9",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 0 {
		t.Fatalf("PlannedResolves = %d, want 0 (already cancelled)", result.PlannedResolves)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0 (no mutation needed)", len(linear.updated))
	}
}

func TestRunKeepsTemporaryIgnoreOpenWithExtendedDueDate(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ignoreExpires := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:     "snyk:project-a:issue-1",
					SnykIssueID:     "issue-1",
					ProjectID:       "project-a",
					ProjectName:     "Project A",
					IssueTitle:      "CVE-2026-1234",
					Severity:        "high",
					Status:          model.FindingOpen,
					CreatedAt:       time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
					IgnoreExpiresAt: ignoreExpires,
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
				Priority:    2,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Temporary ignore should NOT be cancelled or moved to Backlog.
	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	updated := linear.updated[0]
	if updated.State != model.StateTodo {
		t.Fatalf("updated state = %q, want %q", updated.State, model.StateTodo)
	}
	// Due date should be calculated from IgnoreExpiresAt (2026-06-01) + 30 days for high = 2026-07-01
	if updated.DueDate != "2026-07-01" {
		t.Fatalf("updated due date = %q, want %q", updated.DueDate, "2026-07-01")
	}
}

func TestDesiredIssueDueDateUsesIgnoreExpiresAt(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
	}
	finding := model.Finding{
		Fingerprint:     "snyk:project-a:issue-1",
		SnykIssueID:     "issue-1",
		ProjectName:     "Project A",
		IssueType:       "code",
		Severity:        "high",
		Status:          model.FindingOpen,
		CreatedAt:       time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		IgnoreExpiresAt: time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	if desired.DueDate != "2026-07-01" {
		t.Fatalf("desired due date = %q, want %q", desired.DueDate, "2026-07-01")
	}
	if desired.State != model.StateTodo {
		t.Fatalf("desired state = %q, want %q", desired.State, model.StateTodo)
	}
}

func TestRunRespectsManualBacklogMove(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Backlog = "Backlog"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Backlog",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (Backlog override should prevent state-only update)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

func TestRunUpdatesTitleButKeepsBacklogState(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Backlog = "Backlog"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title",
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Backlog",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (title changed, state kept in Backlog)", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateBacklog {
		t.Fatalf("updated state = %q, want %q", linear.updated[0].State, model.StateBacklog)
	}
}

func TestRunDoesNotOverrideBacklogForFixedFindings(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Backlog = "Backlog"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingFixed,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Backlog",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (fixed finding should move to Done)", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateDone {
		t.Fatalf("updated state = %q, want %q", linear.updated[0].State, model.StateDone)
	}
}

func TestRunRespectsManualTodoMove(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Todo",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (Todo override should prevent state-only update)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

func TestRunUpdatesTitleButKeepsTodoState(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title",
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Todo",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (title changed, state kept in Todo)", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].PreserveState != true {
		t.Fatalf("updated[0].PreserveState = %v, want true", linear.updated[0].PreserveState)
	}
}

func TestIsConfiguredBacklogState(t *testing.T) {
	cases := []struct {
		existing   string
		configured string
		want       bool
	}{
		{"Backlog", "Backlog", true},
		{"backlog", "Backlog", true},
		{"BACKLOG", "Backlog", true},
		{"Todo", "Backlog", false},
		{"Done", "Backlog", false},
		{"Cancelled", "Backlog", false},
		{"", "Backlog", false},
		{"Backlog", "", false},
	}
	for _, tc := range cases {
		got := isConfiguredBacklogState(tc.existing, tc.configured)
		if got != tc.want {
			t.Errorf("isConfiguredBacklogState(%q, %q) = %v, want %v", tc.existing, tc.configured, got, tc.want)
		}
	}
}

// TestDesiredIssueDueDateUsesIgnoreExpiryForExpiredSnooze verifies that when an
// expired snooze still produces a future due date (IgnoreExpiresAt + offset),
// the due date is set correctly. When the result would be in the past, the
// due date is omitted instead (see TestDesiredIssueDueDateOmitsPastDueDateFromExpiredSnooze).
func TestDesiredIssueDueDateUsesIgnoreExpiryForExpiredSnooze(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
	}
	// The snooze expired on a date that still produces a future due date
	// when the offset is added.
	ignoreExpiresAt := time.Date(2026, time.August, 29, 0, 0, 0, 0, time.UTC)
	finding := model.Finding{
		Fingerprint:     "snyk:project-a:issue-1",
		SnykIssueID:     "issue-1",
		ProjectName:     "Project A",
		IssueType:       "code",
		Severity:        "high",
		Status:          model.FindingOpen,
		CreatedAt:       time.Date(2026, time.April, 10, 8, 29, 14, 0, time.UTC),
		IgnoreExpiresAt: ignoreExpiresAt,
	}

	desired := desiredIssue(cfg, finding)

	// Due date should be IgnoreExpiresAt (August 29) + 30 days = September 28.
	if desired.DueDate != "2026-09-28" {
		t.Fatalf("desired due date = %q, want %q (ignore expiry + high offset)", desired.DueDate, "2026-09-28")
	}
}

// TestDesiredIssueDisregardIfFixableMapsToBacklog verifies that an issue with
// disregardIfFixable=true is mapped to FindingAwaitingFix, placed in Backlog
// with no due date, and receives the triage-dependency label.
func TestDesiredItemDisregardIfFixableMapsToBacklog(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.Labels.AwaitingFix = "triage-dependency"
	finding := model.Finding{
		Fingerprint:        "snyk:project-a:issue-1",
		SnykIssueID:        "issue-1",
		ProjectName:        "Project A",
		IssueType:          "package_vulnerability",
		Severity:           "medium",
		Status:             model.FindingAwaitingFix,
		CreatedAt:          time.Date(2026, time.April, 30, 11, 59, 47, 0, time.UTC),
		DisregardIfFixable: true,
	}

	desired := desiredIssue(cfg, finding)

	if desired.State != model.StateBacklog {
		t.Fatalf("desired state = %q, want %q for disregard-if-fixable issue", desired.State, model.StateBacklog)
	}
	if desired.DueDate != "" {
		t.Fatalf("desired due date = %q, want empty for disregard-if-fixable issue", desired.DueDate)
	}
	if desired.DueDateBase != "" {
		t.Fatalf("desired due date base = %q, want empty for disregard-if-fixable issue", desired.DueDateBase)
	}
	labelFound := false
	for _, label := range desired.ManagedLabels {
		if label == "triage-dependency" {
			labelFound = true
		}
	}
	if !labelFound {
		t.Fatalf("managed labels = %v, want triage-dependency for disregard-if-fixable issue", desired.ManagedLabels)
	}
	if !strings.Contains(desired.Description, "ignored (no fix available)") {
		t.Fatalf("description should contain 'ignored (no fix available)', got: %s", desired.Description)
	}
}

// TestNeedsUpdateAlwaysCorrectsDueDate verifies that the sync always flags
// a due date update when the desired date differs from the existing one.
// Snyk is authoritative: the sync must correct manual overrides and stale
// dates, even if the desired date is a floored "today" value.
func TestNeedsUpdateAlwaysCorrectsDueDate(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-07-15", // manually-overridden future date
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-06-02", // floored to today (authoritative from Snyk)
		State:       model.StateTodo,
		Priority:    2,
	}

	if !needsUpdate(existing, desired) {
		t.Fatal("needsUpdate() = false, want true (Snyk-derived due date must correct manual override)")
	}
}

// TestNeedsUpdateStillDetectsDueDateChangeWhenBothNonEmpty verifies that the
// due date change detection still works when both dates are non-empty.
func TestNeedsUpdateStillDetectsDueDateChangeWhenBothNonEmpty(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-07-01",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-07-15",
		State:       model.StateTodo,
		Priority:    2,
	}

	if !needsUpdate(existing, desired) {
		t.Fatal("needsUpdate() = false, want true (due dates differ)")
	}
}

// TestRunSetsFlooredDueDateOnNewIssueWithOldCreatedAt verifies that when a new
// Snyk finding has an old CreatedAt, the sync creates the Linear issue with
// today's date as the due date (floored from the past SLA date).
func TestRunSetsFlooredDueDateOnNewIssueWithOldCreatedAt(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "Old issue",
					Severity:    "high",
					Status:      model.FindingOpen,
					CreatedAt:   time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC), // old → due date would be past
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{}}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedCreates != 1 {
		t.Fatalf("PlannedCreates = %d, want 1", result.PlannedCreates)
	}
	if len(linear.created) != 1 {
		t.Fatalf("created = %d, want 1", len(linear.created))
	}
	today := time.Now().Format(time.DateOnly)
	if linear.created[0].DueDate != today {
		t.Fatalf("created due date = %q, want %q (past due date floored to today)", linear.created[0].DueDate, today)
	}
}

// TestRunCorrectsOverriddenDueDateWithAuthoritativeCalculation verifies that
// when the Snyk-derived due date differs from the Linear due date, the sync
// always updates it — Snyk is authoritative, even over manual overrides.
func TestRunCorrectsOverriddenDueDateWithAuthoritativeCalculation(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Old issue",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)
	today := time.Now().Format(time.DateOnly)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     "2026-07-15", // manually-overridden future date
				StateName:   "Todo",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// The sync must correct the manually-overridden due date to the
	// authoritative Snyk-derived value (floored to today for past SLAs).
	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (Snyk due date must correct manual override)", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].DueDate != today {
		t.Fatalf("updated due date = %q, want %q (authoritative Snyk date floored to today)", linear.updated[0].DueDate, today)
	}
}

// TestRunAwaitingFixIssueGoesToBacklogWithNoDueDate verifies the full flow for
// a Snyk finding with disregardIfFixable=true: the sync creates the Linear
// issue in Backlog with no due date and the triage-dependency label.
func TestRunAwaitingFixIssueGoesToBacklogWithNoDueDate(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Backlog = "Backlog"
	cfg.Linear.Labels.AwaitingFix = "triage-dependency"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:        "snyk:project-a:issue-1",
					SnykIssueID:        "issue-1",
					ProjectID:          "project-a",
					ProjectName:        "Project A",
					IssueTitle:         "XSS in postcss",
					IssueType:          "package_vulnerability",
					Severity:           "medium",
					Status:             model.FindingAwaitingFix,
					CreatedAt:          time.Date(2026, time.April, 24, 20, 20, 42, 0, time.UTC),
					DisregardIfFixable: true,
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{}}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedCreates != 1 {
		t.Fatalf("PlannedCreates = %d, want 1", result.PlannedCreates)
	}
	if len(linear.created) != 1 {
		t.Fatalf("created = %d, want 1", len(linear.created))
	}
	created := linear.created[0]
	if created.State != model.StateBacklog {
		t.Fatalf("created state = %q, want %q", created.State, model.StateBacklog)
	}
	if created.DueDate != "" {
		t.Fatalf("created due date = %q, want empty for awaiting-fix issue", created.DueDate)
	}
	labelFound := false
	for _, label := range created.ManagedLabels {
		if label == "triage-dependency" {
			labelFound = true
		}
	}
	if !labelFound {
		t.Fatalf("created managed labels = %v, want triage-dependency", created.ManagedLabels)
	}
	if !strings.Contains(created.Description, "ignored (no fix available)") {
		t.Fatalf("description should contain 'ignored (no fix available)'")
	}
}

// TestRunAwaitingFixIssueMovedFromTodoToBacklog verifies that when an existing
// issue was previously synced as Todo (before the awaiting-fix feature) and
// the Snyk finding now maps to FindingAwaitingFix, the sync moves it to
// Backlog, clears the due date, and adds the triage-dependency label.
func TestRunAwaitingFixIssueMovedFromTodoToBacklog(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Backlog = "Backlog"
	cfg.Linear.Labels.AwaitingFix = "triage-dependency"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint:        "snyk:project-a:issue-1",
		SnykIssueID:        "issue-1",
		ProjectID:          "project-a",
		ProjectName:        "Project A",
		IssueTitle:         "XSS in postcss",
		IssueType:          "package_vulnerability",
		Severity:           "medium",
		Status:             model.FindingAwaitingFix,
		CreatedAt:          time.Date(2026, time.April, 24, 20, 20, 42, 0, time.UTC),
		DisregardIfFixable: true,
	}

	desired := desiredIssue(cfg, finding)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:            "existing-1",
				Identifier:    "SEC-1",
				Title:         desired.Title,
				Description:   desired.Description,
				DueDate:       "2026-06-08", // old due date from before awaiting-fix
				StateName:     "Todo",       // was in Todo before
				Fingerprint:   finding.Fingerprint,
				Priority:      desired.Priority,
				ManagedLabels: []string{"snyk-automation"},
				Labels:        []model.IssueLabel{{ID: "l1", Name: "snyk-automation"}},
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	updated := linear.updated[0]
	if updated.State != model.StateBacklog {
		t.Fatalf("updated state = %q, want %q", updated.State, model.StateBacklog)
	}
	if updated.DueDate != "" {
		t.Fatalf("updated due date = %q, want empty (cleared for awaiting-fix)", updated.DueDate)
	}
	labelFound := false
	for _, label := range updated.ManagedLabels {
		if label == "triage-dependency" {
			labelFound = true
		}
	}
	if !labelFound {
		t.Fatalf("updated managed labels = %v, want triage-dependency", updated.ManagedLabels)
	}
}

func TestComputeDiffDetectsAllChanges(t *testing.T) {
	existing := model.ExistingIssue{
		ID:            "issue-1",
		Identifier:    "SEC-1",
		Title:         "old title",
		Description:   "old description",
		DueDate:       "2026-04-01",
		StateName:     "Todo",
		Priority:      3,
		ManagedLabels: []string{"snyk-automation"},
		Labels:        []model.IssueLabel{{ID: "label-1", Name: "snyk-automation"}},
	}
	desired := model.DesiredIssue{
		Title:         "new title",
		Description:   "new description",
		DueDate:       "2026-05-01",
		State:         model.StateBacklog,
		Priority:      1,
		ManagedLabels: []string{"snyk-automation", "snyk-code"},
	}

	diff := ComputeDiff(existing, desired)

	if !diff.TitleChanged {
		t.Fatal("expected TitleChanged")
	}
	if diff.TitleFrom != "old title" || diff.TitleTo != "new title" {
		t.Fatalf("title diff = %q → %q", diff.TitleFrom, diff.TitleTo)
	}
	if !diff.DescriptionChanged {
		t.Fatal("expected DescriptionChanged")
	}
	if !diff.DueDateChanged {
		t.Fatal("expected DueDateChanged")
	}
	if diff.DueDateFrom != "2026-04-01" || diff.DueDateTo != "2026-05-01" {
		t.Fatalf("due date diff = %q → %q", diff.DueDateFrom, diff.DueDateTo)
	}
	if !diff.StateChanged {
		t.Fatal("expected StateChanged")
	}
	if diff.StateTo != "backlog" {
		t.Fatalf("state to = %q", diff.StateTo)
	}
	if !diff.PriorityChanged {
		t.Fatal("expected PriorityChanged")
	}
	if diff.PriorityFrom != 3 || diff.PriorityTo != 1 {
		t.Fatalf("priority diff = %d → %d", diff.PriorityFrom, diff.PriorityTo)
	}
	if len(diff.LabelsAdded) != 1 || diff.LabelsAdded[0] != "snyk-code" {
		t.Fatalf("labels added = %v, want [snyk-code]", diff.LabelsAdded)
	}
	if len(diff.LabelsRemoved) != 0 {
		t.Fatalf("labels removed = %v, want []", diff.LabelsRemoved)
	}
	if !diff.LabelsNeedUpdate {
		t.Fatal("expected LabelsNeedUpdate when labels are added")
	}
}

func TestComputeDiffDetectsNoChanges(t *testing.T) {
	existing := model.ExistingIssue{
		Title:         "same title",
		Description:   "same description",
		DueDate:       "2026-04-01",
		StateName:     "Todo",
		Priority:      2,
		ManagedLabels: []string{"snyk-automation"},
	}
	desired := model.DesiredIssue{
		Title:         "same title",
		Description:   "same description",
		DueDate:       "2026-04-01",
		State:         model.StateTodo,
		Priority:      2,
		ManagedLabels: []string{"snyk-automation"},
	}

	diff := ComputeDiff(existing, desired)

	if diff.TitleChanged || diff.DescriptionChanged || diff.DueDateChanged ||
		diff.StateChanged || diff.PriorityChanged || diff.LabelsNeedUpdate ||
		len(diff.LabelsAdded) > 0 || len(diff.LabelsRemoved) > 0 {
		t.Fatalf("expected no changes, got: %+v", diff)
	}
}

func TestComputeDiffDetectsLabelRemoval(t *testing.T) {
	existing := model.ExistingIssue{
		Title:         "title",
		Description:   "desc",
		DueDate:       "2026-04-01",
		StateName:     "Todo",
		Priority:      2,
		ManagedLabels: []string{"snyk-automation", "snyk-code"},
		Labels: []model.IssueLabel{
			{ID: "l1", Name: "snyk-automation"},
			{ID: "l2", Name: "snyk-code"},
		},
	}
	desired := model.DesiredIssue{
		Title:         "title",
		Description:   "desc",
		DueDate:       "2026-04-01",
		State:         model.StateTodo,
		Priority:      2,
		ManagedLabels: []string{"snyk-automation"},
	}

	diff := ComputeDiff(existing, desired)

	if len(diff.LabelsRemoved) != 1 || diff.LabelsRemoved[0] != "snyk-code" {
		t.Fatalf("labels removed = %v, want [snyk-code]", diff.LabelsRemoved)
	}
	if !diff.LabelsNeedUpdate {
		t.Fatal("expected LabelsNeedUpdate when labels are removed")
	}
}

func TestComputeDiffNoStateChangeWhenPreserveState(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "desc",
		DueDate:     "2026-04-01",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:         "title",
		Description:   "desc",
		DueDate:       "2026-04-01",
		State:         model.StateBacklog,
		PreserveState: true,
		ManagedLabels: []string{"snyk-automation"},
	}

	diff := ComputeDiff(existing, desired)

	if diff.StateChanged {
		t.Fatal("expected no state change when PreserveState=true")
	}
}

func TestComputeDiffDetectsLabelNotOnIssue(t *testing.T) {
	existing := model.ExistingIssue{
		Title:         "title",
		Description:   "desc",
		DueDate:       "2026-04-01",
		StateName:     "Todo",
		Priority:      2,
		ManagedLabels: []string{"snyk-automation", "snyk-code"},
		// snyk-code is managed but not actually on the issue (failed to apply).
		Labels: []model.IssueLabel{
			{ID: "l1", Name: "snyk-automation"},
		},
	}
	desired := model.DesiredIssue{
		Title:         "title",
		Description:   "desc",
		DueDate:       "2026-04-01",
		State:         model.StateTodo,
		Priority:      2,
		ManagedLabels: []string{"snyk-automation", "snyk-code"},
	}

	diff := ComputeDiff(existing, desired)

	if !diff.LabelsNeedUpdate {
		t.Fatal("expected LabelsNeedUpdate when managed label is not on issue")
	}
	if len(diff.LabelsAdded) != 0 {
		t.Fatalf("LabelsAdded = %v, want empty (label was in previous managed set)", diff.LabelsAdded)
	}
	if len(diff.LabelsRemoved) != 0 {
		t.Fatalf("LabelsRemoved = %v, want empty", diff.LabelsRemoved)
	}
}

func TestRunPostsChangeCommentsOnUpdate(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "Updated title",
					PackageName: "github.com/example/pkg",
					Severity:    "high",
					Status:      model.FindingOpen,
					CreatedAt:   time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
				Priority:    3,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	if len(linear.comments) != 1 {
		t.Fatalf("comments = %d, want 1", len(linear.comments))
	}
}

// TestRunPreservesNonTerminalStateWhenUserMovesToTodo verifies the core bug
// fix: when the configured open state is "Triage" and a user manually moves
// an open finding's issue to "Todo", the sync must not drag it back to
// "Triage". This was the original isManualTodoState check, now generalized
// to cover any non-terminal state.
func TestRunPreservesNonTerminalStateWhenUserMovesToTodo(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage" // simulate the real workspace config
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	// The user manually moved the issue from Triage to Todo.
	desired := desiredIssue(cfg, finding)
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Todo", // not the configured open state "Triage"
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (Todo state should be preserved)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

// TestRunPreservesNonTerminalStateWhenUserMovesToInProgress verifies that the
// general non-terminal state override also covers custom states like "In
// Progress" — not just the hardcoded "todo" that the old isManualTodoState
// checked for.
func TestRunPreservesNonTerminalStateWhenUserMovesToInProgress(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	desired := desiredIssue(cfg, finding)
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "In Progress", // custom non-terminal state
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (In Progress state should be preserved)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

// TestRunPreservesTodoWhenFindingIsAwaitingFix verifies that the sync does
// not override a user's manual move from Backlog to Todo when the Snyk
// finding is still in "awaiting fix" status. The old isManualTodoState check
// only fired when desired.State was Todo; when the finding was awaiting fix
// (desired Backlog), the check was bypassed and the issue was dragged back
// to Backlog.
func TestRunPreservesTodoWhenFindingIsAwaitingFix(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	cfg.Linear.States.Backlog = "Backlog"
	cfg.Linear.Labels.AwaitingFix = "triage-dependency"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint:        "snyk:project-a:issue-1",
		SnykIssueID:        "issue-1",
		ProjectID:          "project-a",
		ProjectName:        "Project A",
		IssueTitle:         "Outdated package",
		Severity:           "high",
		Status:             model.FindingAwaitingFix,
		CreatedAt:          time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
		DisregardIfFixable: true,
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	// The user manually moved the issue from Backlog to Todo despite the
	// finding still being awaiting-fix. The sync must respect this.
	desired := desiredIssue(cfg, finding)
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:            "existing-1",
				Identifier:    "SEC-1",
				Title:         desired.Title,
				Description:   desired.Description,
				DueDate:       "", // awaiting-fix has no due date
				StateName:     "Todo",
				Fingerprint:   finding.Fingerprint,
				Priority:      desired.Priority,
				ManagedLabels: desired.ManagedLabels,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (Todo state should be preserved even when finding is awaiting fix)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

// TestRunDoesNotPreserveTerminalStates verifies that the non-terminal state
// override does NOT apply when the existing state is a terminal state like
// Done or Cancelled. If a user manually marks an open finding as Done, the
// sync should still move it back to the configured open state.
func TestRunDoesNotPreserveTerminalStates(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title",
				Description: "old description",
				StateName:   "Done", // terminal state — should NOT be preserved
				Fingerprint: finding.Fingerprint,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates == 0 {
		t.Fatal("PlannedUpdates = 0, want > 0 (Done state should NOT be preserved for open finding)")
	}
}

// TestRunPreservesNonTerminalStateWithOtherFieldChanges verifies that when
// PreserveState is set due to a non-terminal state override, an update that
// changes OTHER fields (like title) still omits stateId from the mutation
// so the user's state choice is preserved.
func TestRunPreservesNonTerminalStateWithOtherFieldChanges(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "New title from Snyk",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	desired := desiredIssue(cfg, finding)
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "Stale title", // different from desired
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Todo", // user moved to Todo — should be preserved
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (title changed, state preserved)", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	// The state should be preserved as Todo via PreserveState.
	// The user moved the issue to Todo; the sync should not override it
	// back to the configured open state (Triage).
	if linear.updated[0].State != model.StateTodo {
		t.Fatalf("updated state = %q, want %q (Todo state should be preserved when other fields change)", linear.updated[0].State, model.StateTodo)
	}
}

// TestRunNonTerminalOverrideDoesNotFireWhenStateMatchesConfig verifies that
// PreserveState is NOT set when the existing state already matches the
// configured state for the desired model state. This prevents the sync from
// unnecessarily adding ":preserve" to the Snyk hash.
func TestRunNonTerminalOverrideDoesNotFireWhenStateMatchesConfig(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	desired := desiredIssue(cfg, finding)
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Triage", // matches configured Todo state
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (no override needed when state matches config)", result.PlannedUpdates)
	}
}

func TestRunSkipsCommentsForResolve(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:            "existing-1",
				Identifier:    "SEC-1",
				Title:         "resolved issue",
				Description:   "old description\n\u003c!-- snyk-linear-sync\nfingerprint: snyk:project-z:issue-9\n--\u003e",
				StateName:     "Todo",
				Fingerprint:   "snyk:project-z:issue-9",
				ManagedLabels: []string{"snyk-automation"},
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.comments) != 0 {
		t.Fatalf("comments = %d, want 0 (no comments for resolve)", len(linear.comments))
	}
}
