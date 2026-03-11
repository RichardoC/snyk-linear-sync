package sync

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/RichardoC/snyk-linear-sync/internal/cache"
	"github.com/RichardoC/snyk-linear-sync/internal/config"
	"github.com/RichardoC/snyk-linear-sync/internal/model"
)

type fakeSnyk struct {
	findings []model.Finding
}

func (f fakeSnyk) ListFindings(context.Context) ([]model.Finding, error) {
	return f.findings, nil
}

type fakeLinear struct {
	snapshot []model.ExistingIssue
	created  []model.DesiredIssue
	updated  []model.DesiredIssue
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
	}
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
		findings: []model.Finding{
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
				CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
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
				CreatedAt:   time.Date(2026, time.January, 1, 9, 0, 0, 0, time.UTC),
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
	if linear.created[0].DueDate != "2026-04-01" {
		t.Fatalf("created due date = %q, want %q", linear.created[0].DueDate, "2026-04-01")
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
		findings: []model.Finding{
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
	}
	desired := desiredIssue(cfg.Linear.Due, snyk.findings[0])
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

func TestDesiredIssueDueDateUsesSnykCreatedAt(t *testing.T) {
	dueCfg := config.DueDateConfig{
		CriticalDays: 15,
		HighDays:     30,
		MediumDays:   45,
		LowDays:      90,
	}
	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectName: "Project A",
		Severity:    "critical",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 11, 23, 30, 0, 0, time.FixedZone("minus0500", -5*60*60)),
	}

	desired := desiredIssue(dueCfg, finding)

	if desired.DueDate != "2026-03-27" {
		t.Fatalf("desired due date = %q, want %q", desired.DueDate, "2026-03-27")
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
