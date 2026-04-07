package sync

import (
	"context"
	"io"
	"log/slog"
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
	if linear.created[0].DueDate != "2026-04-01" {
		t.Fatalf("created due date = %q, want %q", linear.created[0].DueDate, "2026-04-01")
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
	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectName: "Project A",
		IssueType:   "code",
		Severity:    "critical",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 11, 23, 30, 0, 0, time.FixedZone("minus0500", -5*60*60)),
	}

	desired := desiredIssue(cfg, finding)

	if desired.DueDate != "2026-03-27" {
		t.Fatalf("desired due date = %q, want %q", desired.DueDate, "2026-03-27")
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
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
