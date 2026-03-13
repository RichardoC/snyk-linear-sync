package sync

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/RichardoC/snyk-linear-sync/internal/cache"
	"github.com/RichardoC/snyk-linear-sync/internal/config"
	"github.com/RichardoC/snyk-linear-sync/internal/model"
)

type SnykClient interface {
	LoadSnapshot(ctx context.Context) (model.SnykSnapshot, error)
}

type LinearClient interface {
	LoadSnapshot(ctx context.Context) ([]model.ExistingIssue, error)
	CreateIssues(ctx context.Context, desired []model.DesiredIssue) error
	UpdateIssues(ctx context.Context, updates []model.IssueUpdate) error
}

type CacheStore interface {
	Load(ctx context.Context) (cache.Snapshot, error)
	Save(ctx context.Context, snapshot cache.Snapshot) error
}

type Service struct {
	cfg    config.Config
	logger *slog.Logger
	snyk   SnykClient
	linear LinearClient
	cache  CacheStore
}

const (
	progressLogEvery = 1000
	createBatchSize  = 10
)

var linearAutoLinkPattern = regexp.MustCompile(`\[([^\]]+)\]\((?:<)?[^)\n]+(?:>)?\)`)
var markdownEscapePattern = regexp.MustCompile(`\\([\\` + "`" + `*_{}\[\]()#+\-.!~])`)

type RunResult struct {
	Findings        int
	ExistingIssues  int
	Conflicts       int
	PlannedCreates  int64
	PlannedUpdates  int64
	PlannedResolves int64
	FailedOps       int64
}

func New(cfg config.Config, logger *slog.Logger, snyk SnykClient, linear LinearClient, cacheStore CacheStore) *Service {
	return &Service{
		cfg:    cfg,
		logger: logger,
		snyk:   snyk,
		linear: linear,
		cache:  cacheStore,
	}
}

func (s *Service) Run(ctx context.Context) (RunResult, error) {
	runCtx := ctx
	var (
		snykSnapshot   model.SnykSnapshot
		findings       []model.Finding
		existingIssues []model.ExistingIssue
	)
	cacheEnabled := s.cache != nil && !s.cfg.Cache.BypassCache
	cacheSignature := managedSchemaSignature()
	cacheSnapshot := cache.Snapshot{
		SnykHashes:   map[string]string{},
		LinearHashes: map[string]string{},
	}

	if s.cfg.Cache.BypassCache {
		s.logger.Info("bypassing sync cache for this run")
	} else if s.cache != nil {
		loaded, err := s.cache.Load(ctx)
		if err != nil {
			return RunResult{}, err
		}
		if loaded.SchemaSignature != "" && loaded.SchemaSignature != cacheSignature {
			cacheEnabled = false
			s.logger.Info("ignoring sync cache because managed schema changed",
				slog.String("cached_signature", loaded.SchemaSignature),
				slog.String("current_signature", cacheSignature),
			)
		} else {
			cacheSnapshot = loaded
		}
	}

	s.logger.Info("loading Snyk findings and Linear snapshot")
	loadGroup, loadCtx := errgroup.WithContext(ctx)
	loadGroup.Go(func() error {
		var err error
		snykSnapshot, err = s.snyk.LoadSnapshot(loadCtx)
		if err != nil {
			return err
		}
		findings = snykSnapshot.Findings
		return err
	})
	loadGroup.Go(func() error {
		var err error
		existingIssues, err = s.linear.LoadSnapshot(loadCtx)
		return err
	})
	if err := loadGroup.Wait(); err != nil {
		return RunResult{}, err
	}
	s.logger.Info("loaded source data",
		slog.Int("findings", len(findings)),
		slog.Int("existing_issues", len(existingIssues)),
	)

	existingByFingerprint := map[string]model.ExistingIssue{}
	conflicted := map[string]struct{}{}
	for _, issue := range existingIssues {
		if issue.Fingerprint != "" {
			if prior, exists := existingByFingerprint[issue.Fingerprint]; exists {
				s.logger.Warn("duplicate fingerprint labels found on Linear issues",
					slog.String("fingerprint", issue.Fingerprint),
					slog.String("issue_a", prior.Identifier),
					slog.String("issue_b", issue.Identifier),
				)
				conflicted[issue.Fingerprint] = struct{}{}
				continue
			}
			existingByFingerprint[issue.Fingerprint] = issue
		}
	}

	desiredByFingerprint := make(map[string]model.DesiredIssue, len(findings))
	snykHashes := make(map[string]string, len(findings))
	for _, finding := range findings {
		desired := desiredIssue(s.cfg, finding)
		desiredByFingerprint[finding.Fingerprint] = desired
		snykHashes[finding.Fingerprint] = desiredIssueHash(desired)
	}

	currentLinearHashes := make(map[string]string, len(existingByFingerprint))
	for fingerprint, issue := range existingByFingerprint {
		currentLinearHashes[fingerprint] = existingIssueHash(issue)
	}

	jobs := make(chan job)
	var result RunResult
	result.Findings = len(findings)
	result.ExistingIssues = len(existingIssues)
	result.Conflicts = len(conflicted)
	var queuedJobs int64

	g, workerCtx := errgroup.WithContext(runCtx)
	for i := 0; i < s.cfg.Sync.Workers; i++ {
		g.Go(func() error {
			for job := range jobs {
				if err := s.executeJob(workerCtx, job, &result); err != nil {
					return err
				}
			}
			return nil
		})
	}

	g.Go(func() error {
		defer close(jobs)

		seen := make(map[string]struct{}, len(desiredByFingerprint))
		createBatch := make([]model.DesiredIssue, 0, createBatchSize)
		updateBatch := make([]model.IssueUpdate, 0, createBatchSize)
		for fingerprint, desired := range desiredByFingerprint {
			if _, blocked := conflicted[fingerprint]; blocked {
				continue
			}
			seen[fingerprint] = struct{}{}
			existing, ok := existingByFingerprint[fingerprint]
			if !ok {
				createBatch = append(createBatch, desired)
				if len(createBatch) == createBatchSize {
					jobs <- job{kind: jobCreateBatch, desiredBatch: append([]model.DesiredIssue(nil), createBatch...)}
					s.logQueueProgress(&queuedJobs, int64(len(createBatch)))
					createBatch = createBatch[:0]
				}
				continue
			}
			if cacheEnabled && cacheSnapshot.SnykHashes[fingerprint] == snykHashes[fingerprint] && cacheSnapshot.LinearHashes[fingerprint] == currentLinearHashes[fingerprint] {
				continue
			}
			if needsUpdate(existing, desired) {
				updateBatch = append(updateBatch, model.IssueUpdate{Existing: existing, Desired: desired})
				if len(updateBatch) == createBatchSize {
					jobs <- job{kind: jobUpdate, updateBatch: append([]model.IssueUpdate(nil), updateBatch...)}
					s.logQueueProgress(&queuedJobs, int64(len(updateBatch)))
					updateBatch = updateBatch[:0]
				}
			}
		}
		if len(createBatch) > 0 {
			jobs <- job{kind: jobCreateBatch, desiredBatch: append([]model.DesiredIssue(nil), createBatch...)}
			s.logQueueProgress(&queuedJobs, int64(len(createBatch)))
		}
		if len(updateBatch) > 0 {
			jobs <- job{kind: jobUpdate, updateBatch: append([]model.IssueUpdate(nil), updateBatch...)}
			s.logQueueProgress(&queuedJobs, int64(len(updateBatch)))
		}

		resolveBatch := make([]model.IssueUpdate, 0, createBatchSize)
		for fingerprint, existing := range existingByFingerprint {
			if _, blocked := conflicted[fingerprint]; blocked {
				continue
			}
			if _, ok := seen[fingerprint]; ok {
				continue
			}
			desiredState := missingFindingState(existing.Fingerprint, snykSnapshot.ProjectIDs)
			resolved := model.DesiredIssue{
				Fingerprint:  existing.Fingerprint,
				Title:        existing.Title,
				Description:  upsertManagedMetadata(existing.Description, existing.Fingerprint, s.cfg.Linear.Labels.Managed),
				DueDate:      existing.DueDate,
				State:        desiredState,
				ManagedLabel: s.cfg.Linear.Labels.Managed,
				Priority:     existing.Priority,
			}
			if needsUpdate(existing, resolved) {
				resolveBatch = append(resolveBatch, model.IssueUpdate{Existing: existing, Desired: resolved})
				if len(resolveBatch) == createBatchSize {
					jobs <- job{kind: jobResolve, updateBatch: append([]model.IssueUpdate(nil), resolveBatch...)}
					s.logQueueProgress(&queuedJobs, int64(len(resolveBatch)))
					resolveBatch = resolveBatch[:0]
				}
			}
		}
		if len(resolveBatch) > 0 {
			jobs <- job{kind: jobResolve, updateBatch: append([]model.IssueUpdate(nil), resolveBatch...)}
			s.logQueueProgress(&queuedJobs, int64(len(resolveBatch)))
		}

		return nil
	})

	if err := g.Wait(); err != nil {
		return result, err
	}

	if !s.cfg.DryRun && s.cache != nil {
		if result.FailedOps > 0 {
			s.logger.Warn("skipping cache refresh because some sync operations failed",
				slog.Int64("failed_ops", result.FailedOps),
			)
		} else {
			cacheLinearHashes := currentLinearHashes
			if result.PlannedCreates > 0 || result.PlannedUpdates > 0 || result.PlannedResolves > 0 {
				refreshedIssues, err := s.linear.LoadSnapshot(runCtx)
				if err != nil {
					return result, err
				}
				cacheLinearHashes = linearHashesByFingerprint(refreshedIssues)
			}
			nextSnapshot := cache.Snapshot{
				SchemaSignature: cacheSignature,
				SnykHashes:      snykHashes,
				LinearHashes:    cacheLinearHashes,
			}
			if err := s.cache.Save(runCtx, nextSnapshot); err != nil {
				return result, err
			}
			s.logger.Info("refreshed sync cache",
				slog.Int("snyk_rows", len(nextSnapshot.SnykHashes)),
				slog.Int("linear_rows", len(nextSnapshot.LinearHashes)),
			)
		}
	}

	return result, nil
}

type jobKind string

const (
	jobCreateBatch jobKind = "create"
	jobUpdate      jobKind = "update"
	jobResolve     jobKind = "resolve"
)

type job struct {
	kind         jobKind
	desiredBatch []model.DesiredIssue
	updateBatch  []model.IssueUpdate
}

func (s *Service) executeJob(ctx context.Context, job job, result *RunResult) error {
	switch job.kind {
	case jobCreateBatch:
		creates := atomic.AddInt64(&result.PlannedCreates, int64(len(job.desiredBatch)))
		s.logExecutionProgress("create", creates)
		if s.cfg.DryRun {
			return nil
		}
		if err := s.linear.CreateIssues(ctx, job.desiredBatch); err != nil {
			s.logger.Warn("batch create failed, retrying issues individually",
				slog.Int("batch_size", len(job.desiredBatch)),
				slog.Any("error", err),
			)
			for _, desired := range job.desiredBatch {
				if err := s.linear.CreateIssues(ctx, []model.DesiredIssue{desired}); err != nil {
					atomic.AddInt64(&result.FailedOps, 1)
					s.logger.Error("failed to create issue",
						slog.String("fingerprint", desired.Fingerprint),
						slog.Any("error", err),
					)
				}
			}
		}
		return nil
	case jobUpdate:
		updates := atomic.AddInt64(&result.PlannedUpdates, int64(len(job.updateBatch)))
		s.logExecutionProgress("update", updates)
		if s.cfg.DryRun {
			return nil
		}
		if err := s.linear.UpdateIssues(ctx, job.updateBatch); err != nil {
			s.logger.Warn("batch update failed, retrying issues individually",
				slog.Int("batch_size", len(job.updateBatch)),
				slog.Any("error", err),
			)
			for _, update := range job.updateBatch {
				if err := s.linear.UpdateIssues(ctx, []model.IssueUpdate{update}); err != nil {
					atomic.AddInt64(&result.FailedOps, 1)
					s.logger.Error("failed to update issue",
						slog.String("issue", update.Existing.Identifier),
						slog.String("fingerprint", update.Desired.Fingerprint),
						slog.Any("error", err),
					)
				}
			}
		}
		return nil
	case jobResolve:
		resolves := atomic.AddInt64(&result.PlannedResolves, int64(len(job.updateBatch)))
		s.logExecutionProgress("resolve", resolves)
		if s.cfg.DryRun {
			return nil
		}
		if err := s.linear.UpdateIssues(ctx, job.updateBatch); err != nil {
			s.logger.Warn("batch resolve failed, retrying issues individually",
				slog.Int("batch_size", len(job.updateBatch)),
				slog.Any("error", err),
			)
			for _, update := range job.updateBatch {
				if err := s.linear.UpdateIssues(ctx, []model.IssueUpdate{update}); err != nil {
					atomic.AddInt64(&result.FailedOps, 1)
					s.logger.Error("failed to resolve issue",
						slog.String("issue", update.Existing.Identifier),
						slog.String("fingerprint", update.Desired.Fingerprint),
						slog.Any("error", err),
					)
				}
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown job kind %q", job.kind)
	}
}

func (s *Service) logQueueProgress(counter *int64, delta int64) {
	queued := atomic.AddInt64(counter, delta)
	if queued == 1 || queued%progressLogEvery == 0 {
		s.logger.Info("queued sync work", slog.Int64("jobs", queued))
	}
}

func (s *Service) logExecutionProgress(kind string, completed int64) {
	if completed == 1 || completed%progressLogEvery == 0 {
		s.logger.Info("sync progress",
			slog.String("kind", kind),
			slog.Int64("completed", completed),
		)
	}
}

func desiredIssue(cfg config.Config, finding model.Finding) model.DesiredIssue {
	return model.DesiredIssue{
		Fingerprint:  finding.Fingerprint,
		Title:        issueTitle(finding),
		Description:  issueDescription(cfg.Source, cfg.Linear.Labels.Managed, finding),
		DueDate:      issueDueDate(cfg.Linear.Due, finding),
		State:        issueState(finding.Status),
		ManagedLabel: cfg.Linear.Labels.Managed,
		Priority:     issuePriority(finding.Severity),
	}
}

func issueTitle(finding model.Finding) string {
	base := strings.TrimSpace(finding.PackageName)
	if base == "" {
		base = strings.TrimSpace(finding.IssueTitle)
	}
	if base == "" {
		base = finding.SnykIssueID
	}
	return fmt.Sprintf("Snyk: %s %s in %s", strings.ToLower(finding.Severity), base, finding.ProjectName)
}

func issueDescription(sourceCfg config.SourceConfig, managedLabel string, finding model.Finding) string {
	issueURL := finding.IssueURL
	if issueURL == "" {
		issueURL = finding.IssueAPIURL
	}

	sourceFileLabel, sourceFileURL := sourceFileLink(sourceCfg, finding)
	sourceCommitURL := sourceCommitLink(sourceCfg, finding)

	lines := []string{
		fmt.Sprintf("Snyk issue: %s", issueURL),
		fmt.Sprintf("Snyk API issue: %s", finding.IssueAPIURL),
		fmt.Sprintf("Project: %s (%s)", finding.ProjectName, finding.ProjectID),
		fmt.Sprintf("Issue ID: %s", finding.SnykIssueID),
		fmt.Sprintf("Issue key: %s", finding.SnykIssueKey),
		fmt.Sprintf("Title: %s", finding.IssueTitle),
		fmt.Sprintf("Severity: %s", finding.Severity),
		fmt.Sprintf("Status: %s", finding.Status),
	}

	if finding.Repository != "" {
		lines = append(lines, fmt.Sprintf("Repository: %s", finding.Repository))
	}
	if finding.ProjectReference != "" {
		lines = append(lines, fmt.Sprintf("Project reference: %s", finding.ProjectReference))
	}
	if finding.ProjectTargetFile != "" {
		lines = append(lines, fmt.Sprintf("Project target file: %s", finding.ProjectTargetFile))
	}
	if finding.ProjectOrigin != "" {
		lines = append(lines, fmt.Sprintf("Project origin: %s", finding.ProjectOrigin))
	}

	if finding.PackageName != "" {
		lines = append(lines, fmt.Sprintf("Package: %s", finding.PackageName))
	}
	if finding.VulnerableVersion != "" {
		lines = append(lines, fmt.Sprintf("Vulnerable version: %s", finding.VulnerableVersion))
	}
	if finding.FixedVersion != "" {
		lines = append(lines, fmt.Sprintf("Fixed version: %s", finding.FixedVersion))
	}
	if finding.ExploitMaturity != "" {
		lines = append(lines, fmt.Sprintf("Exploit maturity: %s", finding.ExploitMaturity))
	}
	if finding.IntroducedThrough != "" {
		lines = append(lines, fmt.Sprintf("Introduced through: %s", finding.IntroducedThrough))
	}
	if finding.SourceFile != "" {
		if sourceFileURL != "" {
			lines = append(lines, fmt.Sprintf("Source file: [%s](%s)", sourceFileLabel, sourceFileURL))
		} else {
			lines = append(lines, fmt.Sprintf("Source file: %s", finding.SourceFile))
		}
	}
	if finding.SourceLineStart > 0 && sourceFileURL == "" {
		lines = append(lines, fmt.Sprintf("Source region: %s", sourceRegionString(finding)))
	}
	if finding.SourceCommitID != "" {
		if sourceCommitURL != "" {
			lines = append(lines, fmt.Sprintf("Source commit: [%s](%s)", finding.SourceCommitID, sourceCommitURL))
		} else {
			lines = append(lines, fmt.Sprintf("Source commit: %s", finding.SourceCommitID))
		}
	}

	lines = append(lines, "", metadataBlock(finding.Fingerprint, managedLabel), fmt.Sprintf("Fingerprint: %s", finding.Fingerprint))
	return strings.Join(lines, "\n")
}

func metadataBlock(fingerprint, managedLabel string) string {
	lines := []string{
		"<!-- snyk-linear-sync",
		"DO NOT EDIT, REMOVE, OR REFORMAT THIS BLOCK. It is required by snyk-linear-sync for deduplication and safe updates.",
		fmt.Sprintf("fingerprint: %s", fingerprint),
	}
	if strings.TrimSpace(managedLabel) != "" {
		lines = append(lines, fmt.Sprintf("managed_label: %s", managedLabel))
	}
	lines = append(lines, "-->")
	return strings.Join(lines, "\n")
}

func issueState(status model.FindingStatus) model.IssueState {
	switch status {
	case model.FindingIgnored:
		return model.StateCancelled
	case model.FindingSnoozed:
		return model.StateBacklog
	case model.FindingFixed:
		return model.StateDone
	default:
		return model.StateTodo
	}
}

func issuePriority(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	case "low":
		return 4
	default:
		return 0
	}
}

func issueDueDate(dueCfg config.DueDateConfig, finding model.Finding) string {
	if finding.CreatedAt.IsZero() {
		return ""
	}

	createdAtUTC := finding.CreatedAt.UTC()
	createdDate := time.Date(createdAtUTC.Year(), createdAtUTC.Month(), createdAtUTC.Day(), 0, 0, 0, 0, time.UTC)

	var days int
	switch issuePriority(finding.Severity) {
	case 1:
		days = dueCfg.CriticalDays
	case 2:
		days = dueCfg.HighDays
	case 3:
		days = dueCfg.MediumDays
	case 4:
		days = dueCfg.LowDays
	default:
		return ""
	}

	return createdDate.AddDate(0, 0, days).Format(time.DateOnly)
}

func needsUpdate(existing model.ExistingIssue, desired model.DesiredIssue) bool {
	if existing.Title != desired.Title {
		return true
	}
	if normalizeDescriptionForCompare(existing.Description) != normalizeDescriptionForCompare(desired.Description) {
		return true
	}
	if desired.DueDate != "" && existing.DueDate != desired.DueDate {
		return true
	}
	if normalizeWorkflowStateName(existing.StateName) != normalizeWorkflowStateName(stateName(desired.State)) {
		return true
	}
	if existing.Priority != desired.Priority {
		return true
	}
	if managedLabelUpdateNeeded(existing, desired.ManagedLabel) {
		return true
	}
	return false
}

func stateName(state model.IssueState) string {
	switch state {
	case model.StateTodo:
		return "todo"
	case model.StateBacklog:
		return "backlog"
	case model.StateDone:
		return "done"
	case model.StateCancelled:
		return "cancelled"
	default:
		return ""
	}
}

func missingFindingState(fingerprint string, activeProjects map[string]struct{}) model.IssueState {
	projectID, ok := fingerprintProjectID(fingerprint)
	if !ok {
		return model.StateDone
	}
	if _, exists := activeProjects[projectID]; exists {
		return model.StateDone
	}
	return model.StateCancelled
}

func fingerprintProjectID(fingerprint string) (string, bool) {
	const prefix = "snyk:"
	if !strings.HasPrefix(fingerprint, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(fingerprint, prefix)
	projectID, _, ok := strings.Cut(rest, ":")
	if !ok || strings.TrimSpace(projectID) == "" {
		return "", false
	}
	return projectID, true
}

func normalizeDescriptionForCompare(description string) string {
	description = strings.TrimSpace(strings.ReplaceAll(description, "\r\n", "\n"))
	description = linearAutoLinkPattern.ReplaceAllString(description, "$1")
	description = markdownEscapePattern.ReplaceAllString(description, "$1")
	description = strings.ReplaceAll(description, "DO NOT EDIT OR REMOVE THIS BLOCK. Used by snyk-linear-sync for deduplication.", "__SNYK_LINEAR_METADATA_WARNING__")
	description = strings.ReplaceAll(description, "DO NOT EDIT, REMOVE, OR REFORMAT THIS BLOCK. It is required by snyk-linear-sync for deduplication and safe updates.", "__SNYK_LINEAR_METADATA_WARNING__")
	return description
}

func sourceFileLink(sourceCfg config.SourceConfig, finding model.Finding) (string, string) {
	if sourceCfg.Provider != "github" {
		return "", ""
	}
	if strings.TrimSpace(finding.Repository) == "" || strings.TrimSpace(finding.SourceFile) == "" || strings.TrimSpace(finding.SourceCommitID) == "" {
		return "", ""
	}

	link := &url.URL{
		Scheme:   "https",
		Host:     "github.com",
		Path:     fmt.Sprintf("/%s/blob/%s/%s", finding.Repository, finding.SourceCommitID, finding.SourceFile),
		Fragment: githubLineAnchor(finding),
	}

	label := finding.SourceFile
	if finding.SourceLineStart > 0 {
		label = fmt.Sprintf("%s (%s)", finding.SourceFile, sourceRegionString(finding))
	}
	return label, link.String()
}

func sourceCommitLink(sourceCfg config.SourceConfig, finding model.Finding) string {
	if sourceCfg.Provider != "github" {
		return ""
	}
	if strings.TrimSpace(finding.Repository) == "" || strings.TrimSpace(finding.SourceCommitID) == "" {
		return ""
	}

	link := &url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   fmt.Sprintf("/%s/commit/%s", finding.Repository, finding.SourceCommitID),
	}
	return link.String()
}

func githubLineAnchor(finding model.Finding) string {
	if finding.SourceLineStart <= 0 {
		return ""
	}
	if finding.SourceLineEnd > finding.SourceLineStart {
		return fmt.Sprintf("L%d-L%d", finding.SourceLineStart, finding.SourceLineEnd)
	}
	return fmt.Sprintf("L%d", finding.SourceLineStart)
}

func normalizeWorkflowStateName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "canceled":
		return "cancelled"
	default:
		return value
	}
}

func managedLabelUpdateNeeded(existing model.ExistingIssue, desiredManagedLabel string) bool {
	existingManagedLabel := normalizeLabelName(existing.ManagedLabel)
	desiredManagedLabel = normalizeLabelName(desiredManagedLabel)

	switch {
	case desiredManagedLabel == "":
		return existingManagedLabel != "" && hasLabelNamed(existing.Labels, existingManagedLabel)
	case desiredManagedLabel != existingManagedLabel:
		if !hasLabelNamed(existing.Labels, desiredManagedLabel) {
			return true
		}
		return existingManagedLabel != "" && hasLabelNamed(existing.Labels, existingManagedLabel)
	default:
		return !hasLabelNamed(existing.Labels, desiredManagedLabel)
	}
}

func upsertManagedMetadata(description, fingerprint, managedLabel string) string {
	description = strings.TrimSpace(strings.ReplaceAll(description, "\r\n", "\n"))
	block := metadataBlock(fingerprint, managedLabel)

	start := strings.Index(description, metadataHeaderStart())
	if start >= 0 {
		if relEnd := strings.Index(description[start:], "-->"); relEnd >= 0 {
			end := start + relEnd + len("-->")
			description = strings.TrimSpace(description[:start] + block + description[end:])
			return description
		}
	}

	if description == "" {
		return strings.Join([]string{block, fmt.Sprintf("Fingerprint: %s", fingerprint)}, "\n")
	}
	return strings.TrimSpace(strings.Join([]string{description, "", block, fmt.Sprintf("Fingerprint: %s", fingerprint)}, "\n"))
}

func metadataHeaderStart() string {
	return "<!-- snyk-linear-sync"
}

func hasLabelNamed(labels []model.IssueLabel, name string) bool {
	name = normalizeLabelName(name)
	if name == "" {
		return false
	}
	for _, label := range labels {
		if normalizeLabelName(label.Name) == name {
			return true
		}
	}
	return false
}

func normalizeLabelName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func linearHashesByFingerprint(issues []model.ExistingIssue) map[string]string {
	out := make(map[string]string, len(issues))
	for _, issue := range issues {
		if issue.Fingerprint == "" {
			continue
		}
		out[issue.Fingerprint] = existingIssueHash(issue)
	}
	return out
}

func sourceRegionString(finding model.Finding) string {
	if finding.SourceLineEnd <= 0 {
		return fmt.Sprintf("line %d:%d", finding.SourceLineStart, finding.SourceColumnStart)
	}
	if finding.SourceLineStart == finding.SourceLineEnd {
		return fmt.Sprintf("line %d:%d-%d", finding.SourceLineStart, finding.SourceColumnStart, finding.SourceColumnEnd)
	}
	return fmt.Sprintf("line %d:%d to %d:%d", finding.SourceLineStart, finding.SourceColumnStart, finding.SourceLineEnd, finding.SourceColumnEnd)
}
