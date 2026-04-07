package sync

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
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

var linearAutoLinkPattern = regexp.MustCompile(`\[([^\]]+)\]\((?:<)?([^)\n>]+)(?:>)?\)`)
var markdownEscapePattern = regexp.MustCompile(`\\([\\` + "`" + `*_{}\[\]()#+\-.!~])`)

type RunResult struct {
	Findings            int
	ExistingIssues      int
	Conflicts           int
	PlannedCreates      int64
	PlannedUpdates      int64
	PlannedResolves     int64
	CancelledDuplicates int64
	FailedOps           int64
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
	var duplicatesToCancel []model.ExistingIssue
	for _, issue := range existingIssues {
		if issue.Fingerprint != "" {
			if prior, exists := existingByFingerprint[issue.Fingerprint]; exists {
				canonical, duplicate := prior, issue
				if identifierNum(issue.Identifier) < identifierNum(prior.Identifier) {
					canonical, duplicate = issue, prior
				}
				s.logger.Warn("duplicate fingerprint found on Linear issues, will cancel higher-identifier copy",
					slog.String("fingerprint", issue.Fingerprint),
					slog.String("canonical", canonical.Identifier),
					slog.String("duplicate", duplicate.Identifier),
				)
				existingByFingerprint[issue.Fingerprint] = canonical
				duplicatesToCancel = append(duplicatesToCancel, duplicate)
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
	result.Conflicts = len(duplicatesToCancel)
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
			if _, ok := seen[fingerprint]; ok {
				continue
			}
			desiredState := missingFindingState(existing.Fingerprint, snykSnapshot.ProjectIDs)
			resolved := model.DesiredIssue{
				Fingerprint:   existing.Fingerprint,
				Title:         existing.Title,
				Description:   upsertManagedMetadata(existing.Description, existing.Fingerprint, existing.ManagedLabels),
				DueDate:       existing.DueDate,
				State:         desiredState,
				ManagedLabels: existing.ManagedLabels,
				Priority:      existing.Priority,
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

		cancelBatch := make([]model.IssueUpdate, 0, createBatchSize)
		for _, duplicate := range duplicatesToCancel {
			desired := model.DesiredIssue{
				Fingerprint:   duplicate.Fingerprint,
				Title:         duplicate.Title,
				Description:   duplicate.Description,
				DueDate:       duplicate.DueDate,
				State:         model.StateCancelled,
				ManagedLabels: duplicate.ManagedLabels,
				Priority:      duplicate.Priority,
			}
			if needsUpdate(duplicate, desired) {
				cancelBatch = append(cancelBatch, model.IssueUpdate{Existing: duplicate, Desired: desired})
				if len(cancelBatch) == createBatchSize {
					jobs <- job{kind: jobCancelDuplicate, updateBatch: append([]model.IssueUpdate(nil), cancelBatch...)}
					s.logQueueProgress(&queuedJobs, int64(len(cancelBatch)))
					cancelBatch = cancelBatch[:0]
				}
			}
		}
		if len(cancelBatch) > 0 {
			jobs <- job{kind: jobCancelDuplicate, updateBatch: append([]model.IssueUpdate(nil), cancelBatch...)}
			s.logQueueProgress(&queuedJobs, int64(len(cancelBatch)))
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
	jobCreateBatch     jobKind = "create"
	jobUpdate          jobKind = "update"
	jobResolve         jobKind = "resolve"
	jobCancelDuplicate jobKind = "cancel-duplicate"
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
	case jobCancelDuplicate:
		cancels := atomic.AddInt64(&result.CancelledDuplicates, int64(len(job.updateBatch)))
		s.logExecutionProgress("cancel-duplicate", cancels)
		if s.cfg.DryRun {
			return nil
		}
		if err := s.linear.UpdateIssues(ctx, job.updateBatch); err != nil {
			s.logger.Warn("batch cancel-duplicate failed, retrying issues individually",
				slog.Int("batch_size", len(job.updateBatch)),
				slog.Any("error", err),
			)
			for _, update := range job.updateBatch {
				if err := s.linear.UpdateIssues(ctx, []model.IssueUpdate{update}); err != nil {
					atomic.AddInt64(&result.FailedOps, 1)
					s.logger.Error("failed to cancel duplicate issue",
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
		Fingerprint:   finding.Fingerprint,
		Title:         issueTitle(finding),
		Description:   issueDescription(cfg.Source, managedLabels(cfg.Linear.Labels, finding), finding),
		DueDate:       issueDueDate(cfg.Linear.Due, finding),
		State:         issueState(finding.Status),
		ManagedLabels: managedLabels(cfg.Linear.Labels, finding),
		Priority:      issuePriority(finding.Severity),
	}
}

func issueTitle(finding model.Finding) string {
	contextLabel := issueTitleContext(finding)
	severity := strings.ToLower(strings.TrimSpace(finding.Severity))
	title := strings.TrimSpace(finding.IssueTitle)
	subject := issueTitleSubject(finding)
	if contextLabel == "" {
		if subject == "" {
			return fmt.Sprintf("Snyk: [%s] %s", severity, title)
		}
		return fmt.Sprintf("Snyk: [%s] %s in %s", severity, title, subject)
	}
	if subject == "" {
		return fmt.Sprintf("Snyk: [%s] %s: %s", severity, contextLabel, title)
	}
	return fmt.Sprintf("Snyk: [%s] %s: %s in %s", severity, contextLabel, title, subject)
}

func issueDescription(sourceCfg config.SourceConfig, managedLabels []string, finding model.Finding) string {
	issueURL := finding.IssueURL
	if issueURL == "" {
		issueURL = finding.IssueAPIURL
	}

	sourceFileLabel, sourceFileURL := sourceFileLink(sourceCfg, finding)
	sourceCommitURL := sourceCommitLink(sourceCfg, finding)
	repositoryURL := repositoryLink(sourceCfg, finding)
	targetFileURL := projectTargetFileLink(sourceCfg, finding)

	lines := []string{
		fmt.Sprintf("## %s [%s]", strings.TrimSpace(finding.IssueTitle), strings.ToUpper(strings.TrimSpace(finding.Severity))),
	}

	if finding.Repository != "" {
		if repositoryURL != "" {
			lines = append(lines, fmt.Sprintf("Repository: [%s](%s)", finding.Repository, repositoryURL))
		} else {
			lines = append(lines, fmt.Sprintf("Repository: %s", finding.Repository))
		}
	}
	if finding.ProjectReference != "" {
		refLine := fmt.Sprintf("Ref: `%s`", finding.ProjectReference)
		if sourceCommitURL != "" {
			refLine += fmt.Sprintf(" at [`%s`](%s)", shortCommit(finding.SourceCommitID), sourceCommitURL)
		} else if finding.SourceCommitID != "" {
			refLine += fmt.Sprintf(" at `%s`", shortCommit(finding.SourceCommitID))
		}
		lines = append(lines, refLine)
	} else if finding.SourceCommitID != "" {
		if sourceCommitURL != "" {
			lines = append(lines, fmt.Sprintf("Commit: [`%s`](%s)", shortCommit(finding.SourceCommitID), sourceCommitURL))
		} else {
			lines = append(lines, fmt.Sprintf("Commit: `%s`", shortCommit(finding.SourceCommitID)))
		}
	}

	if finding.SourceFile != "" {
		if sourceFileURL != "" {
			lines = append(lines, fmt.Sprintf("File: [%s](%s)", sourceFileLabel, sourceFileURL))
		} else {
			lines = append(lines, fmt.Sprintf("File: `%s`", sourceFileLabel))
		}
	} else if finding.ProjectTargetFile != "" {
		if targetFileURL != "" {
			lines = append(lines, fmt.Sprintf("Target file: [%s](%s)", finding.ProjectTargetFile, targetFileURL))
		} else {
			lines = append(lines, fmt.Sprintf("Target file: `%s`", finding.ProjectTargetFile))
		}
	}

	lines = append(lines, "")
	if issueURL != "" {
		lines = append(lines, fmt.Sprintf("Snyk: [Open issue](%s)", issueURL))
	}
	if finding.IssueAPIURL != "" {
		lines = append(lines, fmt.Sprintf("API: [Issue details](%s)", finding.IssueAPIURL))
	}

	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("Status: `%s`", finding.Status))
	if finding.PackageName != "" {
		lines = append(lines, fmt.Sprintf("Package: `%s`", finding.PackageName))
	}
	if finding.IntroducedThrough != "" {
		lines = append(lines, fmt.Sprintf("Introduced through: `%s`", finding.IntroducedThrough))
	}
	if finding.VulnerableVersion != "" {
		lines = append(lines, fmt.Sprintf("Vulnerable version: `%s`", finding.VulnerableVersion))
	}
	if finding.FixedVersion != "" {
		lines = append(lines, fmt.Sprintf("Fix version: `%s`", finding.FixedVersion))
	}
	if finding.ExploitMaturity != "" {
		lines = append(lines, fmt.Sprintf("Exploit maturity: `%s`", finding.ExploitMaturity))
	}

	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("Project: `%s` (`%s`)", finding.ProjectName, finding.ProjectID))
	lines = append(lines, fmt.Sprintf("Issue ID: `%s`", finding.SnykIssueID))
	if finding.SnykIssueKey != "" {
		lines = append(lines, fmt.Sprintf("Issue key: `%s`", finding.SnykIssueKey))
	}
	if finding.ProjectOrigin != "" {
		lines = append(lines, fmt.Sprintf("Project origin: `%s`", finding.ProjectOrigin))
	}

	lines = append(lines, "", metadataBlock(finding.Fingerprint, managedLabels))
	return strings.Join(lines, "\n")
}

func issueTitleSubject(finding model.Finding) string {
	switch {
	case strings.TrimSpace(finding.SourceFile) != "":
		return path.Base(strings.TrimSpace(finding.SourceFile))
	case strings.TrimSpace(finding.PackageName) != "":
		return strings.TrimSpace(finding.PackageName)
	case strings.TrimSpace(finding.ProjectTargetFile) != "":
		return strings.TrimSpace(finding.ProjectTargetFile)
	case strings.TrimSpace(finding.ProjectName) != "":
		return strings.TrimSpace(finding.ProjectName)
	default:
		return ""
	}
}

func issueTitleContext(finding model.Finding) string {
	repository := strings.TrimSpace(finding.Repository)
	reference := strings.TrimSpace(finding.ProjectReference)

	switch {
	case strings.TrimSpace(finding.SourceFile) != "" && repository != "":
		return repository
	case strings.TrimSpace(finding.ProjectTargetFile) != "" && repository == "" && reference != "":
		return reference
	case repository != "":
		return repository
	case reference != "":
		return reference
	default:
		return ""
	}
}

func metadataBlock(fingerprint string, managedLabels []string) string {
	lines := []string{
		"<!-- snyk-linear-sync",
		fmt.Sprintf("fingerprint: %s", fingerprint),
	}
	if labels := normalizeManagedLabelNames(managedLabels); len(labels) > 0 {
		lines = append(lines, fmt.Sprintf("managed_labels: %s", strings.Join(labels, ",")))
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
	if managedLabelsUpdateNeeded(existing, desired.ManagedLabels) {
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
	description = linearAutoLinkPattern.ReplaceAllString(description, "[$1]($2)")
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

func projectTargetFileLink(sourceCfg config.SourceConfig, finding model.Finding) string {
	if sourceCfg.Provider != "github" {
		return ""
	}
	if strings.TrimSpace(finding.Repository) == "" || strings.TrimSpace(finding.ProjectReference) == "" || strings.TrimSpace(finding.ProjectTargetFile) == "" {
		return ""
	}

	link := &url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   fmt.Sprintf("/%s/blob/%s/%s", finding.Repository, finding.ProjectReference, finding.ProjectTargetFile),
	}
	return link.String()
}

func repositoryLink(sourceCfg config.SourceConfig, finding model.Finding) string {
	if sourceCfg.Provider != "github" {
		return ""
	}
	if strings.TrimSpace(finding.Repository) == "" {
		return ""
	}

	link := &url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   fmt.Sprintf("/%s", finding.Repository),
	}
	return link.String()
}

func shortCommit(commit string) string {
	commit = strings.TrimSpace(commit)
	if len(commit) <= 7 {
		return commit
	}
	return commit[:7]
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

func managedLabelsUpdateNeeded(existing model.ExistingIssue, desiredManagedLabels []string) bool {
	existingManaged := normalizeManagedLabelNames(existing.ManagedLabels)
	desiredManaged := normalizeManagedLabelNames(desiredManagedLabels)

	if strings.Join(existingManaged, ",") != strings.Join(desiredManaged, ",") {
		return true
	}

	for _, label := range desiredManaged {
		if !hasLabelNamed(existing.Labels, label) {
			return true
		}
	}
	for _, label := range existingManaged {
		if hasLabelNamed(existing.Labels, label) && !containsNormalizedLabel(desiredManaged, label) {
			return true
		}
	}
	return false
}

func upsertManagedMetadata(description, fingerprint string, managedLabels []string) string {
	description = strings.TrimSpace(strings.ReplaceAll(description, "\r\n", "\n"))
	block := metadataBlock(fingerprint, managedLabels)

	start := strings.Index(description, metadataHeaderStart())
	if start >= 0 {
		if relEnd := strings.Index(description[start:], "-->"); relEnd >= 0 {
			end := start + relEnd + len("-->")
			description = strings.TrimSpace(description[:start] + block + description[end:])
			description = stripVisibleFingerprintLine(description)
			return description
		}
	}

	if description == "" {
		return block
	}
	description = stripVisibleFingerprintLine(description)
	return strings.TrimSpace(strings.Join([]string{description, "", block}, "\n"))
}

func metadataHeaderStart() string {
	return "<!-- snyk-linear-sync"
}

func stripVisibleFingerprintLine(description string) string {
	lines := strings.Split(description, "\n")
	filtered := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "Fingerprint:") {
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.TrimSpace(strings.Join(filtered, "\n"))
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

func normalizeManagedLabelNames(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizeLabelName(value)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	return out
}

func containsNormalizedLabel(labels []string, target string) bool {
	target = normalizeLabelName(target)
	for _, label := range labels {
		if normalizeLabelName(label) == target {
			return true
		}
	}
	return false
}

func managedLabels(labelCfg config.LabelConfig, finding model.Finding) []string {
	labels := make([]string, 0, 3)
	if managed := strings.TrimSpace(labelCfg.Managed); managed != "" {
		labels = append(labels, managed)
	}

	issueType := strings.ToLower(strings.TrimSpace(finding.IssueType))
	if issueType != "" {
		if mapped := strings.TrimSpace(labelCfg.Tool[issueType]); mapped != "" {
			labels = append(labels, mapped)
		} else if fallback := strings.TrimSpace(labelCfg.ToolDefault); fallback != "" {
			labels = append(labels, fallback)
		}
	}

	projectOrigin := strings.ToLower(strings.TrimSpace(finding.ProjectOrigin))
	if projectOrigin != "" {
		if mapped := strings.TrimSpace(labelCfg.Origin[projectOrigin]); mapped != "" {
			labels = append(labels, mapped)
		} else if fallback := strings.TrimSpace(labelCfg.OriginDefault); fallback != "" {
			labels = append(labels, fallback)
		}
	}

	return normalizeManagedLabelNames(labels)
}

// identifierNum extracts the numeric suffix from a Linear identifier (e.g. "SNYK-42" → 42).
// Returns 0 if the identifier does not contain a dash or the suffix is not a number.
func identifierNum(identifier string) int {
	_, after, ok := strings.Cut(identifier, "-")
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(after)
	if err != nil {
		return 0
	}
	return n
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
