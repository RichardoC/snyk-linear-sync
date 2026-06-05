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
	PostComments(ctx context.Context, updates []model.IssueUpdate) error
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

		if existing, ok := existingByFingerprint[finding.Fingerprint]; ok {
			// Respect manual Backlog override: if a user moved an open ticket from
			// Todo to Backlog, don't move it back on subsequent syncs.
			if desired.State == model.StateTodo && isConfiguredBacklogState(existing.StateName, s.cfg.Linear.States.Backlog) {
				desired.State = model.StateBacklog
			}
			// Respect manual non-terminal state override: when both the desired
			// model state and the existing Linear state are non-terminal, preserve
			// the user's chosen Linear state. This prevents the sync from dragging
			// an issue back to the configured open state (e.g. "Triage") when a
			// user has manually moved it to "Todo", "In Progress", or any other
			// non-terminal state. It also handles the case where the existing
			// state already matches the configured state, avoiding false-positive
			// state-change detection due to model state names ("todo") differing
			// from configured Linear state names ("Triage").
			if isNonTerminalModelState(desired.State) && isNonTerminalLinearState(existing.StateName, s.cfg.Linear.States) {
				desired.PreserveState = true
			}

			// When a fix becomes available for a previously-blocked issue,
			// recalculate the due date from today instead of the original
			// created_at. The original SLA date is meaningless because the
			// team couldn't act on the issue while no fix was available. A
			// fresh SLA from fix-availability gives a meaningful triage
			// deadline without the daily churn that the old floor-to-today
			// caused for all overdue issues.
			if finding.Status == model.FindingOpen && wasAwaitingFix(existing.ManagedLabels, s.cfg.Linear.Labels.AwaitingFix) {
				desired.DueDate, desired.DueDateBase, desired.DueDateReason = issueDueDateFromFixAvailability(s.cfg.Linear.Due, finding)
			}
		}

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
			// The cache fast-path may not suppress a pending move into a terminal
			// state: a finding that became fixed/ignored (desired Done/Cancelled)
			// while its ticket sat in an open column must still be closed, even
			// if its Snyk/Linear hashes are unchanged since the last run. Benign
			// open-state divergences stay cache-suppressed as before.
			if cacheEnabled && cacheSnapshot.SnykHashes[fingerprint] == snykHashes[fingerprint] && cacheSnapshot.LinearHashes[fingerprint] == currentLinearHashes[fingerprint] && !pendingTerminalTransition(existing, desired) {
				continue
			}
			if needsUpdate(existing, desired) {
				update := model.IssueUpdate{Existing: existing, Desired: desired}
				update.Diff = ComputeDiff(existing, desired)
				updateBatch = append(updateBatch, update)
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
			desiredState, stateReason := missingFindingState(existing.Fingerprint, snykSnapshot.ProjectIDs, snykSnapshot.InactiveProjectIDs)
			resolved := model.DesiredIssue{
				Fingerprint:   existing.Fingerprint,
				Title:         existing.Title,
				Description:   upsertManagedMetadata(existing.Description, existing.Fingerprint, existing.ManagedLabels),
				DueDate:       existing.DueDate,
				State:         desiredState,
				StateReason:   stateReason,
				ManagedLabels: existing.ManagedLabels,
				Priority:      existing.Priority,
			}
			if needsUpdate(existing, resolved) {
				resolvedUpdate := model.IssueUpdate{Existing: existing, Desired: resolved}
				resolvedUpdate.Diff = ComputeDiff(existing, resolved)
				resolveBatch = append(resolveBatch, resolvedUpdate)
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
				StateReason:   "duplicate of another managed issue",
				ManagedLabels: duplicate.ManagedLabels,
				Priority:      duplicate.Priority,
			}
			if needsUpdate(duplicate, desired) {
				cancelUpdate := model.IssueUpdate{Existing: duplicate, Desired: desired}
				cancelUpdate.Diff = ComputeDiff(duplicate, desired)
				cancelBatch = append(cancelBatch, cancelUpdate)
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
		} else {
			if err := s.linear.PostComments(ctx, job.updateBatch); err != nil {
				s.logger.Warn("batch comment post failed, retrying individually",
					slog.Int("batch_size", len(job.updateBatch)),
					slog.Any("error", err),
				)
				for _, update := range job.updateBatch {
					if err := s.linear.PostComments(ctx, []model.IssueUpdate{update}); err != nil {
						s.logger.Warn("failed to post change comment",
							slog.String("issue", update.Existing.Identifier),
							slog.String("fingerprint", update.Desired.Fingerprint),
							slog.Any("error", err),
						)
					}
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
	dueDate, dueDateBase, dueDateReason := issueDueDate(cfg.Linear.Due, finding)
	// No meaningful SLA while blocked on an upstream fix. When a fix becomes
	// available Snyk flips ignored=false; the next run maps it back to
	// FindingOpen (Todo) and recalculates the due date.
	if finding.Status == model.FindingAwaitingFix {
		dueDate = ""
		dueDateBase = ""
		dueDateReason = "awaiting upstream fix, SLA paused"
	}
	return model.DesiredIssue{
		Fingerprint:   finding.Fingerprint,
		Title:         issueTitle(finding),
		Description:   issueDescription(cfg.Source, managedLabels(cfg.Linear.Labels, finding), finding),
		DueDate:       dueDate,
		DueDateBase:   dueDateBase,
		State:         issueState(finding.Status),
		StateReason:   stateReason(finding.Status),
		DueDateReason: dueDateReason,
		ManagedLabels: managedLabels(cfg.Linear.Labels, finding),
		LabelReasons:  buildLabelReasons(cfg.Linear.Labels, finding),
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
	lines = append(lines, fmt.Sprintf("Status: `%s`", statusDisplayName(finding.Status)))
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
	if labels := model.NormalizeManagedLabelNames(managedLabels); len(labels) > 0 {
		lines = append(lines, fmt.Sprintf("managed_labels: %s", strings.Join(labels, ",")))
	}
	lines = append(lines, "-->")
	return strings.Join(lines, "\n")
}

func issueState(status model.FindingStatus) model.IssueState {
	switch status {
	case model.FindingAwaitingFix:
		return model.StateBacklog
	case model.FindingIgnored:
		return model.StateCancelled
	case model.FindingSnoozed:
		return model.StateTodo
	case model.FindingFixed:
		return model.StateDone
	default:
		return model.StateTodo
	}
}

func stateReason(status model.FindingStatus) string {
	switch status {
	case model.FindingOpen:
		return "Snyk reports this finding as open"
	case model.FindingAwaitingFix:
		return "Snyk reports this issue as ignored until a fix is available"
	case model.FindingSnoozed:
		return "Snyk reports this issue as temporarily deferred"
	case model.FindingIgnored:
		return "Snyk reports this issue as permanently ignored"
	case model.FindingFixed:
		return "Snyk reports this finding as fixed"
	default:
		return ""
	}
}

// statusDisplayName renders the FindingStatus value for the Linear issue
// description. The raw constant values are code-internal; the description
// should show what Snyk actually reports.
func statusDisplayName(status model.FindingStatus) string {
	switch status {
	case model.FindingAwaitingFix:
		return "ignored (no fix available)"
	case model.FindingSnoozed:
		return "snoozed"
	default:
		return string(status)
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

func issueDueDate(dueCfg config.DueDateConfig, finding model.Finding) (effective, base, reason string) {
	var baseDate time.Time
	var basis string
	switch {
	case !finding.IgnoreExpiresAt.IsZero():
		expiresUTC := finding.IgnoreExpiresAt.UTC()
		baseDate = time.Date(expiresUTC.Year(), expiresUTC.Month(), expiresUTC.Day(), 0, 0, 0, 0, time.UTC)
		basis = "ignore expiry"
	case !finding.CreatedAt.IsZero():
		createdAtUTC := finding.CreatedAt.UTC()
		baseDate = time.Date(createdAtUTC.Year(), createdAtUTC.Month(), createdAtUTC.Day(), 0, 0, 0, 0, time.UTC)
		basis = "issue creation"
	default:
		return "", "", ""
	}

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
		return "", "", ""
	}

	dueDate := baseDate.AddDate(0, 0, days)
	dueDateStr := dueDate.Format(time.DateOnly)

	severityName := strings.ToLower(strings.TrimSpace(finding.Severity))
	if severityName == "" {
		severityName = "unknown"
	}
	reason = fmt.Sprintf("%s severity SLA: %d days from %s", severityName, days, basis)

	// A past due date is left as-is. Linear renders past due dates as
	// "overdue", and the actual past date is more informative than flooring
	// to today: it tells the triager how long the issue has been past its
	// SLA, not just that it is overdue. Flooring to today caused daily
	// churn — each run would advance the floor by one day, triggering a
	// spurious update even when the underlying Snyk data was unchanged.

	return dueDateStr, dueDateStr, reason
}

// issueDueDateFromFixAvailability calculates a due date for an issue that has
// just become actionable after being blocked on an upstream fix. Unlike
// issueDueDate which uses the Snyk created_at as the base, this uses today
// as the base — the SLA clock starts when the fix becomes available, not
// when the issue was originally found (which would give a meaningless past
// date because the team couldn't act on it while no fix existed).
func issueDueDateFromFixAvailability(dueCfg config.DueDateConfig, finding model.Finding) (string, string, string) {
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
		return "", "", ""
	}

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dueDate := today.AddDate(0, 0, days)
	dueDateStr := dueDate.Format(time.DateOnly)

	severityName := strings.ToLower(strings.TrimSpace(finding.Severity))
	if severityName == "" {
		severityName = "unknown"
	}
	reason := fmt.Sprintf("%s severity SLA: %d days from fix availability", severityName, days)

	return dueDateStr, dueDateStr, reason
}

// pendingTerminalTransition reports whether the issue still needs to move into
// a terminal Linear state (Done/Cancelled) that it is not already in. Such a
// transition must never be hidden by the cache fast-path, otherwise a finding
// that became fixed or ignored while its ticket sat in an open column would
// stay open indefinitely. Open-state divergences are intentionally excluded so
// the cache continues to batch benign churn.
func pendingTerminalTransition(existing model.ExistingIssue, desired model.DesiredIssue) bool {
	if desired.PreserveState {
		return false
	}
	if desired.State != model.StateDone && desired.State != model.StateCancelled {
		return false
	}
	return model.NormalizeWorkflowStateName(existing.StateName) != model.NormalizeWorkflowStateName(model.StateName(desired.State))
}

func needsUpdate(existing model.ExistingIssue, desired model.DesiredIssue) bool {
	return ComputeDiff(existing, desired).HasChanges()
}

// ComputeDiff returns a diff describing which managed fields changed between
// the existing and desired Linear issue. The caller is responsible for only
// displaying a change when the corresponding field is non-empty (e.g. a
// resolved issue may carry the existing issue's title and description).
func ComputeDiff(existing model.ExistingIssue, desired model.DesiredIssue) *model.IssueDiff {
	d := &model.IssueDiff{}

	if existing.Title != desired.Title {
		d.TitleChanged = true
		d.TitleFrom = existing.Title
		d.TitleTo = desired.Title
	}

	if normalizeDescriptionForCompare(existing.Description) != normalizeDescriptionForCompare(desired.Description) {
		d.DescriptionChanged = true
	}

	if existing.DueDate != desired.DueDate {
		if desired.DueDate != "" || existing.DueDate != "" {
			d.DueDateChanged = true
			d.DueDateFrom = existing.DueDate
			d.DueDateTo = desired.DueDate
		}
	}

	if !desired.PreserveState {
		existingNorm := model.NormalizeWorkflowStateName(existing.StateName)
		desiredNorm := model.NormalizeWorkflowStateName(model.StateName(desired.State))
		if existingNorm != desiredNorm {
			d.StateChanged = true
			d.StateFrom = existing.StateName
			d.StateTo = desiredNorm
		}
	}

	if existing.Priority != desired.Priority {
		d.PriorityChanged = true
		d.PriorityFrom = existing.Priority
		d.PriorityTo = desired.Priority
	}

	existingLabels := make(map[string]struct{}, len(existing.Labels))
	for _, l := range existing.Labels {
		existingLabels[model.NormalizeLabelName(l.Name)] = struct{}{}
	}
	desiredLabelSet := make(map[string]struct{}, len(desired.ManagedLabels))
	for _, l := range desired.ManagedLabels {
		desiredLabelSet[model.NormalizeLabelName(l)] = struct{}{}
	}
	previousManaged := make(map[string]struct{}, len(existing.ManagedLabels))
	for _, l := range existing.ManagedLabels {
		previousManaged[model.NormalizeLabelName(l)] = struct{}{}
	}

	for label := range desiredLabelSet {
		if _, inPrevious := previousManaged[label]; inPrevious {
			continue
		}
		if _, inExisting := existingLabels[label]; !inExisting {
			d.LabelsAdded = append(d.LabelsAdded, label)
		}
	}

	for _, label := range existing.ManagedLabels {
		norm := model.NormalizeLabelName(label)
		if _, exists := desiredLabelSet[norm]; !exists {
			d.LabelsRemoved = append(d.LabelsRemoved, norm)
		}
	}

	d.LabelsNeedUpdate = len(d.LabelsAdded) > 0 || len(d.LabelsRemoved) > 0

	// Also detect labels that are in the managed set but not actually present
	// on the issue. This covers the case where a label was supposed to be
	// applied in a previous run but the Linear mutation failed. Only check
	// this when we have label data to compare against; an empty Labels
	// list on the existing issue means label data was not loaded.
	if !d.LabelsNeedUpdate && len(existingLabels) > 0 {
		for label := range desiredLabelSet {
			if _, inExisting := existingLabels[label]; !inExisting {
				d.LabelsNeedUpdate = true
				break
			}
		}
	}

	return d
}

func missingFindingState(fingerprint string, activeProjects map[string]struct{}, inactiveProjects map[string]struct{}) (model.IssueState, string) {
	projectID, ok := fingerprintProjectID(fingerprint)
	if !ok {
		return model.StateDone, "this Snyk finding is no longer present"
	}
	if _, exists := activeProjects[projectID]; exists {
		return model.StateDone, "this Snyk finding is no longer present"
	}
	if _, exists := inactiveProjects[projectID]; exists {
		return model.StateCancelled, "the Snyk project has been deactivated"
	}
	// Both deleted and inactive projects result in Cancelled: the issue is no
	// longer actionable regardless of why the project stopped producing findings.
	return model.StateCancelled, "the Snyk project no longer exists"
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

// isConfiguredBacklogState returns true if the existing Linear issue state name
// matches the configured Backlog state (case-insensitive, with normalization
// for common variants like "Canceled" → "Cancelled").
func isConfiguredBacklogState(existingStateName, configuredBacklog string) bool {
	return model.NormalizeWorkflowStateName(existingStateName) == model.NormalizeWorkflowStateName(configuredBacklog)
}

// wasAwaitingFix reports whether the existing Linear issue was previously in
// the awaiting-fix state, based on the managed label recorded in the metadata
// block. This detects issues that were blocked on an upstream fix and have
// now become actionable.
func wasAwaitingFix(managedLabels []string, awaitingFixLabel string) bool {
	if awaitingFixLabel == "" {
		return false
	}
	normalized := model.NormalizeLabelName(awaitingFixLabel)
	return slices.Contains(model.NormalizeManagedLabelNames(managedLabels), normalized)
}

// isNonTerminalModelState reports whether the desired model state is
// non-terminal. Todo and Backlog are non-terminal; Done and Cancelled are
// terminal. When the sync wants a terminal state the transition must always
// be allowed (handled by pendingTerminalTransition), so PreserveState only
// applies to non-terminal desired states.
func isNonTerminalModelState(state model.IssueState) bool {
	return state == model.StateTodo || state == model.StateBacklog
}

// isNonTerminalLinearState reports whether the existing Linear issue state is
// non-terminal (i.e. not the configured Done or Cancelled state). Users can
// freely move issues between non-terminal states as part of triage; the sync
// should not override those manual decisions.
func isNonTerminalLinearState(stateName string, states config.StateConfig) bool {
	normalized := model.NormalizeWorkflowStateName(stateName)
	if normalized == model.NormalizeWorkflowStateName(states.Done) {
		return false
	}
	if normalized == model.NormalizeWorkflowStateName(states.Cancelled) {
		return false
	}
	return true
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

func managedLabels(labelCfg config.LabelConfig, finding model.Finding) []string {
	labels := make([]string, 0, 4)
	if managed := strings.TrimSpace(labelCfg.Managed); managed != "" {
		labels = append(labels, managed)
	}

	if finding.Status == model.FindingAwaitingFix && strings.TrimSpace(labelCfg.AwaitingFix) != "" {
		labels = append(labels, labelCfg.AwaitingFix)
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

	return model.NormalizeManagedLabelNames(labels)
}

// buildLabelReasons returns a map from normalized label name to a short reason
// string explaining why that label is included in the managed set. This gives
// change comments a "why" instead of just listing added labels.
func buildLabelReasons(labelCfg config.LabelConfig, finding model.Finding) map[string]string {
	reasons := make(map[string]string)

	if finding.Status == model.FindingAwaitingFix && strings.TrimSpace(labelCfg.AwaitingFix) != "" {
		reasons[model.NormalizeLabelName(labelCfg.AwaitingFix)] = "awaiting upstream fix"
	}

	issueType := strings.ToLower(strings.TrimSpace(finding.IssueType))
	if issueType != "" {
		if mapped, ok := labelCfg.Tool[issueType]; ok && strings.TrimSpace(mapped) != "" {
			reasons[model.NormalizeLabelName(mapped)] = fmt.Sprintf("Snyk issue type is %s", issueType)
		} else if strings.TrimSpace(labelCfg.ToolDefault) != "" {
			reasons[model.NormalizeLabelName(labelCfg.ToolDefault)] = fmt.Sprintf("Snyk issue type is %s", issueType)
		}
	}

	projectOrigin := strings.ToLower(strings.TrimSpace(finding.ProjectOrigin))
	if projectOrigin != "" {
		if mapped, ok := labelCfg.Origin[projectOrigin]; ok && strings.TrimSpace(mapped) != "" {
			reasons[model.NormalizeLabelName(mapped)] = fmt.Sprintf("Snyk project origin is %s", projectOrigin)
		} else if strings.TrimSpace(labelCfg.OriginDefault) != "" {
			reasons[model.NormalizeLabelName(labelCfg.OriginDefault)] = fmt.Sprintf("Snyk project origin is %s", projectOrigin)
		}
	}

	return reasons
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
