package linear

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	gqlclient "git.sr.ht/~emersion/gqlclient"
	linearapi "github.com/guillermo/linear/linear-api"

	"github.com/RichardoC/snyk-linear-sync/internal/config"
	"github.com/RichardoC/snyk-linear-sync/internal/httpx"
	"github.com/RichardoC/snyk-linear-sync/internal/model"
)

const (
	titlePrefix    = "Snyk:"
	metadataHeader = "<!-- snyk-linear-sync"
)

type Client struct {
	cfg config.LinearConfig
	gql *gqlclient.Client
	log *slog.Logger

	mu             sync.RWMutex
	resolvedTeam   string
	statesByName   map[string]string
	statesByType   map[string]string
	managedLabelID string
	blockedUntil   time.Time
}

func New(cfg config.LinearConfig, maxConcurrency int, logger *slog.Logger) *Client {
	base := httpx.NewAdaptiveTransport("linear", maxConcurrency, logger, nil)
	httpClient := &http.Client{
		Transport: &httpx.HeaderTransport{
			Base:  base,
			Key:   "Authorization",
			Value: cfg.APIKey,
		},
	}

	return &Client{
		cfg:          cfg,
		gql:          gqlclient.New("https://api.linear.app/graphql", httpClient),
		log:          logger,
		statesByName: map[string]string{},
		statesByType: map[string]string{},
	}
}

func (c *Client) LoadSnapshot(ctx context.Context) ([]model.ExistingIssue, error) {
	if err := c.resolveTeam(ctx); err != nil {
		return nil, err
	}
	if err := c.loadStates(ctx); err != nil {
		return nil, err
	}
	if err := c.loadManagedLabel(ctx); err != nil {
		return nil, err
	}
	return c.loadIssues(ctx)
}

func (c *Client) StateID(state model.IssueState) (string, error) {
	var name string
	switch state {
	case model.StateTodo:
		name = c.cfg.States.Todo
	case model.StateBacklog:
		name = c.cfg.States.Backlog
	case model.StateDone:
		name = c.cfg.States.Done
	case model.StateCancelled:
		name = c.cfg.States.Cancelled
	default:
		return "", fmt.Errorf("unknown issue state %q", state)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	id := c.statesByName[strings.ToLower(name)]
	if id == "" {
		typeID := c.statesByType[stateType(state)]
		if typeID != "" {
			return typeID, nil
		}
		return "", fmt.Errorf("Linear state %q not found for team %s", name, c.teamRef())
	}
	return id, nil
}

func (c *Client) CreateIssues(ctx context.Context, desired []model.DesiredIssue) error {
	if len(desired) == 0 {
		return nil
	}
	if err := c.resolveTeam(ctx); err != nil {
		return err
	}
	if err := c.ensureStatesLoaded(ctx); err != nil {
		return err
	}
	if err := c.loadManagedLabel(ctx); err != nil {
		return err
	}

	op := gqlclient.NewOperation(createIssuesMutation(len(desired)))
	for i, issue := range desired {
		stateID, err := c.StateID(issue.State)
		if err != nil {
			return err
		}

		title := issue.Title
		description := issue.Description
		priority := int32(issue.Priority)
		input := linearapi.IssueCreateInput{
			Title:       &title,
			Description: &description,
			TeamId:      c.teamID(),
			StateId:     &stateID,
			Priority:    &priority,
			LabelIds:    c.createLabelIDs(issue),
			DueDate:     timelessDatePtr(issue.DueDate),
		}
		op.Var(fmt.Sprintf("input%d", i), input)
	}

	resp := map[string]struct {
		Success bool `json:"success"`
		Issue   struct {
			ID         string `json:"id"`
			Identifier string `json:"identifier"`
		} `json:"issue"`
	}{}
	if err := c.execute(ctx, op, &resp); err != nil {
		return fmt.Errorf("create Linear issues: %w", err)
	}

	for alias, result := range resp {
		if !result.Success {
			return fmt.Errorf("create Linear issues failed without GraphQL error for %s", alias)
		}
	}

	return nil
}

func (c *Client) UpdateIssues(ctx context.Context, updates []model.IssueUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	if err := c.resolveTeam(ctx); err != nil {
		return err
	}
	if err := c.ensureStatesLoaded(ctx); err != nil {
		return err
	}
	if err := c.loadManagedLabel(ctx); err != nil {
		return err
	}

	op := gqlclient.NewOperation(updateIssuesMutation(len(updates)))
	for i, update := range updates {
		stateID, err := c.StateID(update.Desired.State)
		if err != nil {
			return err
		}

		title := update.Desired.Title
		description := update.Desired.Description
		priority := int32(update.Desired.Priority)
		labelIDs, err := c.desiredLabelIDs(update.Existing, update.Desired)
		if err != nil {
			return err
		}
		input := linearapi.IssueUpdateInput{
			Title:       &title,
			Description: &description,
			StateId:     &stateID,
			Priority:    &priority,
			LabelIds:    labelIDs,
			DueDate:     timelessDatePtr(update.Desired.DueDate),
		}
		op.Var(fmt.Sprintf("id%d", i), update.Existing.ID)
		op.Var(fmt.Sprintf("input%d", i), input)
	}

	resp := map[string]struct {
		Success bool `json:"success"`
	}{}
	if err := c.execute(ctx, op, &resp); err != nil {
		return fmt.Errorf("update Linear issues: %w", err)
	}

	for alias, result := range resp {
		if !result.Success {
			return fmt.Errorf("update Linear issues failed without GraphQL error for %s", alias)
		}
	}

	return nil
}

func (c *Client) loadStates(ctx context.Context) error {
	var after *string
	states := map[string]string{}
	stateTypes := map[string]string{}

	for {
		op := gqlclient.NewOperation(`
query teamStates($id: String!, $after: String) {
  team(id: $id) {
    states(first: 100, after: $after) {
      nodes {
        id
        name
        type
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
}`)
		op.Var("id", c.teamID())
		op.Var("after", after)

		var resp struct {
			Team struct {
				States struct {
					Nodes []struct {
						ID   string `json:"id"`
						Name string `json:"name"`
						Type string `json:"type"`
					} `json:"nodes"`
					PageInfo struct {
						HasNextPage bool    `json:"hasNextPage"`
						EndCursor   *string `json:"endCursor"`
					} `json:"pageInfo"`
				} `json:"states"`
			} `json:"team"`
		}
		if err := c.execute(ctx, op, &resp); err != nil {
			return fmt.Errorf("fetch Linear states: %w", err)
		}

		for _, state := range resp.Team.States.Nodes {
			states[strings.ToLower(state.Name)] = state.ID
			if _, exists := stateTypes[state.Type]; !exists {
				stateTypes[state.Type] = state.ID
			}
		}

		if !resp.Team.States.PageInfo.HasNextPage || resp.Team.States.PageInfo.EndCursor == nil {
			break
		}
		after = resp.Team.States.PageInfo.EndCursor
	}

	c.mu.Lock()
	c.statesByName = states
	c.statesByType = stateTypes
	c.mu.Unlock()
	return nil
}

func (c *Client) loadIssues(ctx context.Context) ([]model.ExistingIssue, error) {
	filter := linearapi.IssueFilter{
		Team: &linearapi.TeamFilter{
			Id: &linearapi.IDComparator{Eq: c.teamID()},
		},
		Or: []linearapi.IssueFilter{
			{
				Title: &linearapi.StringComparator{
					StartsWith: new(titlePrefix),
				},
			},
			{
				Description: &linearapi.NullableStringComparator{
					Contains: new("Fingerprint: snyk:"),
				},
			},
			{
				Description: &linearapi.NullableStringComparator{
					Contains: new(metadataHeader),
				},
			},
		},
	}

	var after *string
	var issues []model.ExistingIssue

	for {
		op := gqlclient.NewOperation(`
query existingIssues($filter: IssueFilter!, $after: String) {
  issues(first: 100, after: $after, filter: $filter) {
    nodes {
      id
      identifier
      title
      description
      url
      priority
      dueDate
      state {
        id
        name
      }
      labels {
        nodes {
          id
          name
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}`)
		op.Var("filter", filter)
		op.Var("after", after)

		var resp struct {
			Issues struct {
				Nodes []struct {
					ID          string  `json:"id"`
					Identifier  string  `json:"identifier"`
					Title       string  `json:"title"`
					Description *string `json:"description"`
					URL         string  `json:"url"`
					Priority    int     `json:"priority"`
					DueDate     *string `json:"dueDate"`
					State       struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"state"`
					Labels struct {
						Nodes []struct {
							ID   string `json:"id"`
							Name string `json:"name"`
						} `json:"nodes"`
					} `json:"labels"`
				} `json:"nodes"`
				PageInfo struct {
					HasNextPage bool    `json:"hasNextPage"`
					EndCursor   *string `json:"endCursor"`
				} `json:"pageInfo"`
			} `json:"issues"`
		}
		if err := c.execute(ctx, op, &resp); err != nil {
			return nil, fmt.Errorf("fetch Linear issues: %w", err)
		}

		for _, issue := range resp.Issues.Nodes {
			description := deref(issue.Description)
			labels := make([]model.IssueLabel, 0, len(issue.Labels.Nodes))
			for _, label := range issue.Labels.Nodes {
				labels = append(labels, model.IssueLabel{
					ID:   label.ID,
					Name: label.Name,
				})
			}
			existing := model.ExistingIssue{
				ID:           issue.ID,
				Identifier:   issue.Identifier,
				Title:        issue.Title,
				URL:          issue.URL,
				StateID:      issue.State.ID,
				StateName:    issue.State.Name,
				Description:  description,
				Priority:     issue.Priority,
				DueDate:      deref(issue.DueDate),
				Fingerprint:  extractFingerprint(description),
				ManagedLabel: extractManagedLabel(description),
				Labels:       labels,
			}
			issues = append(issues, existing)
		}

		if !resp.Issues.PageInfo.HasNextPage || resp.Issues.PageInfo.EndCursor == nil {
			break
		}
		after = resp.Issues.PageInfo.EndCursor
	}

	return issues, nil
}

func (c *Client) resolveTeam(ctx context.Context) error {
	c.mu.RLock()
	if c.resolvedTeam != "" {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	teamRef := c.cfg.TeamID
	if isLikelyUUID(teamRef) {
		c.mu.Lock()
		c.resolvedTeam = teamRef
		c.mu.Unlock()
		return nil
	}

	op := gqlclient.NewOperation(`
query resolveTeam($key: String!) {
  teams(first: 1, filter: { key: { eqIgnoreCase: $key } }) {
    nodes {
      id
      key
      name
    }
  }
}`)
	op.Var("key", teamRef)

	var resp struct {
		Teams struct {
			Nodes []struct {
				ID   string `json:"id"`
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"nodes"`
		} `json:"teams"`
	}
	if err := c.execute(ctx, op, &resp); err != nil {
		return fmt.Errorf("resolve Linear team %q: %w", teamRef, err)
	}
	if len(resp.Teams.Nodes) == 0 {
		return fmt.Errorf("Linear team %q was not found by key", teamRef)
	}

	c.mu.Lock()
	c.resolvedTeam = resp.Teams.Nodes[0].ID
	c.mu.Unlock()
	return nil
}

func (c *Client) teamID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.resolvedTeam != "" {
		return c.resolvedTeam
	}
	return c.cfg.TeamID
}

func (c *Client) teamRef() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.resolvedTeam != "" {
		return c.resolvedTeam
	}
	return c.cfg.TeamID
}

func extractFingerprint(description string) string {
	for line := range strings.SplitSeq(description, "\n") {
		trimmed := strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(trimmed, "fingerprint:"); ok {
			return strings.TrimSpace(after)
		}
		if after, ok := strings.CutPrefix(trimmed, "Fingerprint:"); ok {
			return strings.TrimSpace(after)
		}
	}
	return ""
}

func extractManagedLabel(description string) string {
	for line := range strings.SplitSeq(description, "\n") {
		trimmed := strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(trimmed, "managed_label:"); ok {
			return strings.TrimSpace(after)
		}
	}
	return ""
}

func (c *Client) ensureStatesLoaded(ctx context.Context) error {
	c.mu.RLock()
	loaded := len(c.statesByName) > 0 || len(c.statesByType) > 0
	c.mu.RUnlock()
	if loaded {
		return nil
	}
	return c.loadStates(ctx)
}

func (c *Client) loadManagedLabel(ctx context.Context) error {
	managedLabel := strings.TrimSpace(c.cfg.Labels.Managed)
	if managedLabel == "" {
		c.mu.Lock()
		c.managedLabelID = ""
		c.mu.Unlock()
		return nil
	}

	c.mu.RLock()
	if c.managedLabelID != "" {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	var after *string
	var teamMatches []string
	var globalMatches []string
	for {
		op := gqlclient.NewOperation(`
query managedIssueLabels($name: String!, $after: String) {
  issueLabels(first: 100, after: $after, filter: { name: { eqIgnoreCase: $name } }) {
    nodes {
      id
      name
      team {
        id
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}`)
		op.Var("name", managedLabel)
		op.Var("after", after)

		var resp struct {
			IssueLabels struct {
				Nodes []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
					Team *struct {
						ID string `json:"id"`
					} `json:"team"`
				} `json:"nodes"`
				PageInfo struct {
					HasNextPage bool    `json:"hasNextPage"`
					EndCursor   *string `json:"endCursor"`
				} `json:"pageInfo"`
			} `json:"issueLabels"`
		}
		if err := c.execute(ctx, op, &resp); err != nil {
			return fmt.Errorf("fetch Linear labels: %w", err)
		}

		for _, label := range resp.IssueLabels.Nodes {
			if !strings.EqualFold(label.Name, managedLabel) {
				continue
			}
			switch {
			case label.Team != nil && label.Team.ID == c.teamID():
				teamMatches = append(teamMatches, label.ID)
			case label.Team == nil:
				globalMatches = append(globalMatches, label.ID)
			}
		}

		if !resp.IssueLabels.PageInfo.HasNextPage || resp.IssueLabels.PageInfo.EndCursor == nil {
			break
		}
		after = resp.IssueLabels.PageInfo.EndCursor
	}

	var resolved string
	switch {
	case len(teamMatches) == 1:
		resolved = teamMatches[0]
	case len(teamMatches) > 1:
		return fmt.Errorf("managed Linear label %q is ambiguous for team %s; keep only one matching label", managedLabel, c.teamRef())
	case len(globalMatches) == 1:
		resolved = globalMatches[0]
	case len(globalMatches) > 1:
		return fmt.Errorf("managed Linear label %q is ambiguous across workspace labels; keep only one matching label", managedLabel)
	default:
		return fmt.Errorf("managed Linear label %q was not found; create the label in Linear or set LINEAR_MANAGED_LABEL=off", managedLabel)
	}

	c.mu.Lock()
	c.managedLabelID = resolved
	c.mu.Unlock()
	return nil
}

func (c *Client) createLabelIDs(desired model.DesiredIssue) []string {
	if strings.TrimSpace(desired.ManagedLabel) == "" {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.managedLabelID == "" {
		return nil
	}
	return []string{c.managedLabelID}
}

func (c *Client) desiredLabelIDs(existing model.ExistingIssue, desired model.DesiredIssue) ([]string, error) {
	out := make([]string, 0, len(existing.Labels)+1)
	seen := make(map[string]struct{}, len(existing.Labels)+1)
	previousManaged := normalizeLabelName(existing.ManagedLabel)
	desiredManaged := normalizeLabelName(desired.ManagedLabel)

	for _, label := range existing.Labels {
		normalized := normalizeLabelName(label.Name)
		if previousManaged != "" && normalized == previousManaged {
			continue
		}
		if desiredManaged != "" && normalized == desiredManaged {
			continue
		}
		if _, exists := seen[label.ID]; exists {
			continue
		}
		out = append(out, label.ID)
		seen[label.ID] = struct{}{}
	}

	if desiredManaged == "" {
		return out, nil
	}

	c.mu.RLock()
	managedLabelID := c.managedLabelID
	c.mu.RUnlock()
	if managedLabelID == "" {
		return nil, fmt.Errorf("managed Linear label %q was not resolved", desired.ManagedLabel)
	}
	if _, exists := seen[managedLabelID]; !exists {
		out = append(out, managedLabelID)
	}
	return out, nil
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

//go:fix inline
func stringPtr(value string) *string {
	return new(value)
}

func timelessDatePtr(value string) *linearapi.TimelessDate {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	date := linearapi.TimelessDate(value)
	return &date
}

func isLikelyUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	dashes := 0
	for i, r := range value {
		switch {
		case r == '-':
			if i != 8 && i != 13 && i != 18 && i != 23 {
				return false
			}
			dashes++
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return dashes == 4
}

func stateType(state model.IssueState) string {
	switch state {
	case model.StateTodo:
		return "unstarted"
	case model.StateBacklog:
		return "backlog"
	case model.StateDone:
		return "completed"
	case model.StateCancelled:
		return "canceled"
	default:
		return ""
	}
}

func normalizeLabelName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func createIssuesMutation(size int) string {
	var builder strings.Builder
	builder.WriteString("mutation issueCreateBatch(")
	for i := range size {
		if i > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(fmt.Sprintf("$input%d: IssueCreateInput!", i))
	}
	builder.WriteString(") {\n")
	for i := range size {
		builder.WriteString(fmt.Sprintf("  issueCreate%d: issueCreate(input: $input%d) {\n", i, i))
		builder.WriteString("    success\n")
		builder.WriteString("    issue {\n")
		builder.WriteString("      id\n")
		builder.WriteString("      identifier\n")
		builder.WriteString("    }\n")
		builder.WriteString("  }\n")
	}
	builder.WriteString("}")
	return builder.String()
}

func updateIssuesMutation(size int) string {
	var builder strings.Builder
	builder.WriteString("mutation issueUpdateBatch(")
	for i := range size {
		if i > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(fmt.Sprintf("$id%d: String!, $input%d: IssueUpdateInput!", i, i))
	}
	builder.WriteString(") {\n")
	for i := range size {
		builder.WriteString(fmt.Sprintf("  issueUpdate%d: issueUpdate(id: $id%d, input: $input%d) {\n", i, i, i))
		builder.WriteString("    success\n")
		builder.WriteString("  }\n")
	}
	builder.WriteString("}")
	return builder.String()
}

func (c *Client) execute(ctx context.Context, op *gqlclient.Operation, out any) error {
	var lastErr error

	for attempt := range 6 {
		if err := c.waitForRateLimitWindow(ctx); err != nil {
			return err
		}

		if err := c.gql.Execute(ctx, op, out); err != nil {
			lastErr = err
			if !isLinearRateLimitError(err) {
				return err
			}

			delay := linearRateLimitBackoff(attempt)
			c.noteRateLimit(delay)
			c.log.Warn("Linear GraphQL rate limit reached",
				slog.Duration("retry_after", delay),
				slog.Int("attempt", attempt+1),
			)

			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}

		return nil
	}

	return lastErr
}

func (c *Client) waitForRateLimitWindow(ctx context.Context) error {
	for {
		c.mu.RLock()
		until := c.blockedUntil
		c.mu.RUnlock()

		if until.IsZero() || time.Now().After(until) {
			return nil
		}

		timer := time.NewTimer(time.Until(until))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *Client) noteRateLimit(delay time.Duration) {
	until := time.Now().Add(delay)

	c.mu.Lock()
	if until.After(c.blockedUntil) {
		c.blockedUntil = until
	}
	c.mu.Unlock()
}

func isLinearRateLimitError(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "ratelimit exceeded") || strings.Contains(msg, "rate limit exceeded")
}

func linearRateLimitBackoff(attempt int) time.Duration {
	backoff := 5 * time.Second
	for range attempt {
		backoff *= 2
		if backoff >= time.Minute {
			return time.Minute
		}
	}
	return backoff
}
