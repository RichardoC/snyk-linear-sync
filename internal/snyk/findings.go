package snyk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	snyksdk "github.com/pavel-snyk/snyk-sdk-go/v2/snyk"

	"github.com/RichardoC/snyk-linear-sync/internal/model"
)

type projectRef struct {
	ID              string
	Name            string
	Origin          string
	TargetReference string
	TargetFile      string
	Repository      string
	Active          bool
}

type issueListResponse struct {
	Data  []issueResource `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

type issueResource struct {
	ID            string             `json:"id"`
	Type          string             `json:"type"`
	Attributes    issueAttributes    `json:"attributes"`
	Relationships issueRelationships `json:"relationships"`
}

type issueAttributes struct {
	CreatedAt         string         `json:"created_at"`
	UpdatedAt         string         `json:"updated_at"`
	EffectiveSeverity string         `json:"effective_severity_level"`
	Ignored           bool           `json:"ignored"`
	Status            string         `json:"status"`
	Title             string         `json:"title"`
	Key               string         `json:"key"`
	Type              string         `json:"type"`
	ExploitDetails    exploitDetails `json:"exploit_details"`
	Problems          []problem      `json:"problems"`
	Coordinates       []coordinate   `json:"coordinates"`
	Resolution        resolution     `json:"resolution"`
}

type exploitDetails struct {
	MaturityLevels []maturityLevel `json:"maturity_levels"`
}

type maturityLevel struct {
	Format string `json:"format"`
	Level  string `json:"level"`
}

type problem struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
}

type coordinate struct {
	IsFixableManually   bool             `json:"is_fixable_manually"`
	IsFixableSnyk       bool             `json:"is_fixable_snyk"`
	IsFixableUpstream   bool             `json:"is_fixable_upstream"`
	IsPatchable         bool             `json:"is_patchable"`
	State               string           `json:"state"`
	LastResolvedAt      string           `json:"last_resolved_at"`
	LastResolvedDetails string           `json:"last_resolved_details"`
	Remedies            []remedy         `json:"remedies"`
	Representations     []representation `json:"representations"`
}

type remedy struct {
	Details remedyDetails `json:"details"`
}

type remedyDetails struct {
	UpgradePackage string `json:"upgrade_package"`
}

type representation struct {
	Dependency     dependencyRepresentation     `json:"dependency"`
	SourceLocation sourceLocationRepresentation `json:"sourceLocation"`
}

type dependencyRepresentation struct {
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
}

type sourceLocationRepresentation struct {
	CommitID string       `json:"commit_id"`
	File     string       `json:"file"`
	Region   sourceRegion `json:"region"`
}

type sourceRegion struct {
	Start sourcePosition `json:"start"`
	End   sourcePosition `json:"end"`
}

type sourcePosition struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

type resolution struct {
	Type    string `json:"type"`
	Details string `json:"details"`
}

type issueRelationships struct {
	ScanItem relationshipData `json:"scan_item"`
}

type relationshipData struct {
	Data relationshipRef `json:"data"`
}

type relationshipRef struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type orgResponse struct {
	Data struct {
		Attributes struct {
			Slug string `json:"slug"`
		} `json:"attributes"`
	} `json:"data"`
}

// v1IgnoreEntry represents a single ignore record from the Snyk v1 API.
// The v1 API returns two different shapes depending on project type:
//
//   1. Flat:   {"created": "...", "expires": "...", ...}
//   2. Nested: {"*": {"created": "...", "expires": "...", ...}}
//
// The custom UnmarshalJSON tries both formats and only extracts the fields
// we need (created and expires).
type v1IgnoreEntry struct {
	Created string `json:"created"`
	Expires string `json:"expires"`
}

func (e *v1IgnoreEntry) UnmarshalJSON(data []byte) error {
	// Try nested format first: {"*": {...}} or {"path": {...}}
	var nested map[string]struct {
		Created string `json:"created"`
		Expires string `json:"expires"`
	}
	if err := json.Unmarshal(data, &nested); err == nil && len(nested) > 0 {
		for _, details := range nested {
			e.Created = details.Created
			e.Expires = details.Expires
			return nil
		}
	}

	// Try flat format: {...}
	var flat struct {
		Created string `json:"created"`
		Expires string `json:"expires"`
	}
	if err := json.Unmarshal(data, &flat); err == nil {
		e.Created = flat.Created
		e.Expires = flat.Expires
		return nil
	}

	return nil
}

// v1ProjectIgnores is the response shape from the Snyk v1 API
// GET /v1/org/{org_id}/project/{project_id}/ignores.
// Top-level keys can be either SNYK-* issue keys or issue UUIDs depending on
// the project type; values are arrays of ignore entries.
type v1ProjectIgnores map[string][]v1IgnoreEntry

func (c *Client) LoadSnapshot(ctx context.Context) (model.SnykSnapshot, error) {
	orgSlug, err := c.orgSlug(ctx)
	if err != nil {
		return model.SnykSnapshot{}, err
	}

	projects, err := c.listProjects(ctx)
	if err != nil {
		return model.SnykSnapshot{}, err
	}

	projectDetails := make(map[string]projectRef, len(projects))
	projectIDs := make(map[string]struct{}, len(projects))
	inactiveProjectIDs := make(map[string]struct{})
	for _, project := range projects {
		projectDetails[project.ID] = project
		if project.Active {
			projectIDs[project.ID] = struct{}{}
		} else {
			inactiveProjectIDs[project.ID] = struct{}{}
		}
	}

	findings := make([]model.Finding, 0, len(projects))
	// Build a lookup from issue key / issue ID -> latest ignore expiry across
	// all pages. We cache v1 ignores per project ID to avoid redundant API calls
	// when the same project spans multiple pages of issues.
	ignoreExpiryByKey := make(map[string]time.Time)
	v1IgnoresCache := make(map[string]v1ProjectIgnores)

	nextCursor := ""
	for {
		page, cursor, err := c.listIssuesPage(ctx, nextCursor)
		if err != nil {
			return model.SnykSnapshot{}, err
		}

		// Collect project IDs that have ignored issues so we can fetch
		// v1 ignore metadata (expiration dates) for them.
		ignoredProjectIDs := make(map[string]struct{})
		for _, issue := range page {
			if issue.Attributes.Ignored {
				projectID := issue.Relationships.ScanItem.Data.ID
				if projectID != "" {
					ignoredProjectIDs[projectID] = struct{}{}
				}
			}
		}

		for projectID := range ignoredProjectIDs {
			ignores, ok := v1IgnoresCache[projectID]
			if !ok {
				var err error
				ignores, err = c.fetchProjectIgnores(ctx, projectID)
				if err != nil {
					return model.SnykSnapshot{}, fmt.Errorf("fetch v1 ignores for project %s: %w", projectID, err)
				}
				v1IgnoresCache[projectID] = ignores
			}
			for issueKey, entries := range ignores {
				if expiry := latestIgnoreExpiry(entries); !expiry.IsZero() {
					ignoreExpiryByKey[issueKey] = expiry
				}
			}
		}

		for _, issue := range page {
			projectID := issue.Relationships.ScanItem.Data.ID
			if projectID == "" {
				continue
			}
			if issue.Relationships.ScanItem.Data.Type != "" && issue.Relationships.ScanItem.Data.Type != "project" {
				continue
			}
			if _, inactive := inactiveProjectIDs[projectID]; inactive {
				continue
			}

			project := projectDetails[projectID]
			issueKey := coalesce(issue.Attributes.Key, firstProblemID(issue.Attributes.Problems), issue.ID)
			source := sourceLocation(issue.Attributes.Coordinates)
			createdAt, err := parseIssueCreatedAt(issue.Attributes.CreatedAt)
			if err != nil {
				return model.SnykSnapshot{}, fmt.Errorf("parse Snyk issue created_at for %s: %w", issue.ID, err)
			}

			ignoreExpiresAt := ignoreExpiryByKey[issueKey]
			// The v1 API uses either SNYK-* keys or issue UUIDs as top-level keys
			// depending on project type. If the first lookup failed, try the issue ID.
			if ignoreExpiresAt.IsZero() && issue.ID != "" && issueKey != issue.ID {
				ignoreExpiresAt = ignoreExpiryByKey[issue.ID]
			}

			finding := model.Finding{
				Fingerprint:       model.Fingerprint(projectID, issue.ID),
				SnykIssueID:       issue.ID,
				SnykIssueKey:      issueKey,
				IssueType:         strings.ToLower(strings.TrimSpace(issue.Attributes.Type)),
				CreatedAt:         createdAt,
				ProjectID:         projectID,
				ProjectName:       project.Name,
				ProjectOrigin:     project.Origin,
				ProjectReference:  project.TargetReference,
				ProjectTargetFile: project.TargetFile,
				Repository:        project.Repository,
				IssueTitle:        coalesce(issue.Attributes.Title, problemTitle(issue.Attributes.Problems), issue.Attributes.Key, issue.ID),
				Severity:          coalesce(issue.Attributes.EffectiveSeverity, firstProblemSeverity(issue.Attributes.Problems), "unknown"),
				ExploitMaturity:   exploitMaturity(issue.Attributes.ExploitDetails.MaturityLevels),
				PackageName:       packageName(issue.Attributes.Coordinates),
				VulnerableVersion: vulnerableVersion(issue.Attributes.Coordinates),
				FixedVersion:      fixedVersion(issue.Attributes.Coordinates),
				IssueURL:          c.issueUIURL(orgSlug, projectID, issueKey),
				IssueAPIURL:       c.issueAPIURL(issue.ID),
				Status:            mapStatus(issue.Attributes, ignoreExpiresAt),
				IntroducedThrough: introducedThrough(issue.Attributes.Coordinates),
				SourceFile:        source.File,
				SourceCommitID:    source.CommitID,
				SourceLineStart:   source.Region.Start.Line,
				SourceColumnStart: source.Region.Start.Column,
				SourceLineEnd:     source.Region.End.Line,
				SourceColumnEnd:   source.Region.End.Column,
				IgnoreExpiresAt:   ignoreExpiresAt,
			}

			findings = append(findings, finding)
		}

		if cursor == "" {
			break
		}
		nextCursor = cursor
	}

	return model.SnykSnapshot{
		Findings:           findings,
		ProjectIDs:         projectIDs,
		InactiveProjectIDs: inactiveProjectIDs,
	}, nil
}

func (c *Client) ListFindings(ctx context.Context) ([]model.Finding, error) {
	snapshot, err := c.LoadSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	return snapshot.Findings, nil
}

func (c *Client) fetchProjectIgnores(ctx context.Context, projectID string) (v1ProjectIgnores, error) {
	endpoint, err := c.v1Base.Parse(fmt.Sprintf("org/%s/project/%s/ignores", c.orgID, projectID))
	if err != nil {
		return nil, fmt.Errorf("build v1 ignores URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		c.logger.Warn("v1 ignores endpoint returned 404, treating project ignores as unavailable",
			"project_id", projectID,
		)
		return v1ProjectIgnores{}, nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("snyk v1 ignores API %s %s failed with %d: %s",
			resp.Request.Method, resp.Request.URL, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var ignores v1ProjectIgnores
	if err := json.NewDecoder(resp.Body).Decode(&ignores); err != nil {
		return nil, fmt.Errorf("decode v1 ignores: %w", err)
	}

	return ignores, nil
}

// latestIgnoreExpiry returns the expiry of the most recently created ignore
// entry among the provided ignore entries.
func latestIgnoreExpiry(entries []v1IgnoreEntry) time.Time {
	var latestCreated time.Time
	var latestExpires time.Time

	for _, entry := range entries {
		createdAt, err := parseTime(entry.Created)
		if err != nil {
			continue
		}

		if latestCreated.IsZero() || createdAt.After(latestCreated) {
			latestCreated = createdAt
			if entry.Expires != "" {
				expiresAt, err := parseTime(entry.Expires)
				if err == nil {
					latestExpires = expiresAt
				} else {
					latestExpires = time.Time{}
				}
			} else {
				latestExpires = time.Time{}
			}
		}
	}

	return latestExpires
}

func parseTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("empty time string")
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, raw)
}

func (c *Client) listProjects(ctx context.Context) ([]projectRef, error) {
	projects := make([]projectRef, 0, 256)
	opts := &snyksdk.ListProjectsOptions{}

	for {
		page, resp, err := c.sdk.Projects.List(ctx, c.orgID, opts)
		if err != nil {
			return nil, fmt.Errorf("list Snyk projects: %w", err)
		}

		for _, project := range page {
			name := ""
			origin := ""
			targetReference := ""
			targetFile := ""
			status := ""
			if project.Attributes != nil {
				name = project.Attributes.Name
				origin = project.Attributes.Origin
				targetReference = project.Attributes.TargetReference
				targetFile = project.Attributes.TargetFile
				status = project.Attributes.Status
			}
			projects = append(projects, projectRef{
				ID:              project.ID,
				Name:            name,
				Origin:          origin,
				TargetReference: targetReference,
				TargetFile:      targetFile,
				Repository:      projectRepository(name, origin),
				Active:          isActiveProjectStatus(status),
			})
		}

		if resp == nil || resp.Links == nil || resp.Links.Next == "" {
			break
		}

		cursor, err := extractCursor(resp.Links.Next)
		if err != nil {
			return nil, err
		}
		if cursor == "" {
			break
		}
		opts.StartingAfter = cursor
	}

	return projects, nil
}

func (c *Client) orgSlug(ctx context.Context) (string, error) {
	endpoint, err := c.restBase.Parse(fmt.Sprintf("orgs/%s", c.orgID))
	if err != nil {
		return "", err
	}

	query := endpoint.Query()
	query.Set("version", issuesAPIVersion)
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.api+json")

	var payload orgResponse
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	if err := c.decodeJSON(resp, &payload); err != nil {
		return "", err
	}

	return strings.TrimSpace(payload.Data.Attributes.Slug), nil
}

func (c *Client) listIssuesPage(ctx context.Context, cursor string) ([]issueResource, string, error) {
	endpoint, err := c.restBase.Parse(fmt.Sprintf("orgs/%s/issues", c.orgID))
	if err != nil {
		return nil, "", err
	}

	query := endpoint.Query()
	query.Set("version", issuesAPIVersion)
	query.Set("limit", "100")
	if cursor != "" {
		query.Set("starting_after", cursor)
	}
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.api+json")

	var payload issueListResponse
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	if err := c.decodeJSON(resp, &payload); err != nil {
		return nil, "", err
	}

	nextCursor, err := extractCursor(payload.Links.Next)
	if err != nil {
		return nil, "", err
	}

	return payload.Data, nextCursor, nil
}

func extractCursor(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse pagination link %q: %w", raw, err)
	}
	return parsed.Query().Get("starting_after"), nil
}

func parseIssueCreatedAt(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("missing created_at")
	}
	createdAt, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, err
	}
	return createdAt, nil
}

func mapStatus(issue issueAttributes, ignoreExpiresAt time.Time) model.FindingStatus {
	if issue.Ignored {
		if !ignoreExpiresAt.IsZero() && time.Now().Before(ignoreExpiresAt) {
			return model.FindingOpen
		}
		return model.FindingIgnored
	}

	resolutionType := strings.ToLower(issue.Resolution.Type)
	resolutionDetails := strings.ToLower(issue.Resolution.Details)
	status := strings.ToLower(issue.Status)

	switch {
	case strings.Contains(resolutionType, "snooz") || strings.Contains(resolutionDetails, "snooz"):
		return model.FindingSnoozed
	case status == "resolved" || status == "fixed" || coordinateResolved(issue.Coordinates) || strings.Contains(resolutionType, "fix"):
		return model.FindingFixed
	default:
		return model.FindingOpen
	}
}

func fixedVersion(coords []coordinate) string {
	for _, coord := range coords {
		for _, remedy := range coord.Remedies {
			if remedy.Details.UpgradePackage != "" {
				return remedy.Details.UpgradePackage
			}
		}
	}
	return ""
}

func packageName(coords []coordinate) string {
	for _, coord := range coords {
		for _, rep := range coord.Representations {
			if rep.Dependency.PackageName == "" {
				continue
			}
			return rep.Dependency.PackageName
		}
	}
	return ""
}

func vulnerableVersion(coords []coordinate) string {
	for _, coord := range coords {
		for _, rep := range coord.Representations {
			if rep.Dependency.PackageVersion != "" {
				return rep.Dependency.PackageVersion
			}
		}
	}
	return ""
}

func introducedThrough(coords []coordinate) string {
	for _, coord := range coords {
		for _, rep := range coord.Representations {
			if rep.Dependency.PackageName != "" || rep.Dependency.PackageVersion != "" {
				return strings.TrimSpace(rep.Dependency.PackageName + " " + rep.Dependency.PackageVersion)
			}
		}
	}
	return ""
}

func problemTitle(problems []problem) string {
	for _, problem := range problems {
		if problem.Title != "" {
			return problem.Title
		}
	}
	return ""
}

func firstProblemID(problems []problem) string {
	for _, problem := range problems {
		if problem.ID != "" {
			return problem.ID
		}
	}
	return ""
}

func firstProblemSeverity(problems []problem) string {
	for _, problem := range problems {
		if problem.Severity != "" {
			return problem.Severity
		}
	}
	return ""
}

func (c *Client) issueAPIURL(issueID string) string {
	u, err := c.restBase.Parse(fmt.Sprintf("orgs/%s/issues/%s", c.orgID, issueID))
	if err != nil {
		return ""
	}
	query := u.Query()
	query.Set("version", issuesAPIVersion)
	u.RawQuery = query.Encode()
	return u.String()
}

func (c *Client) issueUIURL(orgSlug, projectID, issueKey string) string {
	if strings.TrimSpace(orgSlug) == "" || strings.TrimSpace(projectID) == "" || strings.TrimSpace(issueKey) == "" {
		return ""
	}

	u, err := url.Parse("https://app.snyk.io")
	if err != nil {
		return ""
	}
	u.Path = fmt.Sprintf("/org/%s/project/%s", orgSlug, projectID)
	u.Fragment = "issue-" + issueKey
	return u.String()
}

func coalesce(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func exploitMaturity(levels []maturityLevel) string {
	out := make([]string, 0, len(levels))
	for _, level := range levels {
		value := strings.TrimSpace(level.Level)
		if value == "" {
			continue
		}
		if format := strings.TrimSpace(level.Format); format != "" {
			out = append(out, format+": "+value)
			continue
		}
		out = append(out, value)
	}
	return strings.Join(out, ", ")
}

func coordinateResolved(coords []coordinate) bool {
	if len(coords) == 0 {
		return false
	}
	for _, coord := range coords {
		if !strings.EqualFold(coord.State, "resolved") {
			return false
		}
	}
	return true
}

func sourceLocation(coords []coordinate) sourceLocationRepresentation {
	for _, coord := range coords {
		for _, rep := range coord.Representations {
			if rep.SourceLocation.File != "" {
				return rep.SourceLocation
			}
		}
	}
	return sourceLocationRepresentation{}
}

// isActiveProjectStatus returns true for projects that are being monitored.
// Snyk uses "active" for monitored projects and "inactive" for de-activated ones.
// An empty status is treated as active to be forward-compatible with API responses
// that omit the field.
func isActiveProjectStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "inactive":
		return false
	default:
		return true
	}
}

func projectRepository(name, origin string) string {
	switch origin {
	case "github", "gitlab", "bitbucket", "azure-repos":
	default:
		return ""
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if idx := strings.Index(name, "("); idx > 0 {
		name = strings.TrimSpace(name[:idx])
	}
	return name
}
