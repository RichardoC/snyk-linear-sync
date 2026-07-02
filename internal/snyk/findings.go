package snyk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	snyksdk "github.com/pavel-snyk/snyk-sdk-go/v2/snyk"

	"github.com/RichardoC/snyk-linear-sync/internal/cache"
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
	CreatedAt         string          `json:"created_at"`
	UpdatedAt         string          `json:"updated_at"`
	EffectiveSeverity string          `json:"effective_severity_level"`
	Ignored           bool            `json:"ignored"`
	Status            string          `json:"status"`
	Title             string          `json:"title"`
	Key               string          `json:"key"`
	Type              string          `json:"type"`
	ExploitDetails    exploitDetails  `json:"exploit_details"`
	Problems          []problem       `json:"problems"`
	Coordinates       []coordinate    `json:"coordinates"`
	Resolution        resolution      `json:"resolution"`
	Classes           []classEntry    `json:"classes"`
	Description       string          `json:"description"`
	Severities        []severityEntry `json:"severities"`
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

// classEntry is a Snyk weakness class attached to an issue. The ID is the
// durable identifier such as "CWE-22" and Source identifies the taxonomy
// (e.g. "CWE"). The Snyk REST schema (Class) exposes id, source, type, and
// url only — there is no title field — so callers should treat the ID as the
// displayable identifier.
type classEntry struct {
	ID     string `json:"id"`
	Source string `json:"source"`
}

// severityEntry is one CVSS score reported for an issue. Snyk can emit
// several entries from different sources (e.g. "Snyk", "NVD", "Red Hat")
// and CVSS versions (3.1, 4.0); selectCVSS picks one for display.
type severityEntry struct {
	Source string   `json:"source"`
	Score  *float64 `json:"score"`
}

type coordinate struct {
	IsFixableManually   bool             `json:"is_fixable_manually"`
	IsFixableSnyk       bool             `json:"is_fixable_snyk"`
	IsFixableUpstream   bool             `json:"is_fixable_upstream"`
	IsPatchable         bool             `json:"is_patchable"`
	IsPinnable          bool             `json:"is_pinnable"`
	IsUpgradeable       bool             `json:"is_upgradeable"`
	State               string           `json:"state"`
	LastResolvedAt      string           `json:"last_resolved_at"`
	LastResolvedDetails string           `json:"last_resolved_details"`
	Remedies            []remedy         `json:"remedies"`
	Representations     []representation `json:"representations"`
}

type remedy struct {
	Description string        `json:"description"`
	Details     remedyDetails `json:"details"`
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
//  1. Flat:   {"created": "...", "expires": "...", ...}
//  2. Nested: {"*": {"created": "...", "expires": "...", ...}}
//
// The custom UnmarshalJSON tries both formats and only extracts the fields
// we need (created, expires, and disregardIfFixable).
// projectIssueKey is the composite key for looking up v1 ignore metadata.
// The same Snyk vulnerability key can appear in multiple projects with
// different ignore expiries, so the project ID must be part of the key to
// avoid cross-project collisions.
type projectIssueKey struct {
	ProjectID string
	IssueKey  string
}

type v1IgnoreEntry struct {
	Created            string `json:"created"`
	Expires            string `json:"expires"`
	DisregardIfFixable bool   `json:"disregardIfFixable"`
}

func (e *v1IgnoreEntry) UnmarshalJSON(data []byte) error {
	// Try nested format first: {"*": {...}} or {"path": {...}}
	var nested map[string]struct {
		Created            string `json:"created"`
		Expires            string `json:"expires"`
		DisregardIfFixable bool   `json:"disregardIfFixable"`
	}
	if err := json.Unmarshal(data, &nested); err == nil && len(nested) > 0 {
		for _, details := range nested {
			e.Created = details.Created
			e.Expires = details.Expires
			e.DisregardIfFixable = details.DisregardIfFixable
			return nil
		}
	}

	// Try flat format: {...}
	var flat struct {
		Created            string `json:"created"`
		Expires            string `json:"expires"`
		DisregardIfFixable bool   `json:"disregardIfFixable"`
	}
	if err := json.Unmarshal(data, &flat); err == nil {
		e.Created = flat.Created
		e.Expires = flat.Expires
		e.DisregardIfFixable = flat.DisregardIfFixable
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
	// Build a lookup from issue key / issue ID -> ignore metadata across all
	// pages. We cache v1 ignores per project ID to avoid redundant API calls
	// when the same project spans multiple pages of issues.
	//
	// We fetch v1 ignore metadata for all projects that appear in the issues
	// pages, not just those with currently-ignored issues. This ensures we
	// preserve the snooze expiry for due date calculation even after a timed
	// ignore expires (the REST API flips ignored=false but the v1 record
	// persists), and also captures disregardIfFixable for "ignore until fix
	// available" ignores.
	//
	// Keyed by (projectID, issueKey) because the same vulnerability key can
	// appear in multiple projects with different ignore expiries. Using just
	// the issueKey caused cross-project collisions where whichever project was
	// processed last overwrote the others, producing flip-flopping due dates.
	ignoreMetaByProjectIssue := make(map[projectIssueKey]ignoreMetadata)
	v1IgnoresCache := make(map[string]v1ProjectIgnores)

	nextCursor := ""
	for {
		page, cursor, err := c.listIssuesPage(ctx, nextCursor)
		if err != nil {
			return model.SnykSnapshot{}, err
		}

		// Collect all project IDs that appear in this page so we can fetch
		// v1 ignore metadata (expiration dates and disregardIfFixable).
		projectIDsInPage := make(map[string]struct{})
		for _, issue := range page {
			projectID := issue.Relationships.ScanItem.Data.ID
			if projectID != "" {
				projectIDsInPage[projectID] = struct{}{}
			}
		}

		for projectID := range projectIDsInPage {
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
				if meta := maxExpiryIgnoreMeta(entries); !meta.ExpiresAt.IsZero() || meta.DisregardIfFixable {
					ignoreMetaByProjectIssue[projectIssueKey{ProjectID: projectID, IssueKey: issueKey}] = meta
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
			createdAt, err := parseIssueCreatedAt(issue.Attributes.CreatedAt)
			if err != nil {
				return model.SnykSnapshot{}, fmt.Errorf("parse Snyk issue created_at for %s: %w", issue.ID, err)
			}

			ignoreMeta, ok := ignoreMetaByProjectIssue[projectIssueKey{ProjectID: projectID, IssueKey: issueKey}]
			// The v1 API uses either SNYK-* keys or issue UUIDs as top-level keys
			// depending on project type. If the first lookup failed, try the issue ID.
			if !ok && issue.ID != "" && issueKey != issue.ID {
				ignoreMeta, ok = ignoreMetaByProjectIssue[projectIssueKey{ProjectID: projectID, IssueKey: issue.ID}]
			}

			finding := c.findingFromIssue(issue, projectID, project, orgSlug, issueKey, createdAt, ignoreMeta)

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

// findingFromIssue maps a decoded Snyk REST issue resource into the sync's
// model.Finding shape. It is split out from LoadSnapshot so the JSON decode
// → Finding mapping is unit-testable against a response fixture without
// needing a live Snyk org (see TestFindingFromIssueDecodesRealIssueShape).
// createdAt is passed in rather than re-parsed because LoadSnapshot already
// validates it.
func (c *Client) findingFromIssue(
	issue issueResource,
	projectID string,
	project projectRef,
	orgSlug, issueKey string,
	createdAt time.Time,
	ignoreMeta ignoreMetadata,
) model.Finding {
	source := sourceLocation(issue.Attributes.Coordinates)
	return model.Finding{
		Fingerprint:        model.Fingerprint(projectID, issue.ID),
		SnykIssueID:        issue.ID,
		SnykIssueKey:       issueKey,
		IssueType:          strings.ToLower(strings.TrimSpace(issue.Attributes.Type)),
		CreatedAt:          createdAt,
		ProjectID:          projectID,
		ProjectName:        project.Name,
		ProjectOrigin:      project.Origin,
		ProjectReference:   project.TargetReference,
		ProjectTargetFile:  project.TargetFile,
		Repository:         project.Repository,
		IssueTitle:         coalesce(issue.Attributes.Title, problemTitle(issue.Attributes.Problems), issue.Attributes.Key, issue.ID),
		Severity:           coalesce(issue.Attributes.EffectiveSeverity, firstProblemSeverity(issue.Attributes.Problems), "unknown"),
		CVSS:               selectCVSS(issue.Attributes.Severities),
		ExploitMaturity:    exploitMaturity(issue.Attributes.ExploitDetails.MaturityLevels),
		PackageName:        packageName(issue.Attributes.Coordinates),
		VulnerableVersion:  vulnerableVersion(issue.Attributes.Coordinates),
		FixedVersion:       fixedVersion(issue.Attributes.Coordinates),
		IssueURL:           c.issueUIURL(orgSlug, projectID, issueKey),
		IssueAPIURL:        c.issueAPIURL(issue.ID),
		Status:             mapStatus(issue.Attributes, ignoreMeta.ExpiresAt, ignoreMeta.DisregardIfFixable),
		IntroducedThrough:  introducedThrough(issue.Attributes.Coordinates),
		SourceFile:         source.File,
		SourceCommitID:     source.CommitID,
		SourceLineStart:    source.Region.Start.Line,
		SourceColumnStart:  source.Region.Start.Column,
		SourceLineEnd:      source.Region.End.Line,
		SourceColumnEnd:    source.Region.End.Column,
		IgnoreExpiresAt:    ignoreMeta.ExpiresAt,
		DisregardIfFixable: ignoreMeta.DisregardIfFixable,
		Classes:            issueClasses(issue.Attributes.Classes),
		CVEs:               cveIDs(issue.Attributes.Problems),
		Description:        strings.TrimSpace(issue.Attributes.Description),
		Remediation:        remediationDescription(issue.Attributes.Coordinates),
		HasCoordinates:     len(issue.Attributes.Coordinates) > 0,
		IsFixableManually:  anyFixable(issue.Attributes.Coordinates, func(c coordinate) bool { return c.IsFixableManually }),
		IsFixableSnyk:      anyFixable(issue.Attributes.Coordinates, func(c coordinate) bool { return c.IsFixableSnyk }),
		IsFixableUpstream:  anyFixable(issue.Attributes.Coordinates, func(c coordinate) bool { return c.IsFixableUpstream }),
		IsPatchable:        anyFixable(issue.Attributes.Coordinates, func(c coordinate) bool { return c.IsPatchable }),
		IsPinnable:         anyFixable(issue.Attributes.Coordinates, func(c coordinate) bool { return c.IsPinnable }),
		IsUpgradeable:      anyFixable(issue.Attributes.Coordinates, func(c coordinate) bool { return c.IsUpgradeable }),
	}
}

func (c *Client) fetchProjectIgnores(ctx context.Context, projectID string) (v1ProjectIgnores, error) {
	var cached v1ProjectIgnores
	if c.cache != nil {
		cachedMeta, err := c.cache.LoadIgnores(ctx, projectID)
		if err != nil {
			c.logger.Warn("failed to load cached v1 ignores",
				"project_id", projectID,
				"error", err,
			)
		} else if len(cachedMeta) > 0 {
			cached = cacheIgnoresToV1(cachedMeta)
		}
	}

	// The Snyk v1 ignores endpoint sometimes returns inconsistent expiry dates
	// for the same ignore. Make several attempts and take the maximum expiry
	// seen across all successful responses so the first run is seeded with the
	// highest reasonable value. This is still Snyk-only data and does not trust
	// mutable Linear state.
	const maxAttempts = 3
	apiIgnores, err := c.fetchProjectIgnoresWithRetry(ctx, projectID, maxAttempts)
	if err != nil {
		if len(cached) > 0 {
			c.logger.Warn("v1 ignores API failed, falling back to cached ignores",
				"project_id", projectID,
				"error", err,
			)
			return cached, nil
		}
		return nil, err
	}

	merged := mergeIgnores(apiIgnores, cached)

	if c.cache != nil {
		if err := c.cache.SaveIgnores(ctx, projectID, v1IgnoresToCache(merged)); err != nil {
			c.logger.Warn("failed to cache v1 ignores",
				"project_id", projectID,
				"error", err,
			)
		}
	}

	if len(cached) == 0 && len(merged) > 0 {
		c.logger.Info("seeded v1 ignores cache from API",
			"project_id", projectID,
			"count", len(merged),
		)
	} else if len(cached) > 0 {
		cachedMeta := maxExpiryIgnoreMeta(flattenIgnores(cached))
		mergedMeta := maxExpiryIgnoreMeta(flattenIgnores(merged))
		if len(merged) > len(cached) {
			c.logger.Info("v1 ignores cache gained new keys from API",
				"project_id", projectID,
				"cached_count", len(cached),
				"merged_count", len(merged),
			)
		}
		if !mergedMeta.ExpiresAt.IsZero() && !mergedMeta.ExpiresAt.Equal(cachedMeta.ExpiresAt) {
			c.logger.Info("v1 ignores merged expiry changed for project",
				"project_id", projectID,
				"cached_expiry", cachedMeta.ExpiresAt,
				"merged_expiry", mergedMeta.ExpiresAt,
			)
		}
	}

	return merged, nil
}

// flattenIgnores returns all entries from a v1ProjectIgnores map as a single
// slice so maxExpiryIgnoreMeta can be applied across a whole project.
func flattenIgnores(ignores v1ProjectIgnores) []v1IgnoreEntry {
	var out []v1IgnoreEntry
	for _, entries := range ignores {
		out = append(out, entries...)
	}
	return out
}

func (c *Client) fetchProjectIgnoresWithRetry(ctx context.Context, projectID string, maxAttempts int) (v1ProjectIgnores, error) {
	endpoint, err := c.v1Base.Parse(fmt.Sprintf("org/%s/project/%s/ignores", c.orgID, projectID))
	if err != nil {
		return nil, fmt.Errorf("build v1 ignores URL: %w", err)
	}

	var apiIgnores v1ProjectIgnores
	var lastErr error

	for attempt := range maxAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			c.logger.Warn("v1 ignores request failed, retrying",
				"project_id", projectID,
				"attempt", attempt+1,
				"max_attempts", maxAttempts,
				"error", err,
			)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			c.logger.Warn("v1 ignores endpoint returned 404, treating project ignores as unavailable",
				"project_id", projectID,
			)
			if len(apiIgnores) > 0 {
				return apiIgnores, nil
			}
			return v1ProjectIgnores{}, nil
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("snyk v1 ignores API %s %s failed with %d: %s",
				resp.Request.Method, resp.Request.URL, resp.StatusCode, strings.TrimSpace(string(body)))
			c.logger.Warn("v1 ignores request failed, retrying",
				"project_id", projectID,
				"attempt", attempt+1,
				"max_attempts", maxAttempts,
				"status", resp.StatusCode,
			)
			continue
		}

		var attemptIgnores v1ProjectIgnores
		if err := json.Unmarshal(body, &attemptIgnores); err != nil {
			lastErr = fmt.Errorf("decode v1 ignores: %w", err)
			c.logger.Warn("v1 ignores decode failed, retrying",
				"project_id", projectID,
				"attempt", attempt+1,
				"max_attempts", maxAttempts,
				"error", err,
			)
			continue
		}

		apiIgnores = mergeIgnores(apiIgnores, attemptIgnores)
		lastErr = nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("v1 ignores API failed after %d attempts: %w", maxAttempts, lastErr)
	}

	return apiIgnores, nil
}

// mergeIgnores combines live API ignores with cached ignores. For each issue
// key, it synthesizes a single merged entry with:
//   - the maximum expiry seen from either source (high-water mark), so the
//     due date never moves earlier because of a stale API response;
//   - the most recently created timestamp and disregard-if-fixable flag from
//     the source that has the most recent created timestamp.
//
// Cached entries are kept for keys that disappear from the API response so a
// partial response does not wipe stable data.
func mergeIgnores(api, cached v1ProjectIgnores) v1ProjectIgnores {
	allKeys := make(map[string]struct{}, len(api)+len(cached))
	for key := range api {
		allKeys[key] = struct{}{}
	}
	for key := range cached {
		allKeys[key] = struct{}{}
	}

	merged := make(v1ProjectIgnores, len(allKeys))
	for key := range allKeys {
		apiMeta := maxExpiryIgnoreMeta(api[key])
		cachedMeta := maxExpiryIgnoreMeta(cached[key])

		var disregard bool
		var createdAt time.Time
		if apiMeta.CreatedAt.After(cachedMeta.CreatedAt) {
			disregard = apiMeta.DisregardIfFixable
			createdAt = apiMeta.CreatedAt
		} else {
			disregard = cachedMeta.DisregardIfFixable
			createdAt = cachedMeta.CreatedAt
		}

		maxExpiry := apiMeta.ExpiresAt
		if cachedMeta.ExpiresAt.After(maxExpiry) {
			maxExpiry = cachedMeta.ExpiresAt
		}

		if maxExpiry.IsZero() && !disregard {
			continue
		}

		entry := v1IgnoreEntry{
			DisregardIfFixable: disregard,
		}
		if !maxExpiry.IsZero() {
			entry.Expires = maxExpiry.UTC().Format(time.RFC3339)
		}
		if !createdAt.IsZero() {
			entry.Created = createdAt.UTC().Format(time.RFC3339)
		}
		merged[key] = []v1IgnoreEntry{entry}
	}

	return merged
}

// maxExpiryIgnoreMeta returns the maximum ignore expiry and the metadata of
// the most recently created entry. These may come from different entries, so
// the returned ExpiresAt is the high-water mark while DisregardIfFixable is
// the value from the latest created entry.
func maxExpiryIgnoreMeta(entries []v1IgnoreEntry) ignoreMetadata {
	var meta ignoreMetadata
	var latestCreated time.Time
	var maxExpiry time.Time

	for _, entry := range entries {
		createdAt, errCreated := parseTime(entry.Created)
		if errCreated == nil {
			if latestCreated.IsZero() || createdAt.After(latestCreated) {
				latestCreated = createdAt
				meta.CreatedAt = createdAt
				meta.DisregardIfFixable = entry.DisregardIfFixable
			}
		}

		if entry.Expires == "" {
			continue
		}
		expiresAt, err := parseTime(entry.Expires)
		if err != nil {
			continue
		}
		if expiresAt.After(maxExpiry) {
			maxExpiry = expiresAt
			meta.ExpiresAt = expiresAt
		}
	}

	return meta
}

// v1IgnoresToCache converts v1 ignore entries into a cache-friendly map keyed
// by issue key. Only entries with an expiry or a disregard-if-fixable flag are
// kept, because those are the only fields the sync uses.
func v1IgnoresToCache(ignores v1ProjectIgnores) map[string]cache.IgnoreMeta {
	out := make(map[string]cache.IgnoreMeta, len(ignores))
	for issueKey, entries := range ignores {
		meta := maxExpiryIgnoreMeta(entries)
		if meta.ExpiresAt.IsZero() && !meta.DisregardIfFixable {
			continue
		}
		out[issueKey] = cache.IgnoreMeta{
			IssueKey:           issueKey,
			ExpiresAt:          meta.ExpiresAt,
			DisregardIfFixable: meta.DisregardIfFixable,
			CreatedAt:          meta.CreatedAt,
		}
	}
	return out
}

// cacheIgnoresToV1 reconstructs the v1 ignore response shape from cached
// metadata. Each cached issue key becomes a single-entry array so that the
// rest of the sync logic can use maxExpiryIgnoreMeta unchanged.
func cacheIgnoresToV1(cached map[string]cache.IgnoreMeta) v1ProjectIgnores {
	out := make(v1ProjectIgnores, len(cached))
	for issueKey, meta := range cached {
		entry := v1IgnoreEntry{
			DisregardIfFixable: meta.DisregardIfFixable,
		}
		if !meta.ExpiresAt.IsZero() {
			entry.Expires = meta.ExpiresAt.UTC().Format(time.RFC3339)
		}
		if !meta.CreatedAt.IsZero() {
			entry.Created = meta.CreatedAt.UTC().Format(time.RFC3339)
		}
		out[issueKey] = []v1IgnoreEntry{entry}
	}
	return out
}

// ignoreMetadata carries the v1 ignore fields that the sync logic needs:
// the snooze expiry date and whether the ignore is conditional on no fix being
// available (disregardIfFixable).
type ignoreMetadata struct {
	ExpiresAt          time.Time
	DisregardIfFixable bool
	CreatedAt          time.Time
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

func mapStatus(issue issueAttributes, ignoreExpiresAt time.Time, disregardIfFixable bool) model.FindingStatus {
	if issue.Ignored {
		// "Ignore until a fix is available" maps to FindingAwaitingFix so the
		// sync places the issue in Backlog with no due date, signalling that the
		// issue is blocked on an upstream fix. When a fix appears, Snyk flips
		// ignored=false and the next run maps it back to FindingOpen (Todo).
		if disregardIfFixable {
			return model.FindingAwaitingFix
		}
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

// issueClasses copies Snyk weakness class entries into the model shape,
// dropping empty IDs. Class entries are not deduplicated or sorted here so
// the rendering can preserve Snyk's ordering.
func issueClasses(classes []classEntry) []model.IssueClass {
	out := make([]model.IssueClass, 0, len(classes))
	for _, class := range classes {
		id := strings.TrimSpace(class.ID)
		if id == "" {
			continue
		}
		out = append(out, model.IssueClass{
			ID:     id,
			Source: strings.TrimSpace(class.Source),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// cveIDs extracts CVE identifiers from a Snyk issue's problems list. Snyk
// reports each CVE as a problem whose id is the CVE identifier (e.g.
// "CVE-2025-7783"); the problems[].source field names the reporting database
// (commonly "NVD"), not the literal string "CVE", so matching by source is
// unreliable. We therefore match on a case-insensitive "CVE-" id prefix,
// which is source-agnostic and robust.
func cveIDs(problems []problem) []string {
	seen := make(map[string]struct{}, len(problems))
	out := make([]string, 0, len(problems))
	for _, problem := range problems {
		id := strings.TrimSpace(problem.ID)
		if id == "" || !strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// anyFixable reports whether any coordinate satisfies the predicate. It is
// used to aggregate per-coordinate is_fixable_* flags into a single
// finding-level boolean.
func anyFixable(coords []coordinate, ok func(coordinate) bool) bool {
	return slices.ContainsFunc(coords, ok)
}

// selectCVSS picks a single CVSS score to display from the severities Snyk
// reports for an issue. Snyk may emit several entries from different sources
// (e.g. "Snyk", "NVD", "Red Hat") and CVSS versions (3.1, 4.0). We prefer a
// NVD score, then Red Hat, then Snyk, then any other source; within a source
// we take the highest score so a more severe, well-sourced score wins. 0 is
// returned (and the renderer omits the line) when Snyk reports no scores —
// which is legitimate for non-vulnerability issue types.
func selectCVSS(severities []severityEntry) float64 {
	const (
		scoreSnyk = iota
		scoreRedHat
		scoreNVD
		scoreOther
	)
	rank := func(source string) int {
		switch strings.ToLower(strings.TrimSpace(source)) {
		case "snyk":
			return scoreSnyk
		case "red hat":
			return scoreRedHat
		case "nvd":
			return scoreNVD
		default:
			return scoreOther
		}
	}

	var bestRank = -1
	var best float64
	found := false
	for _, sev := range severities {
		if sev.Score == nil {
			continue
		}
		score := *sev.Score
		r := rank(sev.Source)
		if !found || r < bestRank || (r == bestRank && score > best) {
			bestRank = r
			best = score
			found = true
		}
	}
	return best
}

// remediationDescription aggregates every non-empty remedy description
// across a finding's coordinates. Snyk exposes remediation prose at
// coordinates[].remedies[].description (a markdown string); there is no
// top-level remediation field on the issue resource. Code and cloud findings
// carry prose here; package_vulnerability findings usually carry only a
// details.upgrade_package (already surfaced as Fix version) and no prose.
//
// A finding can carry several distinct remedy descriptions (e.g. a cloud
// finding with Terraform, CloudFormation, and inline-rule messages). Rather
// than dropping all but the first, we collect them in Snyk's order and join
// with a blank line so the Linear ### Remediation section is self-sufficient.
// Descriptions are deduplicated by trimmed content so repeated remedies across
// coordinates collapse to one entry.
func remediationDescription(coords []coordinate) string {
	var out []string
	seen := make(map[string]struct{})
	for _, coord := range coords {
		for _, remedy := range coord.Remedies {
			desc := strings.TrimSpace(remedy.Description)
			if desc == "" {
				continue
			}
			if _, exists := seen[desc]; exists {
				continue
			}
			seen[desc] = struct{}{}
			out = append(out, desc)
		}
	}
	return strings.Join(out, "\n\n")
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
