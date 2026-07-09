package snyk

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/RichardoC/snyk-linear-sync/internal/model"
)

func TestMapStatusTemporaryIgnoreOpen(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	issue := issueAttributes{
		Ignored: true,
		Status:  "open",
	}
	got := mapStatus(issue, future, false)
	if got != model.FindingOpen {
		t.Fatalf("mapStatus() = %q, want %q for temporary ignore", got, model.FindingOpen)
	}
}

func TestMapStatusPermanentIgnoreCancelled(t *testing.T) {
	issue := issueAttributes{
		Ignored: true,
		Status:  "open",
	}
	got := mapStatus(issue, time.Time{}, false)
	if got != model.FindingIgnored {
		t.Fatalf("mapStatus() = %q, want %q for permanent ignore", got, model.FindingIgnored)
	}
}

func TestMapStatusExpiredIgnoreCancelled(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	issue := issueAttributes{
		Ignored: true,
		Status:  "open",
	}
	got := mapStatus(issue, past, false)
	if got != model.FindingIgnored {
		t.Fatalf("mapStatus() = %q, want %q for expired temporary ignore", got, model.FindingIgnored)
	}
}

func TestMapStatusDisregardIfFixableAwaitingFix(t *testing.T) {
	issue := issueAttributes{
		Ignored: true,
		Status:  "open",
	}
	got := mapStatus(issue, time.Time{}, true)
	if got != model.FindingAwaitingFix {
		t.Fatalf("mapStatus() = %q, want %q for disregard-if-fixable ignore", got, model.FindingAwaitingFix)
	}
}

func TestMapStatusWontFixIsNotFixed(t *testing.T) {
	// "wont_fix" contains the substring "fix" but does NOT mean the issue
	// was fixed. It must not map to FindingFixed (Done). When ignored=false
	// and status is not resolved, it should fall through to FindingOpen.
	issue := issueAttributes{
		Ignored: false,
		Status:  "open",
		Resolution: resolution{Type: "wont_fix"},
	}
	got := mapStatus(issue, time.Time{}, false)
	if got != model.FindingOpen {
		t.Fatalf("mapStatus(wont_fix) = %q, want %q (must not be treated as fixed)", got, model.FindingOpen)
	}
}

func TestMapStatusFixedResolutionIsFixed(t *testing.T) {
	issue := issueAttributes{
		Ignored:    false,
		Status:     "open",
		Resolution: resolution{Type: "fixed"},
	}
	got := mapStatus(issue, time.Time{}, false)
	if got != model.FindingFixed {
		t.Fatalf("mapStatus(fixed) = %q, want %q", got, model.FindingFixed)
	}
}

func TestMapStatusDisregardIfFixableTakesPrecedenceOverExpiry(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	issue := issueAttributes{
		Ignored: true,
		Status:  "open",
	}
	// Even with a past expiry, disregardIfFixable returns FindingAwaitingFix.
	got := mapStatus(issue, past, true)
	if got != model.FindingAwaitingFix {
		t.Fatalf("mapStatus() = %q, want %q for disregard-if-fixable with past expiry", got, model.FindingAwaitingFix)
	}
}

func TestMaxExpiryIgnoreMeta(t *testing.T) {
	cases := []struct {
		name    string
		entries []v1IgnoreEntry
		want    ignoreMetadata
	}{
		{
			name: "single temporary ignore",
			entries: []v1IgnoreEntry{
				{Created: "2026-03-18T12:00:00Z", Expires: "2026-04-18T12:00:00Z"},
			},
			want: ignoreMetadata{
				ExpiresAt: time.Date(2026, time.April, 18, 12, 0, 0, 0, time.UTC),
				CreatedAt: time.Date(2026, time.March, 18, 12, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "permanent ignore no expires",
			entries: []v1IgnoreEntry{
				{Created: "2026-03-18T12:00:00Z", Expires: ""},
			},
			want: ignoreMetadata{
				CreatedAt: time.Date(2026, time.March, 18, 12, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "multiple ignores picks max expiry",
			entries: []v1IgnoreEntry{
				{Created: "2026-03-18T12:00:00Z", Expires: "2026-04-18T12:00:00Z"},
				{Created: "2026-04-01T12:00:00Z", Expires: "2026-05-01T12:00:00Z"},
			},
			want: ignoreMetadata{
				ExpiresAt: time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC),
				CreatedAt: time.Date(2026, time.April, 1, 12, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "max expiry can come from an older entry",
			entries: []v1IgnoreEntry{
				{Created: "2026-03-18T12:00:00Z", Expires: "2026-06-17T23:00:00Z"},
				{Created: "2026-04-01T12:00:00Z", Expires: "2026-06-14T23:00:00Z"},
			},
			want: ignoreMetadata{
				ExpiresAt:          time.Date(2026, time.June, 17, 23, 0, 0, 0, time.UTC),
				CreatedAt:          time.Date(2026, time.April, 1, 12, 0, 0, 0, time.UTC),
				DisregardIfFixable: false,
			},
		},
		{
			name: "latest has no expiry still uses max expiry",
			entries: []v1IgnoreEntry{
				{Created: "2026-03-18T12:00:00Z", Expires: "2026-04-18T12:00:00Z"},
				{Created: "2026-04-01T12:00:00Z", Expires: ""},
			},
			want: ignoreMetadata{
				ExpiresAt: time.Date(2026, time.April, 18, 12, 0, 0, 0, time.UTC),
				CreatedAt: time.Date(2026, time.April, 1, 12, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "ignore until fix available",
			entries: []v1IgnoreEntry{
				{Created: "2026-03-18T12:00:00Z", Expires: "", DisregardIfFixable: true},
			},
			want: ignoreMetadata{
				DisregardIfFixable: true,
				CreatedAt:          time.Date(2026, time.March, 18, 12, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "disregardIfFixable from latest created entry",
			entries: []v1IgnoreEntry{
				{Created: "2026-03-18T12:00:00Z", Expires: "2026-04-18T12:00:00Z", DisregardIfFixable: true},
				{Created: "2026-04-01T12:00:00Z", Expires: "2026-05-01T12:00:00Z", DisregardIfFixable: false},
			},
			want: ignoreMetadata{
				ExpiresAt:          time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC),
				CreatedAt:          time.Date(2026, time.April, 1, 12, 0, 0, 0, time.UTC),
				DisregardIfFixable: false,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := maxExpiryIgnoreMeta(tc.entries)
			if !got.ExpiresAt.Equal(tc.want.ExpiresAt) {
				t.Fatalf("maxExpiryIgnoreMeta().ExpiresAt = %v, want %v", got.ExpiresAt, tc.want.ExpiresAt)
			}
			if !got.CreatedAt.Equal(tc.want.CreatedAt) {
				t.Fatalf("maxExpiryIgnoreMeta().CreatedAt = %v, want %v", got.CreatedAt, tc.want.CreatedAt)
			}
			if got.DisregardIfFixable != tc.want.DisregardIfFixable {
				t.Fatalf("maxExpiryIgnoreMeta().DisregardIfFixable = %v, want %v", got.DisregardIfFixable, tc.want.DisregardIfFixable)
			}
		})
	}
}

func TestV1IgnoreEntryUnmarshalJSON(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want v1IgnoreEntry
	}{
		{
			name: "flat format",
			raw:  `{"created":"2026-03-18T12:00:00Z","expires":"2026-04-18T12:00:00Z"}`,
			want: v1IgnoreEntry{Created: "2026-03-18T12:00:00Z", Expires: "2026-04-18T12:00:00Z"},
		},
		{
			name: "nested format",
			raw:  `{"*":{"created":"2026-03-18T12:00:00Z","expires":"2026-04-18T12:00:00Z"}}`,
			want: v1IgnoreEntry{Created: "2026-03-18T12:00:00Z", Expires: "2026-04-18T12:00:00Z"},
		},
		{
			name: "nested format with different path key",
			raw:  `{"path1":{"created":"2026-03-18T12:00:00Z","expires":"2026-04-18T12:00:00Z"}}`,
			want: v1IgnoreEntry{Created: "2026-03-18T12:00:00Z", Expires: "2026-04-18T12:00:00Z"},
		},
		{
			name: "flat format with disregardIfFixable",
			raw:  `{"created":"2026-03-18T12:00:00Z","expires":"","disregardIfFixable":true}`,
			want: v1IgnoreEntry{Created: "2026-03-18T12:00:00Z", DisregardIfFixable: true},
		},
		{
			name: "nested format with disregardIfFixable",
			raw:  `{"*":{"created":"2026-03-18T12:00:00Z","expires":"","disregardIfFixable":true}}`,
			want: v1IgnoreEntry{Created: "2026-03-18T12:00:00Z", DisregardIfFixable: true},
		},
		{
			name: "unparsable",
			raw:  `"not an object"`,
			want: v1IgnoreEntry{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got v1IgnoreEntry
			if err := got.UnmarshalJSON([]byte(tc.raw)); err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("UnmarshalJSON() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestIsActiveProjectStatus(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		{"active", true},
		{"Active", true},
		{"ACTIVE", true},
		{"inactive", false},
		{"Inactive", false},
		{"INACTIVE", false},
		// Unknown or empty status is treated as active for forward-compatibility.
		{"", true},
		{"unknown", true},
	}
	for _, tc := range cases {
		got := isActiveProjectStatus(tc.status)
		if got != tc.want {
			t.Errorf("isActiveProjectStatus(%q) = %v, want %v", tc.status, got, tc.want)
		}
	}
}

func TestIssueClasses(t *testing.T) {
	cases := []struct {
		name    string
		classes []classEntry
		want    []model.IssueClass
	}{
		{
			name:    "nil",
			classes: nil,
			want:    nil,
		},
		{
			name: "drops empty ids",
			classes: []classEntry{
				{ID: "", Source: "CWE"},
				{ID: "CWE-22", Source: "CWE"},
			},
			want: []model.IssueClass{{ID: "CWE-22", Source: "CWE"}},
		},
		{
			name: "preserves ordering and trims whitespace",
			classes: []classEntry{
				{ID: "  CWE-22  ", Source: " CWE "},
				{ID: "CWE-78", Source: "CWE"},
			},
			want: []model.IssueClass{
				{ID: "CWE-22", Source: "CWE"},
				{ID: "CWE-78", Source: "CWE"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := issueClasses(tc.classes)
			if len(got) != len(tc.want) {
				t.Fatalf("issueClasses() = %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("issueClasses()[%d] = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestCVEIDs(t *testing.T) {
	cases := []struct {
		name     string
		problems []problem
		want     []string
	}{
		{
			name:     "no problems",
			problems: nil,
			want:     nil,
		},
		{
			name: "matches CVE id prefix regardless of source and deduplicates",
			problems: []problem{
				{ID: "SNYK-DEBIAN-ZLIB-1", Source: "SNYK"},
				{ID: "CVE-2024-12345", Source: "NVD"},
				{ID: "CVE-2024-12345", Source: "NVD"},
				{ID: "cve-2024-99999", Source: "NVD"},
				{ID: "CVE-2024-11111", Source: "Red Hat"},
				{ID: "NOT-A-CVE", Source: "CVE"},
				{ID: "", Source: "CVE"},
			},
			want: []string{"CVE-2024-12345", "cve-2024-99999", "CVE-2024-11111"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cveIDs(tc.problems)
			if len(got) != len(tc.want) {
				t.Fatalf("cveIDs() = %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("cveIDs()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestAnyFixable(t *testing.T) {
	coords := []coordinate{
		{IsFixableManually: false, IsFixableSnyk: false},
		{IsFixableManually: true, IsFixableSnyk: false},
	}
	if !anyFixable(coords, func(c coordinate) bool { return c.IsFixableManually }) {
		t.Fatal("anyFixable(IsFixableManually) = false, want true")
	}
	if anyFixable(coords, func(c coordinate) bool { return c.IsFixableSnyk }) {
		t.Fatal("anyFixable(IsFixableSnyk) = true, want false")
	}
	if anyFixable(nil, func(c coordinate) bool { return c.IsFixableSnyk }) {
		t.Fatal("anyFixable(nil) = true, want false")
	}
	upgradeOnly := []coordinate{{IsUpgradeable: true}}
	if !anyFixable(upgradeOnly, func(c coordinate) bool { return c.IsUpgradeable }) {
		t.Fatal("anyFixable(IsUpgradeable) = false, want true")
	}
	pinOnly := []coordinate{{IsPinnable: true}}
	if !anyFixable(pinOnly, func(c coordinate) bool { return c.IsPinnable }) {
		t.Fatal("anyFixable(IsPinnable) = false, want true")
	}
}

func TestRemediationDescription(t *testing.T) {
	cases := []struct {
		name   string
		coords []coordinate
		want   string
	}{
		{name: "no coordinates", coords: nil, want: ""},
		{name: "empty remedies", coords: []coordinate{{Remedies: nil}}, want: ""},
		{name: "aggregates all non-empty in order, dedupes",
			coords: []coordinate{
				{Remedies: []remedy{{Description: "  "}}},
				{Remedies: []remedy{{Description: "Upgrade pkg to 1.2.3"}}},
				{Remedies: []remedy{{Description: "Pin pkg to 1.0.0"}, {Description: "Upgrade pkg to 1.2.3"}}},
			},
			want: "Upgrade pkg to 1.2.3\n\nPin pkg to 1.0.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := remediationDescription(tc.coords)
			if got != tc.want {
				t.Fatalf("remediationDescription() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSelectCVSS(t *testing.T) {
	cases := []struct {
		name       string
		severities []severityEntry
		want       float64
	}{
		{name: "nil", severities: nil, want: 0},
		{name: "no scores", severities: []severityEntry{{Source: "NVD"}}, want: 0},
		{name: "single snyk", severities: []severityEntry{{Source: "Snyk", Score: new(7.5)}}, want: 7.5},
		{name: "prefers snyk over nvd", severities: []severityEntry{
			{Source: "NVD", Score: new(7.5)},
			{Source: "Snyk", Score: new(9.8)},
		}, want: 9.8},
		{name: "prefers red hat over nvd but not snyk", severities: []severityEntry{
			{Source: "Snyk", Score: new(9.8)},
			{Source: "Red Hat", Score: new(5.4)},
			{Source: "NVD", Score: new(6.0)},
		}, want: 9.8},
		{name: "red hat beats nvd when no snyk", severities: []severityEntry{
			{Source: "NVD", Score: new(6.0)},
			{Source: "Red Hat", Score: new(5.4)},
		}, want: 5.4},
		{name: "highest within same source wins", severities: []severityEntry{
			{Source: "Snyk", Score: new(9.3)}, // CVSSv4
			{Source: "Snyk", Score: new(9.8)}, // CVSSv3.1
		}, want: 9.8},
		{name: "falls back to other source", severities: []severityEntry{
			{Source: "SUSE", Score: new(4.2)},
		}, want: 4.2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selectCVSS(tc.severities)
			if got != tc.want {
				t.Fatalf("selectCVSS() = %v, want %v", got, tc.want)
			}
		})
	}
}

//go:fix inline
func ptr(f float64) *float64 { return new(f) }

func TestMergeIgnoresPicksLatestExpiry(t *testing.T) {
	api := v1ProjectIgnores{
		"SNYK-1": []v1IgnoreEntry{{Created: "2026-06-01T00:00:00Z", Expires: "2026-06-14T23:00:00Z"}},
	}
	cached := v1ProjectIgnores{
		"SNYK-1": []v1IgnoreEntry{{Created: "2026-05-29T00:00:00Z", Expires: "2026-06-17T23:00:00Z"}},
	}

	merged := mergeIgnores(api, cached)
	entries, ok := merged["SNYK-1"]
	if !ok {
		t.Fatal("merged missing SNYK-1")
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Expires != "2026-06-17T23:00:00Z" {
		t.Fatalf("expires = %q, want 2026-06-17T23:00:00Z", entries[0].Expires)
	}
	if entries[0].Created != "2026-06-01T00:00:00Z" {
		t.Fatalf("created = %q, want 2026-06-01T00:00:00Z (latest created from API)", entries[0].Created)
	}
}

func TestFetchProjectIgnoresRetriesAndUsesMaxExpiry(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		var expires string
		if requestCount == 1 {
			expires = "2026-06-14T23:00:00Z"
		} else {
			expires = "2026-06-17T23:00:00Z"
		}

		body := map[string][]v1IgnoreEntry{
			"SNYK-1": {
				{Created: "2026-06-01T00:00:00Z", Expires: expires},
			},
		}
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Fatalf("encode mock response: %v", err)
		}
	}))
	defer server.Close()

	base, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	c := &Client{
		httpClient: server.Client(),
		v1Base:     base,
		orgID:      "test-org",
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	ignores, err := c.fetchProjectIgnores(context.Background(), "test-project")
	if err != nil {
		t.Fatalf("fetchProjectIgnores() error = %v", err)
	}
	if requestCount != 3 {
		t.Fatalf("requestCount = %d, want 3", requestCount)
	}

	entries, ok := ignores["SNYK-1"]
	if !ok {
		t.Fatal("ignores missing SNYK-1")
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Expires != "2026-06-17T23:00:00Z" {
		t.Fatalf("expires = %q, want 2026-06-17T23:00:00Z", entries[0].Expires)
	}
}

func TestMergeIgnoresUsesLatestCreatedFromAPI(t *testing.T) {
	api := v1ProjectIgnores{
		"SNYK-1": []v1IgnoreEntry{{Created: "2026-06-15T00:00:00Z", Expires: "2026-06-14T23:00:00Z", DisregardIfFixable: true}},
	}
	cached := v1ProjectIgnores{
		"SNYK-1": []v1IgnoreEntry{{Created: "2026-05-29T00:00:00Z", Expires: "2026-06-17T23:00:00Z"}},
	}

	merged := mergeIgnores(api, cached)
	entries, ok := merged["SNYK-1"]
	if !ok {
		t.Fatal("merged missing SNYK-1")
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Expires != "2026-06-17T23:00:00Z" {
		t.Fatalf("expires = %q, want 2026-06-17T23:00:00Z", entries[0].Expires)
	}
	if entries[0].Created != "2026-06-15T00:00:00Z" {
		t.Fatalf("created = %q, want 2026-06-15T00:00:00Z (latest created from API)", entries[0].Created)
	}
	if !entries[0].DisregardIfFixable {
		t.Fatalf("DisregardIfFixable = false, want true (from latest created API entry)")
	}
}

func TestMergeIgnoresKeepsCachedKeyWhenMissingFromAPI(t *testing.T) {
	api := v1ProjectIgnores{}
	cached := v1ProjectIgnores{
		"SNYK-1": []v1IgnoreEntry{{Created: "2026-05-29T00:00:00Z", Expires: "2026-06-17T23:00:00Z"}},
	}

	merged := mergeIgnores(api, cached)
	entries, ok := merged["SNYK-1"]
	if !ok {
		t.Fatal("merged missing SNYK-1")
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Expires != "2026-06-17T23:00:00Z" {
		t.Fatalf("expires = %q, want 2026-06-17T23:00:00Z", entries[0].Expires)
	}
}

func TestLocationKey(t *testing.T) {
	tests := []struct {
		name   string
		coords []coordinate
		want   string
	}{
		{
			"source file",
			[]coordinate{{
				Representations: []representation{{
					SourceLocation: sourceLocationRepresentation{File: "e2e/prerequisite_gate.py"},
				}},
			}},
			"e2e/prerequisite_gate.py",
		},
		{
			"dependency with version",
			[]coordinate{{
				Representations: []representation{{
					Dependency: dependencyRepresentation{PackageName: "lodash", PackageVersion: "4.17.21"},
				}},
			}},
			"lodash@4.17.21",
		},
		{
			"dependency without version",
			[]coordinate{{
				Representations: []representation{{
					Dependency: dependencyRepresentation{PackageName: "lodash"},
				}},
			}},
			"lodash",
		},
		{
			"source file takes precedence over dependency",
			[]coordinate{{
				Representations: []representation{{
					Dependency:     dependencyRepresentation{PackageName: "lodash", PackageVersion: "4.17.21"},
					SourceLocation: sourceLocationRepresentation{File: "src/index.py"},
				}},
			}},
			"src/index.py",
		},
		{
			"empty coordinates",
			[]coordinate{},
			"",
		},
		{
			"no representations",
			[]coordinate{{}},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := locationKey(tt.coords)
			if got != tt.want {
				t.Fatalf("locationKey() = %q, want %q", got, tt.want)
			}
		})
	}
}
