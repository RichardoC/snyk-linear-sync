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
	if requestCount != 2 {
		t.Fatalf("requestCount = %d, want 2", requestCount)
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
