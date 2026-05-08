package snyk

import (
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
	got := mapStatus(issue, future)
	if got != model.FindingOpen {
		t.Fatalf("mapStatus() = %q, want %q for temporary ignore", got, model.FindingOpen)
	}
}

func TestMapStatusPermanentIgnoreCancelled(t *testing.T) {
	issue := issueAttributes{
		Ignored: true,
		Status:  "open",
	}
	got := mapStatus(issue, time.Time{})
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
	got := mapStatus(issue, past)
	if got != model.FindingIgnored {
		t.Fatalf("mapStatus() = %q, want %q for expired temporary ignore", got, model.FindingIgnored)
	}
}

func TestLatestIgnoreExpiry(t *testing.T) {
	cases := []struct {
		name    string
		entries []v1IgnoreEntry
		want    time.Time
	}{
		{
			name: "single temporary ignore",
			entries: []v1IgnoreEntry{
				{Created: "2026-03-18T12:00:00Z", Expires: "2026-04-18T12:00:00Z"},
			},
			want: time.Date(2026, time.April, 18, 12, 0, 0, 0, time.UTC),
		},
		{
			name: "permanent ignore no expires",
			entries: []v1IgnoreEntry{
				{Created: "2026-03-18T12:00:00Z", Expires: ""},
			},
			want: time.Time{},
		},
		{
			name: "multiple ignores picks latest",
			entries: []v1IgnoreEntry{
				{Created: "2026-03-18T12:00:00Z", Expires: "2026-04-18T12:00:00Z"},
				{Created: "2026-04-01T12:00:00Z", Expires: "2026-05-01T12:00:00Z"},
			},
			want: time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name: "latest has no expiry falls back to older",
			entries: []v1IgnoreEntry{
				{Created: "2026-03-18T12:00:00Z", Expires: "2026-04-18T12:00:00Z"},
				{Created: "2026-04-01T12:00:00Z", Expires: ""},
			},
			want: time.Time{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := latestIgnoreExpiry(tc.entries)
			if !got.Equal(tc.want) {
				t.Fatalf("latestIgnoreExpiry() = %v, want %v", got, tc.want)
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
