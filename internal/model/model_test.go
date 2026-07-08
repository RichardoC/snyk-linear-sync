package model

import "testing"

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name        string
		projectID   string
		issueID     string
		locationKey string
		want        string
	}{
		{"coarse (no location)", "proj-a", "issue-1", "", "snyk:proj-a:issue-1"},
		{"code location", "proj-a", "issue-1", "e2e/prerequisite_gate.py", "snyk:proj-a:issue-1:e2e/prerequisite_gate.py"},
		{"dependency location", "proj-a", "issue-1", "lodash@4.17.21", "snyk:proj-a:issue-1:lodash@4.17.21"},
		{"empty issueID with location", "proj-a", "", "file.py", "snyk:proj-a::file.py"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Fingerprint(tt.projectID, tt.issueID, tt.locationKey)
			if got != tt.want {
				t.Fatalf("Fingerprint(%q, %q, %q) = %q, want %q", tt.projectID, tt.issueID, tt.locationKey, got, tt.want)
			}
		})
	}
}

func TestCoarseFingerprint(t *testing.T) {
	tests := []struct {
		name string
		fp   string
		want string
	}{
		{"fine-grained (code)", "snyk:proj-a:issue-1:e2e/prerequisite_gate.py", "snyk:proj-a:issue-1"},
		{"fine-grained (dep)", "snyk:proj-a:issue-1:lodash@4.17.21", "snyk:proj-a:issue-1"},
		{"already coarse", "snyk:proj-a:issue-1", "snyk:proj-a:issue-1"},
		{"no prefix", "random-string", "random-string"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CoarseFingerprint(tt.fp)
			if got != tt.want {
				t.Fatalf("CoarseFingerprint(%q) = %q, want %q", tt.fp, got, tt.want)
			}
		})
	}
}

