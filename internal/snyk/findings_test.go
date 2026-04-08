package snyk

import "testing"

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
