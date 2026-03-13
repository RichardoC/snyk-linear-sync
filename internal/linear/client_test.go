package linear

import (
	"slices"
	"testing"

	"github.com/RichardoC/snyk-linear-sync/internal/config"
	"github.com/RichardoC/snyk-linear-sync/internal/model"
)

func TestDesiredLabelIDsReplacesPreviousManagedLabel(t *testing.T) {
	client := &Client{
		cfg: config.LinearConfig{
			Labels: config.LabelConfig{
				Managed: "snyk-automation",
			},
		},
		managedLabelID: "label-new",
	}

	existing := model.ExistingIssue{
		ManagedLabel: "old-managed",
		Labels: []model.IssueLabel{
			{ID: "label-unrelated", Name: "customer-visible"},
			{ID: "label-old", Name: "old-managed"},
		},
	}
	desired := model.DesiredIssue{
		ManagedLabel: "snyk-automation",
	}

	labelIDs, err := client.desiredLabelIDs(existing, desired)
	if err != nil {
		t.Fatalf("desiredLabelIDs() error = %v", err)
	}
	if len(labelIDs) != 2 {
		t.Fatalf("labelIDs len = %d, want 2", len(labelIDs))
	}
	if !containsString(labelIDs, "label-unrelated") {
		t.Fatalf("labelIDs = %#v, want unrelated label preserved", labelIDs)
	}
	if !containsString(labelIDs, "label-new") {
		t.Fatalf("labelIDs = %#v, want new managed label present", labelIDs)
	}
	if containsString(labelIDs, "label-old") {
		t.Fatalf("labelIDs = %#v, want old managed label removed", labelIDs)
	}
}

func TestDesiredLabelIDsRemovesManagedLabelWhenDisabled(t *testing.T) {
	client := &Client{}
	existing := model.ExistingIssue{
		ManagedLabel: "snyk-automation",
		Labels: []model.IssueLabel{
			{ID: "label-unrelated", Name: "customer-visible"},
			{ID: "label-managed", Name: "snyk-automation"},
		},
	}

	labelIDs, err := client.desiredLabelIDs(existing, model.DesiredIssue{})
	if err != nil {
		t.Fatalf("desiredLabelIDs() error = %v", err)
	}
	if len(labelIDs) != 1 || labelIDs[0] != "label-unrelated" {
		t.Fatalf("labelIDs = %#v, want only unrelated label", labelIDs)
	}
}

func TestExtractFingerprintPrefersMetadataBlock(t *testing.T) {
	description := "## Example\n\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\nmanaged_label: snyk-automation\n-->"

	got := extractFingerprint(description)

	if got != "snyk:project-a:issue-1" {
		t.Fatalf("extractFingerprint() = %q, want %q", got, "snyk:project-a:issue-1")
	}
}

func containsString(values []string, want string) bool {
	return slices.Contains(values, want)
}
