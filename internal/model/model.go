package model

import (
	"fmt"
	"strings"
	"time"
)

type FindingStatus string

const (
	FindingOpen        FindingStatus = "open"
	FindingAwaitingFix FindingStatus = "awaiting_fix"
	FindingSnoozed     FindingStatus = "snoozed"
	FindingFixed       FindingStatus = "fixed"
	FindingIgnored     FindingStatus = "ignored"
)

type Finding struct {
	Fingerprint        string
	SnykIssueID        string
	SnykIssueKey       string
	IssueType          string
	CreatedAt          time.Time
	ProjectID          string
	ProjectName        string
	ProjectOrigin      string
	ProjectReference   string
	ProjectTargetFile  string
	Repository         string
	IssueTitle         string
	Severity           string
	CVSS               float64
	ExploitMaturity    string
	PackageName        string
	VulnerableVersion  string
	FixedVersion       string
	IssueURL           string
	IssueAPIURL        string
	Status             FindingStatus
	IntroducedThrough  string
	SourceFile         string
	SourceCommitID     string
	SourceLineStart    int
	SourceColumnStart  int
	SourceLineEnd      int
	SourceColumnEnd    int
	IgnoreExpiresAt    time.Time
	DisregardIfFixable bool
}

type SnykSnapshot struct {
	Findings           []Finding
	ProjectIDs         map[string]struct{}
	InactiveProjectIDs map[string]struct{}
}

type IssueLabel struct {
	ID   string
	Name string
}

type IssueState string

const (
	StateTodo      IssueState = "todo"
	StateBacklog   IssueState = "backlog"
	StateDone      IssueState = "done"
	StateCancelled IssueState = "cancelled"
)

type ExistingIssue struct {
	ID            string
	Identifier    string
	URL           string
	Title         string
	Description   string
	DueDate       string
	StateID       string
	StateName     string
	Fingerprint   string
	ManagedLabels []string
	SubscriberIDs []string
	Labels        []IssueLabel
	Priority      int
}

type DesiredIssue struct {
	Fingerprint   string
	Title         string
	Description   string
	DueDate       string // effective due date written to Linear (floored to today if the raw SLA date is past)
	DueDateBase   string // raw SLA date from Snyk data (CreatedAt or IgnoreExpiresAt + offset); used for cache hashing so that the floor-to-today adjustment does not cause daily cache churn
	State         IssueState
	ManagedLabels []string
	Priority      int
	PreserveState bool
}

// IssueDiff captures which managed fields changed between the existing and
// desired Linear issue. It is used to generate human-readable change
// comments posted after each update batch.
type IssueDiff struct {
	TitleChanged       bool
	TitleFrom          string
	TitleTo            string
	DescriptionChanged bool
	DueDateChanged     bool
	DueDateFrom        string
	DueDateTo          string
	StateChanged       bool
	StateFrom          string
	StateTo            string
	PriorityChanged    bool
	PriorityFrom       int
	PriorityTo         int
	LabelsAdded        []string
	LabelsRemoved      []string
}

type IssueUpdate struct {
	Existing ExistingIssue
	Desired  DesiredIssue
	Diff     *IssueDiff
}

// NormalizeLabelName normalizes a label name for comparison.
func NormalizeLabelName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// NormalizeWorkflowStateName normalizes a Linear state name for comparison.
// It lowercases the value, strips whitespace, and maps common variants
// (e.g. "Canceled" → "cancelled") so state matching works regardless of
// how the Linear workspace is configured.
func NormalizeWorkflowStateName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "canceled":
		return "cancelled"
	default:
		return value
	}
}

// StateName returns the canonical state name for a model.IssueState.
func StateName(state IssueState) string {
	switch state {
	case StateTodo:
		return "todo"
	case StateBacklog:
		return "backlog"
	case StateDone:
		return "done"
	case StateCancelled:
		return "cancelled"
	default:
		return ""
	}
}

func Fingerprint(projectID, issueID string) string {
	return fmt.Sprintf("snyk:%s:%s", projectID, issueID)
}

func (i ExistingIssue) HasLabel(name string) bool {
	for _, label := range i.Labels {
		if label.Name == name {
			return true
		}
	}
	return false
}
