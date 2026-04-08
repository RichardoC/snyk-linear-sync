package model

import (
	"fmt"
	"time"
)

type FindingStatus string

const (
	FindingOpen    FindingStatus = "open"
	FindingSnoozed FindingStatus = "snoozed"
	FindingFixed   FindingStatus = "fixed"
	FindingIgnored FindingStatus = "ignored"
)

type Finding struct {
	Fingerprint       string
	SnykIssueID       string
	SnykIssueKey      string
	IssueType         string
	CreatedAt         time.Time
	ProjectID         string
	ProjectName       string
	ProjectOrigin     string
	ProjectReference  string
	ProjectTargetFile string
	Repository        string
	IssueTitle        string
	Severity          string
	CVSS              float64
	ExploitMaturity   string
	PackageName       string
	VulnerableVersion string
	FixedVersion      string
	IssueURL          string
	IssueAPIURL       string
	Status            FindingStatus
	IntroducedThrough string
	SourceFile        string
	SourceCommitID    string
	SourceLineStart   int
	SourceColumnStart int
	SourceLineEnd     int
	SourceColumnEnd   int
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
	DueDate       string
	State         IssueState
	ManagedLabels []string
	Priority      int
}

type IssueUpdate struct {
	Existing ExistingIssue
	Desired  DesiredIssue
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
