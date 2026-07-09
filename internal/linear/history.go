package linear

import (
	"context"
	"fmt"
	"time"

	gqlclient "git.sr.ht/~emersion/gqlclient"
)

// HistoryEntry is a single Linear issue history record, focused on the
// fields needed to detect state transitions (in particular reopens, where a
// terminal state moves back to a non-terminal state).
type HistoryEntry struct {
	CreatedAt     time.Time
	ActorName     string // empty if the change was made by an integration
	FromStateName string
	FromStateType string // Linear WorkflowState.Type: triage|backlog|unstarted|started|completed|canceled
	ToStateName   string
	ToStateType   string
	// UpdatedDescription is true when this history entry also rewrote the
	// issue description. The snyk-linear-sync rewrites the description on
	// every update, so a reopen accompanied by a description rewrite is the
	// fingerprint of the sync reopening a ticket.
	UpdatedDescription bool
}

// LoadIssueHistory returns the history entries for a single Linear issue,
// ordered oldest-first as Linear returns them. The issue id is the Linear
// node UUID (ExistingIssue.ID), not the human identifier.
func (c *Client) LoadIssueHistory(ctx context.Context, id string) ([]HistoryEntry, error) {
	if id == "" {
		return nil, fmt.Errorf("LoadIssueHistory: empty issue id")
	}

	var entries []HistoryEntry
	var after *string

	for {
		op := gqlclient.NewOperation(`
query issueHistory($id: String!, $after: String) {
  issue(id: $id) {
    history(first: 100, after: $after) {
      nodes {
        createdAt
        actor { name }
        fromState { name type }
        toState { name type }
        updatedDescription
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
}`)
		op.Var("id", id)
		op.Var("after", after)

		var resp struct {
			Issue *struct {
				History struct {
					Nodes []struct {
						CreatedAt string `json:"createdAt"`
						Actor     *struct {
							Name string `json:"name"`
						} `json:"actor"`
						FromState *struct {
							Name string `json:"name"`
							Type string `json:"type"`
						} `json:"fromState"`
						ToState *struct {
							Name string `json:"name"`
							Type string `json:"type"`
						} `json:"toState"`
						UpdatedDescription *bool `json:"updatedDescription"`
					} `json:"nodes"`
					PageInfo struct {
						HasNextPage bool    `json:"hasNextPage"`
						EndCursor   *string `json:"endCursor"`
					} `json:"pageInfo"`
				} `json:"history"`
			} `json:"issue"`
		}
		if err := c.execute(ctx, op, &resp); err != nil {
			return nil, fmt.Errorf("fetch Linear issue history for %s: %w", id, err)
		}
		if resp.Issue == nil {
			return nil, fmt.Errorf("Linear issue %s not found", id)
		}

		for _, n := range resp.Issue.History.Nodes {
			entry := HistoryEntry{CreatedAt: parseHistoryTime(n.CreatedAt)}
			if n.Actor != nil {
				entry.ActorName = n.Actor.Name
			}
			if n.FromState != nil {
				entry.FromStateName = n.FromState.Name
				entry.FromStateType = n.FromState.Type
			}
			if n.ToState != nil {
				entry.ToStateName = n.ToState.Name
				entry.ToStateType = n.ToState.Type
			}
			if n.UpdatedDescription != nil {
				entry.UpdatedDescription = *n.UpdatedDescription
			}
			entries = append(entries, entry)
		}

		if !resp.Issue.History.PageInfo.HasNextPage || resp.Issue.History.PageInfo.EndCursor == nil {
			break
		}
		after = resp.Issue.History.PageInfo.EndCursor
	}

	return entries, nil
}

func parseHistoryTime(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t
		}
	}
	return time.Time{}
}
