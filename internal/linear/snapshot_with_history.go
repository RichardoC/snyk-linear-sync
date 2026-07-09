package linear

import (
	"context"
	"fmt"
	"time"

	gqlclient "git.sr.ht/~emersion/gqlclient"
	linearapi "github.com/guillermo/linear/linear-api"
)

// IssueWithHistory is an existing issue plus its pre-fetched history entries.
// Fetching history inline with the issues query eliminates the per-ticket
// history API calls that made the original detection tool impractical at
// scale (thousands of tickets → thousands of calls → Linear rate-limit wall).
type IssueWithHistory struct {
	ID          string
	Identifier  string
	Title       string
	URL         string
	Description string
	StateName   string
	History     []HistoryEntry
}

// LoadSnapshotWithHistorySince fetches Snyk-managed Linear issues updated since
// the given cutoff, WITH their history entries inlined in the same query.
//
// This is the optimized path for reopen detection: instead of
//
//	pages_of_issues + N_per_ticket_history_calls
//
// it costs only
//
//	pages_of_issues_with_history
//
// — typically a 20-100x reduction in API calls for large teams.
//
// The issue page size is reduced to 50 (from the usual 100) to keep GraphQL
// complexity within Linear's budget when nesting the history connection.
// History is capped at 100 entries per issue; tickets with more than 100
// history entries are rare and the reopen signature is usually recent, so
// this is sufficient for detection. Callers can fall back to
// LoadIssueHistory for any ticket needing deeper history.
func (c *Client) LoadSnapshotWithHistorySince(ctx context.Context, since time.Time) ([]IssueWithHistory, error) {
	if err := c.resolveTeam(ctx); err != nil {
		return nil, err
	}
	sinceStr := since.UTC().Format(time.RFC3339)
	filter := linearapi.IssueFilter{
		Team: &linearapi.TeamFilter{
			Id: &linearapi.IDComparator{Eq: c.teamID()},
		},
		UpdatedAt: &linearapi.DateComparator{
			Gte: (*linearapi.DateTime)(&sinceStr),
		},
		Or: []linearapi.IssueFilter{
			{
				Title: &linearapi.StringComparator{
					StartsWith: new(titlePrefix),
				},
			},
			{
				Description: &linearapi.NullableStringComparator{
					Contains: new(metadataHeader),
				},
			},
		},
	}

	var after *string
	var out []IssueWithHistory
	page := 0

	for {
		op := gqlclient.NewOperation(`
query existingIssuesWithHistory($filter: IssueFilter!, $after: String) {
  issues(first: 50, after: $after, filter: $filter) {
    nodes {
      id
      identifier
      title
      description
      url
      state { id name }
      history(first: 100) {
        nodes {
          createdAt
          actor { name }
          fromState { name type }
          toState { name type }
          updatedDescription
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}`)
		op.Var("filter", filter)
		op.Var("after", after)

		var resp struct {
			Issues struct {
				Nodes []struct {
					ID          string  `json:"id"`
					Identifier  string  `json:"identifier"`
					Title       string  `json:"title"`
					Description *string `json:"description"`
					URL         string  `json:"url"`
					State       struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"state"`
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
					} `json:"history"`
				} `json:"nodes"`
				PageInfo struct {
					HasNextPage bool    `json:"hasNextPage"`
					EndCursor   *string `json:"endCursor"`
				} `json:"pageInfo"`
			} `json:"issues"`
		}
		if err := c.execute(ctx, op, &resp); err != nil {
			return nil, fmt.Errorf("fetch Linear issues+history (page %d): %w", page, err)
		}

		for _, n := range resp.Issues.Nodes {
			iwh := IssueWithHistory{
				ID:         n.ID,
				Identifier: n.Identifier,
				Title:      n.Title,
				URL:        n.URL,
				StateName:  n.State.Name,
				History:    make([]HistoryEntry, 0, len(n.History.Nodes)),
			}
			if n.Description != nil {
				iwh.Description = *n.Description
			}
			for _, h := range n.History.Nodes {
				entry := HistoryEntry{CreatedAt: parseHistoryTime(h.CreatedAt)}
				if h.Actor != nil {
					entry.ActorName = h.Actor.Name
				}
				if h.FromState != nil {
					entry.FromStateName = h.FromState.Name
					entry.FromStateType = h.FromState.Type
				}
				if h.ToState != nil {
					entry.ToStateName = h.ToState.Name
					entry.ToStateType = h.ToState.Type
				}
				if h.UpdatedDescription != nil {
					entry.UpdatedDescription = *h.UpdatedDescription
				}
				iwh.History = append(iwh.History, entry)
			}
			out = append(out, iwh)
		}
		page++

		if !resp.Issues.PageInfo.HasNextPage || resp.Issues.PageInfo.EndCursor == nil {
			break
		}
		after = resp.Issues.PageInfo.EndCursor
	}

	return out, nil
}
