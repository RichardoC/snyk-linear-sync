package linear

import (
	"context"
	"fmt"
	"time"

	gqlclient "git.sr.ht/~emersion/gqlclient"
	linearapi "github.com/guillermo/linear/linear-api"

	"github.com/RichardoC/snyk-linear-sync/internal/model"
)

// LoadSnapshotUpdatedSince returns Snyk-managed Linear issues whose updatedAt
// is >= since, using a server-side IssueFilter so we don't download the full
// 15k-issue snapshot just to narrow it client-side. This is the difference
// between ~150 paginated list calls + thousands of history calls (rate-limit
// blowing up) and a handful of pages.
//
// The filter mirrors loadIssues' team + (title-prefix OR description-marker)
// predicate and adds updatedAt >= since. State-type filtering is left to the
// caller (client-side) because Linear's WorkflowStateFilter.Type comparator
// is a StringComparator without a convenient "not in" for terminal types.
func (c *Client) LoadSnapshotUpdatedSince(ctx context.Context, since time.Time) ([]model.ExistingIssue, error) {
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
	var nodes []linearIssueNode

	for {
		op := gqlclient.NewOperation(`
query existingIssuesSince($filter: IssueFilter!, $after: String) {
  issues(first: 100, after: $after, filter: $filter) {
    nodes {
      id
      identifier
      title
      description
      url
      priority
      dueDate
      state {
        id
        name
      }
      labels {
        nodes {
          id
          name
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}`)
		op.Var("filter", filter)
		op.Var("after", after)

		var resp struct {
			Issues struct {
				Nodes    []linearIssueNode `json:"nodes"`
				PageInfo struct {
					HasNextPage bool    `json:"hasNextPage"`
					EndCursor   *string `json:"endCursor"`
				} `json:"pageInfo"`
			} `json:"issues"`
		}
		if err := c.execute(ctx, op, &resp); err != nil {
			return nil, fmt.Errorf("fetch Linear issues updated since %s: %w", sinceStr, err)
		}

		nodes = append(nodes, resp.Issues.Nodes...)

		if !resp.Issues.PageInfo.HasNextPage || resp.Issues.PageInfo.EndCursor == nil {
			break
		}
		after = resp.Issues.PageInfo.EndCursor
	}

	var out []model.ExistingIssue
	for _, n := range nodes {
		out = append(out, linearIssueToModel(n))
	}
	return out, nil
}
