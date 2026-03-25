package linear

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"

	gqlclient "git.sr.ht/~emersion/gqlclient"

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
		managedLabelIDs: map[string]string{
			"snyk-automation": "label-new",
			"snyk-code":       "label-code",
		},
	}

	existing := model.ExistingIssue{
		ManagedLabels: []string{"old-managed"},
		Labels: []model.IssueLabel{
			{ID: "label-unrelated", Name: "customer-visible"},
			{ID: "label-old", Name: "old-managed"},
		},
	}
	desired := model.DesiredIssue{
		ManagedLabels: []string{"snyk-automation", "snyk-code"},
	}

	labelIDs, err := client.desiredLabelIDs(existing, desired)
	if err != nil {
		t.Fatalf("desiredLabelIDs() error = %v", err)
	}
	if len(labelIDs) != 3 {
		t.Fatalf("labelIDs len = %d, want 3", len(labelIDs))
	}
	if !containsString(labelIDs, "label-unrelated") {
		t.Fatalf("labelIDs = %#v, want unrelated label preserved", labelIDs)
	}
	if !containsString(labelIDs, "label-new") {
		t.Fatalf("labelIDs = %#v, want new managed label present", labelIDs)
	}
	if !containsString(labelIDs, "label-code") {
		t.Fatalf("labelIDs = %#v, want tool label present", labelIDs)
	}
	if containsString(labelIDs, "label-old") {
		t.Fatalf("labelIDs = %#v, want old managed label removed", labelIDs)
	}
}

func TestDesiredLabelIDsRemovesManagedLabelWhenDisabled(t *testing.T) {
	client := &Client{}
	existing := model.ExistingIssue{
		ManagedLabels: []string{"snyk-automation", "snyk-code"},
		Labels: []model.IssueLabel{
			{ID: "label-unrelated", Name: "customer-visible"},
			{ID: "label-managed", Name: "snyk-automation"},
			{ID: "label-tool", Name: "snyk-code"},
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
	description := "## Example\n\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\nmanaged_labels: snyk-automation,snyk-code\n-->"

	got := extractFingerprint(description)

	if got != "snyk:project-a:issue-1" {
		t.Fatalf("extractFingerprint() = %q, want %q", got, "snyk:project-a:issue-1")
	}
}

func TestExtractManagedLabelsSupportsLegacyAndNewMetadata(t *testing.T) {
	if got := extractManagedLabels("<!-- snyk-linear-sync\nmanaged_label: snyk-automation\n-->"); !slices.Equal(got, []string{"snyk-automation"}) {
		t.Fatalf("extractManagedLabels(legacy) = %#v", got)
	}
	if got := extractManagedLabels("<!-- snyk-linear-sync\nmanaged_labels: snyk-automation,snyk-code\n-->"); !slices.Equal(got, []string{"snyk-automation", "snyk-code"}) {
		t.Fatalf("extractManagedLabels(new) = %#v", got)
	}
}

func TestActorSubscriberIDsForCreateEnabledEncodesEmptyList(t *testing.T) {
	client := &Client{
		cfg: config.LinearConfig{
			UnsubscribeActor: true,
		},
	}

	input := issueCreateInput{
		SubscriberIds: client.actorSubscriberIDsForCreate(),
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if string(raw) != `{"subscriberIds":[],"teamId":""}` {
		t.Fatalf("json.Marshal() = %s, want subscriberIds empty list", raw)
	}
}

func TestSubscriberIDsForUpdatePreservesCurrentSubscribers(t *testing.T) {
	client := &Client{
		cfg: config.LinearConfig{
			UnsubscribeActor: true,
		},
	}

	got := client.subscriberIDsForUpdate(model.ExistingIssue{
		SubscriberIDs: []string{"viewer-1", "user-2", "", "user-3"},
	})
	if got == nil {
		t.Fatal("subscriberIDsForUpdate() = nil, want non-nil")
	}
	if !slices.Equal(*got, []string{"viewer-1", "user-2", "user-3"}) {
		t.Fatalf("subscriberIDsForUpdate() = %#v, want current subscribers preserved", *got)
	}
}

func TestCreateIssuesRemovesActorAfterCreateWhenLinearAutoSubscribesThem(t *testing.T) {
	var requests []struct {
		Query     string
		Variables map[string]any
	}

	client := &Client{
		cfg: config.LinearConfig{
			TeamID:           "team-1",
			UnsubscribeActor: true,
			States: config.StateConfig{
				Todo: "Todo",
			},
		},
		gql: gqlclient.New("http://linear.test/graphql", &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var payload struct {
					Query     string         `json:"query"`
					Variables map[string]any `json:"variables"`
				}
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("ReadAll() error = %v", err)
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("json.Unmarshal() error = %v", err)
				}
				requests = append(requests, struct {
					Query     string
					Variables map[string]any
				}{
					Query:     payload.Query,
					Variables: payload.Variables,
				})

				switch {
				case strings.Contains(payload.Query, "mutation issueCreateBatch"):
					input0 := payload.Variables["input0"].(map[string]any)
					if subscriberIDs := input0["subscriberIds"]; !slices.Equal(anyStrings(subscriberIDs), []string{}) {
						t.Fatalf("create subscriberIds = %#v, want empty list", subscriberIDs)
					}
					return jsonResponse(t, `{"data":{"issueCreate0":{"success":true,"issue":{"id":"issue-1","identifier":"ENG-1"}}}}`), nil
				case strings.Contains(payload.Query, "query viewer"):
					return jsonResponse(t, `{"data":{"viewer":{"id":"actor-1"}}}`), nil
				case strings.Contains(payload.Query, "query issueSubscribers"):
					return jsonResponse(t, `{"data":{"issue0":{"id":"issue-1","subscribers":{"nodes":[{"id":"actor-1"},{"id":"user-2"}]}}}}`), nil
				case strings.Contains(payload.Query, "mutation issueUpdateBatch"):
					if got := payload.Variables["id0"]; got != "issue-1" {
						t.Fatalf("update id0 = %#v, want issue-1", got)
					}
					input0 := payload.Variables["input0"].(map[string]any)
					if subscriberIDs := anyStrings(input0["subscriberIds"]); !slices.Equal(subscriberIDs, []string{"user-2"}) {
						t.Fatalf("update subscriberIds = %#v, want actor removed and other subscribers preserved", subscriberIDs)
					}
					return jsonResponse(t, `{"data":{"issueUpdate0":{"success":true}}}`), nil
				default:
					t.Fatalf("unexpected GraphQL query: %s", payload.Query)
					return nil, nil
				}
			}),
		}),
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolvedTeam: "team-1",
		statesByName: map[string]string{"todo": "state-1"},
		statesByType: map[string]string{"unstarted": "state-1"},
	}

	err := client.CreateIssues(t.Context(), []model.DesiredIssue{{
		Fingerprint: "snyk:project-1:issue-1",
		Title:       "Snyk: example",
		Description: "body",
		State:       model.StateTodo,
		Priority:    3,
	}})
	if err != nil {
		t.Fatalf("CreateIssues() error = %v", err)
	}

	if len(requests) != 4 {
		t.Fatalf("request count = %d, want 4", len(requests))
	}
}

func TestSanitizeSubscriberIDsRemovesExcludedAndDeduplicates(t *testing.T) {
	got, removed := sanitizeSubscriberIDs([]string{" actor-1 ", "user-2", "", "user-2", "user-3"}, "actor-1")
	if !removed {
		t.Fatal("sanitizeSubscriberIDs() removed = false, want true")
	}
	if !slices.Equal(got, []string{"user-2", "user-3"}) {
		t.Fatalf("sanitizeSubscriberIDs() = %#v, want deduplicated actor-free list", got)
	}
}

func containsString(values []string, want string) bool {
	return slices.Contains(values, want)
}

func anyStrings(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			continue
		}
		out = append(out, s)
	}
	return out
}

func jsonResponse(t *testing.T, body string) *http.Response {
	t.Helper()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewBufferString(body)),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
