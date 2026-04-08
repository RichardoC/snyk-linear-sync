# snyk-linear-sync

Sync Snyk findings with Linear issues since there isn't an official integration.

Repo:

```text
github.com/RichardoC/snyk-linear-sync
```

## What It Does

- Authenticates to Snyk with OAuth client credentials.
- Reads all projects in one configured Snyk org.
- Normalizes Snyk findings into one Linear issue per `project + issue`.
- Stores a stable fingerprint in a hidden metadata block in the Linear issue description.
- Optionally renders GitHub source file and commit links when source hosting is configured as `github`.
- Creates missing Linear issues.
- Updates existing Linear issues when managed fields change.
- Ensures a configurable managed label is applied to all managed issues, unless label management is explicitly turned off.
- Moves stale issues to the configured resolved state when the finding is no longer present but the Snyk project still exists.
- Cancels managed Linear issues when their Snyk project no longer exists, such as after project deletion.
- Uses a local SQLite cache to skip unchanged findings and unchanged Linear issues on steady-state runs.
- Sets Linear due dates from Snyk issue creation time using configurable per-severity offsets.

The fingerprint format is:

```text
snyk:<project-id>:<issue-id>
```

## Running

Quickstart without cloning:

Create a local `.env`, then run directly with the repo path:

```bash
go run github.com/RichardoC/snyk-linear-sync/cmd/snyk-linear-sync@latest --env-file .env --dry-run
```

Or install the binary:

```bash
go install github.com/RichardoC/snyk-linear-sync/cmd/snyk-linear-sync@latest
snyk-linear-sync --env-file .env --dry-run
```

Default usage is to pass a dotenv file explicitly:

```bash
go run ./cmd/snyk-linear-sync --env-file .env --dry-run
```

That avoids shell-specific `source` behavior and is the recommended way to run the tool.

Dry run:

```bash
go run ./cmd/snyk-linear-sync --env-file .env --dry-run
```

Normal run:

```bash
go run ./cmd/snyk-linear-sync --env-file .env
```

Installed binary:

```bash
snyk-linear-sync --env-file .env
```

Bypass cache:

```bash
go run ./cmd/snyk-linear-sync --env-file .env --bypass-cache
```

`--env-file` uses `github.com/joho/godotenv`, so the file can be a normal dotenv file and does not need to be sourced by your shell.

## Validation

Required after code changes:

```bash
go fix ./...
go test ./...
go vet ./...
```

## Current Behavior

- Uses `github.com/guillermo/linear/linear-api` plus direct GraphQL mutations for Linear.
- Uses `github.com/pavel-snyk/snyk-sdk-go/v2` where useful, with direct REST calls for issue retrieval.
- Stores a human-facing Snyk UI link in the Linear description.
- Keeps the Snyk REST API link as a secondary reference.
- Includes repository, project reference, target file, and source location details when Snyk provides them.
- Batches Linear create and update mutations to reduce request pressure.
- Retries and backs off on Linear rate limiting.
- Normalizes common Linear markdown rewrites when comparing descriptions so steady-state runs do not churn.

## Linear Permissions

This project is designed to work with:

- `Read`
- `Create issues`
- `Update issues`

It does not require label creation permissions.
If `LINEAR_MANAGED_LABEL` is enabled, the configured label must already exist in Linear.

## Managed Linear Description

Each managed issue contains:

- a heading with vulnerability title and severity
- repo, ref, and file or target-file context near the top
- Snyk UI and API links grouped together
- package/version details when available
- project and issue identifiers lower in the body
- GitHub repository, source file, and commit links when `SOURCE_PROVIDER=github` and the finding includes repository, file, and commit data
- GitHub project target file links when `SOURCE_PROVIDER=github` and Snyk provides repository, branch/reference, and target file data but not a precise source location
- hidden metadata block

The metadata block is required for deduplication and safe updates:

```text
<!-- snyk-linear-sync
fingerprint: snyk:proj-123:issue-456
managed_labels: snyk-automation,snyk-code
-->
```

Changing or removing that block can cause duplicate issues or prevent updates from matching the correct Linear issue.

## Source Links

Use `SOURCE_PROVIDER` to control source-link rendering:

- `unknown` keeps plain-text source file and commit fields
- `github` renders repository, source file, and commit links to public GitHub

For `github`, the file link is commit-pinned and includes line anchors when Snyk provides line numbers.
If Snyk does not provide a source file/commit but does provide `Repository + Project reference + Project target file`, the sync links the project target file in GitHub without line anchors.

## Issue Format

The synced issue body is optimized for fast developer triage:

- heading first: vulnerability title plus severity
- repo, ref, and file or target file immediately below
- Snyk UI and API links grouped together
- package and fix context next
- project and issue IDs lower in the body for debugging and API work

The synced title includes the most useful source context when Snyk provides it:

- repository for code and repository-backed findings
- branch/image/reference for non-GitHub target-file findings such as Kubernetes or container scans

The subject portion then uses this preference:

1. source file basename
2. package name
3. project target file
4. project name

## Managed Labels

`LINEAR_MANAGED_LABEL` controls the automation label applied to managed issues:

- default: `snyk-automation`
- set to another label name to use that label instead
- set to `off` to disable label management

When label management is enabled, the sync:

- adds the configured label to newly created managed issues
- preserves unrelated existing labels
- removes the previously managed label if the configured label changes
- removes the previously managed label if label management is turned off

If the configured label does not exist in Linear, the run fails with a clear message telling the operator to create the label or disable label management.

`LINEAR_TOOL_LABELS` optionally maps Snyk issue `type` values to additional managed Linear labels:

- format: comma-separated `issue_type:label` pairs
- example: `code:snyk-code,package_vulnerability:snyk-open-source,cloud:snyk-cloud`
- labels must already exist in Linear

`LINEAR_TOOL_LABEL_DEFAULT` controls the fallback label for issue types without an explicit mapping:

- default: `snyk-automation`
- set to `off` to disable the fallback

`LINEAR_ORIGIN_LABELS` optionally maps Snyk project `origin` values to additional managed Linear labels:

- format: comma-separated `origin:label` pairs
- example: `github:snyk-github,kubernetes:snyk-kubernetes`
- labels must already exist in Linear

`LINEAR_ORIGIN_LABEL_DEFAULT` controls the fallback label for project origins without an explicit mapping:

- default: `off`
- set to another label name to apply a shared fallback origin label

When tool or origin label mapping is enabled, the sync manages the global automation label plus the derived label set recorded in the metadata block.

`LINEAR_UNSUBSCRIBE_ACTOR` controls whether the Linear API actor should be kept off the subscriber list for managed issue creates and updates:

- default: `true`
- `true`: create issues without subscribing the actor, and preserve the current subscriber list unchanged on updates
- `false`: let Linear use its default subscriber behavior

This setting only controls the issue subscriber list. Linear will still record the API user as the issue creator, and the create mutation response may briefly include that creator in `subscribers` even when the persisted issue subscriber list is empty after a refresh.

## State Mapping

- open -> `Todo`
- snoozed -> `Backlog`
- fixed -> `Done`
- ignored -> `Cancelled`
- missing finding in an existing active Snyk project -> `Done`
- missing finding because the Snyk project no longer exists -> `Cancelled`
- Snyk project is inactive (de-activated) -> `Cancelled`

The configured Linear state names are resolved by name first, then by workflow type where possible.

These distinctions are intentional:

- If a Snyk issue disappears but the project still exists and is active, the tool treats that as the issue being resolved and moves the Linear ticket to `Done`.
- If the Snyk project itself is gone or has been de-activated (inactive), the tool treats the managed Linear ticket as no longer actionable and moves it to `Cancelled`.

Default due date offsets:

- critical -> 15 days after Snyk `created_at`
- high -> 30 days after Snyk `created_at`
- medium -> 45 days after Snyk `created_at`
- low -> 90 days after Snyk `created_at`

## Cache Behavior

The cache lives in SQLite and stores:

- a schema signature for the managed issue format
- a normalized hash for each Snyk finding
- a normalized hash for each managed Linear issue

On a normal run:

1. Load Snyk findings.
2. Load the current Linear snapshot.
3. Skip fingerprints whose Snyk hash and Linear hash both match the last successful run.
4. Apply creates, updates, and resolves for the rest.
5. Refresh the cache from the live post-write Linear snapshot.

Use `--bypass-cache` to ignore the cache for a run and rebuild it from live data.

## Configuration

Required:

- `SNYK_CLIENT_ID`
- `SNYK_CLIENT_SECRET`
- `SNYK_ORG_ID`
- `LINEAR_API_KEY`
- `LINEAR_TEAM_ID`

Optional:

- `--env-file`
- `SNYK_REGION`
- `SNYK_OAUTH_SCOPES`
- `SOURCE_PROVIDER`
- `LINEAR_STATE_TODO`
- `LINEAR_STATE_BACKLOG`
- `LINEAR_STATE_DONE`
- `LINEAR_STATE_CANCELLED`
- `LINEAR_MANAGED_LABEL`
- `LINEAR_TOOL_LABELS`
- `LINEAR_TOOL_LABEL_DEFAULT`
- `LINEAR_ORIGIN_LABELS`
- `LINEAR_ORIGIN_LABEL_DEFAULT`
- `LINEAR_DUE_DAYS_CRITICAL`
- `LINEAR_DUE_DAYS_HIGH`
- `LINEAR_DUE_DAYS_MEDIUM`
- `LINEAR_DUE_DAYS_LOW`
- `SYNC_WORKERS`
- `SNYK_HTTP_CONCURRENCY`
- `LINEAR_HTTP_CONCURRENCY`
- `ERROR_LOG_FILE`
- `CACHE_DB_FILE`

See [.env.example](/workspace/.env.example).


## Logs

- Console logs show startup, load progress, work progress, cache refresh, and final summary.
- Error logs are appended to `ERROR_LOG_FILE`.
- Default error log path: `logs/snyk-linear-sync-errors.log`

## More Detail

See [PROJECT.md](/workspace/PROJECT.md) for the project intent, architecture, sync rules, and operational model.
