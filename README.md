# snyk-linear-sync

Sync Snyk findings into Linear issues.

Repo:

```text
github.com/RichardoC/snyk-linear-sync
```

## What It Does

- Authenticates to Snyk with OAuth client credentials.
- Reads all projects in one configured Snyk org.
- Normalizes Snyk findings into one Linear issue per `project + issue`.
- Stores a stable fingerprint in a hidden metadata block in the Linear issue description.
- Creates missing Linear issues.
- Updates existing Linear issues when managed fields change.
- Moves stale issues to the configured resolved state when the finding is no longer present.
- Uses a local SQLite cache to skip unchanged findings and unchanged Linear issues on steady-state runs.
- Sets Linear due dates from Snyk issue creation time using configurable per-severity offsets.

The fingerprint format is:

```text
snyk:<project-id>:<issue-id>
```

## Running

Quickstart without cloning:

Create a local `.env`, then run directly from the repo path:

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

Useful local checks:

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
- `Create comments`

It does not require label creation or label update permissions.

## Managed Linear Description

Each managed issue contains:

- Snyk UI link
- Snyk API link
- project and issue identifiers
- package/version details when available
- repository and source-location details when available
- due date calculated from Snyk issue creation time and severity
- hidden metadata block
- human-readable `Fingerprint:` line

The metadata block is required for deduplication and safe updates:

```text
<!-- snyk-linear-sync
DO NOT EDIT, REMOVE, OR REFORMAT THIS BLOCK. It is required by snyk-linear-sync for deduplication and safe updates.
fingerprint: snyk:proj-123:issue-456
-->
```

Changing or removing that block can cause duplicate issues or prevent updates from matching the correct Linear issue.

## State Mapping

- open -> `Todo`
- snoozed -> `Backlog`
- fixed -> `Done`
- ignored -> `Cancelled`

The configured Linear state names are resolved by name first, then by workflow type where possible.

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
- `LINEAR_STATE_TODO`
- `LINEAR_STATE_BACKLOG`
- `LINEAR_STATE_DONE`
- `LINEAR_STATE_CANCELLED`
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
