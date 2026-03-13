# Project Overview

## Purpose

This project exists to keep Linear aligned with Snyk.

Canonical module path:

```text
github.com/RichardoC/snyk-linear-sync
```

The intended outcome is:

- every relevant Snyk finding has a corresponding Linear issue
- the Linear issue stays current as the Snyk finding changes
- resolved or ignored findings move to the correct Linear workflow state
- repeated runs become cheap by skipping unchanged records

This is an operational sync tool, not a generic library.

## Core Contract

The project treats Snyk as the source of truth for security finding data and Linear as the execution surface for tracking and triage.

It is responsible for:

- reading Snyk findings
- deciding the desired Linear representation
- reconciling the current Linear state to that desired state

It is not responsible for:

- writing back to Snyk
- preserving arbitrary manual edits inside the managed section of the Linear description
- syncing comments or custom fields beyond the currently managed issue body, title, priority, due date, workflow state, and managed automation label

## Identity Model

Each Snyk finding is identified by:

```text
snyk:<project-id>:<issue-id>
```

That fingerprint is embedded in the Linear description metadata block and is the durable join key between systems.

Without that fingerprint, the sync cannot safely deduplicate or update issues.

## Issue Lifecycle

### Create

Create a Linear issue when:

- a Snyk finding exists
- no Linear issue with the same fingerprint exists

### Update

Update the Linear issue when managed fields differ:

- title
- description
- due date
- priority
- mapped state
- managed automation label

### Resolve

When a previously tracked finding no longer exists in Snyk but its Snyk project still exists, move the Linear issue to the resolved state.

When a previously tracked finding no longer exists because its Snyk project no longer exists, cancel the Linear issue instead.

### Conflict

If multiple Linear issues share the same fingerprint, the sync treats that as a conflict:

- it logs the conflict
- it skips automatic mutation for that fingerprint

## Description Strategy

The Linear issue description is intentionally structured for fast triage first, deep debugging second.

It includes:

- heading with vulnerability title and severity
- repository context near the top
- branch/reference and commit context when available
- source file or project target file context near the top
- human-usable Snyk UI link
- Snyk REST API link
- package/version details
- project identifiers
- issue identifiers
- GitHub repository links when `SOURCE_PROVIDER=github`
- GitHub source file and commit links when `SOURCE_PROVIDER=github`
- GitHub project target file links when `SOURCE_PROVIDER=github` and no precise source location is available
- metadata block

The synced title is also structured for scanability. It includes the best available source context:

- repository for code and repository-backed findings
- branch/image/reference for non-GitHub target-file findings such as Kubernetes or container scans

The subject portion then uses this preference:

1. source file basename
2. package name
3. project target file
4. project name

The metadata block also records the managed automation label name when label management is enabled.

Linear may rewrite parts of the description body when rendering or storing markdown. The sync therefore normalizes known Linear formatting changes during compare and cache hashing.

## Source Hosting

`SOURCE_PROVIDER` controls how source references are rendered.

- `unknown` leaves source references as plain text
- `github` renders public GitHub links for:
  - repositories
  - source files, pinned to the reported commit
  - source commits
  - project target files, pinned to the reported branch/reference when no source commit/file is available

If repository, file, or commit data is missing, the sync falls back to plain text.

## Managed Label

`LINEAR_MANAGED_LABEL` controls the label this tool manages on synced issues.

- default: `snyk-automation`
- `off`: disables label management
- any other value: the exact Linear label name to manage

Behavior:

- the configured managed label is added to new synced issues
- unrelated existing labels are preserved
- if the configured managed label changes, the old managed label is removed and the new one is applied
- if label management is disabled, the previously managed label is removed

The configured label must already exist in Linear. If it does not, the run fails with a clear operator-facing error.

## State Mapping

The current workflow mapping is:

- `open` -> `Todo`
- `snoozed` -> `Backlog`
- `fixed` -> `Done`
- `ignored` -> `Cancelled`
- missing finding in an existing Snyk project -> `Done`
- missing finding because the Snyk project no longer exists -> `Cancelled`

The sync also normalizes workflow naming differences such as `Canceled` vs `Cancelled`.

Due dates are derived from the Snyk issue creation timestamp, not from when the issue first appears in Linear.
Default offsets are:

- critical: 15 days
- high: 30 days
- medium: 45 days
- low: 90 days

## Performance Model

The project is designed for thousands of issues.

It uses:

- concurrent Snyk and Linear snapshot loading
- worker-based reconciliation
- batched Linear mutations
- rate-limit backoff
- SQLite caching

The cache is critical for steady-state performance. A healthy steady-state run should do little or no work when nothing has changed.

## SQLite Cache

The SQLite cache stores:

- Snyk-side normalized hashes keyed by fingerprint
- Linear-side normalized hashes keyed by fingerprint
- a schema signature for the managed issue format

The cache is used only as an optimization. It should never be the only source used to infer real current state.

Normal behavior:

1. Read live Snyk data.
2. Read live Linear data.
3. Compare both against the last successful cached hashes.
4. Skip unchanged fingerprints.
5. After successful writes, refresh the cache from the live post-write Linear snapshot.

The post-write refresh matters because Linear may rewrite markdown bodies after mutation.

## Safety Assumptions

- The metadata block must remain intact.
- The managed description body is owned by this tool.
- Linear issue history matters, so deleting and recreating all issues is a last resort, not a normal repair path.
- Cache bypass is the correct operator action when the rendering schema or compare logic changes.

## Operator Guidance

After any code change, run:

```bash
go fix ./...
go test ./...
go vet ./...
```

Use a normal run for day-to-day sync:

```bash
go run ./cmd/snyk-linear-sync --env-file .env
```

Use a dry run to inspect planned changes:

```bash
go run ./cmd/snyk-linear-sync --env-file .env --dry-run
```

Use cache bypass when you intentionally changed the managed rendering or need a full live reconciliation:

```bash
go run ./cmd/snyk-linear-sync --env-file .env --bypass-cache
```

## Design Boundaries

If this project grows further, the next reasonable extensions would be:

- stronger incremental Snyk fetching using server timestamps where available
- more selective Linear snapshot loading if the API surface allows it safely
- richer cache statistics and observability
- explicit conflict reporting output

The current implementation is intentionally optimized for correctness first, then steady-state efficiency.
