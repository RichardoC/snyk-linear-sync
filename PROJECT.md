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
- syncing labels, comments, or custom fields beyond the currently managed issue body, title, priority, due date, and workflow state

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

### Resolve

When a previously tracked finding no longer exists in Snyk, move the Linear issue to the resolved state.

### Conflict

If multiple Linear issues share the same fingerprint, the sync treats that as a conflict:

- it logs the conflict
- it skips automatic mutation for that fingerprint

## Description Strategy

The Linear issue description is intentionally structured.

It includes:

- human-usable Snyk UI link
- Snyk REST API link
- project identifiers
- issue identifiers
- package/version details
- repository details
- source file and region details for code findings
- metadata block
- human-readable fingerprint line

Linear may rewrite parts of the description body when rendering or storing markdown. The sync therefore normalizes known Linear formatting changes during compare and cache hashing.

## State Mapping

The current workflow mapping is:

- `open` -> `Todo`
- `snoozed` -> `Backlog`
- `fixed` -> `Done`
- `ignored` -> `Cancelled`

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
