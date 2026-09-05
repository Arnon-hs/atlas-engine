# AtlasRepo Core consumer example

This dependency-free Node.js adapter demonstrates a narrow, offline handoff from
AtlasRepo Core v0.2.1 to Atlas Engine. Core's ExecutionPack and ResultPack remain
at their published `v0.1` schema versions in that release. The adapter does not
change either contract.

This adapter is always plan-only. The pinned Dify Decision Pack is
`conditional`, so both `false` and `true` produce a review receipt without
starting a process. `true` records `unresolved-gates`; it is not authorization.

## Boundary

- Core owns evidence-backed plans and the portable ResultPack contract.
- A future execution caller will own acquisition, immutable read-only snapshots,
  process isolation, scheduling, retries, persistence, and publication policy.
- The adapter validates only structured `analyze` and `security` plans and emits
  normalized relative previews plus digests. It never constructs a shell command,
  opens a repository, loads a binary, or starts a process.
- `ExecutionPack.steps[].instruction` is preserved as inert provenance. It is
  never parsed, interpolated, or executed.
- The caller plan is copied into bounded strict plain data before validation.
  Later caller mutations cannot change previews or the returned receipt.
- Evidence must use public, commit-pinned GitHub references. Local files,
  restricted references, credentials, private hosts, and runtime logs are
  rejected or omitted from receipts.
- Every operation's `repositoryId` must match exactly one public Git commit
  reference, which is copied into its preview.
- The receipt records digests and stable relative identifiers, not host paths or
  source output. It also binds the Core `expectedArtifacts`. The ResultPack uses
  the receipt digest as evidence.

This is not an execution adapter, an OS sandbox, or production activation. A
real execution adapter requires a separately pinned, authenticated `ready`
Decision Pack, complete command-specific Atlas Engine JSON Schema validation,
trusted binary provenance, immutable acquisition, an OS sandbox, and a separate
review. Direct Atlas Engine CLI tests are useful engine proof, but do not resolve
the Dify gates and do not authorize Dify execution.

## Test

```bash
node --test examples/core-consumer/adapter.test.mjs
```

The fixture references public Dify evidence from the Core v0.2.1 release. It
does not contain or run Dify source code. Dify's modified license still requires
qualified review for the intended use; this technical example is not legal advice.
