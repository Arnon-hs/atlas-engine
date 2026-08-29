# Diagnostic events and output receipts v1

Atlas Engine 0.4 adds a bounded operational envelope around existing command
output. Primary command data still goes to stdout by default; diagnostics and the
terminal run event go to stderr when `--diagnostics-format jsonl` is selected.
The contract is described by
[`diagnostic-event-v1.schema.json`](../../schemas/diagnostic-event-v1.schema.json).
Human diagnostics mode does not emit a machine terminal receipt.

This envelope reports what the process wrote and how it terminated. It does not
prove that a repository snapshot was complete, authenticate an artifact, replace
the command-specific JSON schemas, or remove the need for an external sandbox.

## Invocation and bounds

The operational flags are global and may appear with any command:

```text
--diagnostics-format human|jsonl
--max-output-bytes BYTES
--output FILE
```

Primary output defaults to a 256 MiB hard limit and accepts an explicit limit from
1 byte through 4 GiB. Exceeding it fails with exit 4 and
`output_limit_exceeded`; partial stdout or a temporary file is not an acceptable
result.

An output file is prepared in its canonical parent directory. For repository
commands it must be outside the scanned root. A symlink, non-regular destination
or existing file is rejected: Atlas Engine never overwrites a previously accepted
artifact. It writes a temporary file, flushes and syncs it, then persists it with
no-clobber semantics at the target and syncs the parent directory. The caller
must choose a unique staging path in a trusted output directory and owns its
permissions.

## Event stream

With `--diagnostics-format jsonl`, stderr contains one JSON object per line:

- `diagnostic` carries a fixed diagnostic code, an optional portable relative
  path and a bounded message;
- `run.completed` terminates an executed command with status `complete`,
  `policy_failed` or `incomplete`;
- `run.failed` terminates setup or execution with status `failed` and a fixed
  `reason_code`.

The terminal `command` is null only when CLI parsing failed before a command
could be accepted.

At most 200 diagnostic objects are emitted. The terminal event records emitted
and suppressed counts. Diagnostics, failure messages and paths must not contain
source snippets, credentials, absolute host paths or terminal control sequences.
If stderr itself cannot be written, a terminal JSON event cannot be guaranteed;
the process exits 4 and the consumer must reject staged output. A newly persisted
candidate can remain visible after such a late diagnostics failure, but it has no
acceptance receipt and must never replace the consumer's prior accepted artifact.

## Output receipt

Every terminal event includes:

| Field | Meaning |
| --- | --- |
| `destination` | `stdout` or `file` |
| `committed` | The selected sink completed its finalize boundary |
| `bytes_written` | Primary-output bytes accepted by the bounded writer |
| `sha256` | Digest of exactly those bytes when committed; otherwise `null` |
| `limit_bytes` | Effective primary-output hard limit |

For stdout, `committed: true` means the bounded stream was flushed; stdout is not
a durable transaction. For file output it means the atomic persistence boundary
was reached. The receipt is an integrity and accounting record, not a signature.
`committed` alone is not policy acceptance: an incomplete or threshold-failed run
can have finalized primary output, and a late failure can report actual output
state. Consumers must evaluate the terminal event and process exit status.
In particular, an output file can already have been atomically persisted when a
later parent-directory sync reports `run.failed`; the receipt then records
`committed: true`, but the run must still be rejected.

## Status and failure codes

| Event/status | Exit | Meaning |
| --- | ---: | --- |
| `run.completed` / `complete` | 0 | Command completed under the requested policy |
| `run.completed` / `policy_failed` | 5 | Explicit finding threshold matched |
| `run.completed` / `incomplete` | 6 | Requested completeness gate could not be satisfied |
| `run.failed` / `failed` | 2 | CLI parse or configuration failure |
| `run.failed` / `failed` | 3 | Repository or external-input failure |
| `run.failed` / `failed` | 4 | Internal, output-limit, output-I/O or diagnostics-I/O failure |

`run.failed.reason_code` is one of `cli_parse_error`, `configuration_error`,
`input_error`, `internal_error`, `output_limit_exceeded`, `output_io_error` or
`diagnostics_io_error`. `run.completed.reason_code` is `null`.

`--require-complete` is available for advanced analysis, security and external
evidence. It converts a valid but incomplete requested result into status
`incomplete` and exit 6. It does not make unsupported analysis complete or turn
missing counts into zero.

## Consumer acceptance

A streaming consumer must:

1. stage stdout or use a trusted output file outside the input repository;
2. validate every primary record against its command-specific schema;
3. validate every stderr JSON line against diagnostic-event schema `1.0`;
4. require exactly one matching terminal event and the actual process exit code;
5. verify the receipt byte count and SHA-256 over the staged primary bytes;
6. require the command-specific completeness and policy status before committing;
7. discard staging on a missing/duplicate terminal event, digest mismatch,
   unacceptable status, signal, timeout, cancellation or consumer error.

An index event transaction still requires its own completion manifest and
consumer-owned compare-and-swap. Security output still requires its coverage
envelope. External evidence still requires trusted acquisition, exact snapshot
binding and isolated scanner execution. Run Atlas Engine with a read-only,
immutable input, denied network access and external CPU, RSS and wall-time limits;
operational receipts do not weaken those boundaries.
