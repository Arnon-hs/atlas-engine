# External security evidence contract v1

External security evidence is passive metadata produced by a trusted consumer
after it runs an independent scanner in an isolated worker. Atlas Engine parses
and validates the metadata; it does not start the scanner, parse the result
artifact, fetch rules or databases, or authenticate the producer. The Rust model
validates metadata only; the CLI streams every declared present private artifact
solely to verify its SHA-256 and byte count, retaining and emitting none of its bytes.

The contract exists so a scanner failure, unsupported scope or missing
measurement cannot be published as a clean zero-result scan. It is not a generic
SARIF importer and does not establish that a finding is exploitable.

The `evidence` CLI validates all three execution states and therefore exits 0 for
a structurally and semantically valid `incomplete` or `failed` manifest. Policy
acceptance is separate: consumers must require `execution.status: complete`.

## Public artifacts

- `schemas/external-security-evidence-v1.schema.json` describes the JSON shape.
- `crates/repo-security/src/evidence.rs` owns the stricter runtime parser and
  typed model.
- `fixtures/evidence/` contains synthetic complete, incomplete and failed
  examples. Their hashes and repository identities are test-only values.

Schema validation alone is not acceptance. Runtime validation also checks byte
and count limits, required nullable fields, sorted unique lists, safe metadata,
material state/digest pairs, status/result invariants, the severity total and the
canonical `evidence_id`.

## Subject identity

`subject` binds the run to consumer-owned repository state:

| Field | Meaning |
| --- | --- |
| `repository_id` | Portable opaque consumer identity; not a URL/absolute path and not proof of remote ownership |
| `commit_sha` | Observed 40/64-hex Git label or `null`; not proof of a clean checkout |
| `snapshot_id` | Exact accepted Atlas snapshot identity |
| `configuration_id` | Atlas configuration identity for that snapshot |
| `selection_id` | Atlas input-selection and ignore-policy identity |

A consumer must compare all five fields with an independently accepted snapshot.
The Rust `validate_evidence_subject` API performs exact equality. A matching
self-consistent manifest still needs a trusted delivery channel; its BLAKE3 ID is
not a signature or attestation.
The repository identity may contain a portable `owner/repository` label or an
opaque token, but absolute POSIX/Windows paths, backslashes and URL forms are
rejected so host locations cannot enter the public manifest.

## Producer and materials

`producer` identifies both the trusted runner and the scanner by a bounded name,
opaque version and exact SHA-256 binary digest. Mutable tags, executable paths,
commands and environment variables are deliberately absent.

`materials` contains exactly one entry of each kind, in this order:

1. `configuration`
2. `database`
3. `ruleset`

Each material has `present`, `not_applicable` or `not_reported` state. `present`
requires a SHA-256 digest; the other states require `sha256: null`.
Configuration must always be present. A complete run cannot contain
`not_reported`. An embedded scanner ruleset can be `not_applicable` when the
reviewed scanner binary digest is the versioned rule identity.

## Scope

The manifest records sorted, unique include/exclude patterns and language or
ecosystem identifiers. `.` means the entire input root. Other patterns are a
portable, bounded glob description: they cannot be absolute, negated, drive-like,
contain backslashes, empty/current/parent segments, terminal controls, Unicode
line/paragraph separators, bidi controls or detected credentials. The external runner remains responsible for
making its actual selection semantics agree with this description and its
configuration digest.

`selected_files` and `evaluated_files` are required fields whose values are a
non-negative integer or `null`. `null` means not reported; it never means zero.
When both are reported, evaluated cannot exceed selected. A complete run requires
both and requires equality.

## Execution status

Only these states are accepted:

| Status | Required result | Result finding totals | Termination |
| --- | --- | --- | --- |
| `complete` | Present artifact metadata | Required; severity sum equals total | `success`, exit 0, selected equals evaluated |
| `incomplete` | Present partial artifact metadata | `finding_count` and `findings_by_severity` are `null` | A non-success bounded reason |
| `failed` | No result metadata | `finding_count` and `findings_by_severity` are `null` | A non-success bounded reason |

Allowed non-success reasons are tool nonzero exit, timeout, CPU/memory/output
limit, sandbox violation, parse failure, unsupported input, cancellation and
runner internal error. There is no free-form reason or log field.
For incomplete runs, scope `selected_files`/`evaluated_files` may retain integer
lower-bound stage observations or be null; neither is a complete coverage total.

Every accepted manifest states `network_access: denied`,
`repository_access: read_only` and `repository_code_executed: false`. These are
producer assertions, not proof that the operating-system sandbox enforced them.
The consumer must retain natural sandbox/job evidence separately.

The private result artifact is described only by a bounded format token, SHA-256
digest and byte length. The Rust evidence model does not read it. `atlas-engine
evidence ... --result PATH` performs a separate nofollow, ordinary-file,
outside-repository streaming digest check under the 64 MiB bound and never parses
or publishes it. The CLI requires `--result` whenever result state is `present`;
only library callers can validate metadata without opening the artifact. A partial artifact may
contain useful findings, but its manifest cannot publish counts because they can
be mistaken for complete coverage.

## Redaction boundary

The manifest has no raw finding, message, snippet, command, environment,
working-directory, URL or artifact-content field. This is stronger than trusting
a producer boolean such as `contains_secrets: false`, which Atlas could not prove
from a digest. Raw SARIF/JSON can contain source excerpts, absolute paths or secret
matches and must remain in the consumer's restricted evidence store.

A future normalized-finding import needs a separate versioned schema, path and
redaction validator, per-tool adapters, hostile fixtures and its own threat-model
review. It must not widen this metadata contract additively.

## Bounds

- manifest input: 1 MiB, including one-byte overflow detection;
- include patterns: 1–1,024; exclude patterns: 0–1,024;
- languages/ecosystems: 1–64;
- selected/evaluated files: at most 1,000,000 when reported;
- private result artifact: 1–64 MiB when present;
- complete finding count: at most 10,000,000.

Duplicate or unknown JSON fields, unsupported schema versions, invalid UTF-8,
unsafe metadata, overflowed severity sums and any cross-field mismatch fail with
a fixed error that does not reflect input text.

## Canonical evidence ID

`evidence_id` is lowercase 64-hex BLAKE3. The producer serializes compact JSON
from the typed fields in declaration order, omitting only `evidence_id`, after
sorting the lists required above. It hashes that byte sequence with BLAKE3
derive-key context:

```text
atlas-engine external security evidence v1
```

The ID detects accidental or untrusted mutation of the typed metadata. It does
not authenticate the runner, the tool binary, the source snapshot or the private
result artifact. Consumers that need authenticity should sign or attest the
manifest outside this contract and verify the signer independently.
