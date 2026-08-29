# Generic Node consumer

Node.js 22+, no dependencies, no npm install. This example consumes index JSONL
from a trusted **built engine binary** with `shell: false`. It never executes a
binary inside the scanned repository. The caller must supply isolation and a
read-only snapshot.

From the engine source checkout after `cargo build --release`, create a trusted
output directory outside the input and pass absolute paths:

```bash
mkdir -p /tmp/atlas-engine-example-output
node examples/node-consumer/consumer.mjs \
  "$PWD/target/release/atlas-engine" \
  "$PWD/fixtures" example/fixtures \
  /tmp/atlas-engine-example-output
node --test examples/node-consumer/consumer.test.mjs
```

For a Git checkout, add the expected full HEAD commit as the last argument. Obtain
it in your trusted acquisition step, not by executing input-defined Git commands.
Omitting it expects `commit_sha: null`; it does not accept an arbitrary commit.
The default expected engine version is `0.3.0` and schema version is `1.0`.
This example deliberately keeps the legacy `--format jsonl` protocol. It does
not consume or apply schema 2.0 snapshot events; do not pass its own
`manifest.json` to `index --since`. The latter requires the engine's
[v2 manifest](../../docs/contracts/index-snapshots-v2.md).
Use an explicit `engineVersion` API value when integrating an older, reviewed
engine; versions are never accepted through an automatic wildcard.

The API `consumeIndex({enginePath, repositoryPath, repositoryId, outputDirectory,
commitSha, engineVersion, signal, ...limits})` accepts a caller `AbortSignal`.
The output directory must already exist. It is resolved before creating a private
staging directory to reject symlink redirection into input. The child receives a
minimal environment without inherited provider credentials.

| Limit | Default |
| --- | --- |
| Wall time | 30 seconds |
| One JSONL record | 256 KiB |
| Total stdout | 128 MiB |
| Stderr retained | First 64 KiB, then truncated while still drained |
| Record count | 100,000 |

Limits are overrideable API options. A decode/provenance/range/path/count/output
error kills the process; timeout/cancellation sends SIGTERM and then SIGKILL if
needed. Valid prefixes remain staged until the child exits 0. Failures remove
staging without replacing existing data. Empty streams are rejected because v1
has no index envelope to verify their provenance. See
[production integration](../../docs/integrations/atlasrepo-scout.md) for handling
empty or incomplete scans safely.

On success a directory keyed by SHA-256 of provenance plus the stream digest
contains `chunks.jsonl`, `manifest.json`, and bounded `diagnostics.json`. Repeating
identical input verifies and reuses the same snapshot. No active database index
is switched by this example. Disk directories are atomic publication boundaries,
not a durable database transaction or a power-loss recovery guarantee.

The validator checks critical record fields, relative paths, coordinates and
provenance, but is not a complete JSON Schema implementation and does not verify
BLAKE3 hashes. Production consumers should run a reviewed schema validator and
independent completeness/redaction policy. Even valid redacted source may be
private or sensitive; the example does not upload, embed or publish it.
