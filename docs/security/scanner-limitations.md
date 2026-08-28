# Scanner limitations

Atlas Engine reports high-signal patterns and dangerous primitives. It does not
prove exploitability, trace end-to-end taint, model authorization, execute code,
resolve every dynamic import/alias, or replace CodeQL, Semgrep, specialist secret
scanners or human review. A finding is a review signal unless separately validated.

Shared sensitive-content matching covers recognizable private-key material,
provider token formats, contextual high-entropy token assignments, credentials
inside URLs/database strings, bearer-like values and selected JWT forms. Regex
and contextual heuristics have false positives and false negatives. Encoded,
encrypted, split, dynamically constructed or unfamiliar secret formats may pass.
Entropy alone is insufficient evidence. Tests contain synthetic non-live values.

The indexer detects on the complete bounded file before making chunks and masks
recognized bytes while preserving offsets and line breaks. It has no v0.1
redaction opt-out. `redacted: false` means no configured pattern matched that
record, not that its contents are safe or public. License-sensitive source,
personal data, proprietary logic and low-entropy credentials still need consumer
policy before upload or embedding.

Security output never needs the full token. It emits a rule, severity, confidence,
relative location, explanation, fingerprint and safe preview. Hash fingerprints
are identifiers, not anonymization guarantees for guessable values. Avoid exposing
them to users who should not see the underlying repository's information.

Configuration checks are bounded pattern/syntax checks, not full Docker Compose,
CORS, shell or GitHub Actions interpreters. `.env` presence does not itself prove
committed-in-HEAD status or live credentials; Git index membership is advisory.
Ignored/unreadable files, binaries, invalid UTF-8, oversized content, unsupported
metadata and exhausted bounds can make a scan incomplete. Review diagnostics.
Security JSON exposes this through `truncated`; an explicit `--fail-on` gate exits
6 on incomplete coverage, before considering the finding threshold (exit 5).
Ordinary scans keep partial results without failing the process. Intentional
policy exclusions, binary files, symlinks and special files remain outside scope;
a successful gate says nothing about those files. SARIF marks an incomplete
invocation unsuccessful. See the [CLI contract](../contracts/cli.md).

Native parser errors may produce fallback records or diagnostics, not fully
accurate symbols. Qualified names and symbol kinds reflect supported grammar
patterns. Large structures split deterministically into bounded parts; file-level
fallback is expected for unsupported languages. No full semantic type checking or
cross-file call/dependency graph is claimed.

Results from the same immutable snapshot, options and engine version should be
deterministic. Concurrent input edits, grammar upgrades, rule changes, different
limits or an incomplete snapshot require explicit revalidation/reindexing.
