# ADR-004: Tree-sitter behind domain models

## Context

PHP, JavaScript, TypeScript and Python need syntax-aware chunks even for imperfect
source files. Complete compiler frontends would be costly and can need builds.

## Decision

Use pinned Tree-sitter grammar dependencies behind a parser registry returning
symbols, source ranges and diagnostics. Do not expose trees as the general library
contract. Bound parser input and cooperative elapsed time. Return useful partial
symbols with parse diagnostics; use bounded file fallback for other languages.

## Consequences

Grammar updates require regression tests. Parsing establishes structure, not type
resolution, taint flow or exploitability. Native grammar code is a dependency trust
boundary and is covered by fuzz targets and external process isolation guidance.

### v0.3 amendment

Rust and Bash grammars are available only through the opt-in extended parser;
legacy index records keep the original four-language AST boundary. The same
owned model exposes supported syntax counts and one bounded Python
parameter-to-dynamic-evaluation/shell flow class. Exceeded or unmodeled paths are
reported as partial coverage, never absence. Trees, identifiers and source text
remain outside the public flow contract.

## Alternatives

Regex-only symbol extraction loses nesting and correct ranges. Character-count
splitting loses structure. Running project compilers violates the threat model.
