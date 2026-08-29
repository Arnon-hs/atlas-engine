# Advanced analysis fixtures

Synthetic, non-production source for the opt-in advanced analyzer contract.
Nothing in this directory is installed, built, imported or executed by Atlas
Engine. The fixture covers an exact TypeScript import, a unique naming heuristic,
an ambiguous basename and extended Rust/Shell grammar metrics.

`history-manifest.json` preserves the distinction between an unavailable
`lines_added` measurement (`null`) and an observed zero `lines_deleted` value.
