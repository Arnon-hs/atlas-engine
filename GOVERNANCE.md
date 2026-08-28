# Governance

Atlas Engine begins as an owner-maintained, single-repository OSS project.
`Arnon-hs` is the GitHub repository owner. This is not an assertion about a legal
entity, all underlying copyright, or a verified list of collaborators.

Maintainers review contributions and uphold the read-only analysis scope,
contracts, testing, security response, and release requirements. Small fixes can
use a focused PR; significant architecture or schema changes need a public issue
and an ADR. Breaking machine semantics need a new schema major. Explain rejected
proposals and retain decision records. No private AtlasRepo requirement overrides
the engine's public boundary.

Code review is the normal merge path. Require a non-author human review before
merging once branch rules are enabled. The owner must recruit an independent
reviewer instead of claiming that self-review satisfies that requirement. Do not
give collaborator or release access automatically after a contribution count or
elapsed period. Review identity, contribution history, security judgment, scope,
and need; grant the smallest role manually; review and remove unused access.

Changes to license, publication authority, security contacts, or governance need
explicit owner approval and a recorded decision. Emergencies may justify an
exception to ordinary process only with a documented reason and follow-up review;
they do not justify exposing reporter information or changing license terms.

The owner remains accountable for GitHub settings and release approval. An
additional administrator, confidential conduct contact, backup security responder,
and verified access roster are pending. See [MAINTAINERS.md](MAINTAINERS.md) and
[the owner checklist](docs/security/github-hardening.md).
