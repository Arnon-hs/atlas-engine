# AtlasRepo publication artifacts

These files preserve the reviewed AtlasRepo Blog and Forum copy together with
the exact source identity used for publication.

| Artifact | Target | Publication evidence |
| --- | --- | --- |
| `atlasrepo-blog-atlas-engine-v0.3-ru.md` | AtlasRepo Blog | Published at <https://atlasrepo.com/blog/atlas-engine-repository-analysis-without-false-zeros/> |
| `atlasrepo-blog-atlas-engine-v0.3.publish-input.json` | AtlasRepo Blog internal projection | Exact approved publish input, including the Forum URL and source commit |
| `atlasrepo-forum-atlas-engine-v0.3-ru.md` | AtlasRepo Forum | Published at <https://forum.atlasrepo.com/t/atlas-engine-v0-3-source-candidate-unknown-zero/124> in `Open Source Repositories` (id `6`) with tag `atlasrepo` |

The factual source is Atlas Engine commit
`c5d448367706ae6f86f6c5ff814d0f0824355ae2` and its open
[pull request #5](https://github.com/Arnon-hs/atlas-engine/pull/5), verified on
2026-08-29. A later documentation-only commit does not change that engine source
identity.

The Forum topic was published first, then its exact public URL was stored as
`editorial.forumTopicUrl` in the Blog payload. The Blog was published on
2026-08-29 at `2026-08-29T10:15:46.004Z`; a reviewed Admin revision at
`2026-08-29T10:18:15.016Z` restored the approved Markdown indentation while
preserving source and editorial metadata. Public API, HTML, canonical metadata,
robots policy and sitemap membership were verified after that revision.

Publication does not change the project boundary: commit `c5d4483` remains a
source candidate in open pull request #5. There is still no v0.3 tag or binary
release.
