# AtlasRepo editorial drafts

These files are review artifacts for AtlasRepo. They are not evidence of a
published Blog article or Forum topic.

| Artifact | Target | Editorial metadata |
| --- | --- | --- |
| `atlasrepo-blog-atlas-engine-v0.3-ru.md` | AtlasRepo Blog | Russian; proposed slug `atlas-engine-repository-analysis-without-false-zeros`; category `Developer Tools` |
| `atlasrepo-blog-atlas-engine-v0.3.publish-input.draft.json` | AtlasRepo Blog internal projection | Draft-only copy of the current Scout publish payload; **do not POST it without final publication approval** |
| `atlasrepo-forum-atlas-engine-v0.3-ru.md` | AtlasRepo Forum | Russian; category `Open Source Repositories` (id `6`); tags `atlasrepo`, `open-source`, `security`, `repositories`, `evidence` |

The factual source is Atlas Engine commit
`c5d448367706ae6f86f6c5ff814d0f0824355ae2` and its open
[pull request #5](https://github.com/Arnon-hs/atlas-engine/pull/5), verified on
2026-08-29. A later documentation-only commit does not change that engine source
identity.

The Forum topic must be created and reviewed first. Only after its exact public
URL is known should `editorial.forumTopicUrl` be added to the Blog payload. The
AtlasRepo internal content endpoint publishes immediately; it is not a draft
creation endpoint.
