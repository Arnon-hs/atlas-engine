# Execution-surface inventory

The execution-surface detector reports bounded capability signals. A signal is
not a vulnerability, exploitability claim, severity rating or instruction to
execute repository code.

The first native inventory covers:

- presence of any nonempty package.json or Composer scripts object, including
  lifecycle hooks and explicitly runnable custom scripts. This follows the
  official [npm scripts model](https://docs.npmjs.com/cli/v11/using-npm/scripts/)
  and [Composer scripts model](https://getcomposer.org/doc/articles/scripts.md)
  without retaining a key or command value;
- Cargo build scripts and build-dependency sections;
- GitHub workflow trigger, permission and `uses` declarations plus mutable
  remote refs that are not a full commit SHA/container digest;
- Dockerfile `ENTRYPOINT`, `CMD` and explicit root `USER` instructions, plus
  Compose `privileged: true`;
- direct literal TLS-verification disable options present in typed call facts.
- typed dynamic-evaluation, process/shell and deserialization primitives. Shell
  options are reported only for direct literal `shell: true`/`shell=True` facts.

Signals contain only a fixed engine-owned kind, a portable relative location and
schema version. Manifest key names, script or command values, callees, option
names and source snippets are discarded. The detector performs no network I/O,
process creation, dependency installation, build, import or repository command.

JSON manifests have a hard input bound and are parsed only to determine whether
a package or Composer script capability is present.
Cargo metadata is parsed as bounded TOML; only root or target-specific Cargo
build dependencies and `package.build` are capabilities. Full JSON/flow-style
workflow and Compose documents are traversed with structure limits. Workflow
signals are scoped to root triggers/permissions, job permissions/reusable-workflow
`uses`, and step `uses`; keys with those names in an `env` map are not
capabilities. Compose privileged mode is scoped to
`services.<service>.privileged`; an unused `x-*` extension is not a runtime
capability. Canonical and `compose.*`/`docker-compose.*` `.yml`/`.yaml` filenames
are selected. When structure-only JSON parsing cannot distinguish duplicate
locations, coverage becomes `partial` and the count is absent. The native
block-YAML detector remains a bounded subset: unsupported flow maps, merge keys,
anchors, aliases and explicit keys make coverage `partial` rather than a clean
zero. YAML block-scalar content is skipped so a workflow script containing text
such as `uses:` does not become a declaration signal. Docker checks use a bounded
instruction subset.
TLS checks consume `ParsedFile` boolean-option facts; they do not search raw
source and cannot establish reachability or attacker control.

Malformed applicable manifests, parser loss and exhausted line/call/signal
budgets return `partial`. Unsupported parser facts return `unsupported`. Signal
counts are absent unless the result is complete.

The signal record is defined by
[`schemas/execution-signal-v1.schema.json`](../../schemas/execution-signal-v1.schema.json).
