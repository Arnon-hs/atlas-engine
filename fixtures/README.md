# Hostile-input and language fixtures

`polyglot/` is source text only. Never install its dependencies, build it, import it
or run its scripts. The engine parses these files without executing them.

Credential-looking values are deterministic test strings containing `TESTONLY`,
the reserved `.invalid` domain or published AWS example identifiers. They have no
associated account and must never be replaced with real credentials.

Integration tests create large sparse files, invalid UTF-8, NUL binary data,
symlinks, FIFO files and inert Git metadata in disposable temporary directories.
Those cases are generated at test time to avoid storing large files or platform
specific filesystem objects in Git. Test source defines their exact construction.
