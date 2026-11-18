# Choose the active vault

`nkp` chooses a vault using the first available source in this order:

1. Explicit `-V PATH` or `--vault PATH`.
2. `NKEEPASS_VAULT`.
3. `NKEEPASS_VAULT_PATH`.
4. The current vault context.
5. The configured default vault.
6. `default.kdbx` in the application data directory.

For ordinary vault commands, an explicit absolute path selects that vault.
A relative `--vault` value is treated as a vault alias, not resolved against
the current directory. Create an alias with
`nkp context set work "$HOME/vaults/work.kdbx"`, then select it with
`nkp --vault work secrets ls`.

`init` is the exception because it creates a file. Its positional `PATH` and
`--vault PATH` target may be relative; the CLI resolves either from the
current working directory. Do not pass both to `init`.

To persist a context selection, run:

```sh
nkp context use work
nkp context show
```

`context show` prints the selected name, path and source. `context ls` and
`context list` print configured vault aliases and paths, plus a directly
selected path and an otherwise unlisted configured default path. A current
path is marked. These commands use readable text by default. With `--json`,
`context ls`/`list` retain their alias-only output contract: one record with
`alias` and `path` per configured vault alias. Unaliased current/default paths
appear only in human-readable output.

To use an environment selection for one shell:

```sh
export NKEEPASS_VAULT="$HOME/vaults/work.kdbx"
nkp secrets ls
```

An explicit `--vault` overrides both vault environment variables. A nonempty
`NKEEPASS_VAULT` takes precedence over `NKEEPASS_VAULT_PATH`.

Vault paths must be absolute and normalized when stored as paths. Entry aliases
are separate from vault aliases. See [vault and context commands](../reference/vault.md).
