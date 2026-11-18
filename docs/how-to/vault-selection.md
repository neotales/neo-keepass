# Choose the active vault

`nkp` chooses a vault using the first available source in this order:

1. Explicit `-V PATH` or `--vault PATH`.
2. `NEO_KEEPASS_VAULT`, `NKP_VAULT`, then legacy `NKEEPASS_VAULT`.
3. `NEO_KEEPASS_VAULT_PATH`, `NKP_VAULT_PATH`, then legacy `NKEEPASS_VAULT_PATH`.
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

`context show` reports the selected vault and its source. `context ls` lists
configured vault aliases and paths.

To use an environment selection for one shell:

```sh
export NEO_KEEPASS_VAULT="$HOME/vaults/work.kdbx"
nkp secrets ls
```

An explicit `--vault` overrides both vault environment variables. For each
name, the `NEO_KEEPASS_*` form takes precedence over `NKP_*`, which takes
precedence over the corresponding legacy `NKEEPASS_*` form. The `VAULT`
variable takes precedence over the `VAULT_PATH` variable after resolving each
name's aliases.

Vault paths must be absolute and normalized when stored as paths. Entry aliases
are separate from vault aliases. See [vault and context commands](../reference/vault.md).
