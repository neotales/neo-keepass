# Vault, context, and alias commands

These commands select a vault and manage names for vaults or entries. Vault
selection follows the precedence in [choose the active vault](../how-to/vault-selection.md).

## `init`

Create a KDBX 4.1 vault.

```text
nkeepass init [PATH] [--size N] [--kdf aes|argon2d|argon2id]
              [--memory KIB] [--iterations N] [--parallelism N]
```

If `PATH` is omitted, the selected vault path is used. Init refuses to
overwrite an existing vault. A positional relative `PATH` is resolved from
the current working directory. If you pass both a positional path and
`--vault`, init refuses the ambiguous target. After creation, init selects the
new vault as the current context when no explicit target was supplied.
Without an explicit credential source or `NKEEPASS_PASSWORD`, init prompts
without echo.

| Option | Meaning |
| --- | --- |
| `--password-env NAME` | Read the master password from this environment variable. |
| `--password-stdin` | Read one password line from stdin. |
| `--password-file PATH` | Read one password line from a file. |
| `--key-file PATH` | Add a key-file credential component. |
| `--password VALUE` | Compatibility option. Exposes the password in process listings and shell history. |
| `--size N` | Generate an N-character password for a new entry. Does not generate the master password. |
| `--kdf aes\|argon2d\|argon2id` | Select the KDF. Default is `aes`. |
| `--memory KIB` | Set Argon2 memory cost. Only valid with Argon2. |
| `--iterations N` | Set AES rounds or Argon2 time cost, according to the KDF. |
| `--parallelism N` | Set Argon2 lanes. Only valid with Argon2. |

The CLI rejects KDF values outside its own read policy. On password-only init,
it writes an age-encrypted password backup after creating the vault. The
identity needed to decrypt the backup is stored separately. A backup failure
does not remove the vault. Secure owner-only writes are unsupported on
Windows, so init fails closed there.

## `context`

```text
nkeepass context ls
nkeepass context show
nkeepass context use ALIAS
nkeepass context set ALIAS ABSOLUTE_PATH
nkeepass context rm ALIAS
```

`ls` lists configured vault aliases and paths. `show` reports the selected
vault and source. `use` selects a configured vault alias. `set` creates or
updates an alias. `rm` removes an alias and clears it as current if needed.
Subcommands have no command-specific options.

## `alias`

```text
nkeepass alias ls
nkeepass alias set NAME TARGET [--kind vault|entry] [--field FIELD]
nkeepass alias resolve NAME
nkeepass alias rm NAME
```

`ls` lists aliases. `set` creates or replaces one. If `--kind` is omitted,
the command infers the target kind. Use `--field` to bind an entry alias to a
field. `resolve` prints the configured target. `rm` removes the alias.

Names use ASCII letters, digits, hyphens, or underscores and are at most 128
bytes. Entry paths use slash-separated group and entry names, reject empty,
`.` and `..` segments, and cannot start with `/`. Entry selectors compare
segments ASCII case-insensitively, allow an optional root-group prefix, and
refuse ambiguous matches. If a selector is also an entry alias name but
resolves to a different existing entry path, the CLI refuses it as ambiguous.
Vault alias names and entry alias names share configuration storage.

Aliases: `alias list` is `alias ls`; `alias remove` is `alias rm`. `context`
has no subcommand aliases.
