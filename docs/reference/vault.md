# Vault, context, and alias commands

These commands select a vault and manage names for vaults or entries. Vault
selection follows the precedence in [choose the active vault](../how-to/vault-selection.md).
Every route accepts `-h` or `--help`; `-V PATH` or `--vault PATH` may precede
the command. Credential flags apply to `init` as listed in
[vault credentials](credentials.md).

## `init`

Create a KDBX 4.1 vault.

```text
nkp [--vault PATH] init [PATH] [--size N] [--kdf aes|argon2d|argon2id]
              [--memory KIB] [--iterations N] [--parallelism N]
```

If `PATH` is omitted, the selected vault path is used. Init refuses to
overwrite an existing vault. A positional relative `PATH` is resolved from
the current working directory. If you pass both a positional path and
`--vault`, init refuses the ambiguous target. After creation, init tries to
select the new vault only when no current context is set. It does not replace
a context you already chose. If init selects the new vault, the JSON result
has `"context_set": true`; otherwise it has `"context_set": false`. With no
explicit target, init uses or creates the `default` vault alias unless that
name already refers elsewhere. An explicit target can become the current
value when no context exists.
See [vault credentials](credentials.md) for credential sources, key files,
and their conflicts.

| Option | Meaning |
| --- | --- |
| `--password-env NAME` | Read the master password from this environment variable. |
| `--password-stdin` | Read one password line from stdin. |
| `--password-file PATH` | Read one password line from a file. |
| `--key-file PATH` | Add a key-file credential component. |
| `--password VALUE` | Compatibility option. Exposes the password in process listings and shell history. |
| `--size N` | Generate a 1 to 4096 character password for a new entry. Does not generate the master password. |
| `--kdf aes\|argon2d\|argon2id` | Select the KDF. Default is `aes`. |
| `--memory KIB` | Set Argon2 memory cost from 1 to 65,536 KiB. Default is 65,536 KiB. Only valid with Argon2. |
| `--iterations N` | Set AES rounds from 1 to 100,000,000 or Argon2 time cost from 1 to 10. Defaults are 600,000 AES rounds or 10 Argon2 passes. |
| `--parallelism N` | Set Argon2 lanes from 1 to 16. Default is 1. Only valid with Argon2. |

The CLI rejects KDF values outside its own read policy. The Argon2 memory,
time, and combined-work limits apply together. On password-only init,
it writes an age-encrypted password backup after creating the vault. The
identity needed to decrypt the backup is stored separately. A backup failure
does not remove the vault. Secure owner-only writes are unsupported on
Windows, so init fails closed there.

`init` accepts `--age-encrypt`, `--age-decrypt`, `-r` /
`--age-recipient`, and `-i` / `--age-identity`, but ignores them. They do not
encrypt or decrypt the vault.

## `context`

```text
nkp context ls
nkp context list
nkp context show
nkp context use ALIAS
nkp context set ALIAS ABSOLUTE_PATH
nkp context rm ALIAS
nkp context remove ALIAS
```

`ls` (also `list`) lists configured vault aliases and paths. `show` reports the selected
vault and source. `use` selects a configured vault alias. `set` creates or
updates an alias. `rm` (also `remove`) removes an alias and clears it as current if needed.
Subcommands have no command-specific options.

## `alias`

```text
nkp alias ls
nkp alias set NAME TARGET [--kind vault|entry] [--field FIELD]
nkp alias resolve NAME
nkp alias rm NAME
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
