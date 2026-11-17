# Command reference

This reference describes the CLI shipped in this checkout. The executable is
`nkeepass`; confirm any invocation against the matching binary with
`nkeepass COMMAND --help`. The parser and generated help are maintained in
`crates/nkeepass/src/main.rs`; tests pin important dispatch aliases and parser
rules. This is an alpha application, not a promise of compatibility across
revisions.

## Safety first

Prefer `--password-stdin`, `--password-env NAME`, or the non-echoing prompt.
`--password VALUE` is retained for compatibility, but exposes the password in
process listings and shell history. The default environment variable is
`NKEEPASS_PASSWORD`; explicit sources take precedence, and `NKEEPASS_SECRET`
has no special meaning. Do not put real passwords, recipient private keys, or
vault contents in examples, shell history, CI logs, issue reports, or command
arguments. Examples below use placeholders and a protected local vault.

`get`, `getx`, `env`, and `exec` explicitly disclose selected values. Stdout,
child environments, terminal scrollback, and CI output may be captured.
`set`/`setx`, imports, and attachment input can alter the vault; export and
attachment output create sensitive plaintext files. Output paths are private,
no-clobber destinations on supported platforms. Operations requiring secure
owner-only writes fail closed on Windows in this version; see the README.

## Global invocation and credentials

```text
nkeepass [GLOBAL OPTIONS] COMMAND
```

`-V, --vault PATH` chooses a vault path or configured vault alias. It can be
placed before the command. `--password-env NAME` and `--password-stdin` select
the master-password source; these are accepted before or after vault commands.
When neither is specified, the CLI uses `NKEEPASS_PASSWORD` if set, otherwise
prompts without echo. For commands with their own credential options,
`--password-file PATH` reads one password line and `--key-file PATH` supplies
the key-file component. Password and value stdin roles cannot be combined.
Input is bounded; malformed, duplicate, or conflicting credential sources are
refused.

Use command-specific help for exact placement:

```sh
nkeepass --help
nkeepass secrets get --help
nkeepass attachment add --help
```

## Command inventory

Names in the left column are canonical. The right column lists aliases
accepted by dispatch; aliases do not imply different behavior.

| Canonical command | Accepted aliases | Purpose |
| --- | --- |
| `tui PATH` | — | Interactive private-terminal vault browser. |
| `init [PATH]` | — | Create a KDBX 4.1 vault; refuses to overwrite. |
| `context ls/show/use/rm/set` | — | List, inspect, select, remove, or configure current vault context. |
| `alias ls/set/rm/resolve` | `ls` → `list`; `rm` → `remove` | Manage vault and entry aliases. |
| `secrets ls/search/env/show/get/getx/set/rm/ensure/otp/setx/import/export/sync` | `ls` → `list`; `env` → `environment`; `rm` → `remove` | Vault data and automation. |
| `automation setx/import/export/sync` | — | Automation entry points for interchange operations. |
| `attachment ls/add/get/rm` | `attachments` group alias; `ls` → `list`; `add` → `import`; `get` → `export`; `rm` → `remove` | List, add, extract, or remove entry attachments. |
| `group ls/add/rm` | `groups` group alias; `ls` → `list`; `add` → `create` or `ensure`; `rm` → `remove` | List, create, or remove groups. |
| `field ls/get/set/rm` | `custom-field` group alias; `ls` → `list`; `get` → `reveal`; `set` → `edit`; `rm` → `remove` | Manage custom fields. |
| `config ls/get/set/rm` | `ls` → `list`; `get` → `show`; `rm` → `remove` | Inspect or change supported configuration values. |
| `exec` | `x` | Run a child with explicitly selected values in its environment. |
| `completion SHELL` | — | Print static shell completion. |
| `version` | `--version` at root | Print version. |
| Root shortcuts `get/getx/ls/search/show/set/rm/ensure/otp/setx/import/export/sync/env` | `list` → `ls`; `remove` → `rm` | Shortcuts for the corresponding `secrets` operations. |

Shortcuts at the root map to the corresponding `secrets` operations:
`get`, `getx`, `list/ls`, `search`, `show`, `set`, `rm/remove`, `ensure`,
`otp`, `setx`, `import`, `export`, `sync`, and `env`.

### Compatibility names not presented as public commands

The dispatcher contains internal action spellings `field-get`, `field-set`,
and `attachment-add` for routing implementation work. They are not public
routes: they are absent from the help tree and are rejected as direct public
secrets/automation commands. Use `field get`, `field set`, and `attachment
add` instead. This distinction is covered by dispatch tests; do not rely on
internal names as compatibility interfaces.

### Entry-selection names

`--key PATH` is the selector spelling; there is no separate `--entry`,
`--selector`, or short `-k` selector option. `PATH` may instead be a
configured **entry alias**: `alias set NAME TARGET --kind entry` creates one,
and `--key NAME` resolves it. `--vault PATH`/`-V` accepts a configured vault
alias. `alias set --field FIELD` binds an entry alias to a field; it does not
introduce a selector flag alias. Path selection is normalized and rejects
escaping `..` or empty path segments.

### Option spellings and short forms

The CLI's implemented short options are `-h` (`--help`), `-V`
(`--vault`), `-r` (`--age-recipient`), and `-i` (`--age-identity`).
All other options in the command help are long-form only. In particular,
there is no `-p` password shortcut. The parser rejects repeated
single-valued options and unknown options; age recipients are repeatable.
The `--` terminator is supported for positional list/search patterns and
`exec`'s child command.

## Vault and context management

`init [PATH]` accepts `--size N`, `--kdf aes|argon2d|argon2id`,
`--memory KIB`, `--iterations N`, and `--parallelism N`. KDF tuning is
validated against the reader's resource limits; Argon2-only knobs are not
silently accepted for AES. `--size` creates a separate random entry password,
not the master password. If init receives a password-only master credential,
it creates an age-encrypted password backup under the data directory and an
identity under the config directory. Keep that identity safe: it decrypts the
backup. A key-file credential means no password-only backup is made. A backup
failure occurs after vault creation and does not roll the vault back.

`context set ALIAS PATH` configures a vault alias; `context use ALIAS` selects
it, `context show` reports the selected vault/source, `context ls` lists
configured vaults, and `context rm ALIAS` removes one. `alias set NAME TARGET`
accepts `--kind vault|entry` and `--field FIELD`; otherwise the target kind is
inferred. Entry aliases may bind a field. `alias resolve NAME` shows the
configured target. Configuration and alias records are metadata, not secret
storage.

## Selecting entries, fields, and output

Entry operations use `--key PATH` (an entry path or entry alias); field
operations use `--field FIELD`. `--field` defaults to `Password` where
applicable. `show` exposes redacted descriptors, not field values. `ls` emits
redacted JSON-lines metadata; its optional positional glob is supported after
`--` too, so a leading-dash pattern is unambiguous. `search QUERY` searches
bounded, allowlisted metadata. Unsafe metadata may be withheld rather than
rendered.

`get` reveals one selected field. Its formats include `text`, `json`, `null`,
and supported named formats; named formats require `--name NAME`.
Named formats include dotenv, shell, PowerShell (`pwsh`/`powershell`),
GitHub Actions, and Azure DevOps. `--is-output` marks Azure DevOps output as
an output variable. Values incompatible with a target format (including
unsafe names or disallowed line breaks/delimiters) are rejected.

`getx` emits selected data as JSON. `otp` generates a TOTP code without
revealing the seed; HOTP is refused. `env` takes repeated `--key PATH`,
optional `--field FIELD`, and `--name NAME` bindings, then `--format FORMAT`;
for OTP, select the `otp` field. It supports the same named output behavior
and Azure DevOps `--is-output`.

```sh
# Avoid putting a real password in shell history or process arguments.
printf '%s\n' "$NKEEPASS_PASSWORD" | nkeepass --vault "$HOME/vault.kdbx" \
  --password-stdin secrets get --key 'Services/Example' --field UserName
```

That example intentionally demonstrates credential transport only; the value
is still disclosed to stdout. Do not use shell tracing (`set -x`) around
secret-handling commands.

## Mutations and interchange

`set` reads a value from exactly one of `--file PATH` or `--stdin`; it can use
`--age-decrypt` and `-i, --age-identity PATH` to decrypt armored or binary age
input first. Age identity files can contain native age identities or
unencrypted SSH private keys; encrypted SSH private keys are not supported.
The command updates one explicitly selected field.

`ensure` creates a missing entry and parent groups, and leaves an existing
entry unchanged. `--size N` generates a password only for a new entry;
`--dry-run` validates/reports without saving. `rm` removes the selected entry
or field and requires `--yes` for destructive confirmation (subject to the
operation's prompt behavior).

`setx --key PATH` takes bounded JSON from `--file` or `--stdin`, sets exact
fields atomically, and supports `--dry-run`. `import` and `sync` likewise
require exactly one input source. Import accepts `--replace` to permit
replacing a non-empty vault; both import and sync accept `--dry-run`.
`sync --strategy newest|source` selects the conflict strategy. `export`
requires `--output PATH` and writes an interchange snapshot to a private
no-clobber file. `automation` exposes these same four operations.

## Attachments, groups, and custom fields

`attachment ls --key PATH` lists attachment metadata. `attachment add
--key PATH --field NAME` reads bytes from `--file PATH` or `--stdin`;
`attachment get --key PATH --field NAME --output PATH` writes a private
no-clobber file. `attachment rm` requires `--yes`. Aliases are `attachments`,
`list`, `import`, `export`, and `remove` as shown in the inventory.

`group ls` lists group paths. `group add --key PATH` (also `create` or
`ensure`) creates missing groups; `--dry-run` avoids saving. `group rm
--key PATH --yes` removes a group and its contents; the root cannot be
removed. It also accepts `--dry-run`.

`field ls --key PATH` lists custom-field names. `field get --key PATH
--field FIELD` (also `reveal`) reveals one custom field and supports the
`get` output and age-encryption options. `field set` (also `edit`) uses the
same explicit input and optional age-decryption options as `secrets set`.
`field rm` removes one custom field.

## Age encryption and decryption

`get --age-encrypt` encrypts the selected value to one or more repeated
`-r, --age-recipient KEY` values. A recipient can be a native age or SSH
public key, `@PATH` for a bounded recipient-key file, `gh:USER` to fetch
public SSH keys, or an HTTPS URL serving newline-delimited public keys.
Network lookup happens only when explicitly requested, requires `curl`, has a
64 KiB response cap and five-second timeout, rejects redirects, and validates
each key. Ciphertext goes to stdout unless `--output PATH` selects a private,
no-clobber file. Do not confuse public recipient keys with private identities.

`set --age-decrypt -i IDENTITY --file PATH --key PATH` decrypts input before
updating a field. The `-i` identity may be a native age identity or an
unencrypted SSH private key. Encrypted SSH identity files are unsupported.

## Running child processes

`exec`/`x` takes repeated `--key PATH [--field FIELD] --env NAME` bindings,
credential options, then `-- COMMAND [ARG ...]`. A selected field is placed
in the child environment under the requested variable name. The child gets a
deliberately restricted environment rather than inheriting arbitrary
`NKEEPASS_*` settings. Child environment values are still disclosed to that
process and any process it launches; only run trusted commands.

## Configuration, completion, and limits

`config ls [GLOB] [--json]` lists the closed set of supported config keys;
`config get KEY` prints one scalar, `config set KEY VALUE` changes a
supported value, and `config rm KEY` clears one. Use `config ls` rather than
guessing keys. Completion is static: `nkeepass completion SHELL` prints the
requested shell script; inspect it before sourcing.

The CLI pins KDBX input at 64 MiB, decompressed data at 64 MiB, AES-KDF
rounds at 100,000,000, Argon2 memory at 64 MiB and time at 10, with bounded
combined work. Not every KeePass feature is an application feature: KDBX
parsing/writing is delegated to the vendored library; desktop UI, passkeys,
HIBP checks, icons, SSH-agent integration, and automatic recipient discovery
are not implemented in this checkout. See the root README for build/test
commands and platform security limitations.

## Audit and self-discovery

The command inventory and option summaries above are transcribed from
`ROOT_COMMANDS` and the help tree in `crates/nkeepass/src/main.rs`, not from
an independent option schema. Verify the exact accepted spelling and
combination for the built revision with:

```sh
cargo +1.98.1 run -p nkeepass -- --help
cargo +1.98.1 run -p nkeepass -- secrets get --help
cargo +1.98.1 run -p nkeepass -- attachment add --help
```

The help output is the authoritative quick reference for options; source
dispatch/parser behavior and tests remain authoritative where help is only a
summary. This document intentionally does not reproduce every command's
complete help output.
