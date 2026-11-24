# Supply vault credentials

Vault commands need a password, a key file, or both. The CLI offers several
ways to supply the password and one independent `--key-file` option.

## Shared flags

Every public command accepts `-h` or `--help`. The global
`-V PATH` or `--vault PATH` option must come before the command:

```text
nkp --vault PATH COMMAND
```

An absolute path selects a vault. A relative value selects a configured vault
alias. `init` is the exception: its relative path is resolved from the current
directory.

Short flags normalized across CLI routes are `-h` (`--help`), `-V` (`--vault`),
`-k` (`--key`), `-f` (`--file`), `-F` (`--field`), `-n` (`--name`),
`-o` (`--output`), `-y` (`--yes`), `-B` (`--bind` on `exec`/`x`), `-b` (`--bin`),
`-c` (`--chars` / `--size`), `-U` (`--upper`), `-L` (`--lower`), `-D`
(`--digits`), `-S` (`--symbols`), `-r` (`--age-recipient`), and `-i`
(`--age-identity`). `--version` is accepted at the root instead of a command.
Neither `version`, `--version`, `tui`, `use`, `alias`, `config`, `completion`,
`trust`, `untrust`, `shell`, nor `context` subcommands other than `context show`
accept a preceding `-V` / `--vault` option.

## Choose one password source

Use at most one of these options:

| Option | What it reads |
| --- | --- |
| `--password-env NAME` | The value of the named environment variable. |
| `--password-file PATH` | The first line of a file, up to the input limit. |
| `--password-stdin` | One line from standard input, up to 64 KiB. |
| `--password VALUE` | The literal command-line value. Avoid this option for real passwords. |

If you omit these options and `--key-file`, the CLI uses `NEO_KEEPASS_PASSWORD`,
then `NKP_PASSWORD` (the first set name) when it is set to a non-empty, valid
Unicode value. Legacy `NKEEPASS_PASSWORD` is ignored; migrate it to one of the
supported names. If both are unset, the CLI
prompts without echo when stdin is a terminal. The first present name wins:
an empty or non-Unicode higher-priority value fails instead of falling back or
prompting.
Without a password source or terminal prompt, the command fails. Explicit
password options override both names. Across the two default names,
`NEO_KEEPASS_*` takes precedence over `NKP_*`. An explicit source that cannot
be read fails; the CLI does not fall back to another source.

The parser rejects more than one password source. For example, do not combine
`--password-env` with `--password-stdin`.

## Add a key file

`--key-file PATH` adds the key-file component to the credentials. It is
independent of the password-source options, so you can combine it with one
password source. If you give only `--key-file`, the CLI uses the key file
without reading `NEO_KEEPASS_PASSWORD` or `NKP_PASSWORD`, or asking for a
password.

Use the non-echoing prompt for interactive work. For scripts, prefer a
restricted environment variable or a file with suitable access controls.
When the value input also uses stdin, provide the password with a different
source such as `--password-env` or `--password-file`.

## Keep stdin roles separate

`--password-stdin` reads the master password. `--stdin` reads command data,
such as a field value, JSON, an import snapshot, or attachment bytes. One stdin
stream cannot serve both roles. On commands that accept both options, the CLI
rejects the combination with
`stdin cannot carry both password and value`.

For example, this invocation is invalid:

```sh
nkp secrets set --key 'Services/Example' --stdin --password-stdin
```

Pass the password through an environment variable or a file when the command
also reads its value from stdin.

## Which commands accept these options

The password options appear only on routes that open or create a vault.
`--password-env` and `--password-stdin` are accepted on these routes:

- `init`
- `exec` and its alias `x`
- `inject` and `shell load`
- Root shortcuts `get` (including `get many`), `ls`, `list`, `search`, `show`, `set`, `rm`,
  `remove`, `ensure`, `otp`, `import`, `export`, `sync`, and `env`
- Subcommands under `secrets`, `automation`, `files`, `attachment`, `attachments`,
  `group`, `groups`, `field`, and `custom-field`

Those same routes also accept `--password-file PATH`, `--key-file PATH`, and
`--password VALUE`. The options are available for every valid operation under
the listed groups. They are not accepted on `tui`, `context`, `alias`, `use`,
`config`, `completion`, `trust`, `untrust`, `shell init|completions|unload|status`,
or `version`. The TUI has its own unlock interaction.

The `--vault PATH` option selects the vault and is accepted independently of
these password options. The [vault-selection guide](../how-to/vault-selection.md)
explains the order used when you omit it.

## Flags by command route

The command reference pages list each command's own flags. Add the shared
flags above and the matching credential flags from this section to get the
complete accepted flag set.

| Route | Additional credential flags |
| --- | --- |
| `init` | `--password-env NAME`, `--password-stdin`, `--password-file PATH`, `--key-file PATH`, `--password VALUE` |
| `exec` and `x` | Same five credential flags |
| `inject` and `shell load` | Same five credential flags |
| Root `get` (including `get many`), `ls`, `list`, `search`, `show`, `set`, `rm`, `remove`, `ensure`, `otp`, `import`, `export`, `sync`, `env` | Same five credential flags |
| Any valid subcommand of `secrets`, `automation`, `files`, `attachment`, `attachments`, `group`, `groups`, `field`, or `custom-field` | Same five credential flags |
| `tui`, `context`, `alias`, `use`, `config`, `completion`, `trust`, `untrust`, `shell init|completions|unload|status`, `version` | No credential flags |

Root `--password-env NAME` and `--password-stdin` may appear before the
command or after the full command route. For nested commands, put them after
the subcommand. `--password-file`, `--key-file`, and `--password` must appear
after the full route. For `exec`, place credential flags after `exec` and
before `-- COMMAND`.

`-r` and `--age-recipient` are accepted only by root/`secrets` `get` routes when
`--age-encrypt` is set. `-i` and `--age-identity` are accepted only by
root/`secrets` `set` routes when `--age-decrypt` is set. These age options are
not accepted by `field get` or `field set` and are omitted from their help. See
the [age how-to](../how-to/age.md).

## Where `--` ends option parsing

Use `--` to start the child command in `exec`. `secrets ls`,
`secrets search`, and `config ls` also accept it before their optional
positional glob or query. Other public commands do not accept positional
arguments after `--`.

`init` accepts one optional positional path and does not accept a `--`
terminator before it. Do not combine the path with `--vault`. `tui` requires
one positional path and does not accept `--`. `secrets ls` accepts at most
one glob, `secrets search` requires one query, and `config ls` accepts at
most one glob. Other command arguments are named subcommands, aliases, or
values described in their reference pages.
