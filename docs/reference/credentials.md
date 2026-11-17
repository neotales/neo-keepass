# Supply vault credentials

Vault commands need a password, a key file, or both. The CLI offers several
ways to supply the password and one independent `--key-file` option.

## Shared flags

Every public command accepts `-h` or `--help`. The global
`-V PATH` or `--vault PATH` option must come before the command:

```text
nkeepass --vault PATH COMMAND
```

An absolute path selects a vault. A relative value selects a configured vault
alias. `init` is the exception: its relative path is resolved from the current
directory.

The short forms are `-h` for `--help`, `-V` for `--vault`, `-r` for
`--age-recipient`, and `-i` for `--age-identity`. No other public flags have
short forms. `--version` is accepted at the root instead of a command. Neither
`version` nor `--version` accepts a preceding `--vault` option.

## Choose one password source

Use at most one of these options:

| Option | What it reads |
| --- | --- |
| `--password-env NAME` | The value of the named environment variable. |
| `--password-file PATH` | The first line of a file, up to the input limit. |
| `--password-stdin` | One line from standard input, up to 64 KiB. |
| `--password VALUE` | The literal command-line value. Avoid this option for real passwords. |

If you omit these options and `--key-file`, the CLI uses `NKEEPASS_PASSWORD`
when it is set to a non-empty, valid Unicode value. If it is unset, the CLI
prompts without echo when stdin is a terminal. An empty or non-Unicode value
fails instead of prompting.
Without a password source or terminal prompt, the command fails. Explicit
password options override `NKEEPASS_PASSWORD`. An explicit source that cannot
be read fails; the CLI does not fall back to another source. `NKEEPASS_SECRET`
is not recognized.

The parser rejects more than one password source. For example, do not combine
`--password-env` with `--password-stdin`.

## Add a key file

`--key-file PATH` adds the key-file component to the credentials. It is
independent of the password-source options, so you can combine it with one
password source. If you give only `--key-file`, the CLI uses the key file
without reading `NKEEPASS_PASSWORD` or asking for a password.

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
nkeepass secrets set --key 'Services/Example' --stdin --password-stdin
```

Pass the password through an environment variable or a file when the command
also reads its value from stdin.

## Which commands accept these options

The password options appear only on routes that open or create a vault.
`--password-env` and `--password-stdin` are accepted on these routes:

- `init`
- `exec` and its alias `x`
- Root shortcuts `get`, `getx`, `ls`, `list`, `search`, `show`, `set`, `rm`,
  `remove`, `ensure`, `otp`, `setx`, `import`, `export`, `sync`, and `env`
- Subcommands under `secrets`, `automation`, `attachment`, `attachments`,
  `group`, `groups`, `field`, and `custom-field`

Those same routes also accept `--password-file PATH`, `--key-file PATH`, and
`--password VALUE`. The options are available for every valid operation under
the listed groups. They are not accepted on `tui`, `context`, `alias`,
`config`, `completion`, or `version`. The TUI has its own unlock interaction.

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
| Root `get`, `getx`, `ls`, `list`, `search`, `show`, `set`, `rm`, `remove`, `ensure`, `otp`, `setx`, `import`, `export`, `sync`, `env` | Same five credential flags |
| Any valid subcommand of `secrets`, `automation`, `attachment`, `attachments`, `group`, `groups`, `field`, or `custom-field` | Same five credential flags |
| `tui`, `context`, `alias`, `config`, `completion`, `version` | No credential flags |

Root `--password-env NAME` and `--password-stdin` may appear before the
command or after the full command route. For nested commands, put them after
the subcommand. `--password-file`, `--key-file`, and `--password` must appear
after the full route. For `exec`, place credential flags after `exec` and
before `-- COMMAND`.

`-r` and `--age-recipient` are accepted only by `get` routes when
`--age-encrypt` is set. `-i` and `--age-identity` are accepted only by `set`
routes when `--age-decrypt` is set. These age options do not work on `field
get` or `field set`, even though generated help currently lists inherited
flags there. See the [age how-to](../how-to/age.md).

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
