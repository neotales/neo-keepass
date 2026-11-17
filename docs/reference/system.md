# Configuration, child processes, completion, and root commands

## `tui`

```text
nkeepass tui PATH
```

Opens the interactive terminal browser for the supplied vault path. This
command requires exactly one path argument. It does not use the active-vault
selection; pass the path to the vault you want to open.

## `config`

### `config ls`

```text
nkeepass config ls [GLOB] [--json]
```

Lists supported configuration keys and values. `--json` emits one JSON
record per key. `list` aliases `ls`.

### `config get`

```text
nkeepass config get KEY
```

Prints one configured scalar value. `show` aliases `get`.

### `config set`

```text
nkeepass config set KEY VALUE
```

Sets one supported configuration value. Unknown or invalid keys fail rather
than being added.

### `config rm`

```text
nkeepass config rm KEY
```

Clears one configured scalar value. `remove` aliases `rm`.

## `exec`

```text
nkeepass exec [--key PATH [--field FIELD] --env NAME]...
  [CREDENTIAL OPTIONS] -- COMMAND [ARG ...]
```

Each binding selects an entry and maps one field to a child environment
variable. Repeat the binding sequence for more values. Omit `--field` to use
the command's default field. The `--` separator marks the child command and
its arguments.

Credential options are `--password-env NAME`, `--password-stdin`,
`--password-file PATH`, `--key-file PATH`, and the unsafe compatibility
option `--password VALUE`. The child receives a fixed allowlist of environment
variables, not the full parent environment. `NKEEPASS_*` variables are not
passed through. The selected secret is visible to the child and to processes
it starts, so run only trusted programs. `x` aliases `exec`.

## `completion`

```text
nkeepass completion SHELL
```

Prints static completion text for the requested shell. The output is printed
to stdout. Inspect generated text before adding it to a shell startup file.
Accepted shell names are `bash`, `sh`, `zsh`, `fish`, `powershell`, `pwsh`,
and `nushell`.

## `version`

```text
nkeepass version
nkeepass --version
```

Prints version information. The root `--version` option is an alias for the
`version` command.

## Root shortcuts

These root commands are shortcuts for `secrets` commands:

| Root command | Equivalent |
| --- | --- |
| `get` | `secrets get` |
| `getx` | `secrets getx` |
| `ls`, `list` | `secrets ls` |
| `search` | `secrets search` |
| `show` | `secrets show` |
| `set` | `secrets set` |
| `rm`, `remove` | `secrets rm` |
| `ensure` | `secrets ensure` |
| `otp` | `secrets otp` |
| `setx` | `secrets setx` |
| `import` | `secrets import` |
| `export` | `secrets export` |
| `sync` | `secrets sync` |
| `env` | `secrets env` |

## Global flags

`-h` and `--help` print help for the selected command. `-V PATH` and
`--vault PATH` select a vault before a command. Root `--version` prints
version information. The only other short options are `-r` for
`--age-recipient` and `-i` for `--age-identity`. Other options use their
long spelling.

`--password-env NAME` and `--password-stdin` select the master password
source. `NKEEPASS_PASSWORD` is the default environment source; an explicit
source takes precedence. `NKEEPASS_SECRET` is not an alias. Password prompts
do not echo. Do not use `--password VALUE` for real credentials because
process listings and shell history can expose it.
