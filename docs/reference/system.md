# Configuration, child processes, completion, and root commands

Every route accepts `-h` or `--help`; `-V PATH` or `--vault PATH` may precede
the command. Password flags are available only on credential routes. See
[vault credentials](credentials.md) for the exact route matrix.

## `tui`

```text
nkp tui PATH
```

Opens the interactive terminal browser for the supplied vault path. This
command requires exactly one path argument. It does not use the active-vault
selection; pass the path to the vault you want to open. The global `--vault`
flag is accepted before `tui` but does not replace the required positional
path.

## `config`

### `config ls`

```text
nkp config ls [GLOB] [--json]
```

Lists supported configuration keys and values. `--json` emits one JSON
record per key. `list` aliases `ls`.

The only keys are `aliases`, `current`, and `default_vault`. `aliases` is a
map managed by the `alias` commands; each record has a `kind` (`vault` or
`entry`), a string `target`, and an optional string `field`. `config set
aliases ...` and `config rm aliases` are refused. Alias names contain at most
128 ASCII letters, digits, hyphens, or underscores.

`current` and `default_vault` are optional string vault selectors. Each must
be an absolute normalized vault path or an existing vault alias. Empty values
and paths containing terminal-control characters are refused.

In text output, an unset scalar appears as its key alone. In `--json` output,
an unset scalar has a `null` value. The `aliases` value is a map in JSON
listing output. `config get aliases` prints valid JSON Lines, one record per
alias. Use `alias ls`, `alias set`, or `alias rm` to manage entries.

### `config get`

```text
nkp config get KEY
```

Prints a configured value. `current` and `default_vault` return scalars;
`aliases` returns valid JSON Lines, one record per alias. `show` aliases
`get`.

### `config set`

```text
nkp config set KEY VALUE
```

Sets one supported configuration value. Unknown or invalid keys fail rather
than being added. Only `current` and `default_vault` are scalar settings.
Each value must resolve to an absolute normalized vault path or an existing
vault alias. Use `context` or `alias` commands for alias management.

### `config rm`

```text
nkp config rm KEY
```

Clears a set `current` or `default_vault` value. It fails when the scalar is
unset. `aliases` is managed with `alias` commands. `remove` aliases `rm`.

## `exec`

```text
nkp exec [--key PATH [--field FIELD] --env NAME]...
  [CREDENTIAL OPTIONS] -- COMMAND [ARG ...]
```

Each binding selects an entry and maps one field to a child environment
variable. At least one `--key` binding is required, and each binding needs
exactly one matching `--env NAME`. Repeat the binding sequence for more
values. Omit `--field` to select the `Password` field. Set `--field otp` to
pass a TOTP code instead; HOTP is refused. The `--` separator marks the child
command and its arguments.

See [vault credentials](credentials.md) for accepted password sources and
their precedence. The child receives a fixed allowlist of environment
variables, not the full parent environment. `NEO_KEEPASS_*` and `NKP_*`
application variables are not passed through. The selected secret
is visible to the child and to processes
it starts, so run only trusted programs. The CLI refuses an output variable
that already exists in the parent environment. Names must be unique and use
ASCII letters, digits, and underscores; the first character must be a letter
or underscore. Both default master-password names are reserved as child
binding names: `NEO_KEEPASS_PASSWORD` and `NKP_PASSWORD`. On Windows, reservation follows the operating system's
case-insensitive environment-name semantics. The environment variable selected
by `--password-env` is also reserved. None of these default password variables
is inherited by the child; only the fixed allowlist and explicitly requested
binding values are passed.

This example uses the public `demo-user` value from the tutorial. It prompts
for the vault password without placing it in the command. Run it in Bash:

```bash
(
  read -r -s -p 'Vault master password: ' DEMO_MASTER
  printf '\n'
  export DEMO_MASTER
  unset DEMO_USERNAME
  nkp --vault ./tutorial.kdbx exec --key 'Demo/Example' --field UserName --env DEMO_USERNAME \
    --password-env DEMO_MASTER -- \
    sh -c 'printf "%s\n" "$DEMO_USERNAME"'
)
```

The child prints `demo-user`. The subshell keeps `DEMO_MASTER` out of the
parent shell after the command exits. `x` aliases `exec`.

## `completion`

```text
nkp completion SHELL
```

Prints static completion text for the requested shell. The output is printed
to stdout. Inspect generated text before adding it to a shell startup file.
Accepted shell names are `bash`, `sh`, `zsh`, `fish`, `powershell`, `pwsh`,
and `nushell`. Filesystem path completion after `set --bin NAME=` is provided
by the Bash completion script; other generated shell scripts currently complete
the command and option vocabulary but leave that path to manual entry.

The tested quoting of that `--bin NAME=` filename completion — candidates
inserted so hostile filenames travel to the command as one literal argument —
requires Bash 4.0 or newer: the script asks readline for `compopt` no-quoting
behavior, and `compopt` first appeared in Bash 4.0. Stock Bash 3.2 — still the
default `/bin/bash` on macOS — predates it and may misquote those filename
candidates or insert them at the wrong position. That is the extent of the
difference on 3.2: the script itself loads, command and option completion
work, and the dynamic vault/keys completion paths work; CI keeps exactly
those paths exercised against a native Bash 3.2 canary, so a regression
there fails the build rather than surfacing on user machines.

## `version`

```text
nkp version
nkp --version
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

Each shortcut accepts the same command-specific flags as its `secrets`
equivalent, along with the shared flags and credential options listed in
[vault credentials](credentials.md). The operation rejects flags that do not
apply to it.

## Global flags

`-h` and `--help` print help for the selected command. `-V PATH` and
`--vault PATH` select a vault before a command. Root `--version` prints
version information. The only other short options are `-r` for
`--age-recipient` and `-i` for `--age-identity`. Other options use their
long spelling.

Password options are available only on vault-opening or vault-creation
commands. See [vault credentials](credentials.md) for route coverage,
precedence, stdin conflicts, and safe source choices.
