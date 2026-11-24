# Configuration, child processes, completion, and root commands

Every route accepts `-h` or `--help`. `-V PATH` or `--vault PATH` may precede
vault-opening commands (it is rejected on `tui`, `use`, `alias`, `config`,
`completion`, `version`, `trust`, `untrust`, `shell`, and `context` subcommands
other than `context show`). Password flags are available only on credential
routes. See [vault credentials](credentials.md) for the exact route matrix.

## Human output color

Place the root option before the command: `nkp --color=auto COMMAND`.
`--color=auto|always|never` controls color on human help and diagnostics;
`--no-color` is an alias for `--color=never`. `--color=basic` and
`--color=truecolor` are also available; unsupported truecolor capability falls
back to basic, and Windows currently uses plain output because safe virtual
terminal support is not detected. The default `auto` colors only when that
output stream is a TTY and `TERM` is not `dumb`. Auto uses truecolor only when
`COLORTERM` is `truecolor` or `24bit`, otherwise basic.

An explicit CLI setting wins over environment variables. Without one, a
nonempty (including non-Unicode) `NO_COLOR` disables color; an empty value is
absent. Otherwise `FORCE_COLOR=0` disables,
`FORCE_COLOR=1`, `true`, or empty enables basic, `2` enables basic, and `3`
requests truecolor. Invalid `FORCE_COLOR` values are ignored. Explicit
`--color=auto` uses terminal capability and ignores both environment overrides.
`--color=always` can color human output redirected to a pager; `TERM=dumb` and
unsupported Windows terminals remain plain.

Color affects only human help and diagnostic labels. A color policy is accepted
but ignored by machine/raw routes to preserve their exact bytes: data output,
JSON, null-delimited and shell formats, completion scripts, files, and
child-process output are never styled, even when color is forced.
Diagnostics for data routes (including `show`, `otp`, all interchange forms,
and `secrets env/environment`) are also always plain. This is intentional:
forcing presentation color never rejects an otherwise valid data command.
Help remains human output even when requested for a data route; styling is
inserted after wrapping, so disabling it leaves exactly the same layout.

For `exec/x`, the first `--` **after the exec route** starts child argv; a
preceding exec value option must be complete before it. A root `-V` / `--vault`
value spelled `--` remains a vault selector, not the child boundary.
Child switches are never normalized or completed
as nkp options. The intentionally limited POSIX `sh` helper has no access to
the full command line: integrations must pass `true` as its optional seventh
`AFTER_SEPARATOR` argument for every child slot, not just the first.

## `tui`

```text
nkp tui PATH
```

Opens the interactive terminal browser for the supplied vault path. This
command requires exactly one path argument. It does not use the active-vault
selection and does not accept `-V` / `--vault`; pass the vault path directly.

The UI pauses key handling below 40 columns by 12 rows. Revealed values own
focus: Esc or Enter hides them; unrelated keys do not open hidden dialogs.
Compact entry views prioritize a scrolling field list, keeping the selected
field visible. Selected-field reveal prompts name that field before consent.
Their indexed target viewport is separate from reserved consent/warning rows,
so long names cannot hide instructions. F2 opens full-name inspection; arrows,
PgUp/PgDn, and Home/End distinguish even names with long colliding prefixes.
Generating a replacement password requires a length followed by a separate
`YES` confirmation. Save explicitly to persist changes.
Action instructions are captured separately from transient status notices;
clipboard expiry cannot replace the instructions of an active confirmation.
Notices have a separate summary row; Esc cancels the action and shows the full
notice in the status area.
Clipboard clear failures and uncertain/manual-clear outcomes additionally
retain an independent actionable warning across action confirmation and status
updates. F3 opens its full text; `a` explicitly acknowledges it only in that
view. Esc/Enter returns without acknowledgement. Acknowledging does not clear
the clipboard or claim that its password is gone.
Warning review preserves the previous modal, including target inspection
position and deletion confirmation drafts; returning or acknowledging restores
that interaction. Unsaved-changes dialogs also expose the F3 warning hint.

In entry view, `n`/`p` selects an attachment and updates its live marker.
Export and removal identify the selected index; removal requires `YES`.
Use F2 before submitting either action to inspect the full attachment name.
Arrows, PgUp/PgDn, and Home/End pan long targets; Esc returns to the action.
Entry/group deletion dialogs also show the row index and allow full-target
inspection with those navigation keys. Failed page continuations retain their
last rows and error; `/` then Enter explicitly restarts the traversal.

These UI safeguards do not establish terminal admission or signal safety.
Split-terminal/Crossterm input identity and signal/input-boundary risks remain
unresolved. Startup behavior, including Windows startup, is unchanged; the
UI PTY checks have been run on Linux, not Windows or macOS.

### Lock and secret lifetime

The unlocked UI owns the credentials needed for explicit saves. After five
minutes idle, a clean vault locks immediately. Unsaved changes or an unfinished
edit instead require a save/discard/cancel decision; until resolved, the vault
and its credentials remain unlocked in memory. Cancel returns to that same
unlocked session. A failed save keeps the decision and credentials available for
retry; a successful save completes the requested lock or exit.

Lock drops the database session and credentials (whose owned master-password
buffer is zeroized on drop), clears the UI's live input/reveal buffers, and
attempts clipboard release. No saves are permitted after lock. There is no
in-place re-unlock or cached-password retry: press `q`, then run `nkp tui PATH`
again and supply credentials afresh. Clipboard warnings remain actionable on
the lock screen; acknowledging one does not erase an external clipboard copy.

This is owned-buffer lifetime reduction, not whole-process memory erasure.
Ordinary heap allocations, previous reallocations, database/model copies,
library temporaries, terminal rendering/frame buffers, terminal-emulator
scrollback, clipboard managers, swap, crash dumps, and screenshots are not
covered by a blanket zeroization guarantee. Normal drop/unwind cleanup does
not run on every forced termination.

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
nkp exec (-B NAME=ENTRY | -k PATH [-F FIELD] --env NAME | --env-file FILE)...
  [CREDENTIAL OPTIONS] -- COMMAND [ARG ...]
```

Each binding maps a vault value into a child environment variable using:
- `-B NAME=ENTRY` / `--bind NAME=ENTRY` (uses `Password`, or the entry alias's
  bound field when `ENTRY` is a field-bound alias),
- `-k PATH [-F FIELD] --env NAME` (`--field` defaults to `Password`, or `otp`
  for a TOTP code; HOTP is refused), or
- `--env-file FILE` (loads `KEY=VALUE` and `nkp://` / `{{nkp://...}}` template
  bindings from a bounded `.env` file).

Repeat bindings as needed; at least one binding or `--env-file` is required. The
first `--` after `exec` / `x` marks the child command and its arguments, after
root option values have been consumed. Root `--password-env` and
`--password-stdin` may appear before or after `exec`/`x`; `--password-file`,
`--key-file`, and `--password` go after `exec`/`x` and before `-- COMMAND`.

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
  nkp -V "$HOME/nkeepass-demo/demo.kdbx" x -k 'Demo/Example' -F UserName --env DEMO_USERNAME \
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
| `get many` | `secrets get many` |
| `ls`, `list` | `secrets ls` |
| `search` | `secrets search` |
| `show` | `secrets show` |
| `set` | `secrets set` |
| `rm`, `remove` | `secrets rm` |
| `ensure` | `secrets ensure` |
| `otp` | `secrets otp` |
| `import` | `secrets import` |
| `export` | `secrets export` |
| `sync` | `secrets sync` |
| `env` | `secrets env` |

Each shortcut accepts the same command-specific flags as its `secrets`
equivalent, along with the shared flags and credential options listed in
[vault credentials](credentials.md). The operation rejects flags that do not
apply to it.

The `use`, `inject`, `trust`, `untrust`, and `shell` commands (`init`,
`completions`/`completion`, `load`, `unload`, `status`) manage active vaults,
`.nkp.toml` project trust, shell hooks, and `nkp://` template rendering. See
[shell integration and secret injection](../how-to/shell-integration.md) and
[`context`](vault.md#context-and-use).

## Global flags

`-h` and `--help` print help for the selected command. `-V PATH` and
`--vault PATH` select a vault before vault-opening commands. Root `--version`
prints version information. Normalized short options across CLI routes are `-h`,
`-V`, `-k` (`--key`), `-f` (`--file`), `-F` (`--field`), `-n` (`--name`), `-o`
(`--output`), `-y` (`--yes`), `-B` (`--bind` on `exec`/`x`), `-b` (`--bin`),
`-c` (`--chars` / `--size`), `-U` (`--upper`), `-L` (`--lower`), `-D`
(`--digits`), `-S` (`--symbols`), `-r` (`--age-recipient`), and `-i`
(`--age-identity`).

Password options are available only on vault-opening or vault-creation
commands. See [vault credentials](credentials.md) for route coverage,
precedence, stdin conflicts, and safe source choices.
