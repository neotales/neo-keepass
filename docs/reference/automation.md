# Automation and interchange commands

The `automation` group provides `setx`, `import`, `export`, and `sync`.
The same operations are available as `secrets` subcommands and root
shortcuts. Inputs are bounded; interchange files can contain secret values.

## `setx`

```text
nkeepass automation setx --key PATH (--file PATH | --stdin) [--dry-run]
```

Reads bounded JSON and sets the entry's exact supplied fields as one update.
Exactly one input source is required. `--dry-run` validates and reports
without saving. `--key` is required.

## `import`

```text
nkeepass automation import (--file PATH | --stdin) [--replace] [--dry-run]
```

Reads a bounded interchange snapshot. Exactly one input source is required.
`--replace` permits replacing a non-empty vault. `--dry-run` validates and
reports without saving. The command does not accept an entry selector.

## `export`

```text
nkeepass automation export --output PATH
```

Writes an interchange snapshot to a private, no-clobber output file.
`--output` is required. It refuses an existing destination.

## `sync`

```text
nkeepass automation sync (--file PATH | --stdin)
  [--strategy newest|source] [--dry-run]
```

Reads a bounded interchange snapshot and synchronizes it with the vault.
Exactly one input source is required. `--strategy` chooses `newest` or
`source`; the default is `newest`. Use
`--dry-run` to report without saving.

The same commands are reachable as `nkeepass secrets setx/import/export/sync`
and root `nkeepass setx/import/export/sync`. No extra aliases are defined for
these four command names.
