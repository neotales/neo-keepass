# Automation and interchange commands

The `automation` group provides `import`, `export`, and `sync`.
The same operations are available as `secrets` subcommands and root
shortcuts. Inputs are bounded; interchange files can contain secret values.
These routes accept the shared vault credential options described in
[vault credentials](credentials.md).
Each route also accepts `-h` or `--help`; `-V PATH` or `--vault PATH` may
precede the command.

## `import`

```text
nkp automation import (--file PATH | --stdin) [--replace] [--dry-run]
```

Reads a bounded interchange snapshot. Exactly one input source is required.
`--replace` permits replacing a non-empty vault. `--dry-run` validates and
reports without saving. The command does not accept an entry selector.
Age encryption and decryption options are unsupported and are rejected.

## `export`

```text
nkp automation export --output PATH
```

Writes an interchange snapshot to a private, no-clobber output file.
`--output` is required. It refuses an existing destination. Export writes
plaintext JSON; age encryption and decryption options are unsupported and are
rejected. `--name NAME` is accepted but has no effect.

## `sync`

```text
nkp automation sync (--file PATH | --stdin)
  [--strategy newest|source] [--dry-run]
```

Reads a bounded interchange snapshot and synchronizes it with the vault.
Exactly one input source is required. `--strategy` chooses `newest` or
`source`; the default is `newest`. Use
`--dry-run` to report without saving. Age encryption and decryption options
are unsupported and are rejected.

The same commands are reachable as `nkp secrets import/export/sync`
and root `nkp import/export/sync`. No extra aliases are defined for
these three command names. For atomic entry field updates, use
[`set --field NAME=VALUE`](secrets.md#secrets-set).
