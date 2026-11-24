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
nkp automation import (SRC | -f SRC | --file SRC | --stdin)
  [--format json|keepass-xml] [--replace] [--dry-run]
```

Reads a bounded interchange snapshot (default format `json`, or `keepass-xml`).
Exactly one input source is required (`SRC`, `-f`/`--file`, or `--stdin`; do
not pass both positional `SRC` and `--file`/`--stdin`).
`--replace` permits replacing a non-empty vault. `--dry-run` validates without
saving. The command does not accept an entry selector.
Age encryption and decryption options are unsupported and are rejected.

## `export`

```text
nkp automation export (DEST | -o DEST | --output DEST)
  [--format json|keepass-xml] [--allow-plaintext]
```

Writes an interchange snapshot to a private, no-clobber output file (positional
`DEST` or `-o`/`--output DEST`; do not supply both).
It refuses an existing destination. Default `--format` is plaintext `json`;
`--format keepass-xml` additionally requires `--allow-plaintext` to acknowledge
plaintext XML output. Age encryption and decryption options and `--name NAME`
are unsupported and are rejected.

## `sync`

```text
nkp automation sync (SRC | -f SRC | --file SRC | --stdin)
  [--strategy newest|source|target] [--dry-run]
```

Reads a bounded interchange snapshot and synchronizes it with the vault.
Exactly one input source is required (`SRC`, `-f`/`--file`, or `--stdin`).
`--strategy` chooses `newest` (default), `source` (prefer imported snapshot on
conflict), or `target` (keep existing vault values on conflict while adding
missing items). Use `--dry-run` to validate and report without saving. Age
encryption and decryption options are unsupported and are rejected.

The same commands are reachable as `nkp secrets import/export/sync`
and root `nkp import/export/sync`. No extra aliases are defined for
these three command names. For atomic entry field updates, use
[`set --field NAME=VALUE`](secrets.md#secrets-set).
