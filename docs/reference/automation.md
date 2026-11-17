# Automation and interchange commands

The `automation` group provides `setx`, `import`, `export`, and `sync`.
The same operations are available as `secrets` subcommands and root
shortcuts. Inputs are bounded; interchange files can contain secret values.
These routes accept the shared vault credential options described in
[vault credentials](credentials.md).
Each route also accepts `-h` or `--help`; `-V PATH` or `--vault PATH` may
precede the command.

## `setx`

```text
nkeepass automation setx --key PATH (--file PATH | --stdin) [--dry-run]
```

Reads bounded JSON and applies its field updates in one update.
Exactly one input source is required. `--dry-run` validates and reports
without saving. `--key` is required. **Warning:** this route accepts
`--age-encrypt`, `--age-decrypt`, `-r` / `--age-recipient`, and
`-i` / `--age-identity` for
compatibility, but ignores them. They do not encrypt or decrypt this JSON.

The document has one required top-level property, `fields`. Its value is a
non-empty array of objects. Every object requires a string `key` and string
`value`. The optional `protected` and `protect_in_memory` properties are
booleans. Unknown properties are rejected at both object levels. Field keys
must be unique and non-empty.

```json
{
  "fields": [
    {
      "key": "UserName",
      "value": "demo-user"
    },
    {
      "key": "Notes",
      "value": "example",
      "protected": false,
      "protect_in_memory": false
    }
  ]
}
```

The file may be at most 1 MiB and nesting may not exceed 8 levels. A document
may contain 1 to 256 fields. Each key is limited to 16 KiB of text, and each
value is limited to 1 MiB. If `protected` is omitted, password and custom
fields default to protected while `UserName`, `URL`, and `Notes` default to
unprotected. If `protect_in_memory` is omitted, it uses the `protected` value.
Only standard fields are added when absent. A supplied custom field is updated
only if it already exists; otherwise it is ignored. The example uses
`UserName` and `Notes`, both standard fields.

## `import`

```text
nkeepass automation import (--file PATH | --stdin) [--replace] [--dry-run]
```

Reads a bounded interchange snapshot. Exactly one input source is required.
`--replace` permits replacing a non-empty vault. `--dry-run` validates and
reports without saving. The command does not accept an entry selector.
**Warning:** it accepts
`--age-encrypt`, `--age-decrypt`, `-r` / `--age-recipient`, and `-i` /
`--age-identity`, but ignores them. Import does not decrypt the input.

## `export`

```text
nkeepass automation export --output PATH
```

Writes an interchange snapshot to a private, no-clobber output file.
`--output` is required. It refuses an existing destination.
**Warning:** it accepts `--name NAME`, `--age-encrypt`, `--age-decrypt`, `-r` /
`--age-recipient`, and `-i` / `--age-identity`, but ignores them. Export
remains plaintext JSON; these options do not encrypt it.

## `sync`

```text
nkeepass automation sync (--file PATH | --stdin)
  [--strategy newest|source] [--dry-run]
```

Reads a bounded interchange snapshot and synchronizes it with the vault.
Exactly one input source is required. `--strategy` chooses `newest` or
`source`; the default is `newest`. Use
`--dry-run` to report without saving. **Warning:** it accepts
`--age-encrypt`, `--age-decrypt`, `-r` / `--age-recipient`, and `-i` /
`--age-identity`, but ignores them. Sync does not encrypt or decrypt the
interchange data.

The same commands are reachable as `nkeepass secrets setx/import/export/sync`
and root `nkeepass setx/import/export/sync`. No extra aliases are defined for
these four command names.
