# Attachments, groups, and custom fields

These routes accept the shared vault credential options described in
[vault credentials](credentials.md).
Each route also accepts `-h` or `--help`; `-V PATH` or `--vault PATH` may
precede the command.

## Attachments

The canonical group name is `files`. `attachment` and `attachments` are
compatibility aliases.

### `files ls`

```text
nkp files ls (ENTRY | --key ENTRY)
```

Lists attachment names and sizes for the selected entry. `list` aliases `ls`.
The entry selector may be positional or supplied with `-k` / `--key`; do not
supply both.

### `files add`

```text
nkp files add (ENTRY | --key ENTRY) --field NAME (--file PATH | --stdin)
```

Reads bytes from exactly one source and adds them as an attachment named by
`--field`. The operation changes the vault. `import` aliases `add`. The entry
selector may be positional or supplied with `-k` / `--key`; do not supply
both.

### `files get`

```text
nkp files get (ENTRY | --key ENTRY) --field NAME --output PATH
```

Writes the attachment bytes to a private, no-clobber file. An entry selector,
`--field`, and `--output` are required. The file contains plaintext attachment
data. `export` aliases `get`. The entry selector may be positional or supplied with `-k` / `--key`;
do not supply both.

### `files rm`

```text
nkp files rm (ENTRY | --key ENTRY) --field NAME --yes
```

Removes the selected attachment. `--yes` is required and the command does not
prompt. `remove` aliases `rm`. The entry selector may be positional or
supplied with `-k` / `--key`; do not supply both.

## Groups

The group name is `group`. `groups` is an alias.

### `group ls`

```text
nkp group ls
```

Lists group paths. `list` aliases `ls`.

### `group add`

```text
nkp group add (PATH | --key PATH) [--dry-run]
```

Creates missing groups in the selected path and leaves existing groups
unchanged. `--dry-run` validates without saving or printing a report.
`create` and `ensure` alias `add`. `PATH` is the group path and may be positional or supplied with
`-k` / `--key`; do not supply both. A leading dash requires `-- PATH`.

### `group rm`

```text
nkp group rm (PATH | --key PATH) --yes [--dry-run]
nkp group rm (PATH | --key PATH) --dry-run
```

Removes the group and its contents. The root group cannot be removed.
`--yes` is required unless `--dry-run` is set. The command does not prompt.
`--dry-run` validates without saving or printing a report; it may also be
combined with `--yes`. `remove` aliases `rm`. `PATH` may be
positional or supplied with `-k` / `--key`; do not supply both.

## Custom fields

The group name is `field`. `custom-field` is an alias.

### `field ls`

```text
nkp field ls (ENTRY | --key ENTRY)
```

Lists all fields present on one entry, including built-in fields such as
`Title`, `UserName`, `Password`, `URL`, and `Notes`. `list` aliases `ls`. The
entry selector may be positional or supplied with `-k` / `--key`; do not
supply both.

### `field get`

```text
nkp field get (ENTRY | --key ENTRY) --field FIELD [--format FORMAT] [--name NAME]
  [--is-output]
```

Reveals one custom field. The format defaults to `text`; supported formats
match `secrets get`. Named formats require `--name`. `--is-output` is valid
only for `azure-devops`. It refuses built-in fields; use `secrets get` to read
them. `reveal` aliases `get`.

`field get` does not accept `--age-encrypt`, `-r` or `--age-recipient`, or
`--output`. Its generated help lists those inherited `get` flags, but the
command rejects them. Use
`nkp secrets get --key PATH --field FIELD --age-encrypt ...` when you
need encrypted output.

### `field set`

```text
nkp field set (ENTRY | --key ENTRY) --field FIELD (--file PATH | --stdin)
```

Reads one value and sets the custom field. Exactly one input source is
required. `edit` aliases `set`. The entry selector may be positional or
supplied with `-k` / `--key`; do not supply both.

`field set` does not accept `--age-decrypt`, `-i`, or `--age-identity`. Its
generated help lists those inherited `set` flags, but the command rejects
them. To decrypt input before updating a custom field, use
`nkp secrets set --key PATH --field FIELD --age-decrypt
--age-identity PATH --file CIPHERTEXT`.

### `field rm`

```text
nkp field rm (ENTRY | --key ENTRY) --field FIELD --yes
```

Removes the selected custom field. `--yes` is required and the command does
not prompt. It refuses built-in fields such as `Title`, `UserName`,
`Password`, `URL`, and `Notes`. `remove` aliases `rm`. The entry selector may
be positional or supplied with `-k` / `--key`; do not supply both.
