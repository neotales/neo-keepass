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
nkp files ls (ENTRY | --key ENTRY) [--format json|human]
```

Lists attachment names, byte sizes, and protection flags for the selected entry
as JSON Lines (`--format json`, the default) or bounded human-readable columns
(`--format human`, marking attachments `[protected]` or `[plain]` and empty
lists `(no attachments)`). `list` aliases `ls`. The entry selector may be
positional or supplied with `-k` / `--key`; do not supply both.

### `files add`

```text
nkp files add (ENTRY | -k ENTRY | --key ENTRY) (NAME | -n NAME | --name NAME | -F NAME | --field NAME) (-f PATH | --file PATH | --stdin)
```

Reads bytes from exactly one source and adds them as an attachment named by
`-n` / `--name`, `-F` / `--field`, or the second positional `NAME` argument. The
operation changes the vault. `import` aliases `add`. The entry selector may be
positional or supplied with `-k` / `--key`; do not supply both, and do not
supply both positional `NAME` and a name/field flag.

### `files get`

```text
nkp files get (ENTRY | -k ENTRY | --key ENTRY) (NAME | -n NAME | --name NAME | -F NAME | --field NAME) (-o PATH | --output PATH)
```

Writes the attachment bytes to a private, no-clobber file. An entry selector,
attachment name (`NAME`, `-n`/`--name`, or `-F`/`--field`), and `-o` /
`--output` are required. The file contains plaintext attachment data. `export`
aliases `get`. The entry selector may be positional or supplied with `-k` /
`--key`; do not supply both.

### `files rm`

```text
nkp files rm (ENTRY | -k ENTRY | --key ENTRY) (NAME | -n NAME | --name NAME | -F NAME | --field NAME) (-y | --yes)
```

Removes the selected attachment (`NAME`, `-n`/`--name`, or `-F`/`--field`). `-y`
/ `--yes` is required and the command does not prompt. `remove` aliases `rm`.
The entry selector may be positional or supplied with `-k` / `--key`; do not
supply both.

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
nkp field ls (ENTRY | --key ENTRY) [--format json|human]
```

Lists all fields present on one entry, including built-in fields such as
`Title`, `UserName`, `Password`, `URL`, and `Notes`, as JSON Lines (`--format
json`, the default) or bounded human-readable columns (`--format human`,
marking `[protected]`/`[plain]`, `[in-memory]`, `[otp]`, and `(no fields)`).
`list` aliases `ls`. The entry selector may be positional or supplied with `-k` /
`--key`; do not supply both.

### `field get`

```text
nkp field get (ENTRY | -k ENTRY | --key ENTRY) (FIELD | -F FIELD | --field FIELD)
  [--format FORMAT] [-n NAME | --name NAME] [--is-output]
```

Reveals one custom field. The format defaults to `text`; supported formats
match `secrets get`. Named formats require `-n` / `--name`. `--is-output` is
an optional Azure DevOps modifier (`azure-devops` works without it). `field get`
refuses built-in fields; use `get` / `secrets get` to read them. `reveal`
aliases `get`.

`field get` does not accept `--age-encrypt`, `-r` / `--age-recipient`,
`--clipboard`, or `-o` / `--output`, and omits them from its help. Use
`nkp get PATH -F FIELD --age-encrypt ...` when you need encrypted output.

### `field set`

```text
nkp field set (ENTRY | -k ENTRY | --key ENTRY) (FIELD | -F FIELD | --field FIELD)
  (-f PATH | --file PATH | --stdin)
```

Reads one value and sets the custom field. Exactly one input source is
required. `edit` aliases `set`. The entry selector may be positional or
supplied with `-k` / `--key`; do not supply both.

`field set` does not accept `--age-decrypt`, `-i`, or `--age-identity`, and
omits them from its help. To decrypt input before updating a custom field, use
`nkp set PATH -F FIELD --age-decrypt -i PATH -f CIPHERTEXT`.

### `field rm`

```text
nkp field rm (ENTRY | -k ENTRY | --key ENTRY) (FIELD | -F FIELD | --field FIELD) (-y | --yes)
```

Removes the selected custom field. `-y` / `--yes` is required and the command does
not prompt. It refuses built-in fields such as `Title`, `UserName`,
`Password`, `URL`, and `Notes`. `remove` aliases `rm`. The entry selector may
be positional or supplied with `-k` / `--key`; do not supply both.
