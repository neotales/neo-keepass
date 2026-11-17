# Attachments, groups, and custom fields

## Attachments

The group name is `attachment`. `attachments` is an alias.

### `attachment ls`

```text
nkeepass attachment ls --key PATH
```

Lists attachment names and sizes for the selected entry. `--key` is required.
`list` aliases `ls`.

### `attachment add`

```text
nkeepass attachment add --key PATH --field NAME (--file PATH | --stdin)
```

Reads bytes from exactly one source and adds them as an attachment named by
`--field`. The operation changes the vault. `import` aliases `add`.

### `attachment get`

```text
nkeepass attachment get --key PATH --field NAME --output PATH
```

Writes the attachment bytes to a private, no-clobber file. All three options
are required. The file contains plaintext attachment data. `export` aliases
`get`.

### `attachment rm`

```text
nkeepass attachment rm --key PATH --field NAME --yes
```

Removes the selected attachment. `--yes` is required and the command does not
prompt. `remove` aliases `rm`.

## Groups

The group name is `group`. `groups` is an alias.

### `group ls`

```text
nkeepass group ls
```

Lists group paths. `list` aliases `ls`.

### `group add`

```text
nkeepass group add --key PATH [--dry-run]
```

Creates missing groups in the selected path and leaves existing groups
unchanged. `--dry-run` reports without saving. `create` and `ensure` alias
`add`.

### `group rm`

```text
nkeepass group rm --key PATH --yes [--dry-run]
```

Removes the group and its contents. The root group cannot be removed.
`--yes` is required unless `--dry-run` is set. The command does not prompt.
`--dry-run` reports without saving. `remove` aliases `rm`.

## Custom fields

The group name is `field`. `custom-field` is an alias.

### `field ls`

```text
nkeepass field ls --key PATH
```

Lists custom-field names for one entry. `list` aliases `ls`.

### `field get`

```text
nkeepass field get --key PATH --field FIELD [--format FORMAT] [--name NAME]
  [--is-output]
```

Reveals one custom field. The format defaults to `text`; supported formats
match `secrets get`. Named formats require `--name`. `--is-output` is valid
only for `azure-devops`. `reveal` aliases `get`.

`field get` does not accept age options. Its generated help currently lists
the shared `get` flags, but the command rejects them. Use
`nkeepass secrets get --key PATH --field FIELD --age-encrypt ...` when you
need encrypted output.

### `field set`

```text
nkeepass field set --key PATH --field FIELD (--file PATH | --stdin)
```

Reads one value and sets the custom field. Exactly one input source is
required. `edit` aliases `set`.

`field set` does not accept age options. Its generated help currently lists
the shared `set` flags, but the command rejects age decryption for this
route. To decrypt input before updating a custom field, use
`nkeepass secrets set --key PATH --field FIELD --age-decrypt
--age-identity PATH --file CIPHERTEXT`.

### `field rm`

```text
nkeepass field rm --key PATH --field FIELD --yes
```

Removes the selected custom field. `--yes` is required and the command does
not prompt. It refuses built-in fields such as `Title`, `UserName`,
`Password`, `URL`, and `Notes`. `remove` aliases `rm`.
