# Add and extract an attachment

The canonical command group is `files`; `attachment` and `attachments` remain
accepted compatibility aliases. Commands operate on one entry.

## Add an attachment

```sh
nkeepass files add --key 'Services/Example' --field 'recovery.txt' \
  --file ./recovery.txt
```

The command reads the file bytes and stores them in the entry. Use
`--stdin` instead of `--file` to read bytes from standard input.

## List and extract

```sh
nkeepass files ls --key 'Services/Example'
nkeepass files get --key 'Services/Example' --field 'recovery.txt' \
  --output ./recovery-copy.txt
```

Listing prints attachment metadata. Extraction writes the contents to a
private, no-clobber file and refuses to overwrite an existing destination.
Choose an output directory with appropriate access controls; extracted
attachments are plaintext.

The root `set` shortcut also accepts repeated `--bin`/`-b` attachments:

```sh
nkeepass set --key 'Services/Example' \
  --bin 'recovery.txt=./recovery.txt' \
  -b 'identity.txt=./identity.txt'
```

The first `=` separates the attachment name and path; additional `=` characters
belong to the path. `--file`/`-f` retains its original behavior and reads a
field value from a file; it is never interpreted as an attachment option.
Attachment names containing `/` or control characters are rejected. A repeated
name, including one already present on the entry, fails without saving any part
of the requested batch. At most 256 `--bin` files and 16 MiB total input are
accepted. `--username VALUE`, `--url VALUE`, and `--notes VALUE` can be combined in
the same `set`; all requested field and attachment changes are saved together
only after validation succeeds.
The three direct field values are command-line arguments and may be visible in
process listings or shell history; use `--file` or `--stdin` for sensitive
values.

Bash completion completes the filesystem path after `NAME=` while retaining
the name prefix. Other generated shell completion scripts do not yet complete
the path portion dynamically.

## Remove an attachment

```sh
nkeepass files rm --key 'Services/Example' --field 'recovery.txt' --yes
```

The command requires `--yes` and does not prompt. It removes the named
attachment from the vault. Check the entry and attachment name before running
it.

See [attachment commands](../reference/entries.md#attachments) for aliases and
complete option details.
