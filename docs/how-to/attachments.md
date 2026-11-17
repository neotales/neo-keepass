# Add and extract an attachment

Attachment commands operate on one entry. The attachment name is supplied
with `--field`.

## Add an attachment

```sh
nkeepass attachment add --key 'Services/Example' --field 'recovery.txt' \
  --file ./recovery.txt
```

The command reads the file bytes and stores them in the entry. Use
`--stdin` instead of `--file` to read bytes from standard input.

## List and extract

```sh
nkeepass attachment ls --key 'Services/Example'
nkeepass attachment get --key 'Services/Example' --field 'recovery.txt' \
  --output ./recovery-copy.txt
```

Listing prints attachment metadata. Extraction writes the contents to a
private, no-clobber file and refuses to overwrite an existing destination.
Choose an output directory with appropriate access controls; extracted
attachments are plaintext.

## Remove an attachment

```sh
nkeepass attachment rm --key 'Services/Example' --field 'recovery.txt' --yes
```

The command requires `--yes` and does not prompt. It removes the named
attachment from the vault. Check the entry and attachment name before running
it.

See [attachment commands](../reference/entries.md#attachments) for aliases and
complete option details.
