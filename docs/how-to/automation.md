# Exchange vault data with automation files

Use `setx` to set fields from JSON, `export` to create a snapshot, and
`import` or `sync` to apply a snapshot. These files can contain secrets.
Protect them like the vault itself and avoid printing their contents.

## Set fields from JSON

Create a JSON file with the fields to set. Then run:

```sh
nkeepass secrets setx --key 'Services/Example' --file entry.json
```

The CLI validates the bounded JSON input and applies the selected fields as
one update. Add `--dry-run` to validate and report without saving.

## Export a snapshot

```sh
nkeepass secrets export --output snapshot.json
```

The CLI prompts for the master password and writes a private, no-clobber
snapshot. It refuses to overwrite an existing destination.

## Import or synchronize

```sh
nkeepass secrets import --file snapshot.json --dry-run
nkeepass secrets sync --file snapshot.json --strategy newest --dry-run
```

Review the dry-run report before repeating the operation without
`--dry-run`. Import refuses to replace a non-empty vault unless you pass
`--replace`. Sync accepts `--strategy newest` or `--strategy source`.
Both operations read from exactly one of `--file PATH` and `--stdin`.

The same four operations are available under `nkeepass automation`. See
[automation command reference](../reference/automation.md) for each option and
its constraints.
