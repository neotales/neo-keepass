# Exchange vault data with automation files

Use `set --field` to set fields, `export` to create a snapshot, and
`import` or `sync` to apply a snapshot. These files can contain secrets.
Protect them like the vault itself and avoid printing their contents.

## Set multiple fields

This example contains only public sample data:

```sh
nkp secrets set 'Demo/Example' --field UserName=demo-user --field Notes=example
```

The selected fields are applied atomically to an existing entry; missing
custom fields are created. Argument values are visible in process listings
and shell history. For a sensitive single value, prefer `--value-stdin`,
`--value-file`, `--value-env`, or the hidden prompt. See the
[set reference](../reference/secrets.md#secrets-set).

## Export a snapshot

```sh
nkp secrets export --output snapshot.json
```

The CLI prompts for the master password and writes a private, no-clobber
snapshot. It refuses to overwrite an existing destination.

## Import or synchronize

```sh
nkp secrets import --file snapshot.json --dry-run
nkp secrets sync --file snapshot.json --strategy newest --dry-run
```

Review the dry-run report before repeating the operation without
`--dry-run`. Import refuses to replace a non-empty vault unless you pass
`--replace`. Sync accepts `--strategy newest` or `--strategy source`.
Both operations read from exactly one of `--file PATH` and `--stdin`.

The three snapshot operations are available under `nkp automation`. See
[automation command reference](../reference/automation.md) for each option and
its constraints.
