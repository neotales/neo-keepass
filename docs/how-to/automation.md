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
nkp export snapshot.json
# Explicit KeePass XML export requires --allow-plaintext:
nkp export snapshot.xml --format keepass-xml --allow-plaintext
```

The CLI prompts for the master password and writes a private, no-clobber
snapshot (`DEST` or `-o` / `--output DEST`). It refuses to overwrite an existing
destination.

## Import or synchronize

```sh
nkp import snapshot.json --dry-run
nkp sync snapshot.json --strategy newest --dry-run
```

`--dry-run` validates without saving or writing a change report. Import refuses
to replace a non-empty vault unless you pass `--replace`, and both `import` and
`sync` accept `--file PATH` / `-f PATH`, positional `SRC`, or `--stdin` (plus
`--format keepass-xml` on `import`). Sync accepts `--strategy newest` (default),
`--strategy source` (prefer imported values), or `--strategy target` (keep
existing vault values on conflict while adding missing items).

The three snapshot operations are available under `nkp automation`. See
[automation command reference](../reference/automation.md) for each option and
its constraints.
