# Secrets and entry commands

Every command below operates on the selected vault. Use `--key PATH` to
select an entry. A key can be a slash-separated entry path or an entry alias.
Use `--field FIELD` where a command reads or changes one field.
Field selection uses `--field FIELD` first. Without it, an entry alias's
bound field is used; if the alias has no field binding, the command uses
`Password`.
Every route accepts `-h` or `--help`; `-V PATH` or `--vault PATH` may precede
the command. The shared credential flags also apply. See
[vault credentials](credentials.md) for the complete flag set and placement.

Entry path segments match ASCII case-insensitively. You may include or omit
the root group name. The CLI rejects `.` and `..`, empty segments, and
ambiguous matches. If a selector is also an entry alias name but resolves to
a different existing entry path, the CLI refuses it as ambiguous.

## List and search

### `secrets ls`

```text
nkeepass secrets ls [--] [GLOB]
```

Prints redacted entry metadata as JSON Lines. `list` is an alias. `GLOB` is
optional. Use `--` before a pattern that begins with a dash. The command does
not reveal field values.

### `secrets search`

```text
nkeepass secrets search [--] QUERY
```

Searches bounded, allowlisted entry metadata. A leading-dash query can follow
`--`. Unsafe labels or metadata that exceed projection limits may be withheld.

### `secrets show`

```text
nkeepass secrets show --key PATH
```

Prints redacted descriptors for one entry. Required option: `--key`. It does
not reveal field values.

### `secrets env`

```text
nkeepass secrets env --key PATH [--field FIELD] --name NAME
  [--key PATH [--field FIELD] --name NAME]...
  [--format FORMAT] [--is-output]
```

Each binding starts with `--key PATH`, may select a field with `--field`,
then must end with `--name NAME`. Repeat the sequence for additional values.
The field is required unless the key is an entry alias that already binds a
field. Use the field name `otp` to emit a TOTP code; HOTP is refused.
**Warning:** `secrets env`, its `environment` alias, and root `env` accept
`--age-encrypt`, `--age-decrypt`, `-r` / `--age-recipient`, and
`-i` / `--age-identity`, but
ignore them. Env output remains plaintext; these options do not encrypt or
decrypt it.

The default format is `shell`. Supported formats are `shell`, `dotenv`,
`pwsh`, `powershell`, `github-actions`, `azure-devops`, `json`, and `null`.
Named formats validate variable names and values before writing output.
`--is-output` applies only to `azure-devops`. Output goes to stdout and
contains the selected values. Treat it as plaintext secret output.

With `--format json`, `env` prints a JSON object whose property names are the
requested `--name` values and whose values are the selected text. With
`--format null`, it writes each name, a NUL byte, the value, and another NUL
byte. `null` means NUL-delimited output, not suppressed output.

## Read selected values

### `secrets get`

```text
nkeepass secrets get --key PATH [--field FIELD] [--format FORMAT]
  [--name NAME] [--is-output] [--age-encrypt] [-r KEY]... [--output PATH]
  [--clipboard]
```

Reveals one selected field. `--field` defaults to `Password`. The default
format is `text`. Supported formats are `text`, `json`, `null`, `dotenv`,
`shell`, `pwsh`, `powershell`, `github-actions`, and `azure-devops`.
Named formats require `--name NAME`. `--is-output` is valid only with
`azure-devops`.

`--age-encrypt` requires one or more recipients via repeated `-r` or
`--age-recipient`. Age encryption requires the `text` format, which is also
the default. Do not combine it with `--name` or `--is-output`. `--output PATH`
is valid only with `--age-encrypt`; it writes ciphertext to a private,
no-clobber file. Without `--output`, ciphertext goes to stdout. Without age
encryption, the selected value is printed as plaintext. Do not route it to
logs.

`--clipboard` explicitly sends plaintext to the system clipboard instead of
stdout. It is mutually exclusive with formatted, encrypted, or file output.
On Linux, `get` remains running for up to 30 seconds so the desktop clipboard
owner can serve paste requests; when the process exits the value may cease to
be available unless the desktop clipboard manager retained it. On Windows,
the clipboard is conditionally cleared after 30 seconds only if its ownership
sequence still matches this write. Other desktop backends do not provide a
safe atomic clear, so the value may remain according to that backend's
clipboard behavior. Clipboard failures and partial writes use static
diagnostics; a failed timed clear explicitly warns that the copied secret may
remain. No selected value is written to stdout or included in errors.

### `secrets getx`

```text
nkeepass secrets getx --key PATH [--field FIELD] [--format json]
```

Reveals the selected field as a JSON object of the form
`{"value":"field text"}`. `--field` defaults to `Password`. Only JSON format
is accepted. It does not accept `--name` or `--is-output`.

For `get`, `--format json` has the same `{"value":"field text"}` shape.
`--format null` writes the field bytes followed by one NUL byte. It does not
suppress output.

### `secrets otp`

```text
nkeepass secrets otp --key PATH [--format FORMAT] [--name NAME] [--is-output]
```

Generates and prints a TOTP code. It does not reveal the seed and refuses
HOTP entries. `--format` defaults to `text`; the other formats are `json`,
`null`, and the named formats listed for `secrets get`. Named formats require
`--name`. `--is-output` requires `azure-devops`.

## Change entries and fields

### `secrets set`

```text
nkeepass secrets set --key PATH [--field FIELD] [--file PATH | --stdin]
  [--age-decrypt -i PATH] [--username VALUE] [--url VALUE] [--notes VALUE]
  [--bin NAME=FILE_PATH]...
```

Reads one value from a file or stdin and updates the selected field. `--file`
and `--stdin` are mutually exclusive; at least one input, direct field update,
or `--bin` is required. `--field` defaults to `Password`. Repeat `--bin` or
`-b` to add attachments using `NAME=FILE_PATH`; the first `=` separates the
name, and further equals signs belong to the path. `--file`/`-f` always retains
its value-input meaning. Combined attachments and fields are saved only after
all requested mutations succeed, with an aggregate 16 MiB attachment input
limit, a 256-file count limit, and no replacement of existing attachment names. `--username`, `--url`,
and `--notes` accept direct values; those arguments can be visible in process
listings and shell history, so use `--file` or `--stdin` for sensitive values.
With
`--age-decrypt`, the input must be age ciphertext and `-i` or
`--age-identity PATH` is required. The CLI supports native age identities and
unencrypted SSH private keys, not encrypted SSH keys. This command saves the
vault; malformed input or credential failures prevent the update.

### `secrets ensure`

```text
nkeepass secrets ensure --key PATH [--size N] [--dry-run]
```

Creates a missing entry and its parent groups, but keeps an existing entry
unchanged. `--size N` generates a 1 to 4096 character password for the new
entry. `--dry-run` validates and reports without saving.

### `secrets rm`

```text
nkeepass secrets rm --key PATH --yes
```

Removes an entry. This command refuses `--field`; it does not delete a field.
`--yes` is required unconditionally. The command does not prompt. To remove a
custom field, use `field rm`.

## Interchange commands

These commands have the same behavior as the matching `automation`
subcommands. The shared credential flags also apply.

### `secrets setx`

```text
nkeepass secrets setx --key PATH (--file PATH | --stdin) [--dry-run]
```

Reads bounded JSON for one existing entry and applies its fields as one
update. Exactly one input source is required. `--dry-run` validates and
reports without saving. See the [setx JSON schema and example](automation.md#setx).
**Warning:** `secrets setx` and root `setx` accept `--age-encrypt`,
`--age-decrypt`, `-r` / `--age-recipient`, and `-i` / `--age-identity`, but
ignore them. They do not
encrypt or decrypt the JSON input.

### `secrets import`

```text
nkeepass secrets import (--file PATH | --stdin) [--replace] [--dry-run]
```

Reads an interchange snapshot. Exactly one input source is required.
`--replace` permits replacing a non-empty vault. `--dry-run` validates and
reports without saving. **Warning:** `secrets import` and root `import` accept
`--age-encrypt`, `--age-decrypt`, `-r` / `--age-recipient`, and `-i` /
`--age-identity`, but ignore them. Import does not decrypt the input.

### `secrets export`

```text
nkeepass secrets export --output PATH
```

Writes an interchange snapshot to a private, no-clobber file. `--output` is
required, and an existing destination is not overwritten. **Warning:**
`secrets export` and root `export` accept `--name NAME`, `--age-encrypt`,
`--age-decrypt`, `-r` / `--age-recipient`, and `-i` / `--age-identity`, but
ignore them. Export
remains plaintext JSON; these options do not encrypt it.

### `secrets sync`

```text
nkeepass secrets sync (--file PATH | --stdin)
  [--strategy newest|source] [--dry-run]
```

Synchronizes an interchange snapshot with the vault. Exactly one input source
is required. `--strategy` defaults to `newest`; `source` is the other
accepted value. `--dry-run` reports without saving. **Warning:** `secrets sync`
and root `sync` accept `--age-encrypt`, `--age-decrypt`, `-r` / `--age-recipient`,
and `-i` / `--age-identity`, but ignore them. Sync does not encrypt or decrypt the
interchange data.

## Output formats and credentials

Named formats emit a variable name and a value. Names must meet the target
format's rules. Azure DevOps output requires `--is-output` to mark an output
variable. The CLI rejects disallowed line breaks and heredoc delimiters rather
than producing malformed output.

These commands accept the shared vault credential options. See
[vault credentials](credentials.md) for source precedence, route availability,
and the `--password-stdin` versus `--stdin` conflict.

## Aliases

`list` aliases `ls`; `remove` aliases `rm`. Root shortcuts such as
`nkeepass get` call the matching `secrets get` operation. The complete
root-shortcut and option alias list is in the [alias index](../commands.md).
Age encryption and decryption steps are in [the age how-to](../how-to/age.md).
