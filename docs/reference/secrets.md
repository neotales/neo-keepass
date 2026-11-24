# Secrets and entry commands

Every command below operates on the selected vault. Use `--key PATH` (or
`-k PATH`) to select an entry. `get`, `set`, `rm`/`remove`, `field`, and
`files` routes also accept the entry path or alias positionally where they
operate on one entry. Do not provide both forms. A key can be a slash-separated
entry path or an entry alias.
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

## Common short workflows

These Bash and PowerShell examples use the same single-quoted path spelling.
They assume the intended vault is selected and normal password prompting is
available. `ensure` creates the entry if it is missing; `show` only lists
redacted metadata, and `otp` emits a one-time code only when that entry has a
TOTP field.

```bash
nkp show 'Services/mail'
nkp ensure 'Services/mail'
nkp otp 'Services/mail'
```

```powershell
nkp show 'Services/mail'
nkp ensure 'Services/mail'
nkp otp 'Services/mail'
```

`show`, `ensure`, and `otp` also keep their explicit `-k` / `--key PATH`
forms. Do not supply both a positional path and `--key`. Use `-- PATH` if a
selector begins with `-`, for example `nkp show -- -example`.

The `field` and `files` routes take their entry selector positionally or with
`-k` / `--key`, and their field or attachment name as the second positional
argument or with `-F` / `--field`. `--name` / `-n` names an output variable on
supported named formats (and `secrets env`), not a field or attachment selector.
For example: `nkp field get 'Services/mail' Token`.

## List and search

### `secrets ls`

```text
nkp secrets ls [--] [GLOB]
```

Prints redacted entry metadata as JSON Lines. `list` is an alias. `GLOB` is
optional. Use `--` before a pattern that begins with a dash. The command does
not reveal field values.

### `secrets search`

```text
nkp secrets search [--] QUERY
```

Searches bounded, allowlisted entry metadata. A leading-dash query can follow
`--`. Unsafe labels or metadata that exceed projection limits may be withheld.

### `secrets show`

```text
nkp secrets show PATH
```

Prints redacted descriptors for one entry. `--key PATH` and `-k PATH` remain
supported alternatives. It does not reveal field values.

### `secrets env`

```text
nkp secrets env (-k PATH [-F FIELD] (-n NAME | --env NAME))...
  [--format FORMAT] [--is-output]
```

Each binding starts with `-k` / `--key PATH`, may select a field with `-F` /
`--field`, then must end with `-n` / `--name NAME` (or compatibility `--env NAME`).
Repeat the sequence for additional values. The field defaults to an entry alias's
bound field when omitted, and is otherwise required (`Password` is not assumed
without an explicit `-F` or field-bound alias). Use `-F otp` to emit a TOTP code;
HOTP is refused.
`secrets env`, its `environment` alias, and root `env` refuse unsupported flags
such as `--age-encrypt`, `--age-decrypt`, `-r` / `--age-recipient`,
`-i` / `--age-identity`, `--dry-run`, `--clipboard`, `--output`, `--replace`,
`--yes`, and generator flags before unlocking or writing output.
Env output is plaintext; use `get many --age-encrypt` for an encrypted bundle.

The default format is `shell`. Supported formats are `shell`, `dotenv`,
`pwsh`, `powershell`, `github-actions`, `azure-devops`, `json`, and `null`.
Named formats validate variable names and values before writing output.
`--is-output` is valid only with `azure-devops` (optional modifier to add
`;isOutput=true`; `azure-devops` does not require it). Output goes to stdout and
contains the selected values. Treat it as plaintext secret output.

With `--format json`, `env` prints a JSON object whose property names are the
requested `--name` values and whose values are the selected text. With
`--format null`, it writes each name, a NUL byte, the value, and another NUL
byte. `null` means NUL-delimited output, not suppressed output.

## Read selected values

### `secrets get`

```text
nkp secrets get [PATH] [--key PATH] [--field FIELD] [--format FORMAT]
  [--name NAME] [--is-output] [--age-encrypt] [-r KEY]... [--output PATH]
  [--clipboard]
```

Reveals one selected field. `--field` defaults to `Password`. The default
format is `text`. Supported formats are `text`, `json`, `null`, `dotenv`,
`shell`, `pwsh`, `powershell`, `github-actions`, and `azure-devops`.
Named formats require `--name NAME`. `--is-output` is valid only with
`azure-devops` (optional modifier to add `;isOutput=true`; `azure-devops`
does not require it).

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

### `secrets get many`

```text
nkp get many PATH... [--field FIELD] [--format FORMAT]
  [--age-encrypt -r RECIPIENT...] [--output PATH] [--is-output]
```

Reveals **one complete bundle** in the supplied path order. The nested route
`nkp secrets get many` is identical. Supply 1 to 256 explicit paths; omitting
paths is an error, not a request to enumerate the vault. The field defaults
to `Password`, including for aliases with a configured default field.
`--field` selects one common field for the entire bundle.

| Format | Bundle |
| --- | --- |
| `text` (default) | Values separated by commas; no trailing comma or newline |
| `null` | Values only, each followed by NUL, including the last |
| `json` | One object mapping literal supplied paths to values, in supplied order |
| `dotenv`, `shell`, `pwsh` / `powershell`, `github-actions`, `azure-devops` | One binding per supplied path, using the existing format's quoting and validation |

Named formats use the supplied path as the binding name, **without**
normalization. They require identifier-style paths or aliases (such as
`DB_PASSWORD`); a path containing `/`, `-`, whitespace or other invalid name
characters is refused. Use JSON for arbitrary paths. This avoids hidden
collisions and shell/workflow injection. `--name`, `--key` and `--clipboard`
are not accepted. `--is-output` applies only to `azure-devops`.

Duplicate literal paths are refused in every format; different aliases to
the same entry are distinct supplied keys unless their output names collide
under the destination's rules. Azure DevOps variables and GitHub Actions
output names are case-insensitive: `TOKEN` and `token` cannot share a bundle.
Both PowerShell spellings also reject case-only collisions on every host,
so output generated on Unix remains safe for Windows environment variables.
Dotenv bindings use host environment casing (case-insensitive on Windows).
POSIX shell bindings and JSON keys retain their literal case distinctions.
The same checks apply to named `secrets env` output, before any binding is
printed. An alias that collides with a
different real entry is refused, as for single `get`. Missing or ambiguous
entries, missing fields, invalid names, and format-validation errors fail
the whole request without printing earlier values. Diagnostics do not include
selected values. Raw text commas/newlines are not escaped; use JSON for
lossless general text. NUL format refuses embedded NUL values.

All values and the rendered plaintext bundle remain in zeroizing buffers.
Input paths are limited to 64 KiB in aggregate, selected values to 16 MiB,
and rendered output to 64 MiB. With `--age-encrypt`, the **complete rendered
bundle** is encrypted once, preserving the requested format inside one age
message. `-r` and `--output` have the same recipient and private no-clobber
behavior as single `get`; plaintext is never printed first.

`many` is reserved only immediately after `get`. To read an entry named
`many` with single-value semantics, use `nkp get -- many` or
`nkp get --key many`. `nkp get many many` includes it in a bundle.
Put options before `--` when passing leading-dash paths to the bundle.

For single-value `get`, `--format json` writes `{"value":"field text"}`.
`--format null` writes the field bytes followed by one NUL byte. It does not
suppress output.

### `secrets otp`

```text
nkp secrets otp PATH [--format FORMAT] [--name NAME] [--is-output]
```

Generates and prints a TOTP code. It does not reveal the seed and refuses
HOTP entries. `--key PATH` and `-k PATH` remain supported alternatives.
`--format` defaults to `text`; the other formats are `json`,
`null`, and the named formats listed for `secrets get`. Named formats require
`-n` / `--name`. `--is-output` is optional and requires `azure-devops`.

## Change entries and fields

### `secrets set`

```text
nkp secrets set [PATH] [--key PATH] [--field NAME=VALUE]...
  [--value VALUE | --value-stdin | --value-env NAME | --value-file PATH | --generate]
  [--chars N] [--upper] [--lower] [--digits] [--symbols]
  [--age-decrypt [-i PATH]] [--username VALUE] [--url VALUE] [--notes VALUE]
  [--bin NAME=FILE_PATH]...
```

Select at most one value source: literal `--value`, exact stdin bytes with
`--value-stdin`, a Unicode environment value with `--value-env NAME`, or bounded
UTF-8 file bytes with `--value-file PATH`. Empty values are allowed; no newline
is removed. `--file` and `--stdin` retain their old meanings as aliases.
`--password-*` options still unlock the vault and do not supply the new value;
stdin cannot carry both an unlock password and a field value.

Repeat `--field NAME=VALUE` to update multiple fields atomically; the first `=`
separates name and value. Duplicate names, including collisions with a value
source or `--username`/`--url`/`--notes`, are refused. The legacy `--field NAME`
selects the value-source target (default `Password`). With assignments it
requires an explicit value source so the selector is not silently ignored.
Direct arguments, including `--value` and field assignments, can appear in
process listings and shell history.

With no field, value-source, generated, or attachment update, `set` prompts
without echo. Enter submits; Ctrl-C, Ctrl-D or Escape cancel with nonzero exit.
The prompt times out after 60 seconds and refuses redirected stdin promptly.
The synchronous reader leaves no input thread behind and restores the saved
terminal mode on submission, cancellation, error and timeout. On Unix it also
handles SIGINT, SIGTERM, SIGHUP and SIGQUIT while reading. As with other terminal
programs, forced termination (such as SIGKILL) cannot perform cleanup.

`--generate` uses the generator policy described under `ensure` below, with
the same flags and default length of 16. Generator flags on `set` require
`--generate`, which conflicts with explicit value sources and `--age-decrypt`.
Repeat `--bin` or
`-b` to add attachments using `NAME=FILE_PATH`; the first `=` separates the
name, and further equals signs belong to the path. `--file`/`-f` always retains
its value-input meaning. Combined attachments and fields are saved only after
all requested mutations succeed, with an aggregate 16 MiB attachment input
limit, a 256-file count limit, and no replacement of existing attachment names. `--username`, `--url`,
and `--notes` accept direct values; those arguments can be visible in process
listings and shell history, so use `--file` or `--stdin` for sensitive values.
In PowerShell, for example:

```powershell
$secureValue = $null
$secureVault = $null
$valueText = $null
$vaultPassword = $null
$bytes = $null
$startInfo = $null
$process = $null
$started = $false
try {
    # Read both secrets without echoing. Neither is placed in command history.
    $secureValue = Read-Host 'New entry password' -AsSecureString
    $valueText = [System.Net.NetworkCredential]::new('', $secureValue).Password
    $secureVault = Read-Host 'Vault master password' -AsSecureString
    $vaultPassword = [System.Net.NetworkCredential]::new('', $secureVault).Password

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = (Get-Command nkp -CommandType Application -ErrorAction Stop).Source
    $startInfo.Arguments =
        'set "Services/Mail Account" --stdin --password-env NEO_KEEPASS_PASSWORD'
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    # Set the unlock credential only in the child environment; don't mutate the shell.
    $startInfo.EnvironmentVariables['NEO_KEEPASS_PASSWORD'] = $vaultPassword
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($valueText)
    if (-not $process.Start()) { throw 'Could not start nkp.' }
    $started = $true
    $startInfo.EnvironmentVariables.Remove('NEO_KEEPASS_PASSWORD')
    $stream = $process.StandardInput.BaseStream
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
    $process.StandardInput.Close() # EOF; no line ending is added.
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw 'nkp set failed.' }
}
finally {
    if ($started -and -not $process.HasExited) {
        $process.StandardInput.Close()
        $process.WaitForExit()
    }
    if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    if ($startInfo) { $startInfo.EnvironmentVariables.Remove('NEO_KEEPASS_PASSWORD') }
    if ($process) { $process.Dispose() }
    $valueText = $null
    $vaultPassword = $null
    if ($secureValue) { $secureValue.Dispose() }
    $secureValue = $null
    if ($secureVault) { $secureVault.Dispose() }
    $secureVault = $null
}

# Alternatively, use pre-existing UTF-8 files with owner-only ACLs.
nkp set 'Services/Mail Account' --file $privateValueFile `
    --password-file $privateVaultPasswordFile
```

For real vault unlock passwords, prefer the hidden terminal prompt, a protected
password file, or `--password-stdin`; do not put a literal password in a
command. `--password VALUE` is explicitly unsafe: it can appear in shell
history and process listings. When `--stdin` supplies the new entry value,
the vault must use a separate unlock source, such as the environment variable
shown or a key file. This approach sends the new value as exact UTF-8 bytes
through a redirected process stdin stream: unlike PowerShell's ordinary
string pipeline, it adds neither a BOM nor a line ending. It creates no
plaintext value file, but the value necessarily exists briefly as a
PowerShell/.NET string and byte array; clearing the array and dropping string
references is best-effort, not guaranteed zeroization. The unlock environment
variable is inherited by the child process and is not a private secret store.
The APIs used are available in Windows PowerShell 5.1/.NET Framework and
PowerShell 7. The unlock value is assigned only to `ProcessStartInfo`'s child
environment, so it does not overwrite or need restoration of the parent
environment. Setup, including executable lookup, is inside `try/finally`.
The exact flow was exercised only with portable PowerShell 7 on Linux, not
native Windows or PowerShell 5.1.
To select a key beginning with `-`, put `--` after the options and immediately
before the selector, for example `nkp get --field Password -- -DashEntry`.
With
`--age-decrypt`, the value source must contain age ciphertext. An explicit
`-i` / `--age-identity PATH` always wins and never falls back. Otherwise the
CLI looks for the application's `init-password.agekey` in its resolved config
directory, then `$XDG_CONFIG_HOME/age/keys.txt` (or `~/.config/age/keys.txt`).
The first existing identity file is used; unreadable or malformed files fail
closed. Discovery never creates a key or contacts a remote service.
The CLI supports native age identities and
unencrypted SSH private keys, not encrypted SSH keys. This command saves the
vault; malformed input or credential failures prevent the update.

### `secrets ensure`

```text
nkp secrets ensure PATH [--chars N] [-U] [-L] [-D] [-S] [--dry-run]
```

Creates a missing entry and its parent groups, but keeps an existing entry
unchanged. A new entry receives a generated 16-character password by default.
`--key PATH` and `-k PATH` remain supported alternatives.
`--chars N` / `-c N` / the retained `--size N` choose its length (up to 4096).
With no class flags, uppercase, lowercase, digits and ASCII punctuation are
all required. Explicit `--upper` / `-U`, `--lower` / `-L`, `--digits` / `-D`
and `--symbols` / `-S` select only those classes, guaranteeing at least one
character from each selected class. Lengths smaller than the number of
required classes are refused, even for dry runs and existing entries.
Randomness comes from the OS; byte and complete-candidate rejection sampling
avoid modulo and composition-placement bias. This composition policy is an
application choice, **not** a NIST requirement or certification.
Existing entries are never regenerated. `--dry-run` validates without
generating a password or saving.

### `secrets rm`

```text
nkp secrets rm (PATH | -k PATH | --key PATH) (-y | --yes)
```

Removes an entry. This command refuses `--field`; it does not delete a field.
`-y` / `--yes` is required unconditionally. The command does not prompt. To remove a
custom field, use `field rm`.

## Interchange commands

These commands have the same behavior as the matching `automation`
subcommands. The shared credential flags also apply.

### `secrets import`

```text
nkp secrets import (SRC | -f SRC | --file SRC | --stdin)
  [--format json|keepass-xml] [--replace] [--dry-run]
```

Reads an interchange snapshot (`json` by default, or `keepass-xml`). Exactly one
input source is required. `--replace` permits replacing a non-empty vault.
`--dry-run` validates and reports without saving. `secrets import` and root
`import` reject `--age-encrypt`, `--age-decrypt`, `-r` / `--age-recipient`, and
`-i` / `--age-identity`. Import does not decrypt the input.

### `secrets export`

```text
nkp secrets export (DEST | -o DEST | --output DEST)
  [--format json|keepass-xml] [--allow-plaintext]
```

Writes an interchange snapshot to a private, no-clobber file (positional `DEST`
or `-o` / `--output DEST`; existing files are refused). Default `--format` is
plaintext `json`; `--format keepass-xml` requires `--allow-plaintext` to
acknowledge plaintext XML output. `secrets export` and root `export` reject
`--name NAME`, `--age-encrypt`, `--age-decrypt`, `-r` / `--age-recipient`, and
`-i` / `--age-identity`.

### `secrets sync`

```text
nkp secrets sync (SRC | -f SRC | --file SRC | --stdin)
  [--strategy newest|source|target] [--dry-run]
```

Synchronizes an interchange snapshot with the vault. Exactly one input source
is required. `--strategy` defaults to `newest`; `source` (prefer imported
snapshot on conflict) and `target` (keep vault value on conflict while adding
missing items) are the other accepted values. `--dry-run` reports without saving.
`secrets sync` and root `sync` reject `--age-encrypt`, `--age-decrypt`,
`-r` / `--age-recipient`, and `-i` / `--age-identity`. Sync does not encrypt or
decrypt the interchange data.

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
`nkp get` call the matching `secrets get` operation. The complete
root-shortcut and option alias list is in the [alias index](../commands.md).
Age encryption and decryption steps are in [the age how-to](../how-to/age.md).
