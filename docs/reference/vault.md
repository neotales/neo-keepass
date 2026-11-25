# Vault, context, and alias commands

These commands select a vault and manage names for vaults or entries. Vault
selection follows the precedence in [choose the active vault](../how-to/vault-selection.md).
Every route accepts `-h` or `--help`. `-V PATH` or `--vault PATH` is accepted
before `init` and `context show`; other `context`, `use`, and `alias` commands
do not open a vault and reject `-V` / `--vault`. Credential flags apply to
`init` as listed in [vault credentials](credentials.md).

## `init`

Create a KDBX 4.1 vault.

```text
nkp [--vault PATH] init [PATH] [--json] [--generate-master-password]
              [--size N] [--kdf aes|argon2d|argon2id]
              [--memory KIB] [--iterations N] [--parallelism N]
```

If `PATH` is omitted, the selected vault path is used. Init refuses to
overwrite an existing vault. A positional relative `PATH` is resolved from
the current working directory. If you pass both a positional path and
`--vault`, init refuses the ambiguous target. After creation, init tries to
select the new vault only when no current context is set. It does not replace
a context you already chose. If init selects the new vault, the JSON result
has `"context_set": true`; otherwise it has `"context_set": false`. With no
explicit target, init uses or creates the `default` vault alias. If that name
is occupied by a different target, it tries `default-1`, `default-2`, and so on
without replacing existing aliases. An explicit target can become the current
value when no context exists.
See [vault credentials](credentials.md) for credential sources, key files,
and their conflicts.

| Option | Meaning |
| --- | --- |
| `--password-env NAME` | Read the master password from this environment variable. |
| `--password-stdin` | Read one password line from stdin. |
| `--password-file PATH` | Read one password line from a file. |
| `--key-file PATH` | Add a key-file credential component. |
| `--password VALUE` | Compatibility option. Exposes the password in process listings and shell history. |
| `--generate-master-password` | Generate a 32-character random master password. Cannot be combined with credential options or a key file. |
| `--json` | Output a machine-readable result instead of the default text. |
| `--size N` | Generate a 1 to 4096 character password for a new entry. Does not generate the master password. |
| `--kdf aes\|argon2d\|argon2id` | Select the KDF. Default is `aes`. |
| `--memory KIB` | Set Argon2 memory cost from 1 to 65,536 KiB. Default is 65,536 KiB. Only valid with Argon2. |
| `--iterations N` | Set AES rounds from 1 to 100,000,000 or Argon2 time cost from 1 to 10. Defaults are 600,000 AES rounds or 10 Argon2 passes. |
| `--parallelism N` | Set Argon2 lanes from 1 to 16. Default is 1. Only valid with Argon2. |

The CLI rejects KDF values outside its own read policy. The Argon2 memory,
time, and combined-work limits apply together. With a supplied password and no
key file, init attempts the age-encrypted backup after successful vault
creation. A failure of that backup leaves the created vault in place. With a
generated master password, backup and recovery association are attempted
before vault creation; a failure in either stops vault creation. The identity
needed to decrypt the backup is stored separately. On Windows private staging requires a filesystem
that supports protected, verified current-user-only DACLs.

With `--generate-master-password`, init installs the encrypted backup **before**
creating the vault, so a reported backup failure does not create an inaccessible
vault. This ordering is not an unconditional power-loss guarantee. If
vault creation or context persistence fails after that, stdout identifies the
target and whether the vault was installed. If installation did not occur,
the report says **unused backup**: that password cannot unlock an existing
vault. JSON uses `init-unused-backup` with `vault_installed: false`; an
installed vault with a later failure uses `init-recovery` with
`vault_installed: true`. Both retain a nonzero exit status. If stdout is
unavailable, stderr retains the original failure and notes that the recovery
report could not be written.

Before installing a generated-password vault, init also creates a private
no-clobber `init-password-*.age.json` candidate record beside the encrypted
backup, containing its vault path, backup path and identity path, but no secret.
If output is lost, inspect those records in the configured data directory and
find candidates for the target path. Each record describes an **attempt**, not
proof of installation: collisions, interrupted attempts, and concurrent init
can leave multiple candidates. In a private environment, try each candidate's
backup with the corresponding identity against the target vault, as below.
Only one that actually opens the vault is its recovery password. Keep candidate
records private and retain them with their corresponding encrypted backups.
On Unix the files and their containing directories are synced before vault
installation; Windows uses the existing private-file durability policy and
owner-only DACL. Neither policy confirms every ancestor directory entry is
durable. A power loss could therefore lose an identity, backup, or candidate
record even after init reports success. On all platforms, success and candidate
records report `"ancestor_durability":"unconfirmed"`; text output warns about
this too. Make independent protected copies of the identity and encrypted
backup, and test recovery before relying on them.
On Unix, reuse independently syncs the identity and its containing directory
before making a new backup, including when another initializer has published
the identity but not yet synced that directory. Preexisting directory entries
and their ancestors are assumed durable; an externally or concurrently
created configuration or data directory may not yet be durable.
The existing Windows policy syncs the staged identity file but cannot confirm
parent-directory durability after
a crash. Windows reuses a validated private identity under that policy; after
power loss, directory entries for the identity or recovery files may not
survive. Make protected independent backups of both the identity and encrypted
password backup. Init reports `"directory_sync_policy":"unconfirmed"` in JSON
and a text warning on Windows; candidate records retain the same policy marker.
The generated master password is not printed. Ambient `NEO_KEEPASS_PASSWORD`
and `NKP_PASSWORD` are ignored for this opt-in mode.
For password-only init, both backup roots must be valid Unicode without control
characters; init checks them before creating the vault so recovery paths can be
reported safely. This backup-path restriction does not apply to key-file-only init.

If installing the candidate record fails, vault creation has not started.
The report identifies the candidate path and distinguishes an already
installed record whose directory durability is unconfirmed from a record not
installed by this attempt. `--json` uses `init-association-failed`; an
encrypted backup may remain unused.

Init reports the database path, backup path, and whether the age identity was
created or reused. Treat the identity as a secret: anyone who obtains both it
and the backup can recover the master password. Protect and back up both
separately from the database, and test your recovery process. For example,
using an independently installed [age](https://age-encryption.org/) executable,
in a private shell where output and pipes are not recorded:

```powershell
age --decrypt -i "IDENTITY_PATH" "BACKUP_PATH" | nkp --vault "DATABASE_PATH" secrets ls --password-stdin
```

Replace the placeholders with the reported paths. This sends the password
directly to `nkp` rather than displaying it; avoid transcript, screen capture,
shell tracing, and untrusted processes. The same pipeline syntax works in POSIX
shells. Do not send the plaintext to a file or a shared terminal.

The generator uses operating-system randomness and unbiased sampling from 62
ASCII letters and digits. The 32-character choice is this application's
policy, not a NIST requirement. [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html)
discusses randomly assigned passwords and password managers; its requirements
address network authentication, not this local vault. This is not a claim of
NIST or FIPS certification.

`init` rejects `--age-encrypt`, `--age-decrypt`, `-r` /
`--age-recipient`, and `-i` / `--age-identity` before creating any files.
These flags do not configure its automatic password backup or vault encryption.

## `context` and `use`

```text
nkp context ls [--json]
nkp context list [--json]
nkp context show [--json]
nkp context use <ALIAS|PATH>
nkp use <ALIAS|PATH>
nkp context set ALIAS ABSOLUTE_PATH
nkp context rm ALIAS
nkp context remove ALIAS
```

`ls` (also `list`) lists configured vault aliases and paths, as well as a
directly selected path as `(current)` and an otherwise unlisted configured
default path as `(default)` in human-readable output. Paths already represented
by aliases are not repeated as direct paths. Rows mark the configured current
path. `show` reports the selected vault, its alias (or `(unnamed)`), and
source. These commands print human-readable text by default. With `--json`,
`ls` emits one JSON object per configured vault alias, retaining the original
`alias` and `path` fields; unaliased current and default paths are omitted.
With no configured vault aliases, JSON output is empty. `show --json` reports
the selected path and source. For compatibility its `alias` is populated only
for the configured current context, even when text names an alias selected
through an argument, environment variable, or configured default. On Windows
path comparisons normalize separators but retain case, since directories may
be case-sensitive. Case variants may therefore appear more than once on
case-insensitive volumes. Displayed spelling is unchanged. This lexical policy
does not resolve symlinks or hard links. `use` (and root `nkp use`) selects a
configured vault alias or a normalized absolute vault path. `set` creates or
updates an alias. `rm` (also `remove`) removes an alias
and clears it as current if needed.
Other subcommands have no command-specific options.

## `alias`

```text
nkp alias ls [--format json|human]
nkp alias set NAME TARGET [--kind vault|entry] [-F FIELD | --field FIELD]
nkp alias resolve NAME
nkp alias rm NAME
```

`ls` lists aliases as JSON Lines (`--format json`, the default) or bounded
human-readable columns (`--format human`, or `(no aliases)` when empty). `set`
creates or replaces one. If `--kind` is omitted,
the command infers the target kind. Use `-F` / `--field` to bind an entry alias
to a field. `resolve` prints the configured target. `rm` removes the alias.

Names use ASCII letters, digits, hyphens, or underscores and are at most 128
bytes. Entry paths use slash-separated group and entry names, reject empty,
`.` and `..` segments, and cannot start with `/`. Entry selectors compare
segments ASCII case-insensitively, allow an optional root-group prefix, and
refuse ambiguous matches. If a selector is also an entry alias name but
resolves to a different existing entry path, the CLI refuses it as ambiguous.
Vault alias names and entry alias names share configuration storage.

Aliases: `alias list` is `alias ls`; `alias remove` is `alias rm`. `context`
has no subcommand aliases.
