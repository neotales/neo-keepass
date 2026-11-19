# neo-keepass

A Rust KeePass CLI/TUI application. The executable is `nkp`. Every Cargo
package lives under `crates/`; the root manifest contains workspace
configuration. KDBX parsing is delegated to `neotales-keepass`, never
reimplemented here.

## Migrating from `nkeepass`

The executable was renamed from `nkeepass` to `nkp`. A previously installed
`nkeepass` binary may remain on your PATH and will keep running the old
version, so uninstall it or point scripts at `nkp`. Diagnostics are now
prefixed `nkp:` instead of `nkeepass:`, which matters if you match on stderr.
Regenerate shell completion for the new name with `nkp completion SHELL`
(`bash`, `sh`, `zsh`, `fish`, `powershell`, `pwsh`, or `nushell`; see the
[command reference](docs/reference/system.md)) and replace the old
`nkeepass` completion script. If you parse `github-actions` output, its
heredoc delimiter changed from `NKEEPASS_EOF` to `NKP_EOF`.

Filesystem paths, config.json, and KDBX formats remain compatible. Legacy
`NKEEPASS_*` application environment variables are no longer read; replace
`NKEEPASS_PASSWORD`, `NKEEPASS_VAULT`, `NKEEPASS_VAULT_PATH`,
`NKEEPASS_CONFIG_DIR`, `NKEEPASS_DATA_DIR`, and `NKEEPASS_COMPLETE_PASSWORD_ENV`
with the corresponding `NEO_KEEPASS_*` name (or its `NKP_*` alias). Explicit
`--password-env NAME` remains literal and can still name any variable.

## Current status

The CLI and interactive terminal browser cover vault navigation and entry
operations; `crates/nkeepass/tests/` exercises the imported application
behavior. KDBX parsing and writing are delegated to the vendored
`neotales-keepass` crate. The `neotales-age` implementation and its required
`neotales-x509` dependency are also vendored under `crates/`, with MIT license
files.

This checkout does **not** yet include a GPUI desktop application
(`nkpui`). Passkeys, HIBP checks, icons, SSH-agent integration, and
automatic recipient discovery remain planned scope. Basic age encryption and
decryption are wired into `get` and `set`; consult command help below for
supported local key forms and current limitations. TOTP support is present too.

`init` takes the vault master password from an explicit source or a non-echoing
terminal prompt. `init --generate-master-password` instead generates a random
master password and installs its encrypted backup and recovery association
before attempting vault creation; a failure in either stops vault creation.
It never prints that password. See the [recovery instructions](docs/reference/vault.md#init)
before using this option. With a supplied password and no key file, init
attempts an age-encrypted password backup after successful vault creation, in a uniquely named file under
`~/.local/share/nkeepass/`; the reusable native age identity is in
`~/.config/nkeepass/init-password.agekey`. The `NEO_KEEPASS_CONFIG_DIR` and
`NEO_KEEPASS_DATA_DIR` app overrides (and their aliases below), and XDG
directory settings select these locations.
Application environment inputs accept `NEO_KEEPASS_*` and `NKP_*` names. For
each setting, the first *present* name wins: `NEO_KEEPASS_*`, then `NKP_*`. An empty higher-priority
value does not fall through. Explicit CLI choices such as `--vault` or
`--password-env` take precedence over defaults.

For the default password names, an empty or non-Unicode selected value is an
error; lower-priority names are not tried. For `VAULT` and `VAULT_PATH`, an
empty or non-Unicode selected path is an error. `VAULT` is checked before
`VAULT_PATH`, so a present `VAULT` value—including an empty one—prevents
`VAULT_PATH` from being considered. Config/data directory overrides use the
selected OS path and fail validation rather than falling back if it is empty
or invalid. The completion password-environment selector treats an empty
selected name as disabled (without trying lower-priority names); a
non-Unicode selected name is an error. The name supplied to
`--password-env` remains literal and is not rewritten.

Environment-name matching follows host semantics: Windows names are
case-insensitive; Unix names are case-sensitive.

Both files are installed privately without overwriting existing files. Keep the
identity safe: it decrypts the backup. Since this checkout has no OS credential
vault integration, this file-based backup is the fallback. When a key file is
also part of the master credentials, no password-only backup is made, because
the password alone cannot unlock that vault. `init --size N` creates a separate
random entry password; it does not generate or store the master password.
If that supplied-password backup fails, init reports the sanitized cause and
leaves the already-created vault in place. Before password-only creation, init
resolves both backup directories and refuses non-Unicode or control-containing
paths because recovery locations must be safely reportable. Key-file-only init
does not impose that backup-path restriction. Init reports paths in readable text; use
`--json` for machine-readable output. On Windows, private files are created with a
protected current-user-only DACL and verified before writing. Volumes must
advertise persistent ACL enforcement; unsupported or unqueryable volumes are
rejected. Private directories may be owned by the built-in Administrators
group when their DACL grants only the current user. Like the Unix implementation,
path-based staging assumes the containing directory is not controlled by an
adversary; it does not defend against administrators or the same user.

The `get` command can encrypt a selected value to native age or SSH recipients:

```sh
nkp secrets get --key service/account --age-encrypt \
  -r age1... --output account.age
```

Without `--output`, armored ciphertext is written to stdout. `-r`/`--age-recipient`
may be repeated; `-r @PATH` reads recipient keys from a bounded key file.
`-r gh:username` looks up that account's public SSH keys; an HTTPS URL may also
serve newline-delimited age or SSH public keys. These network forms make an
explicit HTTPS request only when supplied. They require `curl`, cap responses
at 64 KiB and the request at five seconds, reject redirects, and validate every
returned key before encryption.
`set --age-decrypt -i IDENTITY --value-file ciphertext.age --key service/account`
decrypts armored or binary age input before updating the field. Identity files
may contain native age identities or unencrypted SSH private keys. Encrypted
SSH identities are not supported yet.

`set` accepts `--value`, `--value-stdin`, `--value-env NAME`, or
`--value-file PATH`, plus repeatable `--field NAME=VALUE` assignments.
With no update it prompts without echo, with a 60-second timeout; redirected
stdin requires an explicit source. Without `-i`, age decryption discovers the
init backup identity, then the conventional age `keys.txt` file.
`ensure` generates a 16-character password for new entries by default.
`--chars`/`-c` (or `--size`) changes the length; `--upper`/`-U`, `--lower`/`-L`,
`--digits`/`-D`, and `--symbols`/`-S` select classes and guarantee each selected
class. No selection requires all four. `set --generate` uses the same policy.
This composition policy is not a NIST mandate.

`nkp get many PATH...` (also `nkp secrets get many`) reveals one ordered bundle,
not separate per-entry outputs. Text joins values with commas; `null` terminates
each value with NUL; JSON maps literal supplied paths to values. Named formats
reuse the existing quoting rules and require identifier-style paths or aliases.
`--age-encrypt` encrypts the complete rendered bundle once. See the
[bundle reference](docs/reference/secrets.md#secrets-get-many) for bounds,
collision handling and the spelling for an entry named `many`.

The former JSON-only read and JSON field-update shortcuts are deliberately no
longer accepted. Use `get --format json` and `set --field NAME=VALUE` instead;
the latter creates missing custom fields and does not have a dry-run mode.

KeePass XML is an explicit limited interchange format, not the default JSON
snapshot format. Export requires `--format keepass-xml --allow-plaintext` and
can reveal ordinary protected text values, including passwords. Protected
binary attachments and unsupported data remain rejected. The library's default
`KdbxXml::export` stays restrictive; only its explicitly named plaintext
export path allows protected text fields.
See [the KeePass XML interchange notes](docs/keepass-xml-interchange.md) for
limits and security behavior.

## Workspace layout

- `crates/nkeepass/` — CLI/TUI application and integration tests.
- [`crates/terminal-password/`](crates/terminal-password/README.md) — bounded hidden terminal input and platform restoration tests.
- `crates/neotales-keepass/` — KDBX library.
- `crates/neotales-age/` — age file-encryption library vendored from plab.
- `crates/neotales-x509/` — local dependency required by `neotales-age`.
- Root `Cargo.toml` and `Cargo.lock` — workspace configuration and resolution.

## Build and test

Rust 1.98.1 is pinned in `rust-toolchain.toml`.

```sh
cargo build --workspace
cargo test --workspace
cargo run -p nkeepass -- --help
```

Start with the [documentation index](docs/README.md) for a tutorial, task
guides, and separate command references. The [alias index](docs/commands.md)
maps alternate command and option spellings to those references.

CI/CD, packaging, and benchmarks are documented in `docs/ci-cd.md`; packaging
artifact status is in `packaging/README.md`.
