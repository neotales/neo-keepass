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
heredoc delimiter changed from `NKEEPASS_EOF` to `NKP_EOF`. Everything else
keeps its existing names: `NKEEPASS_*` environment variables, the
`~/.config/nkeepass/` and `~/.local/share/nkeepass/` directories, and the
config.json and KDBX formats, so existing setups and vaults keep working.

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
terminal prompt. After creating the vault, it stores a password-only unlock
password as age-encrypted data in a uniquely named file under
`~/.local/share/nkeepass/`; the reusable native age identity is in
`~/.config/nkeepass/init-password.agekey`. The `NKEEPASS_CONFIG_DIR` and
`NKEEPASS_DATA_DIR` app overrides and XDG directory settings select these
locations.
Both files are installed privately without overwriting existing files. Keep the
identity safe: it decrypts the backup. Since this checkout has no OS credential
vault integration, this file-based backup is the fallback. When a key file is
also part of the master credentials, no password-only backup is made, because
the password alone cannot unlock that vault. `init --size N` creates a separate
random entry password; it does not generate or store the master password.
If backup installation fails, init reports the sanitized cause but leaves the
already-created vault in place. Windows currently does not support secure
owner-only file writes: the implementation cannot safely replace and verify
the full ACL (including explicit grants to other principals). This limitation
applies beyond password backups, including vault creation/mutation, config
writes, and CLI output files; these operations fail closed with an explicit
unsupported-operation diagnostic rather than claiming the file is private.

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
`set --age-decrypt -i IDENTITY --file ciphertext.age --key service/account`
decrypts armored or binary age input before updating the field. Identity files
may contain native age identities or unencrypted SSH private keys. Encrypted
SSH identities are not supported yet.

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
