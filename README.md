# nkeepass

A Rust KeePass CLI/TUI application. Every Cargo package lives under `crates/`;
the root manifest contains workspace configuration. KDBX parsing is delegated
to `neotales-keepass`, never reimplemented here.

## Current status

The CLI and interactive terminal browser cover vault navigation and entry
operations; `crates/nkeepass/tests/` exercises the imported application
behavior. KDBX parsing and writing are delegated to the vendored
`neotales-keepass` crate. The `neotales-age` implementation and its required
`neotales-x509` dependency are also vendored under `crates/`, with MIT license
files.

This checkout does **not** yet include a GPUI desktop application
(`nkeepassui`). Passkeys, HIBP checks, icons, SSH-agent integration, and
automatic recipient discovery remain planned scope. Basic age encryption and
decryption are wired into `get` and `set`; consult command help below for
supported local key forms and current limitations. TOTP support is present too.

`init` currently takes the vault master password from an explicit source or a
non-echoing terminal prompt. `init --size N` creates a separate random entry
password inside the vault; it does not generate or store the master password.
There is no OS credential-vault integration. As a result, init cannot safely
create an automatic age-encrypted master-password backup: it does not own a
generated master password, and silently backing up a caller-provided password
would violate the explicit-source contract.

The `get` command can encrypt a selected value to native age or SSH recipients:

```sh
nkeepass secrets get --key service/account --age-encrypt \
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
