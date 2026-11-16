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
age-encrypted exports remain planned scope. The vendored age library is not
currently wired into user-facing commands. TOTP support is present in the CLI;
consult command help and tests for exact capabilities and limits.

`init` currently takes the vault master password from an explicit source or a
non-echoing terminal prompt. `init --size N` creates a separate random entry
password inside the vault; it does not generate or store the master password.
There is no OS credential-vault integration in this checkout, so an
"OS-vault-unavailable" password-backup fallback cannot yet identify a password
that this application otherwise stores in such a vault.

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
