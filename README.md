# nkeepass

A Rust KeePass CLI/TUI application. This repository starts from the existing
`nkeepass` application implementation; its KDBX parsing is delegated to
`neotales-keepass`, never reimplemented here.

## Current status

The CLI and interactive terminal browser cover vault navigation and entry
operations; `tests/` exercises the imported application behavior. KDBX parsing
and writing are delegated to the vendored `neotales-keepass` crate. Its source
and MIT license are included in `neotales-keepass/`.

This checkout does **not** yet include a GPUI desktop application
(`nkeepassui`). Passkeys, HIBP checks, icons, SSH-agent integration, and
age-encrypted exports remain planned scope. TOTP support is present in the
imported CLI surface; consult command help and tests for exact capabilities and
limits.

## Build and test

Rust 1.98.1 is pinned in `rust-toolchain.toml`.

```sh
cargo build --workspace
cargo test --workspace
cargo run -- --help
```
