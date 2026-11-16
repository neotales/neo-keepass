# nkeepass

A Rust KeePass CLI/TUI application. This repository starts from the existing
`nkeepass` application implementation; its KDBX parsing is delegated to
`neotales-keepass`, never reimplemented here.

## Current status

The imported CLI and interactive terminal browser cover vault navigation and
entry operations. This initial standalone checkout does **not** yet include a
GPUI desktop application (`nkeepassui`). Passkeys, TOTP, HIBP checks, icons,
SSH-agent integration, and age-encrypted exports are not claimed as implemented;
these remain planned scope. See the application module and its tests for the
currently implemented behavior.

The upstream source depends on the `neotales-keepass` workspace crate. That
crate is not vendored into this repository yet, so a self-contained Cargo build
is not currently available.
