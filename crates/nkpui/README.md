# `nkpui` — Rune Desktop UI Scaffold

Isolated nested Cargo workspace for the `neo-keepass` desktop UI built on
[`anomalyco/rune`](https://github.com/anomalyco/rune) (`dev` branch) and
[`nkeepass::VaultService`](../nkeepass/src/service.rs).

## Pinned Rune Revision & Patches

- **Repository:** `https://github.com/anomalyco/rune.git` (`dev` branch)
- **Pinned `rev`:** `761fd132a286b9e87756d8a0889c8957b93c86be`
- **Features:**
  - `rune`: `default-features = false`, `features = ["accessibility", "embedded-fonts", "metal-backend", "native-file-dialog", "svg"]` (`ogg-audio`, `avif`, and `tooling` are omitted; `tooling` is **never** enabled in release builds).
  - `rune-kit`: `default-features = false`.
  - `serde_json`: read-only parsing of non-secret vault aliases from `nkp`'s `config.json`.
- **Workspace isolation:** `crates/nkpui/Cargo.toml` declares `[workspace]` and owns `crates/nkpui/Cargo.lock`, mirroring all 8 `[patch.crates-io]` overrides from Rune's root `Cargo.toml` (`wgpu-hal`, `naga`, `winit`, `sctk-adwaita`, `parley_engine`, `accesskit_windows`, `accesskit_atspi_common`, `accesskit_macos`) without altering the root `neo-keepass` workspace.

## Rust Toolchain (`1.100.0`)

- `neo-keepass` pins `channel = "1.100.0"` in the root `rust-toolchain.toml` (matching `neotales-keepass` `0.0.0-alpha.2`'s `rust-version = "1.100"`).
- `nkpui`, `rune`, `rune-kit`, `nkeepass`, and `neotales-keepass` compile cleanly under `1.100.0` (`cargo fmt --check`, `cargo clippy --all-targets --no-deps -- -D warnings`, `cargo test`, and `cargo build --release`).

## Licensing & Third-Party Dependencies

`nkpui` itself is licensed under `MIT` (`crates/nkpui/Cargo.toml`) and enforces `unsafe_code = "forbid"`.

### `vendor/*` License Check

Inspected every `vendor/*/Cargo.toml` at pinned Rune rev `761fd132a286b9e87756d8a0889c8957b93c86be`:

| Crate | License |
| --- | --- |
| `rune`, `rune-kit` | `MIT` |
| `vendor/sctk-adwaita` | `MIT` |
| `vendor/wgpu-hal` | `MIT OR Apache-2.0` |
| `vendor/naga` | `MIT OR Apache-2.0` |
| `vendor/parley_engine` | `Apache-2.0 OR MIT` |
| `vendor/accesskit_windows` | `MIT OR Apache-2.0` |
| `vendor/accesskit_atspi_common` | `MIT OR Apache-2.0` |
| `vendor/accesskit_macos` | `MIT OR Apache-2.0` |
| `vendor/winit` | `Apache-2.0` |
| `vendor/tiny-skia-path` (`rune-tiny-skia-path`) | `BSD-3-Clause` |
| `rfd` (via `rune/native-file-dialog` on macOS/Windows) | `MIT` |
| `zbus` + async-io stack (via `rune/native-file-dialog` -> `dbus` on Linux XDG FileChooser) | `MIT` |
| `serde_json` | `MIT OR Apache-2.0` |

### Third-Party Transitive Dependency Notice (`spellbook v0.4.2`, `MPL-2.0`)

- **Dependency chain:** `rune v0.0.1` unconditionally depends on `rune-spell v0.0.1`, which on Linux and Wasm targets pulls `spellbook v0.4.2` (`MPL-2.0`) as an unmodified upstream crates.io dependency (`crates/nkpui/Cargo.lock`).
- **Scope & runtime posture:** `MPL-2.0` is a file-level weak copyleft license applying only to `spellbook`'s own unmodified source files. `nkpui` keeps runtime spellchecking disabled on `.secure()` fields and text inputs (`TextEdit`).
- **Distribution notice:** For the `0.0.0-alpha.0` release and any binary distribution that links `spellbook v0.4.2` (such as Linux builds), source availability and `MPL-2.0` notice obligations apply to the unmodified `spellbook v0.4.2` crate alongside the permissive `MIT` / `Apache-2.0` / `BSD-3-Clause` crates listed above.

## Build Prerequisites

- **Linux:**
  - `libxkbcommon-dev` (Debian/Ubuntu) or `libxkbcommon-devel` (Fedora/RHEL) — required at link time because `rune` links `-lxkbcommon` via `xkbcommon = "0.9"`.
  - Vulkan loader (`libvulkan1` / `vulkan-loader`) plus a hardware Vulkan driver or Mesa Lavapipe (`mesa-vulkan-drivers` / `lvp_icd.x86_64.json`) for headless `--snap` / GPU rendering.
- **macOS:** Xcode + Command Line Tools (Metal SDK).
- **Windows:** MSVC Build Tools + Windows 10/11 SDK.

## Running & Headless Verification

Run all commands from `crates/nkpui/`:

```bash
cd crates/nkpui

# Format, lint, and typecheck
cargo fmt --check
cargo clippy --all-targets --no-deps -- -D warnings
cargo check --all-targets
cargo check --release

# Run unit tests (requires libxkbcommon dev library on Linux to link test binary)
cargo test

# Launch desktop UI
cargo run

# Headless element tree & offscreen PNG snapshot (debug builds include Rune tooling;
# release builds omit `tooling`)
cargo run -- --tree
cargo run -- --snap /tmp/nkpui-lock.png
```
