# `nkpui` — Rune Desktop UI Scaffold

Isolated nested Cargo workspace for the `neo-keepass` desktop UI built on
[`anomalyco/rune`](https://github.com/anomalyco/rune) (`dev` branch) and
[`nkeepass::VaultService`](../nkeepass/src/service.rs).

## Pinned Rune Revision & Patches

- **Repository:** `https://github.com/anomalyco/rune.git` (`dev` branch)
- **Pinned `rev`:** `761fd132a286b9e87756d8a0889c8957b93c86be`
- **Features:**
  - `rune`: `default-features = false`, `features = ["accessibility", "embedded-fonts", "metal-backend", "svg"]` (`dbus`, `ogg-audio`, `avif`, and `tooling` are omitted; `tooling` is **never** enabled in release builds).
  - `rune-kit`: `default-features = false`.
- **Workspace isolation:** `crates/nkpui/Cargo.toml` declares `[workspace]` and owns `crates/nkpui/Cargo.lock`, mirroring all 8 `[patch.crates-io]` overrides from Rune's root `Cargo.toml` (`wgpu-hal`, `naga`, `winit`, `sctk-adwaita`, `parley_engine`, `accesskit_windows`, `accesskit_atspi_common`, `accesskit_macos`) without altering the root `neo-keepass` workspace.

## Rust `1.98.1` vs `1.99.1` Finding

- Upstream `anomalyco/rune` (`rev = 761fd132a286b9e87756d8a0889c8957b93c86be`) pins `channel = "1.99.1"` in its `rust-toolchain.toml`.
- `neo-keepass` pins `channel = "1.98.1"` in the root `rust-toolchain.toml`.
- **Verified empirically:** `rustc 1.98.1 (48a229cea 2026-09-01)` compiles `nkpui`, `rune`, `rune-kit`, `nkeepass`, and `neotales-keepass` cleanly (`cargo check --all-targets`, `cargo clippy --all-targets --no-deps -- -D warnings`, and `cargo check --release` all pass with zero warnings in `nkpui`). No root toolchain bump was required.

## `vendor/*` License Check

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

All crates use permissive MIT/Apache-2.0/BSD-3-Clause licenses compatible with `neo-keepass` (`MIT`). `crates/nkpui/Cargo.toml` enforces `unsafe_code = "forbid"`.

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
