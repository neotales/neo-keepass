# Changelog

All notable changes to `neo-keepass` (`nkp` and `nkpui`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.0-alpha.2] - 2026-11-26

### Added

- **`VaultService` APIs & search/path helpers (`nkeepass`):**
  - Added `group_tree`, `list_custom_icons`, `set_entry_custom_icon`, `set_group_custom_icon`, `rename_group`, `move_entry`, `reorder_entry`, `clone_entry`, `recycle_entry`, `restore_entry`, `empty_recycle_bin`, `database_settings`, `update_database_settings`, `otp_metadata`, `hotp_next_code`, and `set_entry_otp_config`.
  - Added wildcard `*`/`?` search and binary-search `complete_path` completion support.
- **OTP & KDBX 4 interoperability (`neotales-keepass` `0.0.0-alpha.2`):**
  - Added Steam Guard, HOTP, padded Base32, and KeePass 2.x `TimeOtp-*` fallback parsing.
- **TUI power features, navigation, and mouse support (`nkp`):**
  - Added `nkp tui [PATH|ALIAS]` vault alias, default vault, and `--vault` launch resolution with synced completions across all 6 shells (`bash`, `sh`, `zsh`, `fish`, `powershell`/`pwsh`, `nushell`).
  - Added mouse capture with click and scroll-wheel support (guarded by lock-before-teardown `MouseCaptureGuard`), 3-pane wide layout, stay-in-subgroup + auto-select on entry creation, and `Ctrl+S` save with `[UNSAVED · Ctrl+S]` badge.
  - Added Move Entry (`m`), Reorder (`Alt+Up`/`Down`, `K`/`J`), Clone (`C`/`Ctrl+D`), Recycle/Restore/Empty Recycle Bin (`R` with confirmed permanent delete/empty), HOTP next-code generation + guided TOTP/HOTP configurator modal, Editable Path Bar (`Ctrl+K`/`Ctrl+G`/`:` with 5-item `Tab` dropdown), and Database Settings modal (`S`/`Ctrl+O`).
- **Desktop UI power features (`nkpui`):**
  - Modularized the desktop UI (`crates/nkpui/src/ui/`) and added a collapsible `TreeView` group sidebar with arrow-key navigation and Rename / New Subgroup / Empty Recycle Bin actions.
  - Added Move Up/Down entry reordering (`Alt+Up`/`Down`), Move-to-Group picker, drag-and-drop entries onto groups or entry slots, Clone Entry, Recycle/Restore/Empty Recycle Bin, and right-click context menus (`rune_kit::context_menu`) with expanded keyboard shortcuts.
  - Added Editable Path Bar (`Ctrl/Cmd+K`, `Ctrl/Cmd+G` with 5-item `Tab` dropdown), wildcard `*`/`?` Search Bar, Copy and Open URL (`http`/`https` only) actions on unprotected standard fields, and a draining 30-second clipboard progress bar.
  - Added embedded custom KDBX icon selection in the Icon Picker alongside the 69 standard KeePass icons, guided TOTP/HOTP configurator, TOTP draining bar, HOTP `"Generate Next Code"`, and Database & Security Settings modal (`Ctrl/Cmd+,`).

### Changed

- **Published `neotales-*` dependencies & Rust `1.100.0` toolchain:**
  - Migrated from vendored `crates/neotales-{keepass,age,x509}` crates to published crates.io `0.0.0-alpha.2` releases (`neotales-keepass`, `neotales-age`, transitive `neotales-x509`, `rsa 0.10.0` only) and bumped Rust toolchain/MSRV to `1.100.0`.
- **KDBX 4 save fidelity & defaults:**
  - Preserved loaded KDBX 4 KDF, cipher, and compression settings on save, while defaulting new vaults to Argon2id + GZip.
- **Auto-lock defaults (`nkpui`):**
  - Configured a 5-minute idle auto-lock default and kept focus-loss auto-lock opt-in (`false`) while masking revealed secrets on focus loss.
- **Version bumps:**
  - Updated `nkeepass`, `nkpui`, RPM spec, and Chocolatey nuspec versions to `0.0.0-alpha.2`.

### Fixed

- **KDBX 4 binary inner-stream & XML ordering (`neotales-keepass` `0.0.0-alpha.2`):**
  - Fixed KDBX 4 `InnerHeader` binary inner-stream desync and document-order XML traversal, resolving real-vault `"password is not valid UTF-8"` errors.
- **Cross-platform TUI input & small-terminal layout (`nkp`):**
  - Filtered Windows `KeyEventKind::Release` duplicate events and hardened small (`40x12`) dialogs and pagination.
- **Desktop secret reveals & UI state (`nkpui`):**
  - Handled empty (`"(empty)"`) and non-UTF-8 secret reveals cleanly, and fixed `instant_changes` propagation, widget secret wipes, and lock overlay clearing.

### Security

- **Fail-closed recycle, OTP, and URL/reveal hardening (`nkp`, `nkpui`):**
  - Hardened TUI recycle/empty-bin fail-closed guards and OTP validation, restricted desktop Open URL to `http`/`https` schemes, and ensured revealed secrets and transient widgets are masked/wiped on focus loss and vault lock.

## [0.0.0-alpha.1] - 2026-11-25

### Added

- **Shared KeePass 2.x standard icon catalog & service APIs (`nkeepass`, `neotales-keepass`):**
  - Canonical KeePass 2.x standard icon catalog (`0..=68`) with opaque `CustomIconId`, `IconInfo`, `VaultService::set_entry_icon`, `VaultService::set_group_icon`, `VaultService::root_icon`, and bounded `VaultService::custom_icon_bytes`.
- **TUI icon picker, modal editors, and adaptive color (`nkp`):**
  - Icon rendering in group trees and entry lists alongside a searchable `I` icon picker modal.
  - Rename title, edit tags, and OTP URI edit modals in the TUI, plus history and recycle-bin integration tests.
  - 4-tier adaptive color detection (`TrueColor -> 256 -> ANSI 16 -> None`), non-Windows 30s best-effort timed clipboard expiry, and dynamic `argv[0]` help name (with `.exe` stripping).
- **Desktop UX, icons, and native file pickers (`nkpui`):**
  - Native `.kdbx`, keyfile, attachment, and `.env` inject file pickers via `rune/native-file-dialog`.
  - 69 vector SVG KeePass icons, bounded custom KDBX icon rendering, and a searchable Icon Picker modal for entries and groups.
  - Configured and recent vault chips on the unlock screen, favorites toggle/filtering, secure OTP URI editor, inline password generator controls, and keyboard shortcuts.

### Changed

- **CLI distribution archive naming:** Renamed CLI distribution archives from `nkeepass-<version>-<triple>.{tar.gz,zip}` to `nkp-<version>-<triple>.{tar.gz,zip}` across packaging scripts, validators, and release workflows.
- **Default entry icon:** `Entry::new` now defaults to standard KeePass key icon `0`.
- **Branding & versions:** Updated `nkp` TUI branding and aligned `nkeepass`, `nkpui`, and packaging manifest versions to `0.0.0-alpha.1`.

### Fixed

- **Windows desktop launch (`nkpui`):** Enabled `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]` so release Windows builds launch without opening a background console window.

### Security

- **Service boundary & icon bounds:** Wrapped internal `KdbxUuid` in opaque `CustomIconId` at the `VaultService` boundary, enforced fail-closed duplicate-UUID and session checks on icon mutation/lookup, and bounded `custom_icon_bytes` payload reads.
- **Desktop image & dialog hardening (`nkpui`):** Hardened image header parsers (`<= 1024x1024` dimension guard before decoding custom KDBX icons) and serialized concurrent native file dialog invocations.

## [0.0.0-alpha.0] - 2026-11-24

Initial tagged alpha release of `neo-keepass` (`nkp` CLI/TUI and experimental `nkpui` desktop UI). See [the `v0.0.0-alpha.0` milestone](docs/milestones/v0.0.0-alpha.0.md) for the full completion checklist and `v0.0.0-alpha.1` roadmap.

### Added

- **CLI shortcuts, `--format human`, and docopt help (`nkp`):**
  - Root shortcuts (`use`, `ls`/`list`, `search`, `show`, `get`, `get many`, `set`, `rm`/`remove`, `ensure`, `otp`, `env`, `import`, `export`, `sync`, `inject`, `trust`, `untrust`, `shell`, `exec`/`x`, `completion`) alongside explicit `secrets`/`automation`/`context`/`alias`/`config`/`files`/`group`/`field` routes.
  - Standardized 88-column docopt-style `--help` across all routes and synced user/reference documentation under `docs/`.
  - `--format human` rendering for metadata routes, `--color`/`--no-color` styling controls, and unified broken-pipe (`EPIPE`) safety across stdout and stderr.
  - Programmable and static completions across 6 shells: `bash`, `sh` (POSIX), `zsh`, `fish`, `powershell`/`pwsh`, and `nushell`.
- **`nkp://` template and `.env` injection:**
  - `nkp://[@vault/]entry[#field|#otp]` URI parser with `%HH` percent-encoding and single-pass template substitution (`nkp inject`).
  - `nkp exec --env-file` (`nkp x --env-file`) for injecting resolved `.env` bindings directly into child processes.
- **Directory-scoped shell integration (`nkp shell` & `nkp trust`):**
  - `.nkp.toml` project manifest (`version = 1`, `[env]` bindings, `env_file`/`env_files`, bounded `inherit = "stop" | "merge"`).
  - Explicit directory trust store (`nkp trust`, `nkp untrust`, `nkp trust list`), revertible environment hook state engine (`nkp shell init|completions|load|unload|status`, `nkp __hook`), and integration for `bash`, `zsh`, `fish`, `powershell`/`pwsh`, and `nushell`.
- **Rune desktop application (`crates/nkpui`):**
  - Cross-platform desktop UI built on pinned `anomalyco/rune` (`unsafe_code = "forbid"`, release builds exclude `tooling`).
  - Vault create/open, group and entry CRUD, tags, custom fields, binary attachments (attach/extract/remove), password generation, TOTP display, search/breadcrumbs, dirty-vault save/discard lock guard, idle and focus-loss auto-lock, and timed clipboard lease clearing.
- **Live KeePassXC interoperability:**
  - Verified live `keepassxc-cli 2.8.0` interop tests (`neotales-keepass` `cli_interop` and `nkeepass` `keepassxc_interop`) and CI lane.

### Changed

- Aligned `nkeepass` (`nkp`) and `nkpui` crate versions and packaging manifests to `0.0.0-alpha.0`.
- Enforced `--locked` Cargo builds across CI and release workflows for both the root workspace and `crates/nkpui`.
- Renamed executable and diagnostic prefix from `nkeepass` to `nkp` while preserving historical `nkeepass` package container identifiers (`tar.gz`, `.zip`, `.deb`, `.rpm`, Arch `pkgname`, `winget`, `choco`).

### Security

- Symlink-safe, bounded file opens (`fs_safe` with `O_NOFOLLOW` / regular-file checks) across CLI vault/config/hook/attachment operations and `nkpui` attachments.
- BiDi override and Unicode line-separator rejection across service metadata and CLI inputs.
- `Zeroizing` buffers for sensitive secret material, hardened `nkp shell load` option parsing, signal-safe TUI terminal restoration, and verified Windows current-user DACL enforcement.
- `nkpui` unlock focus-loss and transient widget wiping, preallocation bounds, and vault-creation password confirmation mismatch checks.

### Release / Packaging

- Added 6-target `.github/workflows/release.yml` building and packaging `nkp` and `nkpui` for `linux-amd64`, `linux-arm64`, `macos-amd64`, `macos-arm64`, `windows-amd64`, and `windows-arm64` with consolidated `SHA256SUMS` and tag-gated GitHub Release publishing.
- Pinned all 54 GitHub Actions `uses:` references across `.github/workflows/` to verified 40-character commit SHAs.
- Validated packaging scripts and manifests (`packaging/scripts/archive.sh`, `packaging/deb/build.sh`, `packaging/rpm/nkeepass.spec`, `packaging/choco/nkeepass.nuspec`, `packaging/winget/Neotales.nkeepass.yaml`, `packaging/validate.sh`, `packaging/test.sh`).
