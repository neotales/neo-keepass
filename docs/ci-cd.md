# CI/CD

Workflows live in `.github/workflows/`. All actions are pinned to commit SHAs
(tag noted in a comment); runners are pinned to specific images. Toolchain is
pinned to Rust 1.98.1 via `rust-toolchain.toml` — do not use `stable` here.

Nothing publishes, pushes, or opens credentials. Artifacts become workflow
artifacts only; there is no release channel yet.

## `ci.yml` — test matrix, lint, audit

Triggered on push to `main`/`dev`, pull requests, and manual dispatch.

| Job | Runner | Runs |
|-----|--------|------|
| `test` | `ubuntu-24.04`, `macos-15`, `windows-2025` | `cargo test --workspace` |
| `lint` | `ubuntu-24.04` | `cargo fmt --check`, `cargo clippy --workspace --all-targets` |
| `audit` | `ubuntu-24.04` | `cargo audit` against the pinned `Cargo.lock` |

**Windows status (exact):** the Windows test job runs unsuppressed and is
expected to fail today. This checkout does not support owner-only secure file
writes on Windows — the implementation cannot safely replace and verify the
full ACL — so vault creation/mutation, config writes, and CLI output-file
operations fail closed with an explicit unsupported-operation diagnostic
(README "Current status"). Tests that exercise those paths fail on
`windows-2025` by design. Do not add `continue-on-error` or `#[cfg(windows)]`
skips to hide this; the red job is the tracking signal.

**Audit status:** as of this writing `cargo audit` reports one vulnerability:
RUSTSEC-2023-0071 (`rsa 0.9.10`, Marvin Attack; fix requires the 0.10 line via
`sad-rsa`/`rsa` dependency work). The `audit` job therefore fails until that
is resolved. Triage means upgrading the dependency or a justified, dated
ignore in `audit.toml` — not removing the job.

## `build.yml` — Linux amd64/arm64 build + packaging

Triggered by tag push `v*` (builds the tag, not the working tree) or manual
dispatch with an optional `ref`. Matrix: `x86_64-unknown-linux-gnu` (native)
and `aarch64-unknown-linux-gnu` (cross-compiled; installs
`gcc-aarch64-linux-gnu`, needed by `ring`'s build script via `rcgen` →
`neotales-x509`). Produces, per target:

- `nkeepass-<version>-<target>.tar.gz` / `.zip` (`packaging/scripts/archive.sh`)
- `nkeepass-<version>-<deb-arch>.deb` (`packaging/deb/build.sh`, amd64/arm64)
- validated by `packaging/validate.sh` before upload

The binary is stripped before packaging. Artifacts are uploaded as
`nkeepass-<target>`. Nothing is attached to a GitHub release.

## `bench.yml` — benchmarks

Manual dispatch only. Runs `cargo bench -p nkeepass` on `ubuntu-24.04` and
uploads `target/criterion` as the `criterion-reports` artifact.

The bench starter is `crates/nkeepass/benches/vault.rs` (criterion 0.8.2,
added as a dev-dependency): glob compile/match, vault create, vault open,
against the pinned `KDBX_LIMITS` with a cheap AES-KDF round count so the
numbers reflect envelope work, not KDF cost. Run locally:

```sh
cargo bench -p nkeepass --bench vault
```

## Packaging

See `packaging/README.md` for the per-target status table. Summary:
tar.gz/zip/deb are functional and validated in `build.yml`; rpm spec and
pacman PKGBUILD are real metadata but are not built in CI; winget manifest
and choco nuspec are stubs with explicit placeholders and are not submittable
or buildable packages.

## Verified locally vs. not

Verified on this machine (Rust 1.98.1): full `cargo test --workspace`,
`cargo fmt --check`, clippy, `cargo bench --bench vault` execution, archive
build + re-run idempotency, validation failure path (corrupt archive), YAML
syntax of all workflows, cargo audit run.

Not verifiable locally: the aarch64 cross-check compiles only up to the
missing `aarch64-linux-gnu-gcc` (cannot install the cross toolchain without
sudo); `dpkg-deb` is absent here so the deb path was not exercised locally —
it runs on the `ubuntu-24.04` CI image; and the workflows themselves have not
been executed on GitHub yet. First run of `build.yml` on a tag is the real
test.
