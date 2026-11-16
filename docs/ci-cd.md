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
| `packaging-tests` | `ubuntu-24.04` | builds the release binary, runs `packaging/test.sh` (real `dpkg-deb` builder path) |
| `audit` | `ubuntu-24.04` | `cargo audit` against the pinned `Cargo.lock` |

**Unix gating of the test matrix:** every integration test file under
`crates/nkeepass/tests/` is `#![cfg(unix)]` — they exercise real file
permissions and terminal password prompts that this checkout does not emulate
elsewhere. The Windows job therefore runs the unit and doc tests only and can
pass while knowing little about Windows behavior. The platform limitation is
unchanged (owner-only secure writes are unsupported on Windows; README
"Current status"); widening Windows coverage means writing `cfg(windows)`
tests, not claiming this job provides it.

**Windows coverage:** the Windows test job runs unsuppressed. Coverage there
is gated by the documented platform limitation (README "Current status"):
owner-only secure file writes are unsupported, so tests exercising vault
creation/mutation, config writes, and CLI output files fail closed with an
explicit unsupported-operation diagnostic. No Windows run of this matrix had
executed at the time of writing, so the actual outcome is unobserved; the job
is left unsuppressed so the first runs report exactly which scenarios fail.
Do not silence them with `continue-on-error` or `#[cfg(windows)]` skips.

**Audit:** `cargo audit` scans the pinned `Cargo.lock`. As of this writing it
reports one vulnerability: RUSTSEC-2023-0071 (`rsa 0.9.10`, Marvin Attack;
fix requires the 0.10 line via `sad-rsa`/`rsa` dependency work). The `audit`
job therefore fails until that is resolved. Triage means upgrading the
dependency or a justified, dated ignore in `audit.toml` — not removing the
job.

## `build.yml` — Linux amd64/arm64 build + packaging

Triggered by tag push `v*` (builds the tag, not the working tree) or manual
dispatch with an optional `ref`. Matrix: `x86_64-unknown-linux-gnu` (native)
and `aarch64-unknown-linux-gnu` (cross-compiled; installs
`gcc-aarch64-linux-gnu`, needed by `ring`'s build script via `rcgen` →
`neotales-x509`; strips with `aarch64-linux-gnu-strip`). Produces, per target:

- `nkeepass-<version>-<target>.tar.gz` / `.zip` (`packaging/scripts/archive.sh`)
- `nkeepass-<version>-<deb-arch>.deb` (`packaging/deb/build.sh`, amd64/arm64)
- validated by `packaging/validate.sh --binary <built>` before upload: every
  target must have the complete set of formats with the expected names, the
  binary in EACH container (tar, zip, deb) is extracted and must be a regular
  non-symlink file with the right ELF architecture, and all containers must
  carry the identical binary (sha256 equal to each other and to the binary
  just built). Deb metadata (package/version/architecture) is checked with
  dpkg-deb on the ubuntu runner. The native target's binary is smoke-run with
  `--help` under `timeout` only after all checks for that target passed — a
  binary that failed any check is never executed. On hosts without dpkg
  tooling the deb metadata is validated structurally via `ar`(1) + `tar`(1);
  `packaging/test.sh` covers the negative cases (wrong ELF architecture,
  wrong deb architecture/version, missing formats, wrong payload binary, and
  a hostile pacman tarball filename that must never reach the generated
  PKGBUILD).

The binary is stripped before packaging. Artifacts are uploaded as
`nkeepass-<target>`. Nothing is attached to a GitHub release.

## `bench.yml` — benchmarks

Manual dispatch only. Runs `cargo bench -p nkeepass` on `ubuntu-24.04` and
uploads `target/criterion` as the `criterion-reports` artifact.

The bench starter is `crates/nkeepass/benches/vault.rs` (criterion 0.8.2,
added as a dev-dependency): glob compile/match, vault create, vault open,
against the pinned `KDBX_LIMITS` with a cheap AES-KDF round count. Honest
caveat, also stated in the bench file: the `vault/*` benchmarks include real
file I/O (temp-directory writes, the unlink create requires because it
refuses to clobber, and the read-back in open), so they measure serialization
plus the host's local disk, not pure CPU work. Run locally:

```sh
cargo bench -p nkeepass --bench vault
```

## Packaging

See `packaging/README.md` for the per-target status table. Summary:
tar.gz/zip/deb are functional and validated in `build.yml` (deb built with
`dpkg-deb` on the ubuntu runner); pacman packages are built by
`packaging/pacman/build.sh` with `makepkg` on Arch hosts — tested locally,
not built in CI (ubuntu runners have no makepkg). The builder rejects any
tarball whose basename is not the canonical `nkeepass-<version>-<triple>`
name, so nothing from the caller-supplied path can reach the generated
PKGBUILD. The rpm spec is real metadata but requires `rpmbuild`, which
neither CI nor this machine has, so it is wired but never built here; the
winget manifest and choco nuspec are stubs with explicit placeholders and are
not submittable or buildable packages.

## Verified locally vs. not

Verified on this machine (Rust 1.98.1 via `rustup run`; the local default
toolchain env is 1.100.0, so every cargo invocation here pins explicitly):
full `cargo test --workspace`, `cargo fmt --check`, clippy, `cargo bench
--bench vault` execution, archive build + re-run idempotency, packaging
self-tests (`packaging/test.sh`: positive validation incl. real `makepkg`
build and smoke run, plus negative cases — wrong ELF arch, wrong deb
arch/version, missing formats — all caught), YAML syntax of all workflows,
cargo audit run.

Not verifiable locally: the aarch64 cross-check compiles only up to the
missing `aarch64-linux-gnu-gcc` (cannot install the cross toolchain without
sudo); `dpkg-deb` is absent on this Arch-based machine (searched `/usr`,
`/opt`, and `~/.local`; no system package was installed), so the real
`dpkg-deb` path of `validate.sh`/`test.sh` runs only on the ubuntu CI runner
— locally the structural `ar`+`tar` fallback is what runs; `actionlint` is
not installed here, so workflow validation is YAML parsing plus manual
review; and the workflows themselves have not been executed on GitHub yet.
First run of `build.yml` on a tag is the real test.
