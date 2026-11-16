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

**Workflow run blocks:** `scripts/check-workflows.sh` (run in the `lint` job)
fails any `run:` block that uses a backslash line continuation outside a
block scalar — YAML plain scalars fold the newline into a space, turning a
trailing backslash into an escaped space, which is valid bash with the wrong
semantics — and `bash -n`-checks every rendered `run:` with `${{ }}`
expressions substituted.

**Windows coverage:** the Windows test job runs unsuppressed. Coverage there
is gated by the documented platform limitation (README "Current status"):
owner-only secure file writes are unsupported, so tests exercising vault
creation/mutation, config writes, and CLI output files fail closed with an
explicit unsupported-operation diagnostic. No Windows run of this matrix had
executed at the time of writing, so the actual outcome is unobserved; the job
is left unsuppressed so the first runs report exactly which scenarios fail.
Do not silence them with `continue-on-error` or `#[cfg(windows)]` skips.

**Audit:** `cargo audit` scans the pinned `Cargo.lock` and currently reports
one vulnerability, RUSTSEC-2023-0071 (`rsa 0.9.10`, Marvin Attack; patched
only in the 0.10 line). The `audit` job is left failing on it honestly:
there is no suppression in this repository. The exact state, reviewed
2026-11-16:

- Reachability: `rsa` 0.9.10 is on the decryption path. The vendored crates
  use it for key parsing/serialization (`PrivateKeyParts` reads of `d` and
  the primes) whose secret-dependent private-key preprocessing feeds the
  hardened implementation, plus public-key verification and OAEP encryption.
  The blinded private-key exponentiation itself runs in the maintained
  `sad-rsa` fork (`decrypt_blinded`), so the advisory's unblinded-decrypt
  oracle is not directly present — but secret-dependent private-key
  preprocessing does run in `rsa` 0.9 code, and that is exactly what a
  "public-key only" claim would wave away.
- Exploitability: **no proven exploit** has been demonstrated for this
  usage; the exposure is an unquantified subset of the advisory's attack
  class, not a clear absence of it.
- Upgrade: unresolved. `rsa` 0.10.0 (the patched line) removed the `sha2`
  feature the vendored crates depend on and requires migrating the vendored
  `neotales-age`/`neotales-x509` source, which must follow those crates'
  upstream. Until that migration lands, the advisory stands and the audit
  job fails. Do not add an ignore; do not describe the advisory as resolved
  or accepted.

**Windows failure of run 43846609261 (first Windows execution):** the `Test`
step failed with exit code 101. What public data shows and what it cannot:
the REST log endpoint requires admin rights (403), the web log fragments
404 anonymously, check-run annotations carry only the exit code, and
artifacts require authentication (401) — the failing test is not identifiable
without credentials. Local reproduction is equally blocked: the `ring` and
`alloca` build scripts cannot run for a Windows target without MSVC/mingw,
which this machine cannot install. Mitigation in `ci.yml`: the test matrix
runs three steps — `Check` (`cargo check --all-targets`: type-checks every
target including the Windows-only `cfg(windows)` code and runs dependency
build scripts, but does not link), `Test compile` (`cargo test --no-run`:
fully builds the test binaries including linking, but does not compile
doctests), and `Test` (compiles and runs lib/bin/integration tests plus
doctests; runtime errors and doctest compile errors surface only here).
This **narrows, but does not conclusively distinguish**, the cause: a Check
failure is a compile defect (Windows-only `cfg(windows)` code compiles
nowhere else); a Test-compile failure is a test-binary build/link defect; a
Test failure with both predecessors green is an assertion failure, a doctest
compile error, or a runtime error.

## `build.yml` — Linux amd64/arm64 build + packaging

Triggered by tag push `v*` (builds the tag, not the working tree), manual
dispatch with an optional `ref`, or pull requests (builds the PR's merge
commit). The pull-request trigger is the credential-free path to exercise
the build and packaging jobs in ordinary development: any pull request runs
them — no tag push, release, or API token required. The `bench` workflow
stays dispatch-only (benchmarks are expensive). Matrix:
`x86_64-unknown-linux-gnu` (native)
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
arch/version, missing formats, wrong payload binary, symlink tar member,
modified/missing pacman payload, hostile pacman filename, smoke-withheld
markers — all caught, run both with the structural ar+tar deb fallback and
with a temporary real `dpkg-deb` via PATH), workflow run-block checking
(`scripts/check-workflows.sh`, incl. expression-scanner selftest), and
`cargo audit` (currently exits 1 on RUSTSEC-2023-0071 — the honest result;
there is no ignore in this repository).

Not verifiable locally: the aarch64 cross-check compiles only up to the
missing `aarch64-linux-gnu-gcc` (cannot install the cross toolchain without
sudo); `dpkg-deb` is absent on this Arch-based machine (searched `/usr`,
`/opt`, and `~/.local`; no system package was installed), so the real
`dpkg-deb` path of `validate.sh`/`test.sh` runs only on the ubuntu CI runner
— locally the structural `ar`+`tar` fallback is what runs; `actionlint` and
the temporary `cargo-audit`/`dpkg-deb` binaries used for verification are
downloaded tools under `/tmp/opencode`, not installed system-wide and not
repo dependencies; and the workflows themselves have not been executed on
GitHub beyond the first `ci` run. First run of `build.yml` on a tag is the
real test.
