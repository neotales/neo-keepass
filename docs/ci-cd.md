# CI/CD

Workflows live in `.github/workflows/`. All actions are pinned to commit SHAs
(tag noted in a comment); runners are pinned to specific images. Toolchain is
pinned to Rust 1.98.1 via `rust-toolchain.toml` — do not use `stable` here.

Nothing publishes, pushes, or opens credentials. Artifacts become workflow
artifacts only; there is no release channel yet.

**Timeouts:** every job carries an explicit `timeout-minutes` (otherwise
GitHub's default 360 applies). The values — 20-40 for the fast `ci.yml`
lanes, 60 for the test matrix, build matrix, bench, and the Windows build —
are conservative caps chosen relative to each job's cost drivers (cold
compiles, interpreter runs, advisory-DB fetches); they are not multiples of
measured CI runs, and no CI timing baseline was used. Steps that *execute*
compiled test/binary code also carry a tighter step bound (test step 30,
completion test 15, packaging self-tests 20, RSA lane 30, bench 45) because
that is the class that can block forever on an unread prompt — run
134478538047 (macos-15) hung >75m in a Bash completion PTY test under the
360 default. The RSA lane round-trips against a committed 16,384-bit test
vector — no key generation happens at test time (see the fixture header in
`crates/neotales-age/tests/rsa_16384.rs`) — so its cost is deterministic,
slow-by-design crypto. Compile, build, and package steps get no step-level
timeout on purpose: the job bound covers them, and a slow cold build must
never trip a premature step bound. Windows packaging steps additionally
enforce their own internal deadlines. Bounds cap a hang; they do not
measure performance.

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

**Audit:** `cargo audit` scans the pinned `Cargo.lock` against the advisory
database available at run time; the database is not pinned, so results can
change over time. A fresh local audit on 2026-11-16 scanned 325 dependencies
and exited 0 with no findings. The RSA migration is complete: the lockfile
uses upstream `rsa 0.10.0`, with no dependency fork or advisory ignore.
The CI job stays unsuppressed so future findings fail visibly.

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

**macOS hang of run 134478538047
(`completion::tests::bash_binary_completion_uses_readline_quoting_for_hostile_filenames`):**
the authenticated macOS `test` job ran past 75 minutes on this one test
while the other 133 tests completed, and job cancellation left an orphaned
`python3` child — the test's PTY driver for interactive bash. What the
incident does and does NOT establish: the wedging syscall was never
captured (the job was cancelled before any dump, and no macOS-native
reproduction is available to this checkout), so the standing explanation —
a blocking pty-master `read` after a select-reported readiness that no
longer held, or a blocking `write` into a tty bash had stopped consuming —
is a hypothesis, not an observed fact. The fix therefore bounds every I/O
and lifecycle path instead of patching a platform: the driver keeps the
master fd non-blocking with deadline-bounded writes and kills bash's
process group on every exit path, and the harness runs the driver under
one exit deadline with separate bounded drain/recovery allowances, in its
own process group with a whole-tree kill. Post-review the driver's
cleanup is group-only — a reaped child's pid is never signaled directly,
since it may already be recycled — and a cleanup failure composes with
the case's primary diagnostic instead of masking it;
`bounded_driver_post_reap_cleanup_kills_group_members_only` and
`bounded_driver_cleanup_failure_appends_to_primary_diagnostic` pin
those contracts. The tree kill's python helper is itself waited under
a deadline and killed-and-reaped if it wedges — no wait in the cleanup
path is unbounded. Regression fixtures
(`bounded_driver_kills_wedged_python_within_deadline`,
`bounded_driver_removes_pipe_holding_descendant_no_orphan_survives`)
assert bounded return and by-PID orphan death; both are unix-gated, which
is honest about reach: Windows tree containment is the packaging harness's
job object, not this test helper's, and macOS-native verification of the
fix has not been performed — the hang mechanism is addressed
OS-agnostically, not observed and not skipped.

**macOS completion failure of run 134548307280 (post-bounds):** with the
hang bounds in place, the same test failed fast (~4.15s) instead of
hanging. What the authenticated transcript shows — and all it shows:
sourcing the generated completion succeeded, TAB produced a completion
display, submitting the line returned to the `bash-3.2$` prompt, and
`exit\n` was never echoed or processed after that, so the driver
waited its full 3s exit deadline before the group kill. It does NOT
prove why the completion displayed what it did, and the argv
comparison was never reached. An early parse-abort theory — that
bash 3.2 rejects `local -a vault_args=()` at parse time — is RETRACTED:
it was an artifact of a locally built bash using
`--enable-minimal-config`, which disables array variables entirely
(even a top-level `x=(1 2)` fails to parse there). A full-featured
bash 3.2.57 parses the initializer fine — confirmed independently by
the product reviewer's PTY reproduction (the script sources,
registers, and produces the same re-quoted, misplaced candidate before
and after the mapfile change) and consistent with the transcript's own
"source succeeded". The one genuine 3.2 incompatibility is `mapfile`
(with readarray, new in bash 4.0 per bash-4.0's NEWS): the dynamic
vault/keys paths previously failed every completion with an
unredirected "mapfile: command not found", and while-read accumulators
replace them — pinned by a canary test that drives both dynamic sites
through a stub `nkp` and asserts the accumulated candidates. What
remains version-bound, deliberately: the hostile-filename matrix pins
`compopt -o noquote -o nospace` quoting, expressible only from bash
4.0 on (compopt is new in 4.0 per the same NEWS) — on bash 3.2's
readline 5.2, candidates get re-quoted and inserted into the post-`=`
word slot (`payload\=space\\ name.bin`), so the matrix cannot pass
there. The test therefore gates on the ambient bash major: below 4 it
prints the reason and yields. That yield is quieter than it looks —
libtest captures a passing test's output, so the notice is invisible in
a default `cargo test` run unless the case fails or `--nocapture` is
passed — which is why the macOS leg also exports
`NKEEPASS_REQUIRE_COMPLETION_BASH`, the flag dedicated to this matrix
(unlike `NKEEPASS_REQUIRE_COMPLETION_SHELLS`, which would also demand
the unrelated zsh and PowerShell interpreters): a lost brew bash fails
the matrix loudly instead of yielding silently. The leg installs
Homebrew's bash (resolved through `brew --prefix`, with no hardcoded
install path) and asserts both the prefix resolution and the major
floor, so CI runs the matrix against a real bash >= 4; and because that
PATH change displaces the legacy bash from PATH resolution for the
whole leg, a canary step pins the generated-script parse, boundary, and
dynamic-path tests to the native `/bin/bash` through
`NKEEPASS_COMPLETION_BASH`, with its own version assert so a future
Apple bash upgrade forces a canary revisit rather than silently
testing bash 5 twice. Both filtered `cargo test` steps that name
specific tests — this canary and the completion-interpreters lane's
zsh/PowerShell syntax test — carry a named-run guard: `cargo test
FILTER` exits 0 even when a renamed or mistyped filter matches no test
at all, so each step asserts by full printed name that every intended
test ran and passed, plus the exact expected run count, with pipefail
carrying cargo's own exit code through the captured output. Without
the guard a renamed test would silently void a step's coverage while
the step stays green. The exit-wedge remains the one macOS behavior NOT
reproduced or explained: it did not occur against bash 3.2.57 on Linux,
so it is macOS-PTY-specific or timing-dependent and stays unverified
without a native run; the bounded failure and transcript are the
observation vehicle, and the brew-bash macOS leg now exercises the
matrix for real there.

**Windows failures of run 134548307275 (first matrix test results):**
four unit-test failures, with two distinct proven causes and two left
to diagnostics. (1) `recipient_fetch_disables_curl_globbing...` —
proven: a socket accepted from the non-blocking fixture listener
inherits Winsock's non-blocking mode, so the fixture's blocking request
read panicked with WouldBlock (os error 10035) and curl exited 56
while the fixture thread died; the fixture now sets the accepted
stream to blocking explicitly, and a regression test replays the
exact accept-then-delayed-write sequence the fixture depends on.
(2) `pty_driver_cleanup_owns_the_group_and_composes_failures` — proven
locally by reproducing the exact logged failure under a CRLF-mangled
working copy: the test reads this file's raw bytes with
`fs::read_to_string`, which bypasses the lexer's CRLF→LF
normalization, and the slice-opening assertion has exactly one failure
mechanism — a line-ending shift — so the Windows runner's checkout
carried CRLF (Git's Windows default; this repo has no
`.gitattributes` override). The source text is now LF-normalized
before the slice, with a synthetic CRLF regression. (3 and 4)
`generated_bash_and_posix_scripts_parse...` and
`bash_filename_completion_does_not_cross...` — root cause NOT proven:
CRLF cannot explain them (rustc normalizes CRLF to LF inside string
literals while lexing, verified by mangling this whole file to CRLF and
watching both tests pass), and their silent `exit N` failures carried
no diagnostics. Both tests now report the exit code, both streams, and
the PATH-resolved interpreter's own `--version` and `command -v`
self-report, so the next Windows run identifies which bash answered
and why it disagreed; nothing was skipped or suppressed.

## `build.yml` — Linux amd64/arm64 build + packaging

Triggered by tag push `v*`, manual dispatch with an optional `ref`, or pull
requests. Event-to-checkout semantics:

- `pull_request`: builds the event's `github.sha` — the PR's **merge
  commit** (head merged into the target branch at trigger time). If the PR
  has merge conflicts, the merge ref does not exist and the workflow cannot
  run. Builds of pull requests from forks or by first-time contributors are
  subject to GitHub's untrusted-PR rules (maintainer approval before first
  run; no secrets — this workflow uses none); the checkout persists no
  credentials.
- `push` (tag): builds the tag's commit (`github.sha`), not a movable ref —
  a moved or deleted tag cannot change what a started run built.
- `workflow_dispatch`: an explicit `ref` input selects the branch, tag, or
  SHA; an empty input defaults to `github.sha` (the dispatched branch head).

The pull-request trigger is the credential-free path to exercise the build
and packaging jobs in ordinary development: any pull request runs them — no
tag push, release, or API token required. The `bench` workflow
stays dispatch-only (benchmarks are expensive). Matrix:
`x86_64-unknown-linux-gnu` (native)
and `aarch64-unknown-linux-gnu` (cross-compiled; installs
`gcc-aarch64-linux-gnu`, needed by `ring`'s build script via `rcgen` →
`neotales-x509`; strips with `aarch64-linux-gnu-strip`). Produces, per target:

- `nkeepass-<version>-<target>.tar.gz` / `.zip` (`packaging/scripts/archive.sh`) —
  the archive basenames keep the historical `nkeepass` package identifier;
  the executable inside is the real `nkp` binary name
- `nkeepass-<version>-<deb-arch>.deb` (`packaging/deb/build.sh`, amd64/arm64) —
  deb `Package:` stays `nkeepass`; the executable installs to `/usr/bin/nkp`
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

## `windows-build.yml` — Windows x64 build + packaging

Triggered by manual dispatch and pull requests. Builds the neo-keepass CLI
(executable `nkp`) for `x86_64-pc-windows-msvc` on `windows-2025` with the
pinned toolchain (1.98.1) and `--locked`, so the produced `nkp.exe` links
exactly the committed `Cargo.lock` dependency set. Locked dependencies pin
what is built; they do not make the build reproducible (compiler, runner
image and toolchain are not pinned bit-for-bit), and no byte-identical
output is claimed.

Event-to-checkout semantics are stricter than `build.yml`:

- `workflow_dispatch`: the `ref` input is **required** and must be a full
  40-character **lowercase hex commit SHA**, matched against the ENTIRE
  string (`[[ "$ref" =~ ^[0-9a-f]{40}$ ]]`). No trimming, no case-folding:
  branches, tags, uppercase, whitespace padding and any multiline value are
  rejected (bash `=~` is unanchored by default, so the `^...$` anchors must
  cover every character — an embedded newline or CR cannot match, and no
  sub-line can sneak past). The input crosses as an env var, never by `${{ }}`
  interpolation, and the step outputs exactly the validated immutable SHA.
- `pull_request`: builds `github.sha` — the merge commit (immutable, same
  semantics as `build.yml`).

Verification before anything is executed or uploaded:

1. the built binary's PE header is parsed and its COFF machine field must
   be `0x8664` (AMD64, `packaging/scripts/windows-validate.ps1`);
2. the packaging scripts' self-tests run in the real target environment
   (`packaging/scripts/test-windows-package.ps1`; every script under test
   runs in an isolated pwsh child process so exit codes are always fresh,
   and negative tests assert the diagnostic text, not just the exit code);
3. the produced artifact is verified as a unit
   (`packaging/scripts/windows-verify-artifact.ps1`), in this order:
   - the zip manifest is parsed and WHITELISTED before anything is opened
     for extraction: exactly the four payloads under one named
     `nkeepass-<version>-<triple>/` root, strict filename charset (no
     separators beyond the root, no `..` segments, no absolute paths), no
     duplicates, no directory entries, no symlink external attributes —
     an out-of-root canary entry is never read, let alone extracted
     (regression-tested);
   - central-directory vs local-header agreement and entry types are
     checked against the RAW zip bytes before any entry stream is opened
     (the ZipArchive API does not expose local headers, so they are
     parsed directly): the local header must carry the same name as the
     central directory; the data-descriptor flag (general purpose bit 3)
     must agree between the two headers; and the CRC and sizes must agree
     with the central directory — in the local header when bit 3 is
     clear, in the trailing data descriptor when it is set (descriptors
     are handled, not rejected — the signature is optional, and because a
     signature-less descriptor's CRC can genuinely equal the signature
     value, both layouts are read and the one consistent with the central
     directory decides; a missing, truncated or disagreeing descriptor is
     malformed); DOS
     directory and reparse-point attribute bits and every non-regular
     Unix file type (symlink, directory, fifo, device, socket) are
     rejected; an empty mandatory payload is rejected (all synthetically
     crafted and regression-tested, including crafted descriptor zips —
     signed, signature-less, and with a CRC that collides with the
     signature value — that must verify end-to-end);
   - every whitelisted entry's CRC32 is computed explicitly and compared
     to the recorded value, so an archive corrupted in transit is
     rejected before extraction (regression-tested by patching the
     recorded CRC);
   - extraction is manual from the validated set into a fresh private
     temp dir (paths built from the constant canonical names, never from
     entry strings);
   - the EXTRACTED exe must be PE x64 and its sha256 equal the binary
     just built; the RAW top-level `nkp.exe` must equal the built
     binary AND the archived (extracted) exe and pass the same PE check;
     the raw `WINDOWS-LIMITATIONS.txt` must be byte-identical to the zip
     copy and both copies must carry the mandated fail-closed warning;
   - `SHA256SUMS` must cover exactly the three published names — every
     name is whitelisted against that exact set BEFORE any file it names
     is opened for hashing (traversal and absolute paths never reach the
     filesystem), a name resolving to a reparse point (symlink/junction)
     is rejected even when its recorded hash is correct, every hash must
     match the actual file, and the canonical
     `nkeepass-<version>-<triple>.zip` in the dist dir must BE the file
     that was checked (same resolved path), so the published hash
     describes exactly the artifact that passed the checks (all
     regression-tested);
   - only then is the EXTRACTED exe smoke-run with `--version` and
     `--help` under ONE deadline covering execution and stream
     completion; cleanup is a separate, fixed, bounded allowance after
     the deadline (terminate+join the child ≤5s, join the pipe drains
     after the job close ≤2s each — ≤9s worst case), so the harness can
     never hang but may return up to that allowance past the deadline.
     On Windows job containment is REQUIRED, not claimed: the child is
     born INTO a kill-on-close job object (create-time assignment via
     `PROC_THREAD_ATTRIBUTE_JOB_LIST` — no assignment race and no
     assign-after-create call), stdin is a real handle to NUL, and if
     the job cannot be created or the child cannot be born into it the
     run FAILS CLOSED with the exact Win32 error — it never proceeds
     with only direct-child termination dressed up as a tree kill. The
     job handle is closed in a finally that also terminates the child
     and closes the native handles, so a descendant that outlives the
     parent while holding the redirected pipes cannot survive the
     harness; the one exception is stated where it occurs: after a
     failed drain the undrained pipe read handles are leaked until
     process exit rather than risk a CloseHandle that blocks on the
     escapee's open handles. The smoke-ok line reports the containment
     actually established, asserted natively on Windows, and the orphan
     fixture (spawned with `-NoNewWindow -ErrorAction Stop` so the
     descendant inherits the redirected handles and spawn failures are
     recorded) asserts the escapee's death by PID. Non-Windows smoke
     runs are a test seam: bounded waits, best-effort tree kill,
     containment reported as n/a; failed assertions print the captured
     child output, so a native failure carries its own diagnostic.

A binary that failed any check is never executed, and a mismatching
artifact never reaches upload.

Produces one artifact, `nkeepass-x86_64-pc-windows-msvc` (retention 14
days): `nkeepass-<version>-x86_64-pc-windows-msvc.zip` (one named root:
binary, README, LICENSE, WINDOWS-LIMITATIONS.txt), the raw `nkp.exe`,
`WINDOWS-LIMITATIONS.txt`, and a sha256sum-compatible `SHA256SUMS`
(`<hex>  <name>`, LF endings — `sha256sum -c` works on Linux/macOS).
Publication is NOT atomic and is not documented as one: the packager
invalidates `SHA256SUMS` first, publishes the payload files, and writes
the manifest last. Invalidation is a hard step: if the existing manifest
cannot be removed (locked by a scanner, ACL-denied), the run FAILS
BEFORE touching any payload file, so the old set stays untouched and
self-consistent. An interrupted run can otherwise leave a mixed set of
old and new payload files with NO manifest — never a manifest describing
a set it does not match; a consumer must treat a missing or failing
`sha256sum -c` as fatal. Both failure modes are regression-tested via
injected failures: `NEOKEEPASS_PACKAGE_FAIL_AFTER` (test-only) fails
after a payload publish, and the self-tests lock the manifest (Windows)
or make the output directory unwritable (Unix) to prove the abort
happens before any file update.
Nothing is attached to a release; no secrets are used; permissions are
`contents: read` and checkout persists no credentials.

**Windows platform limitation (stated plainly):** secure owner-only file
writes are UNSUPPORTED on Windows, and nkp FAILS CLOSED. The
implementation cannot safely replace and verify a full ACL (icacls
`/inheritance:r /grant:r` does not remove explicit grants to other
principals), so on Windows it refuses to write any file it cannot make
private: vault creation/mutation, config writes, and CLI output-to-file
exit with an explicit unsupported-operation diagnostic — these operations
are unavailable on Windows, not "less protected". There is no
inherited-ACL fallback and no permission parity with Unix, and none may be
claimed. What works on Windows: reading existing vaults and stdout output.
The warning ships inside the artifact as `WINDOWS-LIMITATIONS.txt`
(source: `packaging/windows/WINDOWS-LIMITATIONS.txt`). Do not describe
Windows artifacts as protected by file permissions anywhere.

**Coordination with the release pipeline:** the release work builds
Windows archives with its own `archive-windows.ps1`; this workflow uses
`packaging/scripts/windows-package.ps1`. They are separate implementations
and must not diverge in their user-visible contract: archive name
`nkeepass-<version>-x86_64-pc-windows-msvc.zip` (the `archive.sh`
convention), payload `nkp.exe` + `README.md` + `LICENSE.md` +
`WINDOWS-LIMITATIONS.txt` under one named root, and a sha256sum-compatible
`SHA256SUMS` (`<hex>  <name>`, LF, forward slashes). Change both together
or not at all — and before the release pipeline lands its Windows steps,
the two workflows must be reconciled (or the shared packaging lifted into
one script), or runs will race on the same artifact names and formats.

**Tooling note:** the packaging scripts are PowerShell 7 (`pwsh`). The
dev host has no system pwsh but runs the suite through a portable pwsh
7.6.10 (`test-windows-package.ps1`), so the scripts — including their
failure paths — execute locally; the `windows-build.yml` runner re-runs
the same suite in the real target environment on every build.

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
neither CI nor this machine has, so it is wired but **never built and not
build-verified** — the only automated check is the crate-version wiring in
`validate.sh`; the winget manifest and choco nuspec are stubs with explicit
placeholders and are
not submittable or buildable packages.

Naming compatibility: the product is neo-keepass and its executable is
`nkp` (`nkp.exe` on Windows). Package identifiers and archive names
deliberately keep the historical `nkeepass` name — archive basenames and
zip root `nkeepass-<version>-<triple>`, deb `Package:` and `.deb` file
name, rpm `Name:`, pacman `pkgname`, winget/choco identifiers — while the
executable inside every container is shipped as `nkp` / `nkp.exe` and
installed as `/usr/bin/nkp`. See `packaging/README.md`.

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
`cargo audit` (2026-11-16: exited 0, 325 dependencies scanned, no findings).

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

**Windows-native caveats of the packaging gate (stated plainly):** the
C# helpers of `windows-verify-artifact.ps1` are compiled as ONE Add-Type
on every host with the exact source the Windows runner compiles, so C#
syntax errors there fail on the Linux dev host too (the CS1529 class:
a using clause after a type declaration broke only the Windows
concatenation and was invisible locally until the first runner run).
The first native Windows execution of the smoke harness (run
44201279798) failed every `-Smoke` test while every byte-level
zip/SHA256SUMS test passed; the redacted log of the second native run
(44206164232, integrated commit 58d6395) carried the exact failure the
diagnostics were built for: every smoke call failed before child start
at `SetInformationJobObject` with Win32 error 87
(ERROR_INVALID_PARAMETER). Root cause, confirmed against the Microsoft
docs for `JOBOBJECT_BASIC_LIMIT_INFORMATION`: the constant named
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` carried the value 0x00000200 —
which is `JOB_OBJECT_LIMIT_JOB_MEMORY` — so the call set a
job-committed-memory limit of zero, which the kernel rejects; the real
KILL_ON_JOB_CLOSE value is 0x00002000. The wrong value had been present
since the first version of the script, and it explains both failed
native runs. The fix is that one value (fail-closed behavior
unchanged); the job structs are now public and the suite asserts the
documented x64 layout portably (sizes 64/48/144, field offsets at
16/40/48/56/60 and 64/112/136, flag == 0x2000), and the
SetInformationJobObject failure diagnostic names the struct size, the
information class and the flags value, so a future native failure of
this call is self-describing. What a Linux host still cannot do is
EXECUTE the Windows process machinery: the fix is compile- and
layout-verified locally, and the next windows-2025 run is the
behavioral confirmation. The same holds for the negative test that
needs symlink creation where unavailable. The suite reports these skips
by name instead of passing silently.
