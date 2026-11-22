# Shared CLI test support

## UI PTY checks

`cargo test -p nkeepass --test tui_ui` runs `tui_ui_pty.py` via Python 3 on
Linux and macOS only. Both this test crate and its `rustix` dev dependency are
gated to those targets; other Unix targets (including OpenBSD, where this
`waitid` API is absent) and Windows do not compile or run this harness. This is
test scope, not a change to the application's supported platforms.
Every case uses its own disposable vault, HOME/config/data paths, and PTY;
display/clipboard environment access is removed. Captured terminal data is
never printed. The small cursor/erase emulator checks visible cells at 40×12.
Coverage includes disclosure focus, generation consent, long indexed targets,
selected attachment removal/export, and an actionable failed-save decision.
The 40×12 field-navigation case checks selection beyond the compact viewport
and the named target in its reveal prompt before consent. A private reducer
test expires a real lease with a fake clipboard adapter while confirmation is
open, covering successful, refused, and failed clears without clipboard access.
The long-field PTY case inspects two colliding name suffixes before consent,
then verifies only the second field is revealed. Private workflow coverage
confirms a replacement password with a failed-clear warning pending, overwrites
status/refreshes, and checks full warning review and explicit acknowledgement.
Private modal tests check that warning return/acknowledgement restores target
position and deletion drafts, repeated F3 does not nest, and dirty exit/lock
dialogs expose the warning shortcut at the minimum size.
Exact pagination/error retention and projection branches live in `tui.rs` tests.

The Python driver owns the controlling-terminal session until after it checks
the exited app's terminal attributes. Making the app the session leader caused
all seven UI cases in macOS CI run `44962432310` (`4be59aa`) to fail after their
behavior/exit/alternate-screen checks: final `tcgetattr(slave)` raised ENOTTY.
Darwin revokes the controlling terminal on session-leader exit (XNU
`bsd/kern/kern_exit.c`, `SESS_LEADER` / `VNOP_REVOKE` branch).
The driver now stays alive as session leader and launches the app in that
foreground session, like a shell launching an ordinary child. SIGHUP is ignored
only during final driver cleanup, never inherited by the app. Exact termios
equality remains required. A portable lifetime probe checks child session
inheritance and post-exit inspection; negative controls leave ECHO changed and
probe a nonterminal descriptor, ensuring restoration/ioctl failures still fail
with sanitized stage/errno diagnostics rather than captured terminal data.

All master reads/writes are nonblocking. Key sends and cursor-position replies
share a partial-write loop bounded by the case's absolute deadline (20 seconds
for UI cases). Rust separately bounds each Python driver's lifetime to 45
seconds, captures at most 64 KiB per stream from regular files rather than
waiting for pipe EOF, and bounds cleanup observations and observer cleanup
separately (up to seven more seconds including a stalled metadata helper).
A per-run private handshake directory gates app creation: the driver publishes
its session identity, then waits for Rust to verify SID/PGID against its owned
child PID and explicitly grant permission. No app can be spawned before that
permission, including if timeout races session setup.

Unix test support uses the already-locked `rustix` version for safe signaling
and Darwin-compatible `waitid(WNOWAIT)`. Neither polling nor TERM grace reaps
the driver. Once a session is verified, cleanup always issues group KILL while
the leader remains waitable—even if TERM already exited it. Only then is the
leader reaped. Bounded signal-0/metadata observations must then establish
either group absence or a nonempty, positively observed zombie-only group.
EPERM alone is neither absence nor proof of death. Metadata-only `ps` reads
PID/PGID/state, never arguments or environment; unknown, truncated, empty, or
live-member snapshots do not justify a zombie-only verdict.
Before verification no permission can have
been issued, so direct-child-only cleanup cannot race app creation. No
terminating group signal is sent after leader reap.

Negative controls stop a raw-mode child without reading: both large key sends
and cursor replies must hit their write deadline, not the outer watchdog.
A stopped-driver control exercises the outer deadline and graceful cleanup.
Startup controls pause before session creation and after session verification
with permission withheld, asserting no app appears. Another control makes the
driver exit on TERM while its app ignores TERM and HUP. It observes the exited
but unreaped leader alongside the app's retained PID and requires group KILL
before leader reap. It verifies the app/group are absent or positively observed
as zombies, never still running. A retained orphan zombie is **not** reported
as reaped: only the owned leader has been reaped by this harness. A separate
fixture deliberately retains its exited child with WNOWAIT, verifies PID
existence and zombie classification, then actually reaps that owned fixture.
Stopped-reader controls still require their driver-reaped child to be gone;
all watchdog controls preserve an independently owned bystander.
The harness does not print transcripts or send terminating
signals to reaped PIDs; signal 0 is used only to observe the fixture child's
absence.

This is UI coverage, not proof of terminal admission, signal safety, or
Crossterm event-reader identity. No split-terminal or signal machinery is
changed here. Linux was exercised; Windows and macOS runtime behavior is
unverified. Windows startup is not disabled by this patch.

`cli_support.rs` is the library's disposable KDBX fixture and its byte-level
secret-leak checks, copied verbatim from the library crate. `tests/cli.rs`
includes it and maps every scenario to this executable.

## Why it is a copy and not a path

It was originally reached with a `#[path]` attribute pointing into the library
submodule's test support directory. It is now a versioned dependency on a
*published crate*, and neither arrangement works:

- A published crate is unpacked into the cargo registry cache, and its path is
  machine-specific and hash-suffixed. A `#[path]` into that cache is not
  portable across machines or Cargo versions, and may not exist before the
  first build.
- The crate's own `tests/` directory is not part of its public API, so
  referencing it from a dependency is reaching into a private tree.

So it is a copy, and that is a real cost: **this copy and the library's can
diverge.** When the library updates its scenarios, this file does not, and the
divergence is invisible because both compile.

## What to do when they diverge

1. Copy the library's `tests/support/cli_support.rs` over this one.
2. `diff` before committing. A change here is a change in what this repository
   asserts, and it deserves its own commit message.
3. If the library's scenarios changed in *shape* rather than in content, the
   adapter in `tests/cli.rs` needs updating too -- `Scenario` arms map to real
   commands, so a new scenario is a new arm or an existing arm stops matching.

The `Scenario` list is the contract. A scenario this repository has not mapped
is a scenario that is not being tested here, and the test that would have
noticed is the one that stops compiling.
