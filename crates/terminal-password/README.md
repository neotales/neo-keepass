# terminal-password

Small synchronous input boundary for `nkp set`'s hidden value prompt.

`rpassword`'s blocking reader cannot be safely abandoned on timeout. A worker
thread would retain a terminal reader after the caller returned. Crossterm's
shared event reader and Windows cooked-mode reconstruction are not an exact
saved-mode restoration boundary. This crate instead owns one synchronous
reader, waits against an absolute deadline, and restores the actual saved mode.
It does not replace the CLI's unrelated vault-password or TUI input paths.

- Unix: safe nix termios, poll and read calls; a restoration guard; temporary
  scoped sigaction cancellation handlers for SIGINT/SIGTERM/SIGHUP/SIGQUIT.
  Complete prior signal actions (handlers, masks and flags) are restored after
  the prompt; merely unregistering a signal-hook callback would not do that.
  No signal thread. Input polling is capped at 100 ms to observe cancellation.
  `VMIN=VTIME=0` bounds each individual read, including stale/spurious readiness;
  zero-byte reads without hangup mean no input, not EOF. Shared descriptor
  status flags are never changed by the reader.
- Windows: a narrowly isolated unsafe Win32 boundary. Save `GetConsoleMode`,
  disable echo/line/processed input, then `WaitForSingleObject` and
  `ReadConsoleInputW`. Restore the exact saved bitmask, not guessed cooked-mode
  defaults. No crossterm event reader, overlapped read, or background thread.
- Enter submits; Ctrl-C, Ctrl-D and Escape cancel. Unicode backspace is
  supported; input is bounded and held in zeroizing buffers.
  On Unix, a quiet canonical/raw transition and input-only flush discard queued
  typeahead before echo/signals are restored.
- A process-wide try-lock refuses concurrent calls. Callers must not run an
  independent input consumer at the same time.
  Callers must also avoid concurrently replacing process-wide signal actions.
- OS restoration failures are errors; drop retries restoration. Uncatchable
  process termination, including SIGKILL and forced Windows process termination,
  cannot run cleanup.

`cargo test -p terminal-password` runs bounded Unix PTY tests. Windows builds
run `tests/windows_console.rs`, using disposable child consoles for submission,
cancellation, timeout and exact-mode restoration. These Windows tests have
been added but were **not compiled or executed on the Linux implementation
host**. Native Windows validation is a release gate, not an inferred pass.

The short-duration tests exercise the same deadline loop as the CLI's fixed
60-second timeout without making every test wait a minute.

## Canonical restoration on macOS and BSD

Darwin's `TIOCSETA` implementation forces `PENDIN` on when changing from raw to
canonical input, even when there is no pending input. It ORs that state into
the supplied termios flags, so repeating `tcsetattr(TCSANOW)` does not clear it.
See `ttioctl_locked` and `ttyflush` in Apple's
[`bsd/kern/tty.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/tty.c).

Restoration is ordered as three operations:

1. Set the saved canonical/raw discipline with `ECHO`, `ECHONL`, `ISIG`,
   `IEXTEN`, `IXON` and the requested `PENDIN` disabled. Darwin may generate
   `PENDIN` during this transition; any replay or arriving input is still
   private and cannot generate terminal signals or interpret start/stop bytes.
2. Use input-only `tcflush(TCIFLUSH)` to clear queued input and generated
   `PENDIN` **while still quiet**.
3. Restore the complete saved attributes. Canonical mode no longer changes,
   so this step does not generate another `PENDIN`; an originally set bit is
   explicitly preserved.

There is no post-restoration flush with echo/signals enabled. The previous
flush/original-mode/flush sequence left a window in which arriving input could
be replayed visibly before the second flush. Empty queues afterwards did not
prove that input had stayed hidden.

The quiet flush is the input-ownership handoff. Input arriving after it is
future-consumer input, not guaranteed discarded: restoring an originally set
`PENDIN` deliberately restores its normal replay semantics too. This API
cannot atomically exclude physical input across separate POSIX calls or
promise that input arriving after handoff stays hidden. Callers must not
concurrently change modes or read stdin during the operation.

These operations do **not** wait for output, unlike `TCSAFLUSH`/`TCSADRAIN`.
Preparation errors short-circuit before enabling the saved echo/signals; the
unwind guard retries the same staged sequence, with no unsafe direct-mode
fallback. Persistent OS errors are reported and may prevent full restoration.

The macOS CI failure at `fcb669e` reported only a worker that failed to exit
within five seconds. The old parent did not drain the PTY until after exit:
an assertion plus backtrace could block its worker writing diagnostics. A
controlled oversized diagnostic reproduces that harness failure on Linux;
the Darwin `PENDIN` transition is a source-backed explanation for the hidden
mode assertion, **not a native macOS reproduction on this Linux host**.

The parent now drains nonblocking output while waiting, retains a bounded
64 KiB diagnostic tail, scans for echo even after that limit, and kills/reaps
workers on failure. Diagnostics include the scenario, process ID, elapsed
time, terminal attributes and worker progress. Tests keep the 300 ms reader
and five-second parent deadlines, and compare complete termios values without
masking `PENDIN`. They cover original cooked/raw modes, an originally set
`PENDIN`, descriptor-flag preservation, partial-input timeout, hidden
typeahead disposal, signal restoration, and a controlled assertion failure
with output larger than PTY capacity. Native macOS CI must still validate the
kernel-specific restoration path.

Transition tests inject both AFTER-* sentinels before and between the mode
operations, acknowledge their arrival in the real PTY discipline, and scan
actual output as well as checking the final queue and full saved attributes.
Readiness queries force native Darwin `PENDIN` processing while the transition
must still be quiet. The input-injection test reproduced visible sentinel
output with the old ordering on Linux. Fault-injection tests also prohibit
reenabling saved flags after preparation failure. The subprocess scanner
checks both tail sentinels across read boundaries and keeps detecting echo
after its retained transcript overflows.
