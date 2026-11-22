# terminal-password

Small synchronous input boundary for `nkp set`'s hidden value prompt and the
Unix TUI's vault-password prompt and terminal-mode handoff.

`rpassword`'s blocking reader cannot be safely abandoned on timeout. A worker
thread would retain a terminal reader after the caller returned. Crossterm's
shared event reader and Windows cooked-mode reconstruction are not an exact
saved-mode restoration boundary. This crate instead owns one synchronous
reader, waits against an absolute deadline, and restores the actual saved mode.
It does not replace the CLI's unrelated vault-password path or the TUI event
reader. Windows TUI startup remains on its existing rpassword/Ratatui lifecycle.

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

## Unix TUI lifecycle

`read_controlling` uses the same reader, cancellation handlers, deadline and
staged restoration as `read`, but opens `/dev/tty` instead of stdin. This keeps
the TUI password prompt's existing terminal selection. It writes
the supplied prompt only after quiet mode and its restoration guard are active:
prompt visibility is readiness to send a password, not a request to wait for
echo to turn off. Prompt output uses a separately opened `O_NONBLOCK` terminal
description, never changes inherited stdout's open-file-description flags, and
shares the input's absolute deadline and scoped signal cancellation. Writes are
bounded chunks; interrupted/would-block retries recheck cancellation/deadline
and wait for readiness in at most 100 ms slices. There is no output-drain wait,
buffered flush, or background writer. Prompt timeout, cancellation and output
failure all run staged exact-mode restoration. No unbounded trailing-newline
write is attempted after return (in particular after timeout/cancellation).
The TUI prompt now has a
five-minute deadline; Enter submits and Ctrl-C, Ctrl-D or Escape cancels. Queued
password tails are intentionally discarded, not fed to the TUI as commands.

`QuietTerminal` captures the frontend's mode terminal before Crossterm captures
its raw-mode snapshot. The saved backend snapshot has echo, signals and extended
input handling disabled. Ratatui's normal restore and panic hook therefore
cannot replay raw typeahead under the original echo or signal settings.
After backend teardown, the guard uses the same quiet transition, input-only
flush and exact restoration described below. Successful restoration is
idempotent; Drop does not flush a second owner's input.
On normal/error returns the TUI attempts backend raw-mode restoration, alternate
screen exit, and exact-mode restoration independently and in that order, retaining
all errors. A backend mode failure cannot prevent the screen-exit write. Screen
exit writes only LeaveAlternateScreen, never a primary-screen erase. The existing
Ratatui panic hook remains a best-effort fallback, not this fault-tested return
path.

The TUI intentionally discards queued exit typeahead, including bytes typed
after `q` in the same burst. This is an input-ownership handoff, not a promise
to hide input arriving after the quiet flush. No output flush, primary-screen
erase or scrollback clear is used. Original mode flags (including an originally
set PENDIN), control characters and speeds are restored without normalization.
The caller must exclusively own backend mode changes and readers. This adds
no TUI-wide signal handler and does not resolve split-terminal routing or
external-signal cleanup of a running TUI.

`cargo test -p terminal-password` runs bounded Unix PTY tests. Windows builds
run `tests/windows_console.rs`, using disposable child consoles for submission,
cancellation, timeout and exact-mode restoration. These Windows tests have
been added but were **not compiled or executed on the Linux implementation
host**. Native Windows validation is a release gate, not an inferred pass.

The short-duration tests exercise the same deadline loop as the CLI's fixed
60-second timeout without making every test wait a minute.
Stalled-prompt subprocess tests saturate a synthetic PTY without draining its
master, then call `read_controlling` with a large synthetic prompt. They require
deadline timeout and signal cancellation, exact modes before session-leader
exit, unchanged inherited input/stdout status flags and bounded process exit.
The parent kills/reaps any regressed blocking writer; no test reader/writer
thread is detached. Removing `O_NONBLOCK` reproduces the stalled-writer failure.

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

## Darwin file-status flags and PTY diagnostics

At `7be4e11503a735c0fad3a81abd17dd1186307580`, macOS
[run 44622094675](https://github.com/neotales/neo-keepass/actions/runs/44622094675)
reported input `F_GETFL` changing from `0x2` to `0x10002`, despite prompt
success and exact termios restoration. The extra bit is **`FWASWRITTEN`
(`0x10000`)**, not `O_NONBLOCK` (Darwin `0x4`). It is kernel write history,
not a user-settable mode:

- XNU [`bsd/sys/fcntl.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/fcntl.h)
  defines `FWASWRITTEN`, the `OFLAGS` conversion, and the narrower `FCNTLFLAGS`
  settable mask.
- [`fp_writev` in `bsd/kern/sys_generic.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/sys_generic.c)
  sets it after a write transfers bytes, including ordinary `write` calls.
- [`F_GETFL` in `bsd/kern/kern_descrip.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_descrip.c)
  returns `OFLAGS(f_flag)` without removing that bit.

The old harness used `try_clone` for all three child streams: these duplicates
share the parent's input open-file description. Libtest output and worker
diagnostics therefore mark **input** as written. The Unix product reader does
not write or call `F_SETFL`; changing it to reset or mask this bit would conceal
a harness error, not restore a caller-controlled flag.

The harness now reopens the same PTY slave with `O_NOCTTY | O_CLOEXEC` for
stdout/stderr. Output still reaches the PTY master for live draining and echo
scanning; terminal modes remain shared, but output status/history is independent
of stdin. It retains **raw, exact** input `F_GETFL` comparisons before, during,
and after the prompt, adds `F_GETFD` comparisons, and snapshots worker flags
immediately around the product call before printing diagnostics. Failures show
hexadecimal before/active/after flags and XOR deltas.

A no-reader native macOS regression writes through a duplicate to reproduce
`FWASWRITTEN` directly. A cross-platform regression checks that output writes
and `O_NONBLOCK` changes cannot affect input while termios and PTY output
remain shared. Using the old duplicate in that regression failed on Linux
(`0x2` became `0x802`), proving descriptor coupling independently of Darwin's
write-history behavior. Prompt scenarios also cover initially nonblocking
stdin on success and timeout without relaxing secrecy or exact restoration.
Native macOS execution of this fix and its Darwin-only regression remains
required; Linux validation cannot confirm Darwin kernel behavior.
